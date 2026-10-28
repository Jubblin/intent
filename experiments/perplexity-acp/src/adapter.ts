import { randomUUID } from "node:crypto";
import { Peer, RpcFailure } from "./jsonrpc.ts";

export type Mcp = { callTool(name: string, args: Record<string, unknown>): Promise<any> };

type Session = {
  id: string;
  threadId?: string;
  cancelled: boolean;
  seenSteps: Map<string, string>;
};

export type AdapterOptions = {
  pollMs?: number;
  mode?: string;
  hasCredentials?: () => boolean;
  cancelPolls?: number;
  /** Max wait for the client's answer to session/request_permission; expiry is a DENY. Default 120000. */
  permissionTimeoutMs?: number;
};

const TERMINAL = new Set(["completed", "cancelled", "failed", "error"]);

/**
 * ACP agent backed by Perplexity Computer over MCP. EXPERIMENTAL.
 * No fs/terminal methods: Computer runs remotely, so those client capabilities are not used.
 */
export class PerplexityAgent {
  private sessions = new Map<string, Session>();
  private peer: Peer;
  private mcp: Mcp;
  private o: Required<Pick<AdapterOptions, "pollMs" | "cancelPolls" | "permissionTimeoutMs">> & AdapterOptions;

  constructor(peer: Peer, mcp: Mcp, opts: AdapterOptions = {}) {
    this.peer = peer;
    this.mcp = mcp;
    this.o = { pollMs: 3000, cancelPolls: 5, permissionTimeoutMs: 120_000, ...opts };
    peer.onRequest("initialize", () => this.initialize());
    peer.onRequest("authenticate", () => this.authenticate());
    peer.onRequest("session/new", () => this.newSession());
    peer.onRequest("session/load", (p) => this.loadSession(p));
    peer.onRequest("session/prompt", (p) => this.prompt(p));
    peer.onNotification("session/cancel", (p) => void this.cancel(p?.sessionId));
  }

  private initialize() {
    return {
      protocolVersion: 1,
      agentCapabilities: { loadSession: true, promptCapabilities: {} },
      authMethods: [
        {
          id: "oauth",
          name: "Perplexity sign-in",
          description: "Run `login` once in a terminal (browser step), or set PERPLEXITY_ACCESS_TOKEN.",
        },
      ],
      agentInfo: { name: "perplexity-acp-experiment", title: "Perplexity Computer (experimental)", version: "0.0.0" },
    };
  }

  private authenticate() {
    if (this.o.hasCredentials && !this.o.hasCredentials()) {
      throw new RpcFailure(-32000, "Not signed in. Run `login` in a terminal (a browser step is required), then retry.");
    }
    return {};
  }

  private newSession() {
    const s: Session = { id: randomUUID(), cancelled: false, seenSteps: new Map() };
    this.sessions.set(s.id, s);
    return { sessionId: s.id };
  }

  /** The session id of a loaded session is the Perplexity thread_id. */
  private async loadSession(p: any) {
    const threadId = String(p?.sessionId ?? "");
    if (!threadId) throw new RpcFailure(-32602, "sessionId required");
    const t = await this.mcp.callTool("read_thread", { thread_id: threadId });
    if (t.event === "error") throw new RpcFailure(-32000, t.text ?? "read_thread failed");
    const s: Session = { id: threadId, threadId, cancelled: false, seenSteps: new Map() };
    this.sessions.set(threadId, s);
    for (const m of transcriptMessages(t)) {
      this.update(s, {
        sessionUpdate: m.role === "user" ? "user_message_chunk" : "agent_message_chunk",
        content: { type: "text", text: m.text },
      });
    }
    return {};
  }

  /** ACP session id to expose: thread_id once known so clients can session/load later. */
  private update(s: Session, update: unknown) {
    this.peer.notify("session/update", { sessionId: s.id, update });
  }

  private async prompt(p: any) {
    const s = this.sessions.get(p?.sessionId);
    if (!s) throw new RpcFailure(-32602, "Unknown session");
    s.cancelled = false;
    const message = (p.prompt ?? [])
      .filter((b: any) => b.type === "text")
      .map((b: any) => b.text)
      .join("\n");
    const args: Record<string, unknown> = { message };
    if (s.threadId) args.thread_id = s.threadId;
    if (this.o.mode) args.mode = this.o.mode;
    let res = await this.mcp.callTool("call_perplexity_computer", args);
    for (;;) {
      this.track(s, res);
      if (s.cancelled) return this.finishCancel(s);
      switch (res.event) {
        case "complete":
          return this.finish(s, res.text, res.sources);
        case "cancelled":
          return { stopReason: "cancelled" };
        case "error":
          throw new RpcFailure(-32000, res.text ?? "Perplexity error");
        case "confirm_action": {
          const next = await this.confirm(s, res.interactive ?? {}, res.text);
          if (next === "cancelled") return this.finishCancel(s);
          res = next;
          continue;
        }
        case "answer_question":
        case "notify_connected":
          return this.finish(s, `${res.text ?? ""}\n\n(This step must be completed in Perplexity itself; it cannot be answered through ACP.)`);
        default: {
          // timeout / working / input_required: switch to polling read_thread. Never re-call
          // call_perplexity_computer to check status, that would send a new message.
          const polled = await this.poll(s);
          if (polled === "cancelled") return this.finishCancel(s);
          if ("confirm" in polled) {
            const next = await this.confirm(s, polled.confirm, polled.confirm.question);
            if (next === "cancelled") return this.finishCancel(s);
            res = next;
            continue;
          }
          if (polled.status === "cancelled") return { stopReason: "cancelled" };
          return this.finish(s, polled.text);
        }
      }
    }
  }

  private track(s: Session, res: any) {
    const tid = res?.thread_id ?? res?.interactive?.thread_id;
    if (tid && !s.threadId) s.threadId = tid;
  }

  private finish(s: Session, text?: string, sources?: unknown) {
    let out = text ?? "";
    if (Array.isArray(sources) && sources.length) {
      const lines = sources.map((x: any) => (typeof x === "string" ? x : x?.url ?? x?.title)).filter(Boolean);
      if (lines.length) out += "\n\nSources:\n" + lines.map((l) => `- ${l}`).join("\n");
    }
    if (out) this.update(s, { sessionUpdate: "agent_message_chunk", content: { type: "text", text: out } });
    return { stopReason: "end_turn" };
  }

  private async confirm(s: Session, i: any, text?: string): Promise<any> {
    const threadId = i.thread_id ?? s.threadId;
    const toolCallId = `confirm-${i.followup_uuid ?? randomUUID()}`;
    const args: Record<string, unknown> = { thread_id: threadId, followup_uuid: i.followup_uuid };
    let out: any;
    try {
      out = await this.peer.request("session/request_permission", {
      sessionId: s.id,
      toolCall: {
        toolCallId,
        title: i.action ?? "Perplexity needs confirmation",
        kind: "other",
        status: "pending",
        content: [{ type: "content", content: { type: "text", text: i.placeholder ?? i.question ?? text ?? "" } }],
      },
      options: [
        { optionId: "approve", name: "Approve", kind: "allow_once" },
        { optionId: "deny", name: "Deny", kind: "reject_once" },
      ],
      }, this.o.permissionTimeoutMs);
    } catch (e: any) {
      // Fail closed: an errored, rejected or timed-out permission request is a DENY, never an approval.
      s.cancelled = true;
      try {
        await this.mcp.callTool(i.deny_with_tool ?? "confirm_action_deny", { ...args, result: "Denied: permission request failed or timed out" });
      } catch {}
      await this.backendCancel(s);
      throw new RpcFailure(-32000, `Permission request failed (${e?.message ?? e}); the action was denied and the task cancelled.`);
    }
    const selected = out?.outcome?.outcome === "selected" ? out.outcome.optionId : undefined;
    if (!selected || s.cancelled) {
      s.cancelled = true;
      return "cancelled";
    }
    if (selected === "approve") return this.mcp.callTool(i.approve_with_tool ?? "confirm_action_approve", args);
    return this.mcp.callTool(i.deny_with_tool ?? "confirm_action_deny", { ...args, result: "Denied by user in ACP client" });
  }

  private async poll(s: Session): Promise<"cancelled" | { status: string; text: string } | { confirm: any }> {
    for (;;) {
      if (s.cancelled) return "cancelled";
      await sleep(this.o.pollMs);
      if (s.cancelled) return "cancelled";
      const t = await this.mcp.callTool("read_thread", { thread_id: s.threadId });
      if (t.event === "error") throw new RpcFailure(-32000, t.text ?? "read_thread failed");
      this.emitSteps(s, t);
      const pending = findPendingConfirm(t, s.threadId);
      if (pending) return { confirm: pending };
      const status = t?.web_state?.task_status ?? t?.task_status;
      if (status && TERMINAL.has(status)) {
        const msgs = transcriptMessages(t).filter((m) => m.role !== "user");
        return { status, text: msgs.at(-1)?.text ?? "" };
      }
    }
  }

  private emitSteps(s: Session, t: any) {
    for (const e of t?.web_state?.entries ?? []) {
      for (const [idx, st] of (e.steps ?? []).entries()) {
        const key = String(st.id ?? `${e.id ?? ""}:${idx}`);
        const status = st.status === "completed" || st.status === "done" ? "completed" : st.status === "failed" ? "failed" : "in_progress";
        const prev = s.seenSteps.get(key);
        if (prev === status) continue;
        s.seenSteps.set(key, status);
        if (prev === undefined) {
          this.update(s, { sessionUpdate: "tool_call", toolCallId: `step-${key}`, title: st.title ?? "Working", kind: "other", status });
        } else {
          this.update(s, { sessionUpdate: "tool_call_update", toolCallId: `step-${key}`, status });
        }
      }
    }
  }

  async cancel(sessionId: string) {
    const s = this.sessions.get(sessionId);
    if (!s) return;
    s.cancelled = true;
    await this.backendCancel(s);
  }

  private async backendCancel(s: Session) {
    if (!s.threadId) return;
    // Best effort: cancel_task acknowledged and changed task state in a live mid-run test,
    // but billing/partial-work semantics are unverified.
    try {
      await this.mcp.callTool("cancel_task", { thread_id: s.threadId });
    } catch {}
  }

  private async finishCancel(s: Session) {
    await this.backendCancel(s);
    for (let i = 0; i < this.o.cancelPolls; i++) {
      try {
        const t = await this.mcp.callTool("read_thread", { thread_id: s.threadId });
        const status = t?.web_state?.task_status ?? t?.task_status;
        if (status && TERMINAL.has(status)) break;
      } catch {
        break;
      }
      await sleep(this.o.pollMs);
    }
    return { stopReason: "cancelled" };
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Extract user/assistant turns; drops hidden developer/system preamble. Shape is only partly verified live. */
export function transcriptMessages(t: any): { role: string; text: string }[] {
  const raw = t?.transcript ?? t?.messages ?? [];
  const items = Array.isArray(raw) ? raw : [];
  const out: { role: string; text: string }[] = [];
  for (const m of items) {
    const role = String(m?.role ?? "").toLowerCase();
    if (role !== "user" && role !== "assistant") continue;
    const c = m.text ?? m.content;
    const text = typeof c === "string" ? c : Array.isArray(c) ? c.map((x: any) => x?.text ?? "").join("") : "";
    if (text) out.push({ role, text });
  }
  return out;
}

export function findPendingConfirm(t: any, threadId?: string) {
  for (const e of t?.web_state?.entries ?? []) {
    for (const i of e.interactions ?? []) {
      if (i?.type !== "handle_asi_confirm" || i.response) continue;
      return {
        thread_id: threadId,
        action: i.action ?? i.request?.action,
        question: i.question ?? i.request?.question,
        placeholder: i.placeholder ?? i.request?.placeholder,
        followup_uuid: i.request?.answer_submission_uuid ?? i.followup_uuid,
      };
    }
  }
  return undefined;
}
