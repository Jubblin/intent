import assert from "node:assert/strict";
import { test } from "node:test";
import { PerplexityAgent } from "../src/adapter.ts";
import { Peer } from "../src/jsonrpc.ts";

type Call = { name: string; args: any };

function harness(script: (call: Call, calls: Call[]) => any, permission: (p: any) => any = () => ({ outcome: { outcome: "selected", optionId: "approve" } }), agentOpts: any = {}, rawPermission?: (m: any, peer: Peer) => void) {
  const calls: Call[] = [];
  const out: any[] = [];
  const peer = new Peer((l) => {
    const m = JSON.parse(l);
    out.push(m);
    if (m.method === "session/request_permission" && rawPermission) {
      rawPermission(m, peer);
    } else if (m.method === "session/request_permission") {
      setImmediate(() => peer.feed(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: permission(m.params) }) + "\n"));
    }
  });
  const mcp = {
    async callTool(name: string, args: any) {
      const c = { name, args };
      calls.push(c);
      return script(c, calls);
    },
  };
  new PerplexityAgent(peer, mcp, { pollMs: 1, cancelPolls: 2, hasCredentials: () => true, ...agentOpts });
  const send = (id: number, method: string, params: any = {}) => peer.feed(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  const result = async (id: number) => {
    for (let i = 0; i < 200; i++) {
      const r = out.find((m) => m.id === id && (m.result !== undefined || m.error));
      if (r) return r;
      await new Promise((r) => setTimeout(r, 5));
    }
    throw new Error("timeout");
  };
  return { calls, out, peer, send, result };
}

const texts = (out: any[]) =>
  out.filter((m) => m.method === "session/update" && m.params.update.sessionUpdate === "agent_message_chunk").map((m) => m.params.update.content.text);

test("initialize advertises loadSession and oauth", async () => {
  const h = harness(() => ({}));
  h.send(1, "initialize", { protocolVersion: 1 });
  const r = (await h.result(1)).result;
  assert.equal(r.agentCapabilities.loadSession, true);
  assert.equal(r.authMethods[0].id, "oauth");
});

test("prompt streams text, stores thread_id, follow-up reuses it", async () => {
  const h = harness((c) => ({ event: "complete", text: c.args.message === "a" ? "Paris" : "Seine", thread_id: "T1" }));
  h.send(1, "session/new");
  const sid = (await h.result(1)).result.sessionId;
  h.send(2, "session/prompt", { sessionId: sid, prompt: [{ type: "text", text: "a" }] });
  assert.equal((await h.result(2)).result.stopReason, "end_turn");
  h.send(3, "session/prompt", { sessionId: sid, prompt: [{ type: "text", text: "b" }] });
  await h.result(3);
  assert.equal(h.calls[0].args.thread_id, undefined);
  assert.equal(h.calls[1].args.thread_id, "T1");
  assert.deepEqual(texts(h.out), ["Paris", "Seine"]);
});

const confirm = { event: "confirm_action", thread_id: "T", task_status: "input_required", text: "ok?", interactive: { type: "confirm_action", thread_id: "T", action: "Approve creation", placeholder: "details", approve_with_tool: "confirm_action_approve", deny_with_tool: "confirm_action_deny", followup_uuid: "call_1" } };

test("confirm_action maps to permission request; approve keyed by thread_id + followup_uuid", async () => {
  const h = harness((c) => (c.name === "call_perplexity_computer" ? confirm : { event: "complete", text: "done" }));
  h.send(1, "session/new");
  const sid = (await h.result(1)).result.sessionId;
  h.send(2, "session/prompt", { sessionId: sid, prompt: [{ type: "text", text: "x" }] });
  assert.equal((await h.result(2)).result.stopReason, "end_turn");
  const perm = h.out.find((m) => m.method === "session/request_permission");
  assert.deepEqual(perm.params.options.map((o: any) => o.kind), ["allow_once", "reject_once"]);
  assert.equal(perm.params.toolCall.title, "Approve creation");
  assert.deepEqual(h.calls[1], { name: "confirm_action_approve", args: { thread_id: "T", followup_uuid: "call_1" } });
});

test("reject_once calls confirm_action_deny with a reason", async () => {
  const h = harness((c) => (c.name === "call_perplexity_computer" ? confirm : { event: "complete", text: "not created" }), () => ({ outcome: { outcome: "selected", optionId: "deny" } }));
  h.send(1, "session/new");
  const sid = (await h.result(1)).result.sessionId;
  h.send(2, "session/prompt", { sessionId: sid, prompt: [{ type: "text", text: "x" }] });
  await h.result(2);
  assert.equal(h.calls[1].name, "confirm_action_deny");
  assert.equal(h.calls[1].args.followup_uuid, "call_1");
  assert.ok(h.calls[1].args.result);
  assert.ok(!h.calls.some((c) => c.name === "confirm_action_approve"));
});

test("cancelled permission never approves; cancel_task is called", async () => {
  const h = harness((c) => (c.name === "call_perplexity_computer" ? confirm : { event: "cancelled", web_state: { task_status: "cancelled" } }), () => ({ outcome: { outcome: "cancelled" } }));
  h.send(1, "session/new");
  const sid = (await h.result(1)).result.sessionId;
  h.send(2, "session/prompt", { sessionId: sid, prompt: [{ type: "text", text: "x" }] });
  assert.equal((await h.result(2)).result.stopReason, "cancelled");
  assert.ok(h.calls.some((c) => c.name === "cancel_task"));
  assert.ok(!h.calls.some((c) => c.name === "confirm_action_approve"));
});

test("timeout switches to read_thread polling, emits steps, never re-calls the prompt tool", async () => {
  let reads = 0;
  const h = harness((c) => {
    if (c.name === "call_perplexity_computer") return { event: "timeout", thread_id: "T", task_status: "working" };
    reads++;
    const done = reads >= 2;
    return {
      web_state: { task_status: done ? "completed" : "working", entries: [{ id: "e", steps: [{ id: "s1", title: "Searching", status: done ? "completed" : "running" }] }] },
      transcript: [{ role: "developer", text: "hidden" }, { role: "user", text: "q" }, { role: "assistant", text: "final" }],
    };
  });
  h.send(1, "session/new");
  const sid = (await h.result(1)).result.sessionId;
  h.send(2, "session/prompt", { sessionId: sid, prompt: [{ type: "text", text: "q" }] });
  assert.equal((await h.result(2)).result.stopReason, "end_turn");
  assert.equal(h.calls.filter((c) => c.name === "call_perplexity_computer").length, 1);
  assert.deepEqual(texts(h.out), ["final"]);
  const kinds = h.out.filter((m) => m.method === "session/update").map((m) => m.params.update.sessionUpdate);
  assert.ok(kinds.includes("tool_call") && kinds.includes("tool_call_update"));
});

test("session/cancel during a pending poll calls cancel_task and ends cancelled", async () => {
  const h = harness((c) => {
    if (c.name === "call_perplexity_computer") return { event: "timeout", thread_id: "T" };
    if (c.name === "cancel_task") return { event: "cancelled" };
    return { web_state: { task_status: h.calls.some((x) => x.name === "cancel_task") ? "cancelled" : "working" } };
  });
  h.send(1, "session/new");
  const sid = (await h.result(1)).result.sessionId;
  h.send(2, "session/prompt", { sessionId: sid, prompt: [{ type: "text", text: "q" }] });
  await new Promise((r) => setTimeout(r, 20));
  h.peer.feed(JSON.stringify({ jsonrpc: "2.0", method: "session/cancel", params: { sessionId: sid } }) + "\n");
  assert.equal((await h.result(2)).result.stopReason, "cancelled");
  assert.ok(h.calls.some((c) => c.name === "cancel_task" && c.args.thread_id === "T"));
});

test("session/load replays transcript without the developer preamble", async () => {
  const h = harness(() => ({ transcript: [{ role: "developer", text: "skills" }, { role: "user", text: "hi" }, { role: "assistant", text: "yo" }] }));
  h.send(1, "session/load", { sessionId: "T9", cwd: "/", mcpServers: [] });
  await h.result(1);
  const ups = h.out.filter((m) => m.method === "session/update").map((m) => [m.params.update.sessionUpdate, m.params.update.content.text]);
  assert.deepEqual(ups, [["user_message_chunk", "hi"], ["agent_message_chunk", "yo"]]);
});

test("authenticate fails with login instructions when not signed in", async () => {
  const peer = new Peer(() => {});
  const out: any[] = [];
  const p2 = new Peer((l) => out.push(JSON.parse(l)));
  new PerplexityAgent(p2, { callTool: async () => ({}) }, { hasCredentials: () => false });
  p2.feed(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "authenticate", params: { methodId: "oauth" } }) + "\n");
  await new Promise((r) => setTimeout(r, 10));
  assert.match(out[0].error.message, /login/);
  void peer;
});

for (const [label, opts, raw] of [
  ["errors", {}, (m: any, peer: Peer) => setImmediate(() => peer.feed(JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: -1, message: "boom" } }) + "\n"))],
  ["times out", { permissionTimeoutMs: 20 }, () => {}],
] as const) {
  test(`permission request that ${label} is a deny, cancels, and errors the prompt`, async () => {
    const h = harness((c) => (c.name === "call_perplexity_computer" ? confirm : { event: "cancelled" }), undefined, opts, raw);
    h.send(1, "session/new");
    const sid = (await h.result(1)).result.sessionId;
    h.send(2, "session/prompt", { sessionId: sid, prompt: [{ type: "text", text: "x" }] });
    const r = await h.result(2);
    assert.ok(r.error);
    assert.match(r.error.message, /denied/);
    const names = h.calls.map((c) => c.name);
    assert.ok(!names.includes("confirm_action_approve"));
    const deny = h.calls.find((c) => c.name === "confirm_action_deny")!;
    assert.deepEqual([deny.args.thread_id, deny.args.followup_uuid], ["T", "call_1"]);
    assert.ok(names.includes("cancel_task"));
  });
}
