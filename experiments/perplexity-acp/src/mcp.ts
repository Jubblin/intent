/** Minimal MCP client over streamable HTTP (JSON or SSE responses). Tokens are never logged. */

import { noRedirectFetch } from "./auth.ts";

export class McpAuthError extends Error {}

export type TokenProvider = (forceRefresh?: boolean) => Promise<string>;

export class McpClient {
  private url: string;
  private token: TokenProvider;
  private session?: string;
  private nextId = 1;
  private ready?: Promise<void>;
  private fetchImpl: typeof fetch;

  constructor(url: string, token: TokenProvider, fetchImpl: typeof fetch = fetch) {
    this.url = url;
    this.token = token;
    this.fetchImpl = fetchImpl;
  }

  private async post(body: unknown, retried = false): Promise<any> {
    const bearer = await this.token(retried);
    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${bearer}`,
    };
    if (this.session) headers["mcp-session-id"] = this.session;
    const res = await noRedirectFetch(this.fetchImpl, this.url, { method: "POST", headers, body: JSON.stringify(body) });
    if (res.status === 401) {
      if (!retried) return this.post(body, true);
      throw new McpAuthError("Perplexity rejected the credentials (401). Run `login` again.");
    }
    const sid = res.headers.get("mcp-session-id");
    if (sid) this.session = sid;
    if (!res.ok) throw new Error(`MCP HTTP ${res.status}`);
    const id = (body as any).id;
    if (id === undefined) return undefined;
    const ct = res.headers.get("content-type") ?? "";
    const text = await res.text();
    let msg: any;
    if (ct.includes("text/event-stream")) {
      for (const block of text.split(/\n\n/)) {
        const data = block
          .split("\n")
          .filter((l) => l.startsWith("data:"))
          .map((l) => l.slice(5).trim())
          .join("\n");
        if (!data) continue;
        try {
          const m = JSON.parse(data);
          if (m.id === id) msg = m;
        } catch {}
      }
    } else {
      msg = JSON.parse(text);
    }
    if (!msg) throw new Error("MCP response missing");
    if (msg.error) throw new Error(`MCP error ${msg.error.code}: ${msg.error.message}`);
    return msg.result;
  }

  private init(): Promise<void> {
    this.ready ??= (async () => {
      await this.post({
        jsonrpc: "2.0",
        id: this.nextId++,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "perplexity-acp-experiment", version: "0.0.0" },
        },
      });
      await this.post({ jsonrpc: "2.0", method: "notifications/initialized" });
    })().catch((e) => {
      this.ready = undefined;
      throw e;
    });
    return this.ready;
  }

  /** Calls a tool and returns the parsed JSON payload of its first text block (or {event:"complete",text}). */
  async callTool(name: string, args: Record<string, unknown>): Promise<any> {
    await this.init();
    const result = await this.post({
      jsonrpc: "2.0",
      id: this.nextId++,
      method: "tools/call",
      params: { name, arguments: args },
    });
    const text = (result?.content ?? []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");
    let parsed: any;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { event: result?.isError ? "error" : "complete", text };
    }
    if (result?.isError && parsed.event !== "error") parsed = { ...parsed, event: "error" };
    return parsed;
  }
}
