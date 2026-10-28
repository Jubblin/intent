import assert from "node:assert/strict";
import { mkdtempSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { TokenStore, loadCredentials, saveCredentials } from "../src/auth.ts";
import { McpClient } from "../src/mcp.ts";

function mockMcp(handler: (tool: string, args: any, auth: string) => any, sse = false) {
  const seen: string[] = [];
  const server = createServer((req, res) => {
    let b = "";
    req.on("data", (d) => (b += d));
    req.on("end", () => {
      const m = JSON.parse(b);
      const auth = req.headers.authorization ?? "";
      seen.push(auth);
      if (auth !== "Bearer good") {
        res.statusCode = 401;
        return res.end();
      }
      if (m.id === undefined) return res.end();
      let result: any = {};
      if (m.method === "tools/call") result = { content: [{ type: "text", text: JSON.stringify(handler(m.params.name, m.params.arguments, auth)) }] };
      const body = JSON.stringify({ jsonrpc: "2.0", id: m.id, result });
      res.setHeader("mcp-session-id", "S");
      if (sse) {
        res.setHeader("content-type", "text/event-stream");
        res.end(`event: message\ndata: ${body}\n\n`);
      } else {
        res.setHeader("content-type", "application/json");
        res.end(body);
      }
    });
  });
  return new Promise<{ url: string; seen: string[]; close: () => void }>((r) =>
    server.listen(0, "127.0.0.1", () => r({ url: `http://127.0.0.1:${(server.address() as any).port}/mcp`, seen, close: () => server.close() })),
  );
}

for (const sse of [false, true]) {
  test(`McpClient calls tools (sse=${sse})`, async () => {
    const s = await mockMcp((tool, args) => ({ event: "complete", text: `${tool}:${args.q}` }), sse);
    const c = new McpClient(s.url, async () => "good");
    assert.deepEqual(await c.callTool("x", { q: 1 }), { event: "complete", text: "x:1" });
    s.close();
  });
}

test("McpClient retries once with a forced refresh on 401", async () => {
  const s = await mockMcp(() => ({ event: "complete", text: "ok" }));
  const forced: boolean[] = [];
  const c = new McpClient(s.url, async (f) => {
    forced.push(!!f);
    return f ? "good" : "stale";
  });
  assert.equal((await c.callTool("x", {})).text, "ok");
  assert.deepEqual(forced.slice(0, 2), [false, true]);
  s.close();
});

test("TokenStore refreshes expired token, rotates refresh token, saves 0600, serializes", async () => {
  delete process.env.PERPLEXITY_ACCESS_TOKEN;
  const dir = mkdtempSync(join(tmpdir(), "pplx-"));
  const path = join(dir, "c.json");
  saveCredentials(path, { clientId: "cid", accessToken: "old", refreshToken: "r1", expiresAt: Date.now() - 1000, tokenEndpoint: "http://t/token" });
  let refreshes = 0;
  const f = (async (_u: string, init: any) => {
    refreshes++;
    assert.equal(new URLSearchParams(init.body).get("refresh_token"), "r1");
    return new Response(JSON.stringify({ access_token: "new", refresh_token: "r2", expires_in: 3600 }), { status: 200 });
  }) as unknown as typeof fetch;
  const store = new TokenStore(path, f);
  const [a, b] = await Promise.all([store.provider(), store.provider()]);
  assert.deepEqual([a, b, refreshes], ["new", "new", 1]);
  const saved = loadCredentials(path)!;
  assert.equal(saved.refreshToken, "r2");
  assert.equal(statSync(path).mode & 0o777, 0o600);
});

test("invalid_grant asks for re-login without leaking tokens", async () => {
  delete process.env.PERPLEXITY_ACCESS_TOKEN;
  const dir = mkdtempSync(join(tmpdir(), "pplx-"));
  const path = join(dir, "c.json");
  saveCredentials(path, { clientId: "cid", accessToken: "SECRET", refreshToken: "RSECRET", expiresAt: 1, tokenEndpoint: "http://t" });
  const f = (async () => new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 })) as unknown as typeof fetch;
  await assert.rejects(new TokenStore(path, f).provider(), (e: Error) => /login/.test(e.message) && !/SECRET/.test(e.message));
});
