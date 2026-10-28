import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { TokenStore, login, loadCredentials, saveCredentials, validateMcpUrl } from "../src/auth.ts";
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

test("loadCredentials tightens loose file and directory modes", () => {
  const dir = mkdtempSync(join(tmpdir(), "pplx-"));
  const path = join(dir, "c.json");
  saveCredentials(path, { clientId: "c", accessToken: "SECRET", tokenEndpoint: "http://t" });
  chmodSync(path, 0o644);
  chmodSync(dir, 0o755);
  assert.equal(loadCredentials(path)!.accessToken, "SECRET");
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.equal(statSync(dir).mode & 0o777, 0o700);
});

test("validateMcpUrl: https ok, http only loopback, junk refused", () => {
  validateMcpUrl("https://example.com/mcp");
  validateMcpUrl("http://127.0.0.1:1/mcp");
  validateMcpUrl("http://localhost/mcp");
  assert.throws(() => validateMcpUrl("http://example.com/mcp"), /https/);
  assert.throws(() => validateMcpUrl("ftp://example.com"), /https/);
  assert.throws(() => validateMcpUrl("not a url"), /valid URL/);
});

test("stored token is not sent to a host it was not issued for", async () => {
  delete process.env.PERPLEXITY_ACCESS_TOKEN;
  const dir = mkdtempSync(join(tmpdir(), "pplx-"));
  const path = join(dir, "c.json");
  saveCredentials(path, { clientId: "c", accessToken: "SECRET", tokenEndpoint: "http://t", mcpHost: "www.perplexity.ai" });
  await assert.rejects(new TokenStore(path, fetch, "https://evil.example/mcp").provider(), (e: Error) => /issued for/.test(e.message) && !/SECRET/.test(e.message));
  assert.equal(await new TokenStore(path, fetch, "https://www.perplexity.ai/rest/computer/mcp").provider(), "SECRET");
});

test("login surfaces failing metadata and registration responses without secrets", async () => {
  const dir = mkdtempSync(join(tmpdir(), "pplx-"));
  const quiet = { print: () => {}, path: join(dir, "c.json") };
  const bad = (async () => new Response("SECRET", { status: 500 })) as unknown as typeof fetch;
  await assert.rejects(login({ ...quiet, fetchImpl: bad }), (e: Error) => /metadata.*500/.test(e.message) && !/SECRET/.test(e.message));
  const f = (async (u: string) =>
    String(u).includes("well-known")
      ? new Response(JSON.stringify({ registration_endpoint: "http://r", authorization_endpoint: "http://a", token_endpoint: "http://t" }))
      : new Response("SECRET", { status: 403 })) as unknown as typeof fetch;
  await assert.rejects(login({ ...quiet, fetchImpl: f }), (e: Error) => /registration.*403/.test(e.message) && !/SECRET/.test(e.message));
});

test("login redirect wait times out and closes the listener", async () => {
  const dir = mkdtempSync(join(tmpdir(), "pplx-"));
  const f = (async (u: string) =>
    String(u).includes("well-known")
      ? new Response(JSON.stringify({ registration_endpoint: "http://r", authorization_endpoint: "http://a/auth", token_endpoint: "http://t" }))
      : new Response(JSON.stringify({ client_id: "cid" }))) as unknown as typeof fetch;
  let printed = "";
  await assert.rejects(login({ fetchImpl: f, path: join(dir, "c.json"), timeoutMs: 30, print: (s) => (printed += s) }), /timed out/);
  assert.ok(printed.includes("Open this URL"));
});
