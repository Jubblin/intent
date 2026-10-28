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
  saveCredentials(path, { clientId: "cid", accessToken: "old", refreshToken: "r1", expiresAt: Date.now() - 1000, tokenEndpoint: "https://www.perplexity.ai/token" });
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
  saveCredentials(path, { clientId: "cid", accessToken: "SECRET", refreshToken: "RSECRET", expiresAt: 1, tokenEndpoint: "https://www.perplexity.ai/token" });
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

test("login with a custom MCP URL uses it as resource and records its host", async () => {
  const dir = mkdtempSync(join(tmpdir(), "pplx-"));
  const path = join(dir, "c.json");
  const bodies: string[] = [];
  const f = (async (u: string, init: any) => {
    if (String(u).includes("well-known")) return new Response(JSON.stringify({ registration_endpoint: "http://r", authorization_endpoint: "http://a/auth", token_endpoint: "https://www.perplexity.ai/token" }));
    if (String(u) === "http://r") return new Response(JSON.stringify({ client_id: "cid" }));
    bodies.push(String(init.body));
    return new Response(JSON.stringify({ access_token: "tok" }));
  }) as unknown as typeof fetch;
  let authUrl: URL | undefined;
  await login({
    fetchImpl: f,
    path,
    print: () => {},
    mcpUrl: "https://mcp.example.com/mcp",
    waitForCode: async (a) => {
      authUrl = a;
      return new URL(`http://127.0.0.1/callback?code=C&state=${a.searchParams.get("state")}`);
    },
  });
  assert.equal(authUrl!.searchParams.get("resource"), "https://mcp.example.com/mcp");
  assert.equal(new URLSearchParams(bodies[0]).get("resource"), "https://mcp.example.com/mcp");
  assert.equal(loadCredentials(path)!.mcpHost, "mcp.example.com");
});

test("env token to a custom host needs explicit opt-in and the error omits the token", async () => {
  process.env.PERPLEXITY_ACCESS_TOKEN = "ENVSECRET";
  try {
    delete process.env.PERPLEXITY_ALLOW_ENV_TOKEN_CUSTOM_HOST;
    const s = new TokenStore("/nonexistent/c.json", fetch, "https://evil.example/mcp");
    await assert.rejects(s.provider(), (e: Error) => /ALLOW_ENV_TOKEN_CUSTOM_HOST/.test(e.message) && !/ENVSECRET/.test(e.message));
    process.env.PERPLEXITY_ALLOW_ENV_TOKEN_CUSTOM_HOST = "1";
    assert.equal(await s.provider(), "ENVSECRET");
    delete process.env.PERPLEXITY_ALLOW_ENV_TOKEN_CUSTOM_HOST;
    assert.equal(await new TokenStore("/nonexistent/c.json").provider(), "ENVSECRET");
  } finally {
    delete process.env.PERPLEXITY_ACCESS_TOKEN;
    delete process.env.PERPLEXITY_ALLOW_ENV_TOKEN_CUSTOM_HOST;
  }
});

test("refresh refuses an untrusted tokenEndpoint from the credentials file", async () => {
  delete process.env.PERPLEXITY_ACCESS_TOKEN;
  for (const ep of ["http://www.perplexity.ai/token", "https://evil.example/token", "http://evil.example/token", "garbage"]) {
    const dir = mkdtempSync(join(tmpdir(), "pplx-"));
    const path = join(dir, "c.json");
    saveCredentials(path, { clientId: "c", accessToken: "SECRET", refreshToken: "RSECRET", expiresAt: 1, tokenEndpoint: ep });
    let called = false;
    const f = (async () => ((called = true), new Response("{}"))) as unknown as typeof fetch;
    await assert.rejects(new TokenStore(path, f).provider(), (e: Error) => /token endpoint/.test(e.message) && !/SECRET/.test(e.message));
    assert.equal(called, false, ep);
  }
});

test("validateMcpUrl: userinfo, look-alike, uppercase, port and loopback rules", () => {
  assert.throws(() => validateMcpUrl("http://good@evil.example/mcp"), /https/);
  assert.equal(validateMcpUrl("https://good@evil.example/mcp").host, "evil.example");
  assert.throws(() => validateMcpUrl("http://localhost@evil.example/mcp"), /https/);
  assert.throws(() => validateMcpUrl("http://127.0.0.1.evil.example/mcp"), /https/);
  assert.throws(() => validateMcpUrl("http://localhost.evil.example/mcp"), /https/);
  assert.throws(() => validateMcpUrl("http://[::2]/mcp"), /https/);
  assert.throws(() => validateMcpUrl("http://example.com:8080/mcp"), /https/);
  validateMcpUrl("http://[::1]:8080/mcp");
  validateMcpUrl("http://LOCALHOST:8080/mcp");
  assert.equal(validateMcpUrl("https://WWW.PERPLEXITY.AI/mcp").host, "www.perplexity.ai");
  assert.equal(validateMcpUrl("https://www.perplexity.ai:443/mcp").host, "www.perplexity.ai");
  assert.equal(validateMcpUrl("https://www.perplexity.ai:8443/mcp").host, "www.perplexity.ai:8443");
  assert.equal(validateMcpUrl("https://www.perplexity.ai.evil.example/mcp").host, "www.perplexity.ai.evil.example");
});

test("look-alike and non-default-port hosts do not receive the default host's stored token or env token", async () => {
  delete process.env.PERPLEXITY_ACCESS_TOKEN;
  const dir = mkdtempSync(join(tmpdir(), "pplx-"));
  const path = join(dir, "c.json");
  saveCredentials(path, { clientId: "c", accessToken: "SECRET", tokenEndpoint: "https://www.perplexity.ai/t" });
  for (const u of ["https://www.perplexity.ai.evil.example/mcp", "https://www.perplexity.ai:8443/mcp", "https://good@evil.example/mcp"]) {
    await assert.rejects(new TokenStore(path, fetch, u).provider(), (e: Error) => /issued for/.test(e.message) && !/SECRET/.test(e.message), u);
  }
  process.env.PERPLEXITY_ACCESS_TOKEN = "ENVSECRET";
  try {
    await assert.rejects(new TokenStore(path, fetch, "https://www.perplexity.ai:8443/mcp").provider(), (e: Error) => /ALLOW_ENV/.test(e.message) && !/ENVSECRET/.test(e.message));
  } finally {
    delete process.env.PERPLEXITY_ACCESS_TOKEN;
  }
});

test("custom host works end to end: login, token bound to host, refresh", async () => {
  delete process.env.PERPLEXITY_ACCESS_TOKEN;
  const dir = mkdtempSync(join(tmpdir(), "pplx-"));
  const path = join(dir, "c.json");
  const mcpUrl = "https://mcp.example.com:8443/mcp";
  const calls: { url: string; redirect?: string; body?: string }[] = [];
  const f = (async (u: string, init: any) => {
    calls.push({ url: String(u), redirect: init?.redirect, body: init?.body && String(init.body) });
    if (String(u).includes("well-known")) return new Response(JSON.stringify({ registration_endpoint: "http://r", authorization_endpoint: "http://a/auth", token_endpoint: "https://mcp.example.com:8443/token" }));
    if (String(u) === "http://r") return new Response(JSON.stringify({ client_id: "cid" }));
    const grant = new URLSearchParams(init.body).get("grant_type");
    return new Response(JSON.stringify(grant === "refresh_token" ? { access_token: "tok2", refresh_token: "r2", expires_in: 3600 } : { access_token: "tok1", refresh_token: "r1", expires_in: 1 }));
  }) as unknown as typeof fetch;
  await login({
    fetchImpl: f,
    path,
    print: () => {},
    mcpUrl,
    waitForCode: async (a) => new URL(`http://127.0.0.1/callback?code=C&state=${a.searchParams.get("state")}`),
  });
  assert.equal(loadCredentials(path)!.mcpHost, "mcp.example.com:8443");
  const store = new TokenStore(path, f, mcpUrl);
  assert.equal(await store.provider(), "tok2");
  assert.equal(loadCredentials(path)!.refreshToken, "r2");
  const tokenCalls = calls.filter((c) => c.url === "https://mcp.example.com:8443/token");
  assert.equal(tokenCalls.length, 2);
  assert.ok(tokenCalls.every((c) => c.redirect === "error"));
  await assert.rejects(new TokenStore(path, f, "https://other.example.com/mcp").provider(), /issued for/);
});

for (const status of [307, 308]) {
  test(`token refresh POST answered with ${status} is refused and never re-sent`, async () => {
    delete process.env.PERPLEXITY_ACCESS_TOKEN;
    const hits: string[] = [];
    const target = createServer((req, res) => {
      hits.push("target");
      req.resume();
      res.end("{}");
    });
    await new Promise<void>((r) => target.listen(0, "127.0.0.1", r));
    const tport = (target.address() as any).port;
    const origin = createServer((req, res) => {
      hits.push("origin");
      req.resume();
      res.statusCode = status;
      res.setHeader("location", `http://127.0.0.1:${tport}/steal`);
      res.end();
    });
    await new Promise<void>((r) => origin.listen(0, "127.0.0.1", r));
    const oport = (origin.address() as any).port;
    const dir = mkdtempSync(join(tmpdir(), "pplx-"));
    const path = join(dir, "c.json");
    const host = `127.0.0.1:${oport}`;
    saveCredentials(path, { clientId: "c", accessToken: "old", refreshToken: "RSECRET", expiresAt: 1, tokenEndpoint: `http://${host}/token`, mcpHost: host });
    try {
      await assert.rejects(new TokenStore(path, fetch, `http://${host}/mcp`).provider(), (e: Error) => /redirect/i.test(e.message) && !/RSECRET/.test(e.message));
      assert.deepEqual(hits, ["origin"]);
    } finally {
      target.close();
      origin.close();
      target.closeAllConnections?.();
      origin.closeAllConnections?.();
    }
  });
}

test("a 3xx answer from an injected fetch is refused for token and MCP requests", async () => {
  delete process.env.PERPLEXITY_ACCESS_TOKEN;
  const dir = mkdtempSync(join(tmpdir(), "pplx-"));
  const path = join(dir, "c.json");
  saveCredentials(path, { clientId: "c", accessToken: "old", refreshToken: "RSECRET", expiresAt: 1, tokenEndpoint: "https://www.perplexity.ai/token" });
  let redirectOpt: unknown;
  const f = (async (_u: string, init: any) => {
    redirectOpt = init.redirect;
    return new Response(null, { status: 307, headers: { location: "https://evil.example/" } });
  }) as unknown as typeof fetch;
  await assert.rejects(new TokenStore(path, f).provider(), (e: Error) => /redirect/i.test(e.message) && !/RSECRET/.test(e.message));
  assert.equal(redirectOpt, "error");
  await assert.rejects(new McpClient("https://www.perplexity.ai/mcp", async () => "TOK", f).callTool("x", {}), (e: Error) => /redirect/i.test(e.message) && !/TOK/.test(e.message));
});
