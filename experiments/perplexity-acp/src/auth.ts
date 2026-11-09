import { createHash, randomBytes } from "node:crypto";
import { chmodSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export const MCP_URL = "https://www.perplexity.ai/rest/computer/mcp";
const ISSUER_META = "https://www.perplexity.ai/.well-known/oauth-authorization-server";

export type Credentials = {
  clientId: string;
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
  tokenEndpoint: string;
  /** Host of the MCP server this token was issued for. Missing (older files) means the default host. */
  mcpHost?: string;
};

const DEFAULT_HOST = new URL(MCP_URL).host;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/** https only; http only for loopback hosts (tests, local mocks). Returns the parsed URL. */
export function validateMcpUrl(raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("PERPLEXITY_MCP_URL is not a valid URL.");
  }
  if (u.username || u.password) throw new Error("PERPLEXITY_MCP_URL must not contain a username or password.");
  if (u.protocol === "https:") return u;
  if (u.protocol === "http:" && LOOPBACK.has(u.hostname)) return u;
  throw new Error("PERPLEXITY_MCP_URL must use https (http is allowed only for localhost, 127.0.0.1 or ::1).");
}

/**
 * fetch for any request that carries a bearer token, refresh token, or auth code: redirects are never
 * followed (a 307/308 would re-send the body or header), and a 3xx answer is an error. Errors carry no secrets.
 */
export async function noRedirectFetch(f: typeof fetch, url: string | URL, init: RequestInit = {}): Promise<Response> {
  let res: Response;
  try {
    res = await f(url, { ...init, redirect: "error" });
  } catch {
    throw new Error("Request failed or was redirected; redirects are refused for requests that carry credentials.");
  }
  if (res.status >= 300 && res.status < 400) {
    throw new Error(`Refusing redirect (HTTP ${res.status}) on a request that carries credentials.`);
  }
  return res;
}

export function credentialsPath(): string {
  return (
    process.env.PERPLEXITY_ACP_CREDENTIALS ??
    join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "perplexity-acp", "credentials.json")
  );
}

/** Atomic write, owner-only (0600). */
export function saveCredentials(path: string, c: Credentials) {
  const created = mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  if (created) chmodSync(dirname(path), 0o700);
  const tmp = `${path}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  // "wx" = O_CREAT|O_EXCL: fails on any pre-existing path, including a symlink.
  const fd = openSync(tmp, "wx", 0o600);
  try {
    try {
      writeFileSync(fd, JSON.stringify(c));
    } finally {
      closeSync(fd);
    }
    chmodSync(tmp, 0o600);
    renameSync(tmp, path);
  } catch (e) {
    try {
      unlinkSync(tmp);
    } catch {}
    throw e;
  }
}

/** Tighten a group/world-accessible credentials file (0600), or refuse. Never reads contents. A pre-existing parent directory is only warned about, never chmodded. */
function enforceModes(path: string) {
  const bad = () => new Error(`Credentials file ${path} is accessible to other users and could not be tightened; fix its permissions.`);
  if ((statSync(path).mode & 0o077) !== 0) {
    try {
      chmodSync(path, 0o600);
    } catch {
      throw bad();
    }
    if ((statSync(path).mode & 0o077) !== 0) throw bad();
  }
  const dir = dirname(path);
  if ((statSync(dir).mode & 0o077) !== 0) {
    console.error(`perplexity-acp: warning: credentials directory ${dir} is accessible to other users; not changing it (file is 0600).`);
  }
}

export function loadCredentials(path: string): Credentials | undefined {
  if (!existsSync(path)) return undefined;
  enforceModes(path);
  return JSON.parse(readFileSync(path, "utf8"));
}

/**
 * Supplies bearer tokens. PERPLEXITY_ACCESS_TOKEN (env) wins and is never refreshed.
 * Otherwise uses the credentials file and refreshes (serialized in-process, atomic save)
 * because refresh tokens rotate and replays beyond 30 s revoke the grant.
 */
export class TokenStore {
  private path: string;
  private fetchImpl: typeof fetch;
  private inflight?: Promise<string>;
  private mcpHost: string;

  constructor(path = credentialsPath(), fetchImpl: typeof fetch = fetch, mcpUrl: string = MCP_URL) {
    this.path = path;
    this.fetchImpl = fetchImpl;
    this.mcpHost = validateMcpUrl(mcpUrl).host;
  }

  hasCredentials(): boolean {
    return !!process.env.PERPLEXITY_ACCESS_TOKEN || existsSync(this.path);
  }

  provider = async (forceRefresh = false): Promise<string> => {
    const env = process.env.PERPLEXITY_ACCESS_TOKEN;
    if (env) {
      if (this.mcpHost !== DEFAULT_HOST && process.env.PERPLEXITY_ALLOW_ENV_TOKEN_CUSTOM_HOST !== "1") {
        throw new Error(`Refusing to send PERPLEXITY_ACCESS_TOKEN to ${this.mcpHost}, which is not ${DEFAULT_HOST}. Set PERPLEXITY_ALLOW_ENV_TOKEN_CUSTOM_HOST=1 to allow it.`);
      }
      return env;
    }
    if (this.inflight) return this.inflight;
    this.inflight = this.resolve(forceRefresh).finally(() => {
      this.inflight = undefined;
    });
    return this.inflight;
  };

  private async resolve(force: boolean): Promise<string> {
    const c = loadCredentials(this.path);
    if (!c) throw new Error("Not signed in. Run `login` (browser step required).");
    const issuedFor = c.mcpHost ?? DEFAULT_HOST;
    if (issuedFor !== this.mcpHost) {
      throw new Error(`Refusing to send the stored token to ${this.mcpHost}: it was issued for ${issuedFor}. Run \`login\` against that host or unset PERPLEXITY_MCP_URL.`);
    }
    const fresh = c.expiresAt === undefined || c.expiresAt - Date.now() > 60_000;
    if (fresh && !force) return c.accessToken;
    if (!c.refreshToken) throw new Error("Access token expired and no refresh token. Run `login` again.");
    checkTokenEndpoint(c.tokenEndpoint, issuedFor);
    const res = await noRedirectFetch(this.fetchImpl, c.tokenEndpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: c.refreshToken,
        client_id: c.clientId,
      }),
    });
    const body: any = await res.json().catch(() => ({}));
    if (!res.ok || !body.access_token) {
      if (body.error === "invalid_grant") throw new Error("Refresh grant expired or revoked. Run `login` again.");
      throw new Error(`Token refresh failed (HTTP ${res.status}${body.error ? `, ${body.error}` : ""}).`);
    }
    const next: Credentials = {
      ...c,
      accessToken: body.access_token,
      refreshToken: body.refresh_token ?? c.refreshToken,
      expiresAt: body.expires_in ? Date.now() + body.expires_in * 1000 : undefined,
    };
    saveCredentials(this.path, next);
    return next.accessToken;
  }
}

/** The refresh token is only posted to https (or loopback http) on the host the credentials were issued for or the default issuer. */
function checkTokenEndpoint(raw: unknown, issuedFor: string, phase: "refresh" | "login" = "refresh") {
  const bad = () =>
    new Error(
      phase === "refresh"
        ? `Refusing to refresh: the stored token endpoint is not trusted for ${issuedFor} (https on that host or ${DEFAULT_HOST} required). Run \`login\` again.`
        : `Refusing to sign in: the token endpoint from OAuth discovery is not trusted for ${issuedFor} (https on that host or ${DEFAULT_HOST} required).`,
    );
  let u: URL;
  try {
    u = new URL(String(raw));
  } catch {
    throw bad();
  }
  const okScheme = u.protocol === "https:" || (u.protocol === "http:" && LOOPBACK.has(u.hostname));
  if (!okScheme || (u.host !== issuedFor && u.host !== DEFAULT_HOST)) throw bad();
}

const b64url = (b: Buffer) => b.toString("base64url");

/**
 * One-time interactive sign-in: dynamic client registration + authorization code with PKCE (S256),
 * loopback redirect. DCR redirect-URI rules for loopback are unverified against the live service.
 */
export async function login(
  opts: {
    path?: string;
    fetchImpl?: typeof fetch;
    print?: (s: string) => void;
    waitForCode?: (u: URL) => Promise<URL>;
    /** Max wait for the browser redirect. Default 300000 (env PERPLEXITY_ACP_LOGIN_TIMEOUT_MS). */
    timeoutMs?: number;
    mcpUrl?: string;
  } = {},
): Promise<void> {
  const f = opts.fetchImpl ?? fetch;
  const print = opts.print ?? ((s: string) => process.stderr.write(s + "\n"));
  const mcpUrl = validateMcpUrl(opts.mcpUrl ?? MCP_URL).href;
  const timeoutMs = opts.timeoutMs ?? (Number(process.env.PERPLEXITY_ACP_LOGIN_TIMEOUT_MS) || 300_000);
  const metaRes = await noRedirectFetch(f, ISSUER_META);
  if (!metaRes.ok) throw new Error(`OAuth metadata request failed (HTTP ${metaRes.status}).`);
  const meta: any = await metaRes.json().catch(() => ({}));
  if (!meta.registration_endpoint || !meta.authorization_endpoint || !meta.token_endpoint) {
    throw new Error("OAuth metadata response is missing required endpoints.");
  }
  const server = createServer();
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as any).port;
  const redirect = `http://127.0.0.1:${port}/callback`;
  try {
    const regRes = await noRedirectFetch(f, meta.registration_endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client_name: "perplexity-acp-experiment",
          redirect_uris: [redirect],
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
          token_endpoint_auth_method: "none",
        }),
    });
    if (!regRes.ok) throw new Error(`Dynamic client registration failed (HTTP ${regRes.status}).`);
    const reg: any = await regRes.json().catch(() => ({}));
    if (!reg.client_id) throw new Error("Dynamic client registration failed.");
    const verifier = b64url(randomBytes(32));
    const challenge = b64url(createHash("sha256").update(verifier).digest());
    const state = b64url(randomBytes(16));
    const auth = new URL(meta.authorization_endpoint);
    auth.search = new URLSearchParams({
      response_type: "code",
      client_id: reg.client_id,
      redirect_uri: redirect,
      scope: "asi:query",
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
      resource: mcpUrl,
    }).toString();
    print(`Open this URL in a browser to sign in:\n${auth}`);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Sign-in timed out after ${Math.round(timeoutMs / 1000)} s waiting for the browser redirect.`)), timeoutMs);
    });
    const cb =
      opts.waitForCode?.(auth) ??
      new Promise<URL>((resolve) => {
        server.on("request", (req, res) => {
          const u = new URL(req.url ?? "/", redirect);
          res.end("Signed in. You can close this tab.");
          if (u.pathname === "/callback") resolve(u);
        });
      });
    let url: URL;
    try {
      url = await Promise.race([cb, timeout]);
    } finally {
      clearTimeout(timer);
    }
    if (url.searchParams.get("state") !== state) throw new Error("State mismatch.");
    const code = url.searchParams.get("code");
    if (!code) throw new Error(`Authorization failed: ${url.searchParams.get("error") ?? "no code"}`);
    checkTokenEndpoint(meta.token_endpoint, new URL(mcpUrl).host, "login");
    const tokRes = await noRedirectFetch(f, meta.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirect,
        client_id: reg.client_id,
        code_verifier: verifier,
        resource: mcpUrl,
      }),
    });
    const tok: any = await tokRes.json();
    if (!tok.access_token) throw new Error(`Token exchange failed (HTTP ${tokRes.status}).`);
    saveCredentials(opts.path ?? credentialsPath(), {
      clientId: reg.client_id,
      accessToken: tok.access_token,
      refreshToken: tok.refresh_token,
      expiresAt: tok.expires_in ? Date.now() + tok.expires_in * 1000 : undefined,
      tokenEndpoint: meta.token_endpoint,
      mcpHost: new URL(mcpUrl).host,
    });
    print("Signed in. Credentials saved (mode 0600).");
  } finally {
    server.close();
    server.closeAllConnections?.();
  }
}
