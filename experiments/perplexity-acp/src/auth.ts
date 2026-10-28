import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
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
};

export function credentialsPath(): string {
  return (
    process.env.PERPLEXITY_ACP_CREDENTIALS ??
    join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "perplexity-acp", "credentials.json")
  );
}

/** Atomic write, owner-only (0600). */
export function saveCredentials(path: string, c: Credentials) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(c), { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
}

export function loadCredentials(path: string): Credentials | undefined {
  if (!existsSync(path)) return undefined;
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

  constructor(path = credentialsPath(), fetchImpl: typeof fetch = fetch) {
    this.path = path;
    this.fetchImpl = fetchImpl;
  }

  hasCredentials(): boolean {
    return !!process.env.PERPLEXITY_ACCESS_TOKEN || existsSync(this.path);
  }

  provider = async (forceRefresh = false): Promise<string> => {
    const env = process.env.PERPLEXITY_ACCESS_TOKEN;
    if (env) return env;
    if (this.inflight) return this.inflight;
    this.inflight = this.resolve(forceRefresh).finally(() => {
      this.inflight = undefined;
    });
    return this.inflight;
  };

  private async resolve(force: boolean): Promise<string> {
    const c = loadCredentials(this.path);
    if (!c) throw new Error("Not signed in. Run `login` (browser step required).");
    const fresh = c.expiresAt === undefined || c.expiresAt - Date.now() > 60_000;
    if (fresh && !force) return c.accessToken;
    if (!c.refreshToken) throw new Error("Access token expired and no refresh token. Run `login` again.");
    const res = await this.fetchImpl(c.tokenEndpoint, {
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

const b64url = (b: Buffer) => b.toString("base64url");

/**
 * One-time interactive sign-in: dynamic client registration + authorization code with PKCE (S256),
 * loopback redirect. DCR redirect-URI rules for loopback are unverified against the live service.
 */
export async function login(
  opts: { path?: string; fetchImpl?: typeof fetch; print?: (s: string) => void; waitForCode?: (u: URL) => Promise<URL> } = {},
): Promise<void> {
  const f = opts.fetchImpl ?? fetch;
  const print = opts.print ?? ((s: string) => process.stderr.write(s + "\n"));
  const meta: any = await (await f(ISSUER_META)).json();
  const server = createServer();
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as any).port;
  const redirect = `http://127.0.0.1:${port}/callback`;
  try {
    const reg: any = await (
      await f(meta.registration_endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client_name: "perplexity-acp-experiment",
          redirect_uris: [redirect],
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
          token_endpoint_auth_method: "none",
        }),
      })
    ).json();
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
      resource: MCP_URL,
    }).toString();
    print(`Open this URL in a browser to sign in:\n${auth}`);
    const cb =
      opts.waitForCode?.(auth) ??
      new Promise<URL>((resolve) => {
        server.on("request", (req, res) => {
          const u = new URL(req.url ?? "/", redirect);
          res.end("Signed in. You can close this tab.");
          if (u.pathname === "/callback") resolve(u);
        });
      });
    const url = await cb;
    if (url.searchParams.get("state") !== state) throw new Error("State mismatch.");
    const code = url.searchParams.get("code");
    if (!code) throw new Error(`Authorization failed: ${url.searchParams.get("error") ?? "no code"}`);
    const tokRes = await f(meta.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirect,
        client_id: reg.client_id,
        code_verifier: verifier,
        resource: MCP_URL,
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
    });
    print("Signed in. Credentials saved (mode 0600).");
  } finally {
    server.close();
  }
}
