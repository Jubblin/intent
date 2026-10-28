# perplexity-acp (EXPERIMENTAL, UNSHIPPED)

**Status: experimental prototype. Not published, not registered as an Intent provider, not gated by any env var, no frontend.**
**Perplexity's terms for automated third-party clients on the Computer MCP server are unclear** (the consumer terms ban bots and automation). Do not ship or distribute this. Use only with your own account, supervised, and expect usage to bill your Perplexity credits.

An ACP agent over stdio that delegates to Perplexity Computer (`https://www.perplexity.ai/rest/computer/mcp`). No runtime dependencies; `tsx` (dev dependency) runs the TypeScript.

## Run by hand

```
npm install
npm run login          # one-time browser sign-in (OAuth code + PKCE, dynamic client registration, loopback redirect)
npm start              # ACP over stdio; point any ACP client at this command
```

Credentials: `PERPLEXITY_ACCESS_TOKEN` (env, never refreshed) or `~/.config/perplexity-acp/credentials.json` (mode 0600, override with `PERPLEXITY_ACP_CREDENTIALS`). Tokens are never logged. Refresh is serialized in-process only (no cross-process lock). Optional: `PERPLEXITY_ACP_MODE` (e.g. `light`, `standard`, `high`).

Hardening knobs:
- `PERPLEXITY_ACP_PERMISSION_TIMEOUT_MS` (default 120000): how long to wait for the client's answer to a confirmation request. An error, rejection or timeout is treated as a **deny**: the deny is sent, the task is cancelled best-effort, and the prompt ends with an error. Nothing is ever approved on a failure path.
- `PERPLEXITY_ACP_LOGIN_TIMEOUT_MS` (default 300000): how long `login` waits for the browser redirect before closing the loopback listener.
- Credentials file/dir modes: on load, a group- or world-accessible credentials file is tightened to 0600 (directory 0700); if that fails the adapter refuses with an error.
- `PERPLEXITY_MCP_URL` overrides the MCP endpoint. It must be `https`; `http` is accepted only for `localhost`, `127.0.0.1` or `::1`. A stored token is only sent to the host it was issued for (recorded at `login`; older files count as `www.perplexity.ai`); a different host is refused. `PERPLEXITY_ACCESS_TOKEN` (env) is your explicit choice and is not host-checked.

Smoke test with a raw client:

```
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1}}' \
  '{"jsonrpc":"2.0","id":2,"method":"session/new","params":{"cwd":"/tmp","mcpServers":[]}}' | npm start
```

## Mapping

| ACP | Perplexity MCP |
|---|---|
| initialize / authenticate | local; authenticate checks credentials, sign-in is the `login` command |
| session/new | local session; thread_id learned on first prompt |
| session/load | sessionId = thread_id; `read_thread` replay (developer preamble stripped) |
| session/prompt | `call_perplexity_computer`; on timeout poll `read_thread` (never re-call); steps become `tool_call` updates; text arrives as one `agent_message_chunk` (no token streaming) |
| permission | `confirm_action` -> `session/request_permission` (allow_once / reject_once only); approve/deny keyed by thread_id + followup_uuid |
| session/cancel | `cancel_task`, then poll `read_thread`; best-effort, partial-work billing unverified |

Gaps: no fs/terminal tools; `answer_question`, connector sign-in and policy/device forms must be completed in Perplexity; the approve path and the `read_thread` shape are not verified live.

## Tests

`npm test` uses mocks only (no network, no Perplexity calls). The opt-in live test is not implemented: no live calls without coordinator approval.
