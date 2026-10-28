import { PerplexityAgent } from "./adapter.ts";
import { MCP_URL, TokenStore, login, validateMcpUrl } from "./auth.ts";
import { Peer } from "./jsonrpc.ts";
import { McpClient } from "./mcp.ts";

if (process.argv[2] === "login") {
  await login();
} else {
  const mcpUrl = process.env.PERPLEXITY_MCP_URL ?? MCP_URL;
  try {
    validateMcpUrl(mcpUrl);
  } catch (e: any) {
    process.stderr.write(`${e.message}\n`);
    process.exit(2);
  }
  const store = new TokenStore(undefined, fetch, mcpUrl);
  const peer = new Peer((l) => process.stdout.write(l + "\n"));
  const mcp = new McpClient(mcpUrl, store.provider);
  new PerplexityAgent(peer, mcp, { mode: process.env.PERPLEXITY_ACP_MODE, ...(Number(process.env.PERPLEXITY_ACP_PERMISSION_TIMEOUT_MS) > 0 ? { permissionTimeoutMs: Number(process.env.PERPLEXITY_ACP_PERMISSION_TIMEOUT_MS) } : {}), hasCredentials: () => store.hasCredentials() });
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (c: string) => peer.feed(c));
}
