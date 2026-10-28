import { PerplexityAgent } from "./adapter.ts";
import { MCP_URL, TokenStore, login } from "./auth.ts";
import { Peer } from "./jsonrpc.ts";
import { McpClient } from "./mcp.ts";

if (process.argv[2] === "login") {
  await login();
} else {
  const store = new TokenStore();
  const peer = new Peer((l) => process.stdout.write(l + "\n"));
  const mcp = new McpClient(process.env.PERPLEXITY_MCP_URL ?? MCP_URL, store.provider);
  new PerplexityAgent(peer, mcp, { mode: process.env.PERPLEXITY_ACP_MODE, hasCredentials: () => store.hasCredentials() });
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (c: string) => peer.feed(c));
}
