export type Json = unknown;
export type RpcError = { code: number; message: string; data?: Json };

export class RpcFailure extends Error {
  code: number;
  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

type Handler = (params: any) => Promise<Json> | Json;

/** Minimal newline-delimited JSON-RPC 2.0 peer (ACP over stdio). */
export class Peer {
  private nextId = 1;
  private pending = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void }>();
  private requestHandlers = new Map<string, Handler>();
  private notificationHandlers = new Map<string, (params: any) => void>();
  private buf = "";
  private write: (line: string) => void;

  constructor(write: (line: string) => void) {
    this.write = write;
  }

  onRequest(method: string, h: Handler) {
    this.requestHandlers.set(method, h);
  }
  onNotification(method: string, h: (params: any) => void) {
    this.notificationHandlers.set(method, h);
  }

  feed(chunk: string) {
    this.buf += chunk;
    let i;
    while ((i = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, i).trim();
      this.buf = this.buf.slice(i + 1);
      if (line) this.handleLine(line);
    }
  }

  notify(method: string, params: Json) {
    this.write(JSON.stringify({ jsonrpc: "2.0", method, params }));
  }

  request<T = any>(method: string, params: Json): Promise<T> {
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }));
    });
  }

  private handleLine(line: string) {
    let msg: any;
    try {
      msg = JSON.parse(line);
    } catch {
      this.write(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }));
      return;
    }
    if (msg.method !== undefined) {
      if (msg.id === undefined) {
        this.notificationHandlers.get(msg.method)?.(msg.params);
        return;
      }
      const h = this.requestHandlers.get(msg.method);
      if (!h) {
        this.reply(msg.id, undefined, { code: -32601, message: `Method not found: ${msg.method}` });
        return;
      }
      Promise.resolve()
        .then(() => h(msg.params))
        .then(
          (r) => this.reply(msg.id, r ?? null),
          (e) =>
            this.reply(msg.id, undefined, {
              code: e instanceof RpcFailure ? e.code : -32603,
              message: e?.message ?? String(e),
            }),
        );
      return;
    }
    const p = this.pending.get(msg.id);
    if (!p) return;
    this.pending.delete(msg.id);
    if (msg.error) p.reject(new RpcFailure(msg.error.code, msg.error.message));
    else p.resolve(msg.result);
  }

  private reply(id: number, result?: Json, error?: RpcError) {
    this.write(JSON.stringify(error ? { jsonrpc: "2.0", id, error } : { jsonrpc: "2.0", id, result }));
  }
}
