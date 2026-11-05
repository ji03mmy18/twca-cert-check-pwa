import { describe, expect, it } from "vite-plus/test";
import { readTargetFromBody, runCheck } from "../server/check";
import type { ConnectFn, SocketLike } from "../server/fetch-chain";
import { buildClientHello } from "../server/tls";
import { fixtureDer } from "./helpers";

interface FakeOptions {
  /** 伺服器回應的資料片段 */
  chunks?: Uint8Array[];
  /** 不回應（模擬逾時） */
  hang?: boolean;
  openError?: Error;
  /** 回應後是否關閉 */
  eof?: boolean;
}

function fakeConnect(opts: FakeOptions) {
  const state = { closed: false, written: [] as Uint8Array[], address: null as unknown, options: null as unknown };
  const connect: ConnectFn = (address, options) => {
    state.address = address;
    state.options = options;
    let ctrl!: ReadableStreamDefaultController<Uint8Array>;
    const readable = new ReadableStream<Uint8Array>({ start: (c) => void (ctrl = c) });
    const writable = new WritableStream<Uint8Array>({
      write(chunk) {
        state.written.push(chunk);
        if (opts.hang) return;
        for (const c of opts.chunks ?? []) ctrl.enqueue(c);
        if (opts.eof) ctrl.close();
      },
    });
    const socket: SocketLike = {
      readable,
      writable,
      opened: opts.openError ? Promise.reject(opts.openError) : Promise.resolve({}),
      async close() {
        state.closed = true;
        try {
          ctrl.close();
        } catch {
          /* already closed */
        }
      },
    };
    socket.opened.catch(() => {});
    return socket;
  };
  return { connect, state };
}

function record(type: number, payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(5 + payload.length);
  out.set([type, 3, 3, payload.length >> 8, payload.length & 0xff]);
  out.set(payload, 5);
  return out;
}
function hs(type: number, body: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + body.length);
  out.set([type, body.length >> 16, (body.length >> 8) & 0xff, body.length & 0xff]);
  out.set(body, 4);
  return out;
}
function certMsg(certs: Uint8Array[]): Uint8Array {
  const parts: number[] = [];
  for (const c of certs) parts.push(c.length >> 16, (c.length >> 8) & 0xff, c.length & 0xff, ...c);
  return hs(11, Uint8Array.from([parts.length >> 16, (parts.length >> 8) & 0xff, parts.length & 0xff, ...parts]));
}
const serverHello = hs(2, Uint8Array.from([3, 3, ...new Array(32).fill(1), 0, 0xc0, 0x2f, 0]));

describe("runCheck", () => {
  it("returns evaluation for a TLS 1.2 server and closes the socket", async () => {
    const leaf = fixtureDer("leaf-old.crt");
    const ca = fixtureDer("ca.crt");
    const { connect, state } = fakeConnect({ chunks: [record(0x16, serverHello), record(0x16, certMsg([leaf, ca]))] });
    const out = await runCheck("https://www.example.gov.tw/", { connect });
    expect(out.status).toBe(200);
    expect(out.body.ok).toBe(true);
    if (out.body.ok) {
      expect(out.body.target).toBe("www.example.gov.tw:443");
      expect(out.body.verdict).toBe("needs_update");
      expect(out.body.chain).toHaveLength(2);
    }
    expect(state.closed).toBe(true);
    expect(state.address).toEqual({ hostname: "www.example.gov.tw", port: 443 });
    expect(state.options).toMatchObject({ secureTransport: "off" });
    // 送出的是 ClientHello，且帶正確 SNI
    const sent = state.written[0];
    expect(sent.length).toBe(buildClientHello("www.example.gov.tw").length);
    expect(new TextDecoder().decode(sent)).toContain("www.example.gov.tw");
  });

  it("maps alert to TLS13_ONLY and closes the socket", async () => {
    const { connect, state } = fakeConnect({ chunks: [record(0x15, Uint8Array.of(2, 70))] });
    const out = await runCheck("example.com", { connect });
    expect(out.body).toMatchObject({ ok: false, error: { code: "TLS13_ONLY" } });
    expect(state.closed).toBe(true);
  });

  it("times out and closes the socket", async () => {
    const { connect, state } = fakeConnect({ hang: true });
    const out = await runCheck("example.com", { connect, timeoutMs: 50 });
    expect(out.body).toMatchObject({ ok: false, error: { code: "TIMEOUT" } });
    expect(state.closed).toBe(true);
  });

  it("reports connect failures", async () => {
    const { connect, state } = fakeConnect({
      openError: new Error("proxy request failed, cannot connect to the specified address"),
    });
    const out = await runCheck("example.com", { connect });
    expect(out.body).toMatchObject({ ok: false, error: { code: "CONNECT_FAILED" } });
    expect(state.closed).toBe(true);
  });

  it("handles early EOF", async () => {
    const { connect, state } = fakeConnect({ chunks: [record(0x16, serverHello).subarray(0, 20)], eof: true });
    const out = await runCheck("example.com", { connect });
    expect(out.body).toMatchObject({ ok: false, error: { code: "PARSE_ERROR" } });
    expect(state.closed).toBe(true);
  });

  it("returns PARSE_ERROR when the certificate DER is garbage", async () => {
    const { connect, state } = fakeConnect({
      chunks: [record(0x16, serverHello), record(0x16, certMsg([Uint8Array.of(1, 2, 3)]))],
    });
    const out = await runCheck("example.com", { connect });
    expect(out.body).toMatchObject({ ok: false, error: { code: "PARSE_ERROR" } });
    expect(state.closed).toBe(true);
  });

  it("does not connect for blocked targets", async () => {
    const { connect, state } = fakeConnect({});
    const out = await runCheck("192.168.0.1", { connect });
    expect(out.status).toBe(403);
    expect(out.body).toMatchObject({ ok: false, error: { code: "BLOCKED_ADDRESS" } });
    expect(state.address).toBeNull();
    expect((await runCheck("example.com:22", { connect })).status).toBe(400);
  });
});

describe("readTargetFromBody", () => {
  it("parses valid JSON", () => {
    expect(readTargetFromBody('{"target":"example.com"}')).toEqual({ ok: true, target: "example.com" });
  });
  it("rejects invalid bodies", () => {
    for (const b of ["", "nope", "null", "[]", '{"target":1}', JSON.stringify({ target: "x".repeat(5000) })]) {
      expect(readTargetFromBody(b).ok).toBe(false);
    }
  });
});
