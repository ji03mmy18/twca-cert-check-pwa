import { describe, expect, it } from "vite-plus/test";
import {
  buildClientHello,
  CertificateExtractor,
  CIPHER_SUITES,
  MAX_RESPONSE_BYTES,
  parseCertificateMessage,
  type ExtractResult,
} from "../server/tls";
import { fixtureDer } from "./helpers";

const u16 = (b: Uint8Array, o: number) => (b[o] << 8) | b[o + 1];
const u24 = (b: Uint8Array, o: number) => (b[o] << 16) | (b[o + 1] << 8) | b[o + 2];

/** 解析 ClientHello，回傳 extensions map 與各欄位，順便驗證所有長度欄位。 */
function parseHello(rec: Uint8Array) {
  expect(rec[0]).toBe(0x16);
  expect(u16(rec, 1)).toBe(0x0301);
  expect(u16(rec, 3)).toBe(rec.length - 5);
  const hs = rec.subarray(5);
  expect(hs[0]).toBe(0x01);
  expect(u24(hs, 1)).toBe(hs.length - 4);
  const body = hs.subarray(4);
  let p = 0;
  expect(u16(body, p)).toBe(0x0303);
  p += 2 + 32;
  expect(body[p]).toBe(0); // session id
  p += 1;
  const csLen = u16(body, p);
  p += 2;
  const suites: number[] = [];
  for (let i = 0; i < csLen; i += 2) suites.push(u16(body, p + i));
  p += csLen;
  expect([body[p], body[p + 1]]).toEqual([1, 0]);
  p += 2;
  const extLen = u16(body, p);
  p += 2;
  expect(p + extLen).toBe(body.length);
  const exts = new Map<number, Uint8Array>();
  const end = p + extLen;
  while (p < end) {
    const type = u16(body, p);
    const len = u16(body, p + 2);
    exts.set(type, body.subarray(p + 4, p + 4 + len));
    p += 4 + len;
  }
  expect(p).toBe(end);
  return { suites, exts, random: body.subarray(2, 34) };
}

describe("buildClientHello", () => {
  it("has consistent length fields and required extensions", () => {
    const { suites, exts } = parseHello(buildClientHello("www.example.gov.tw"));
    expect(suites).toEqual(CIPHER_SUITES);
    expect([...exts.keys()].sort((a, b) => a - b)).toEqual([0x0000, 0x000a, 0x000b, 0x000d, 0xff01]);
    expect([...exts.get(0x000b)!]).toEqual([1, 0]);
    expect([...exts.get(0xff01)!]).toEqual([0]);
    const groups = exts.get(0x000a)!;
    expect(u16(groups, 0)).toBe(groups.length - 2);
    expect([u16(groups, 2), u16(groups, 4), u16(groups, 6)]).toEqual([0x001d, 0x0017, 0x0018]);
    const sigs = exts.get(0x000d)!;
    expect(u16(sigs, 0)).toBe(20);
  });

  it("never sends supported_versions", () => {
    const { exts } = parseHello(buildClientHello("example.com"));
    expect(exts.has(0x002b)).toBe(false);
  });

  it("encodes SNI correctly", () => {
    const host = "www.example.gov.tw";
    const sni = parseHello(buildClientHello(host)).exts.get(0x0000)!;
    expect(u16(sni, 0)).toBe(sni.length - 2);
    expect(sni[2]).toBe(0x00);
    expect(u16(sni, 3)).toBe(host.length);
    expect(new TextDecoder().decode(sni.subarray(5))).toBe(host);
  });

  it("omits SNI for IP addresses (null)", () => {
    expect(parseHello(buildClientHello(null)).exts.has(0x0000)).toBe(false);
  });

  it("uses fresh randomness, or the provided random", () => {
    const a = parseHello(buildClientHello("a.com")).random;
    const b = parseHello(buildClientHello("a.com")).random;
    expect(a).not.toEqual(b);
    const fixed = new Uint8Array(32).fill(7);
    expect(parseHello(buildClientHello("a.com", fixed)).random).toEqual(fixed);
  });

  it("rejects non-ASCII SNI", () => {
    expect(() => buildClientHello("例え.jp")).toThrow();
  });
});

// --- server response builders -------------------------------------------

function record(type: number, payload: Uint8Array, version = 0x0303): Uint8Array {
  const out = new Uint8Array(5 + payload.length);
  out.set([type, version >> 8, version & 0xff, payload.length >> 8, payload.length & 0xff]);
  out.set(payload, 5);
  return out;
}
function hsMsg(type: number, body: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + body.length);
  out.set([type, body.length >> 16, (body.length >> 8) & 0xff, body.length & 0xff]);
  out.set(body, 4);
  return out;
}
function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
function serverHello(version = 0x0303): Uint8Array {
  const body = new Uint8Array(2 + 32 + 1 + 2 + 1);
  body.set([version >> 8, version & 0xff]);
  body.set([0xc0, 0x2f, 0x00], 35);
  return hsMsg(2, body);
}
function certificateMsg(certs: Uint8Array[]): Uint8Array {
  const items = cat(
    ...certs.map((c) => cat(Uint8Array.of(c.length >> 16, (c.length >> 8) & 0xff, c.length & 0xff), c)),
  );
  const len = items.length;
  return hsMsg(11, cat(Uint8Array.of(len >> 16, (len >> 8) & 0xff, len & 0xff), items));
}
const done = hsMsg(14, new Uint8Array(0));

function feedAll(chunks: Uint8Array[]): ExtractResult {
  const ex = new CertificateExtractor();
  for (const c of chunks) {
    const r = ex.feed(c);
    if (r) return r;
  }
  return ex.end();
}

const leaf = fixtureDer("leaf-old.crt");
const ca = fixtureDer("ca.crt");

describe("CertificateExtractor", () => {
  it("extracts certificates from a normal response", () => {
    const stream = cat(record(0x16, serverHello()), record(0x16, certificateMsg([leaf, ca])), record(0x16, done));
    const r = feedAll([stream]);
    expect(r.kind).toBe("certificates");
    if (r.kind === "certificates") expect(r.certificates).toEqual([leaf, ca]);
  });

  it("handles a handshake message spanning multiple records", () => {
    const hs = cat(serverHello(), certificateMsg([leaf, ca]), done);
    const recs: Uint8Array[] = [];
    for (let i = 0; i < hs.length; i += 100) recs.push(record(0x16, hs.subarray(i, i + 100)));
    const r = feedAll(recs);
    expect(r.kind).toBe("certificates");
  });

  it("handles multiple handshake messages in one record", () => {
    const r = feedAll([record(0x16, cat(serverHello(), certificateMsg([leaf]), done))]);
    expect(r.kind === "certificates" && r.certificates.length).toBe(1);
  });

  it("handles byte-by-byte delivery", () => {
    const stream = cat(record(0x16, serverHello()), record(0x16, certificateMsg([leaf, ca])));
    const r = feedAll([...stream].map((b) => Uint8Array.of(b)));
    expect(r.kind).toBe("certificates");
  });

  it("stops at Certificate without needing further data", () => {
    const ex = new CertificateExtractor();
    const r = ex.feed(cat(record(0x16, serverHello()), record(0x16, certificateMsg([leaf]))));
    expect(r?.kind).toBe("certificates");
  });

  it("reports truncated data on EOF", () => {
    const stream = cat(record(0x16, serverHello()), record(0x16, certificateMsg([leaf, ca])));
    for (const cut of [0, 3, 10, 60, stream.length - 1]) {
      const r = feedAll([stream.subarray(0, cut)]);
      expect(r.kind).toBe("error");
      if (r.kind === "error") expect(["PARSE_ERROR", "CONNECT_FAILED"]).toContain(r.code);
    }
  });

  it("rejects forged length fields", () => {
    // record length too large
    expect(feedAll([Uint8Array.of(0x16, 3, 3, 0xff, 0xff)])).toMatchObject({ code: "PARSE_ERROR" });
    // handshake length too large
    expect(feedAll([record(0x16, Uint8Array.of(2, 0xff, 0xff, 0xff))])).toMatchObject({ code: "PARSE_ERROR" });
    // certificate list length mismatch
    const bad = certificateMsg([leaf]);
    bad[6] ^= 0x01;
    expect(feedAll([record(0x16, cat(serverHello(), bad))])).toMatchObject({ code: "PARSE_ERROR" });
    // single cert length overflow
    expect(parseCertificateMessage(Uint8Array.of(0, 0, 4, 0, 0, 9, 1))).toMatchObject({ code: "PARSE_ERROR" });
  });

  it("maps protocol_version / handshake_failure alerts to TLS13_ONLY", () => {
    expect(feedAll([record(0x15, Uint8Array.of(2, 70))])).toMatchObject({ code: "TLS13_ONLY" });
    expect(feedAll([record(0x15, Uint8Array.of(2, 40))])).toMatchObject({ code: "TLS13_ONLY" });
  });

  it("maps other alerts to TLS_ALERT", () => {
    const r = feedAll([record(0x15, Uint8Array.of(2, 112))]);
    expect(r).toMatchObject({ code: "TLS_ALERT", alert: { level: 2, description: 112 } });
    if (r.kind === "error") expect(r.message).toContain("unrecognized_name");
    expect(feedAll([record(0x15, Uint8Array.of(2))])).toMatchObject({ code: "PARSE_ERROR" });
  });

  it("rejects non-TLS 1.2 ServerHello", () => {
    expect(feedAll([record(0x16, serverHello(0x0304))])).toMatchObject({ code: "TLS13_ONLY" });
    expect(feedAll([record(0x16, serverHello(0x0301))])).toMatchObject({ code: "UNSUPPORTED_VERSION" });
  });

  it("reports NO_CERTIFICATE when ServerHelloDone arrives first", () => {
    expect(feedAll([record(0x16, cat(serverHello(), done))])).toMatchObject({ code: "NO_CERTIFICATE" });
    expect(feedAll([record(0x16, cat(serverHello(), certificateMsg([])))])).toMatchObject({ code: "NO_CERTIFICATE" });
  });

  it("detects HTTP responses and garbage", () => {
    const http = new TextEncoder().encode("HTTP/1.1 400 Bad Request\r\n\r\n");
    expect(feedAll([http])).toMatchObject({ code: "PARSE_ERROR" });
    expect(feedAll([Uint8Array.of(0x17, 3, 3, 0, 1, 0)])).toMatchObject({ code: "PARSE_ERROR" });
  });

  it("enforces the 64 KB limit", () => {
    const ex = new CertificateExtractor();
    // 合法的 ServerHello 後接大量 HelloRequest（被忽略），直到超過上限
    let r = ex.feed(record(0x16, serverHello()));
    const filler = record(0x16, new Uint8Array(16000));
    for (let i = 0; i < 10 && !r; i++) r = ex.feed(filler);
    expect(r).toMatchObject({ code: "PARSE_ERROR" });
    expect(ex.bytesReceived).toBeGreaterThan(MAX_RESPONSE_BYTES);
  });

  it("never throws on random input", () => {
    let seed = 1;
    const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    const base = cat(record(0x16, serverHello()), record(0x16, certificateMsg([leaf, ca])));
    for (let i = 0; i < 3000; i++) {
      const copy = base.slice(0, Math.floor(rnd() * base.length) + 1);
      for (let k = 0; k < 4; k++) copy[Math.floor(rnd() * copy.length)] = Math.floor(rnd() * 256);
      const r = feedAll([copy]);
      expect(["certificates", "error"]).toContain(r.kind);
    }
  });
});
