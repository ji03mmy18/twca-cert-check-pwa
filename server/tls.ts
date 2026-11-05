/**
 * 最小化的 TLS 1.2 用戶端：只送 ClientHello，讀到伺服器的 Certificate 訊息就停止。
 * TLS 1.2 的 Certificate 訊息是明文，不需要完成握手或金鑰交換。
 *
 * 參考：RFC 5246 §6.2（record）、§7.4.1.2（ClientHello）、§7.4.2（Certificate）、
 *      RFC 6066（SNI）、RFC 8422（EC groups / point formats）。
 */
import type { ApiErrorCode } from "../shared/types";

// ---------------------------------------------------------------------------
// ClientHello
// ---------------------------------------------------------------------------

export const CIPHER_SUITES = [
  0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
export const SUPPORTED_GROUPS = [0x001d, 0x0017, 0x0018]; // x25519, secp256r1, secp384r1
export const SIGNATURE_ALGORITHMS = [0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0201];

export const EXT_SERVER_NAME = 0x0000;
export const EXT_SUPPORTED_GROUPS = 0x000a;
export const EXT_EC_POINT_FORMATS = 0x000b;
export const EXT_SIGNATURE_ALGORITHMS = 0x000d;
export const EXT_RENEGOTIATION_INFO = 0xff01;

class ByteWriter {
  private parts: number[] = [];
  u8(v: number) {
    this.parts.push(v & 0xff);
    return this;
  }
  u16(v: number) {
    return this.u8(v >> 8).u8(v);
  }
  u24(v: number) {
    return this.u8(v >> 16)
      .u8(v >> 8)
      .u8(v);
  }
  bytes(b: ArrayLike<number>) {
    for (let i = 0; i < b.length; i++) this.parts.push(b[i] & 0xff);
    return this;
  }
  get length() {
    return this.parts.length;
  }
  toBytes() {
    return Uint8Array.from(this.parts);
  }
}

function u16List(values: number[]): Uint8Array {
  const w = new ByteWriter();
  for (const v of values) w.u16(v);
  return w.toBytes();
}

function extension(type: number, data: Uint8Array): Uint8Array {
  return new ByteWriter().u16(type).u16(data.length).bytes(data).toBytes();
}

/**
 * 產生只支援 TLS 1.2 的 ClientHello record。
 * @param serverName SNI 主機名（ASCII / punycode）。IP 位址請傳 null（不送 SNI）。
 */
export function buildClientHello(serverName: string | null, random?: Uint8Array): Uint8Array {
  const rnd = random ?? crypto.getRandomValues(new Uint8Array(32));
  if (rnd.length !== 32) throw new Error("random must be 32 bytes");

  const exts: Uint8Array[] = [];
  if (serverName) {
    const host = new TextEncoder().encode(serverName);
    if (host.length === 0 || host.length > 255 || /[^\x21-\x7e]/.test(serverName)) {
      throw new Error("invalid SNI host name");
    }
    const entry = new ByteWriter().u8(0x00).u16(host.length).bytes(host).toBytes();
    exts.push(extension(EXT_SERVER_NAME, new ByteWriter().u16(entry.length).bytes(entry).toBytes()));
  }
  const groups = u16List(SUPPORTED_GROUPS);
  exts.push(extension(EXT_SUPPORTED_GROUPS, new ByteWriter().u16(groups.length).bytes(groups).toBytes()));
  exts.push(extension(EXT_EC_POINT_FORMATS, Uint8Array.of(0x01, 0x00)));
  const sigs = u16List(SIGNATURE_ALGORITHMS);
  exts.push(extension(EXT_SIGNATURE_ALGORITHMS, new ByteWriter().u16(sigs.length).bytes(sigs).toBytes()));
  exts.push(extension(EXT_RENEGOTIATION_INFO, Uint8Array.of(0x00)));
  // 注意：刻意不送 supported_versions（0x002b），避免伺服器選擇 TLS 1.3。

  const extBytes = new ByteWriter();
  for (const e of exts) extBytes.bytes(e);
  const suites = u16List(CIPHER_SUITES);

  const body = new ByteWriter()
    .u16(0x0303) // client_version: TLS 1.2
    .bytes(rnd)
    .u8(0x00) // session_id length
    .u16(suites.length)
    .bytes(suites)
    .u8(0x01) // compression_methods length
    .u8(0x00) // null compression
    .u16(extBytes.length)
    .bytes(extBytes.toBytes())
    .toBytes();

  const handshake = new ByteWriter().u8(0x01).u24(body.length).bytes(body).toBytes();
  return new ByteWriter()
    .u8(0x16) // handshake
    .u16(0x0301) // legacy record version
    .u16(handshake.length)
    .bytes(handshake)
    .toBytes();
}

// ---------------------------------------------------------------------------
// 伺服器回應解析
// ---------------------------------------------------------------------------

export const MAX_RESPONSE_BYTES = 64 * 1024;
/** RFC 5246 §6.2.3：TLSCiphertext 最大 2^14 + 2048 */
const MAX_RECORD_LENGTH = 16384 + 2048;

const CONTENT_ALERT = 0x15;
const CONTENT_HANDSHAKE = 0x16;

const HS_HELLO_REQUEST = 0;
const HS_SERVER_HELLO = 2;
const HS_CERTIFICATE = 11;
const HS_SERVER_KEY_EXCHANGE = 12;
const HS_CERTIFICATE_REQUEST = 13;
const HS_SERVER_HELLO_DONE = 14;

const ALERT_HANDSHAKE_FAILURE = 40;
const ALERT_PROTOCOL_VERSION = 70;

export const ALERT_NAMES: Record<number, string> = {
  0: "close_notify",
  10: "unexpected_message",
  20: "bad_record_mac",
  22: "record_overflow",
  40: "handshake_failure",
  42: "bad_certificate",
  47: "illegal_parameter",
  50: "decode_error",
  51: "decrypt_error",
  70: "protocol_version",
  71: "insufficient_security",
  80: "internal_error",
  86: "inappropriate_fallback",
  90: "user_canceled",
  109: "missing_extension",
  110: "unsupported_extension",
  112: "unrecognized_name",
  120: "no_application_protocol",
};

export type ExtractResult =
  | { kind: "certificates"; certificates: Uint8Array[]; serverVersion: number }
  | { kind: "error"; code: ApiErrorCode; message: string; alert?: { level: number; description: number } };

function err(code: ApiErrorCode, message: string, alert?: { level: number; description: number }): ExtractResult {
  return alert ? { kind: "error", code, message, alert } : { kind: "error", code, message };
}

const TLS13_MESSAGE =
  "此網站可能只支援 TLS 1.3（或不接受 TLS 1.2 的加密套件），無法從伺服器取得憑證，請改用「貼上憑證」模式";

/** 解析 Certificate 訊息本體（不含 handshake header）。 */
export function parseCertificateMessage(body: Uint8Array): ExtractResult {
  if (body.length < 3) return err("PARSE_ERROR", "Certificate 訊息被截斷");
  const total = (body[0] << 16) | (body[1] << 8) | body[2];
  if (total !== body.length - 3) return err("PARSE_ERROR", "Certificate 訊息長度欄位不一致");
  const certificates: Uint8Array[] = [];
  let pos = 3;
  while (pos < body.length) {
    if (pos + 3 > body.length) return err("PARSE_ERROR", "憑證長度欄位被截斷");
    const len = (body[pos] << 16) | (body[pos + 1] << 8) | body[pos + 2];
    pos += 3;
    if (len === 0 || pos + len > body.length) return err("PARSE_ERROR", "憑證長度欄位超出訊息範圍");
    certificates.push(body.slice(pos, pos + len));
    pos += len;
  }
  if (certificates.length === 0) return err("NO_CERTIFICATE", "伺服器送出的 Certificate 訊息中沒有憑證");
  return { kind: "certificates", certificates, serverVersion: 0x0303 };
}

/**
 * 漸進式解析伺服器回應。每收到一段資料就呼叫 feed()；
 * 回傳 null 表示需要更多資料，否則回傳最終結果（之後不應再 feed）。
 * 不信任任何長度欄位，所有讀取都有邊界檢查，不會拋出例外。
 */
export class CertificateExtractor {
  private buf = new Uint8Array(0);
  private hs = new Uint8Array(0);
  private received = 0;
  private serverVersion: number | null = null;
  private result: ExtractResult | null = null;

  get bytesReceived() {
    return this.received;
  }

  feed(chunk: Uint8Array): ExtractResult | null {
    if (this.result) return this.result;
    try {
      this.received += chunk.length;
      if (this.received > MAX_RESPONSE_BYTES) {
        return (this.result = err("PARSE_ERROR", "伺服器回應超過 64 KB 仍未送出憑證，已中止"));
      }
      this.buf = concat(this.buf, chunk);
      return (this.result = this.processRecords());
    } catch (e) {
      // 理論上不會發生；保險起見不讓例外往外拋
      return (this.result = err("PARSE_ERROR", `無法解析伺服器回應（${(e as Error).message}）`));
    }
  }

  /** 連線結束（EOF）時呼叫。 */
  end(): ExtractResult {
    if (this.result) return this.result;
    if (this.received === 0) return (this.result = err("CONNECT_FAILED", "伺服器沒有回應任何資料就關閉了連線"));
    return (this.result = err("PARSE_ERROR", "伺服器在送出憑證之前就關閉了連線"));
  }

  private processRecords(): ExtractResult | null {
    for (;;) {
      if (this.buf.length < 5) return null;
      const type = this.buf[0];
      const major = this.buf[1];
      const len = (this.buf[3] << 8) | this.buf[4];
      if (type !== CONTENT_HANDSHAKE && type !== CONTENT_ALERT) {
        if (type === 0x48 /* 'H' */)
          return err("PARSE_ERROR", "伺服器回應的是 HTTP 而不是 TLS，這個連接埠可能沒有啟用 HTTPS");
        return err("PARSE_ERROR", `收到非預期的 TLS record 類型（${type}）`);
      }
      if (major !== 0x03) return err("PARSE_ERROR", "伺服器回應不是 TLS");
      if (len > MAX_RECORD_LENGTH) return err("PARSE_ERROR", "TLS record 長度欄位超出上限");
      if (this.buf.length < 5 + len) return null;
      const payload = this.buf.slice(5, 5 + len);
      this.buf = this.buf.slice(5 + len);

      if (type === CONTENT_ALERT) return this.handleAlert(payload);

      this.hs = concat(this.hs, payload);
      const r = this.processHandshake();
      if (r) return r;
    }
  }

  private handleAlert(payload: Uint8Array): ExtractResult {
    if (payload.length < 2) return err("PARSE_ERROR", "Alert record 被截斷");
    const level = payload[0];
    const description = payload[1];
    const alert = { level, description };
    if (description === ALERT_PROTOCOL_VERSION || description === ALERT_HANDSHAKE_FAILURE) {
      return err("TLS13_ONLY", TLS13_MESSAGE, alert);
    }
    const name = ALERT_NAMES[description] ?? `alert ${description}`;
    return err("TLS_ALERT", `伺服器回傳 TLS 警示：${name}（${description}）`, alert);
  }

  private processHandshake(): ExtractResult | null {
    for (;;) {
      if (this.hs.length < 4) return null;
      const type = this.hs[0];
      const len = (this.hs[1] << 16) | (this.hs[2] << 8) | this.hs[3];
      if (len > MAX_RESPONSE_BYTES) return err("PARSE_ERROR", "handshake 訊息長度欄位超出上限");
      if (this.hs.length < 4 + len) return null;
      const body = this.hs.slice(4, 4 + len);
      this.hs = this.hs.slice(4 + len);

      switch (type) {
        case HS_HELLO_REQUEST:
          continue;
        case HS_SERVER_HELLO: {
          if (this.serverVersion !== null) return err("PARSE_ERROR", "收到重複的 ServerHello");
          if (body.length < 2) return err("PARSE_ERROR", "ServerHello 被截斷");
          const version = (body[0] << 8) | body[1];
          this.serverVersion = version;
          if (version !== 0x0303) {
            if (version > 0x0303) return err("TLS13_ONLY", TLS13_MESSAGE);
            return err(
              "UNSUPPORTED_VERSION",
              `伺服器選擇了 TLS 1.2 以外的舊版協定（0x${version.toString(16).padStart(4, "0")}），本工具只支援 TLS 1.2，請改用「貼上憑證」模式`,
            );
          }
          continue;
        }
        case HS_CERTIFICATE: {
          if (this.serverVersion === null) return err("PARSE_ERROR", "在 ServerHello 之前收到 Certificate");
          return parseCertificateMessage(body);
        }
        case HS_SERVER_KEY_EXCHANGE:
        case HS_CERTIFICATE_REQUEST:
        case HS_SERVER_HELLO_DONE:
          if (this.serverVersion === null) return err("PARSE_ERROR", "收到非預期的 handshake 訊息");
          return err("NO_CERTIFICATE", "伺服器沒有送出憑證");
        default:
          return err("PARSE_ERROR", `收到非預期的 handshake 訊息類型（${type}）`);
      }
    }
  }
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length === 0) return b.slice();
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
