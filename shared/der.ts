/**
 * 最小化的 DER（ASN.1）讀取器。只處理 X.509 解析需要的部分。
 * 所有長度都做邊界檢查，格式錯誤時拋出 DerError（呼叫端負責捕捉）。
 */

export class DerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DerError";
  }
}

export interface Tlv {
  /** 完整的 tag byte（只支援 low-tag-number form）。 */
  tag: number;
  /** 整個 TLV 的起點 */
  start: number;
  /** value 起點 */
  valueStart: number;
  /** value 結尾（不含） */
  end: number;
}

export function readTlv(buf: Uint8Array, offset: number, limit = buf.length): Tlv {
  if (limit > buf.length) limit = buf.length;
  if (offset + 2 > limit) throw new DerError("資料被截斷（TLV header）");
  const tag = buf[offset];
  if ((tag & 0x1f) === 0x1f) throw new DerError("不支援 high-tag-number form");
  let pos = offset + 1;
  const first = buf[pos++];
  let len: number;
  if (first < 0x80) {
    len = first;
  } else {
    const n = first & 0x7f;
    if (n === 0 || n > 4) throw new DerError("不支援的長度編碼");
    if (pos + n > limit) throw new DerError("資料被截斷（長度欄位）");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[pos++];
  }
  const end = pos + len;
  if (end > limit) throw new DerError("長度欄位超出資料範圍");
  return { tag, start: offset, valueStart: pos, end };
}

/** 讀取 constructed TLV 內的所有子元素。 */
export function children(buf: Uint8Array, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let pos = parent.valueStart;
  while (pos < parent.end) {
    const t = readTlv(buf, pos, parent.end);
    out.push(t);
    pos = t.end;
  }
  return out;
}

export function expectTag(t: Tlv | undefined, tag: number, what: string): Tlv {
  if (!t || t.tag !== tag) throw new DerError(`預期 ${what}`);
  return t;
}

export function value(buf: Uint8Array, t: Tlv): Uint8Array {
  return buf.subarray(t.valueStart, t.end);
}

export function decodeOid(bytes: Uint8Array): string {
  if (bytes.length === 0) throw new DerError("空的 OID");
  const parts: number[] = [];
  let v = 0;
  for (let i = 0; i < bytes.length; i++) {
    v = v * 128 + (bytes[i] & 0x7f);
    if (v > Number.MAX_SAFE_INTEGER / 128) throw new DerError("OID 過長");
    if ((bytes[i] & 0x80) === 0) {
      if (parts.length === 0) {
        const a = v < 40 ? 0 : v < 80 ? 1 : 2;
        parts.push(a, v - a * 40);
      } else {
        parts.push(v);
      }
      v = 0;
    }
  }
  return parts.join(".");
}

const latin1 = (b: Uint8Array) => String.fromCharCode(...b);

export function decodeString(tag: number, bytes: Uint8Array): string {
  switch (tag) {
    case 0x0c: // UTF8String
      return new TextDecoder("utf-8").decode(bytes);
    case 0x1e: {
      // BMPString（UTF-16BE）
      let s = "";
      for (let i = 0; i + 1 < bytes.length; i += 2) s += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
      return s;
    }
    case 0x1c: {
      // UniversalString（UTF-32BE）
      let s = "";
      for (let i = 0; i + 3 < bytes.length; i += 4) {
        const cp = ((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]) >>> 0;
        s += cp <= 0x10ffff ? String.fromCodePoint(cp) : "�";
      }
      return s;
    }
    case 0x13: // PrintableString
    case 0x16: // IA5String
    case 0x14: // TeletexString（以 Latin-1 近似）
    case 0x1a: // VisibleString
    default:
      return latin1(bytes);
  }
}

/** UTCTime（0x17）或 GeneralizedTime（0x18）轉成 Date。 */
export function decodeTime(tag: number, bytes: Uint8Array): Date {
  const s = latin1(bytes);
  let m: RegExpMatchArray | null;
  let year: number;
  let rest: string;
  if (tag === 0x17) {
    m = s.match(/^(\d{2})(\d{10})(\d{2})?Z$/);
    if (!m) throw new DerError("UTCTime 格式錯誤");
    const yy = Number(m[1]);
    year = yy < 50 ? 2000 + yy : 1900 + yy;
    rest = m[2] + (m[3] ?? "00");
  } else if (tag === 0x18) {
    m = s.match(/^(\d{4})(\d{10})(?:\.\d+)?Z$/);
    if (!m) throw new DerError("GeneralizedTime 格式錯誤");
    year = Number(m[1]);
    rest = m[2];
  } else {
    throw new DerError("預期時間欄位");
  }
  const mo = Number(rest.slice(0, 2));
  const d = Number(rest.slice(2, 4));
  const h = Number(rest.slice(4, 6));
  const mi = Number(rest.slice(6, 8));
  const se = Number(rest.slice(8, 10));
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 60) throw new DerError("時間數值錯誤");
  return new Date(Date.UTC(year, mo - 1, d, h, mi, se));
}
