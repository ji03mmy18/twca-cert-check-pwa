/**
 * 貼上 / 上傳模式的輸入解析：
 * - 文字中的一或多段 PEM（忽略 PEM 以外的文字，例如 openssl s_client -showcerts 的輸出）
 * - DER 二進位檔
 */

const PEM_RE = /-----BEGIN (?:X509 |TRUSTED )?CERTIFICATE-----([\s\S]*?)-----END (?:X509 |TRUSTED )?CERTIFICATE-----/g;

export function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/[^A-Za-z0-9+/=]/g, "");
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

export interface PemExtractResult {
  ders: Uint8Array[];
  /** 無法解碼的 PEM 區塊數 */
  invalidBlocks: number;
}

export function extractPemCertificates(text: string): PemExtractResult {
  const ders: Uint8Array[] = [];
  let invalidBlocks = 0;
  for (const m of text.matchAll(PEM_RE)) {
    try {
      const der = base64ToBytes(m[1]);
      if (der.length === 0) throw new Error("empty");
      ders.push(der);
    } catch {
      invalidBlocks++;
    }
  }
  return { ders, invalidBlocks };
}

/** 判斷檔案內容是 PEM 還是 DER，回傳 DER 陣列。 */
export function extractFromFile(bytes: Uint8Array): PemExtractResult {
  // DER 憑證一定以 SEQUENCE（0x30）+ 長度開頭
  if (bytes.length > 2 && bytes[0] === 0x30 && (bytes[1] === 0x82 || bytes[1] === 0x83 || bytes[1] === 0x81)) {
    return { ders: [bytes], invalidBlocks: 0 };
  }
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  return extractPemCertificates(text);
}
