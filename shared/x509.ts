/**
 * 從 DER 取出本工具需要的 X.509 欄位：
 * subject、issuer、notBefore、notAfter、basicConstraints CA 旗標、SHA-256 指紋。
 */
import { children, decodeOid, decodeString, decodeTime, DerError, expectTag, readTlv, value, type Tlv } from "./der";

export interface NameAttribute {
  type: string; // 短名稱（CN、O…）或 OID
  value: string;
}

export interface ParsedCertificate {
  der: Uint8Array;
  subject: string;
  issuer: string;
  subjectAttrs: NameAttribute[];
  issuerAttrs: NameAttribute[];
  notBefore: Date;
  notAfter: Date;
  /** true/false：有 basicConstraints；null：沒有 basicConstraints 擴充 */
  isCA: boolean | null;
  sha256: string;
}

const NAME_OIDS: Record<string, string> = {
  "2.5.4.3": "CN",
  "2.5.4.4": "SN",
  "2.5.4.5": "serialNumber",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.9": "street",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "2.5.4.12": "title",
  "2.5.4.15": "businessCategory",
  "2.5.4.17": "postalCode",
  "2.5.4.42": "GN",
  "2.5.4.97": "organizationIdentifier",
  "1.2.840.113549.1.9.1": "emailAddress",
  "0.9.2342.19200300.100.1.25": "DC",
  "1.3.6.1.4.1.311.60.2.1.1": "jurisdictionL",
  "1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST",
  "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
};

const OID_BASIC_CONSTRAINTS = "2.5.29.19";

function parseName(buf: Uint8Array, name: Tlv): NameAttribute[] {
  expectTag(name, 0x30, "Name SEQUENCE");
  const attrs: NameAttribute[] = [];
  for (const rdn of children(buf, name)) {
    expectTag(rdn, 0x31, "RDN SET");
    for (const atv of children(buf, rdn)) {
      expectTag(atv, 0x30, "AttributeTypeAndValue");
      const [oidT, valT] = children(buf, atv);
      const oid = decodeOid(value(buf, expectTag(oidT, 0x06, "attribute OID")));
      if (!valT) throw new DerError("缺少 attribute value");
      attrs.push({ type: NAME_OIDS[oid] ?? oid, value: decodeString(valT.tag, value(buf, valT)) });
    }
  }
  return attrs;
}

export function formatName(attrs: NameAttribute[]): string {
  return attrs.map((a) => `${a.type}=${a.value}`).join(", ");
}

function parseBasicConstraints(buf: Uint8Array, extensions: Tlv): boolean | null {
  const seq = readTlv(buf, extensions.valueStart, extensions.end);
  expectTag(seq, 0x30, "Extensions SEQUENCE");
  for (const ext of children(buf, seq)) {
    expectTag(ext, 0x30, "Extension");
    const parts = children(buf, ext);
    const oid = decodeOid(value(buf, expectTag(parts[0], 0x06, "extension OID")));
    if (oid !== OID_BASIC_CONSTRAINTS) continue;
    const octet = parts[parts.length - 1];
    expectTag(octet, 0x04, "extnValue OCTET STRING");
    const bc = readTlv(buf, octet.valueStart, octet.end);
    expectTag(bc, 0x30, "BasicConstraints SEQUENCE");
    const first = children(buf, bc)[0];
    if (first && first.tag === 0x01) {
      return first.end > first.valueStart && buf[first.valueStart] !== 0;
    }
    return false; // cA DEFAULT FALSE
  }
  return null;
}

export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export async function sha256Hex(der: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", der as BufferSource);
  return toHex(new Uint8Array(digest));
}

/** 同步解析（不含指紋）。格式錯誤時拋出 DerError。 */
export function parseCertificateFields(input: Uint8Array): Omit<ParsedCertificate, "sha256"> {
  const cert = readTlv(input, 0);
  expectTag(cert, 0x30, "Certificate SEQUENCE");
  // 只取 Certificate 這個 TLV 本身，忽略尾端多餘的 bytes
  const der = input.subarray(0, cert.end);
  const [tbs] = children(der, cert);
  expectTag(tbs, 0x30, "TBSCertificate SEQUENCE");
  const f = children(der, tbs);
  let i = 0;
  if (f[i]?.tag === 0xa0) i++; // version
  expectTag(f[i++], 0x02, "serialNumber");
  expectTag(f[i++], 0x30, "signature AlgorithmIdentifier");
  const issuerT = f[i++];
  const validity = expectTag(f[i++], 0x30, "Validity");
  const subjectT = f[i++];
  expectTag(f[i++], 0x30, "SubjectPublicKeyInfo");
  let isCA: boolean | null = null;
  for (; i < f.length; i++) {
    if (f[i].tag === 0xa3) isCA = parseBasicConstraints(der, f[i]);
  }
  const [nb, na] = children(der, validity);
  if (!nb || !na) throw new DerError("Validity 欄位不完整");
  const issuerAttrs = parseName(der, issuerT);
  const subjectAttrs = parseName(der, subjectT);
  return {
    der,
    subject: formatName(subjectAttrs),
    issuer: formatName(issuerAttrs),
    subjectAttrs,
    issuerAttrs,
    notBefore: decodeTime(nb.tag, value(der, nb)),
    notAfter: decodeTime(na.tag, value(der, na)),
    isCA,
  };
}

export async function parseCertificate(input: Uint8Array): Promise<ParsedCertificate> {
  const fields = parseCertificateFields(input);
  return { ...fields, sha256: await sha256Hex(fields.der) };
}

export function getAttr(attrs: NameAttribute[], type: string): string | undefined {
  return attrs.find((a) => a.type === type)?.value;
}
