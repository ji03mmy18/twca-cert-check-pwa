/**
 * 使用者輸入的目標驗證（防濫用）。
 * 接受：example.com、example.com:8443、https://example.com/path、IPv4、[IPv6]:443。
 */
import type { ApiError } from "../shared/types";

export const ALLOWED_PORTS = [443, 8443];
const MAX_INPUT_LENGTH = 2048;

export interface Target {
  /** 連線用的主機（IPv6 不含方括號） */
  host: string;
  port: number;
  /** SNI；IP 位址為 null */
  serverName: string | null;
  kind: "domain" | "ipv4" | "ipv6";
  /** 顯示用，例如 www.example.gov.tw:443、[2001:db8::1]:443 */
  display: string;
}

export interface TargetOptions {
  /** 只在本機開發時為 true：允許 localhost、私有位址與任意連接埠 */
  allowPrivate?: boolean;
}

export type TargetResult = { ok: true; target: Target } | { ok: false; error: ApiError };

const fail = (code: ApiError["code"], message: string): TargetResult => ({ ok: false, error: { code, message } });

const BLOCKED_SUFFIXES = ["localhost", "local", "internal", "localdomain", "home.arpa", "invalid", "onion"];

// --- IPv4 --------------------------------------------------------------------

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function parseIPv4(s: string): number | null {
  const m = s.match(IPV4_RE);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p, i) => p > 255 || (m[i + 1].length > 1 && m[i + 1].startsWith("0")))) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

const IPV4_BLOCKED: [string, number][] = [
  ["0.0.0.0", 8], // 「這個」網路
  ["10.0.0.0", 8], // 私有
  ["100.64.0.0", 10], // CGNAT
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local
  ["172.16.0.0", 12], // 私有
  ["192.0.0.0", 24], // IETF 協定指派
  ["192.0.2.0", 24], // TEST-NET-1
  ["192.88.99.0", 24], // 6to4 relay
  ["192.168.0.0", 16], // 私有
  ["198.18.0.0", 15], // 效能測試
  ["198.51.100.0", 24], // TEST-NET-2
  ["203.0.113.0", 24], // TEST-NET-3
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // 保留（含 255.255.255.255）
];

export function isBlockedIPv4(ip: number): boolean {
  return IPV4_BLOCKED.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (ip & mask) >>> 0 === (parseIPv4(base)! & mask) >>> 0;
  });
}

// --- IPv6 --------------------------------------------------------------------

/** 解析 IPv6 為 8 個 16-bit 群組；格式錯誤回傳 null。不接受 zone id。 */
export function parseIPv6(s: string): number[] | null {
  if (!/^[0-9a-f:.]+$/i.test(s) || s.length > 45) return null;
  let tail: number[] = [];
  let str = s;
  // 結尾是 IPv4（例如 ::ffff:1.2.3.4）
  const v4m = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (v4m) {
    const v4 = parseIPv4(v4m[2]);
    if (v4 === null) return null;
    tail = [v4 >>> 16, v4 & 0xffff];
    // 移除 IPv4 前的冒號（"::" 本身要保留）
    str = v4m[1].endsWith("::") ? v4m[1] : v4m[1].slice(0, -1);
  }
  const dbl = str.split("::");
  if (dbl.length > 2) return null;
  const toGroups = (part: string): number[] | null => {
    if (part === "") return [];
    const out: number[] = [];
    for (const g of part.split(":")) {
      if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = toGroups(dbl[0]);
  const rest = dbl.length === 2 ? toGroups(dbl[1]) : [];
  if (!head || !rest) return null;
  const total = head.length + rest.length + tail.length;
  if (dbl.length === 2) {
    if (total > 7) return null;
    return [...head, ...new Array(8 - total).fill(0), ...rest, ...tail];
  }
  if (total !== 8) return null;
  return [...head, ...tail];
}

export function isBlockedIPv6(g: number[]): boolean {
  // 只允許全球單播 2000::/3，再排除其中的特殊用途區段
  if ((g[0] & 0xe000) !== 0x2000) return true; // 含 ::、::1、::ffff:0:0/96、64:ff9b::/96、fc00::/7、fe80::/10、ff00::/8
  if (g[0] === 0x2001 && g[1] === 0x0db8) return true; // 文件用途
  if (g[0] === 0x2001 && g[1] < 0x0200) return true; // 2001::/23 IETF 協定指派（含 Teredo）
  if (g[0] === 0x2002) return true; // 6to4（可嵌入私有 IPv4）
  if (g[0] === 0x3fff && g[1] < 0x1000) return true; // 3fff::/20 文件用途
  return false;
}

// --- 網域名稱 ----------------------------------------------------------------------

const LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

export function isValidDomain(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false;
  const labels = host.split(".");
  if (labels.length < 2) return false;
  if (!labels.every((l) => LABEL_RE.test(l))) return false;
  // TLD 不能全是數字（避免把奇怪的 IPv4 寫法當成網域）
  return !/^\d+$/.test(labels[labels.length - 1]);
}

function isBlockedDomain(host: string): boolean {
  return BLOCKED_SUFFIXES.some((s) => host === s || host.endsWith(`.${s}`));
}

// --- 主函式 ------------------------------------------------------------------------

export function parseTarget(input: unknown, options: TargetOptions = {}): TargetResult {
  if (typeof input !== "string") return fail("INVALID_TARGET", "請輸入網址或網域名稱");
  const raw = input.trim();
  if (!raw) return fail("INVALID_TARGET", "請輸入網址或網域名稱");
  if (raw.length > MAX_INPUT_LENGTH || /\s/.test(raw)) return fail("INVALID_TARGET", "網址格式不正確");

  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
  if (hasScheme && !/^https?:\/\//i.test(raw)) return fail("INVALID_TARGET", "只支援 https:// 網址");

  let url: URL;
  try {
    url = new URL(hasScheme ? raw : `https://${raw}`);
  } catch {
    return fail("INVALID_TARGET", "網址格式不正確");
  }
  if (url.username || url.password) return fail("INVALID_TARGET", "網址不可包含帳號密碼");

  let port = 443;
  // URL 會把 https 的 :443（或 http 的 :80）正規化成空字串
  const explicitPort = raw.match(/^(?:[a-z]+:\/\/)?(?:\[[^\]]*\]|[^/:?#[]*):(\d+)/i)?.[1];
  if (url.port) port = Number(url.port);
  else if (explicitPort) port = Number(explicitPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return fail("INVALID_TARGET", "連接埠不正確");
  if (!ALLOWED_PORTS.includes(port) && !options.allowPrivate) {
    return fail("PORT_NOT_ALLOWED", `只允許檢查連接埠 ${ALLOWED_PORTS.join("、")}`);
  }

  let host = url.hostname.toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  const blocked = fail("BLOCKED_ADDRESS", "不允許檢查本機、內部網路或保留位址");

  if (host.startsWith("[") && host.endsWith("]")) {
    const v6 = host.slice(1, -1);
    const groups = parseIPv6(v6);
    if (!groups) return fail("INVALID_TARGET", "IPv6 位址格式不正確");
    if (isBlockedIPv6(groups) && !options.allowPrivate) return blocked;
    return { ok: true, target: { host: v6, port, serverName: null, kind: "ipv6", display: `[${v6}]:${port}` } };
  }

  // URL 會把 0x7f.1、2130706433 等寫法正規化成點分十進位，這裡檢查的是正規化後的結果
  const v4 = parseIPv4(host);
  if (v4 !== null) {
    if (isBlockedIPv4(v4) && !options.allowPrivate) return blocked;
    return { ok: true, target: { host, port, serverName: null, kind: "ipv4", display: `${host}:${port}` } };
  }

  if (options.allowPrivate && host === "localhost") {
    return { ok: true, target: { host, port, serverName: host, kind: "domain", display: `${host}:${port}` } };
  }
  if (isBlockedDomain(host)) return blocked;
  if (!isValidDomain(host)) return fail("INVALID_TARGET", "網域名稱格式不正確");
  return { ok: true, target: { host, port, serverName: host, kind: "domain", display: `${host}:${port}` } };
}
