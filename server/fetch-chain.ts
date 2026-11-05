/**
 * 連到目標主機，送出 TLS 1.2 ClientHello，讀回 Certificate 訊息後立即斷線。
 * connect 由呼叫端注入（正式環境為 cloudflare:sockets 的 connect），方便測試。
 */
import type { ApiError } from "../shared/types";
import type { Target } from "./target";
import { buildClientHello, CertificateExtractor } from "./tls";

export interface SocketLike {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  opened: Promise<unknown>;
  close(): Promise<void>;
}

export type ConnectFn = (
  address: { hostname: string; port: number },
  options: { secureTransport: "off"; allowHalfOpen: boolean },
) => SocketLike;

export const TOTAL_TIMEOUT_MS = 10_000;

export type FetchChainResult = { ok: true; certificates: Uint8Array[] } | { ok: false; error: ApiError };

class TimeoutError extends Error {}

function describeConnectError(e: unknown): ApiError {
  const msg = String((e as Error)?.message ?? e);
  if (/proxy request failed|cannot connect to the specified address/i.test(msg)) {
    return {
      code: "CONNECT_FAILED",
      message:
        "無法連線到此網站。可能原因：網站沒有開啟這個連接埠、位址不允許連線，或網站使用 Cloudflare CDN（Cloudflare Workers 不能連到 Cloudflare 自家的 IP）。請改用「貼上憑證」模式",
    };
  }
  if (/TCP Loop/i.test(msg)) {
    return { code: "CONNECT_FAILED", message: "無法連線到此網站（不允許連回本服務）" };
  }
  if (/dns|resolve|not found|ENOTFOUND|getaddrinfo/i.test(msg)) {
    return { code: "CONNECT_FAILED", message: "找不到此網域（DNS 查詢失敗）" };
  }
  if (/refused|ECONNREFUSED/i.test(msg)) {
    return { code: "CONNECT_FAILED", message: "連線被拒絕，網站可能沒有開啟這個連接埠" };
  }
  return { code: "CONNECT_FAILED", message: "無法連線到此網站" };
}

export async function fetchCertificateChain(
  target: Target,
  connect: ConnectFn,
  timeoutMs = TOTAL_TIMEOUT_MS,
): Promise<FetchChainResult> {
  let socket: SocketLike | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new TimeoutError("timeout")), timeoutMs);
  });
  // 避免 deadline 在完成後變成 unhandled rejection
  deadline.catch(() => {});
  const withDeadline = <T>(p: Promise<T>) => Promise.race([p, deadline]);

  let stage: "connect" | "io" = "connect";
  try {
    socket = connect({ hostname: target.host, port: target.port }, { secureTransport: "off", allowHalfOpen: false });
    await withDeadline(socket.opened);
    stage = "io";

    const writer = socket.writable.getWriter();
    await withDeadline(writer.write(buildClientHello(target.serverName)));
    writer.releaseLock();

    const reader = socket.readable.getReader();
    const extractor = new CertificateExtractor();
    // reader 不需要 releaseLock：結束後直接關閉 socket（逾時時可能還有未完成的 read）
    for (;;) {
      const { value, done } = await withDeadline(reader.read());
      const r = done ? extractor.end() : value && value.length ? extractor.feed(value) : null;
      if (!r) continue;
      if (r.kind === "certificates") return { ok: true, certificates: r.certificates };
      return { ok: false, error: { code: r.code, message: r.message } };
    }
  } catch (e) {
    if (e instanceof TimeoutError) {
      return {
        ok: false,
        error: {
          code: "TIMEOUT",
          message: `連線逾時（超過 ${Math.round(timeoutMs / 1000)} 秒），網站可能無法連線或回應太慢`,
        },
      };
    }
    if (stage === "connect") return { ok: false, error: describeConnectError(e) };
    return { ok: false, error: { code: "CONNECT_FAILED", message: "連線過程中被中斷" } };
  } finally {
    clearTimeout(timer);
    if (socket) {
      try {
        await Promise.race([socket.close(), new Promise((r) => setTimeout(r, 1000))]);
      } catch {
        // 關閉失敗也不影響結果
      }
    }
  }
}
