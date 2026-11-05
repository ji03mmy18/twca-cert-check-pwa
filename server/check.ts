/**
 * /api/check 的核心邏輯（與 Void / Hono 無關，方便測試）。
 */
import { evaluate } from "../shared/evaluate";
import type { ApiError, CheckResponse } from "../shared/types";
import { fetchCertificateChain, type ConnectFn } from "./fetch-chain";
import { parseTarget } from "./target";

export const MAX_BODY_BYTES = 4096;

export interface CheckDeps {
  connect: ConnectFn;
  allowPrivate?: boolean;
  timeoutMs?: number;
}

export interface CheckOutcome {
  status: number;
  body: CheckResponse;
}

const STATUS: Partial<Record<ApiError["code"], number>> = {
  INVALID_TARGET: 400,
  PORT_NOT_ALLOWED: 400,
  BLOCKED_ADDRESS: 403,
  RATE_LIMITED: 429,
  METHOD_NOT_ALLOWED: 405,
  INTERNAL_ERROR: 500,
};

export function errorOutcome(error: ApiError): CheckOutcome {
  // 連線 / TLS 相關的錯誤是「檢查結果」，用 200 回傳，前端統一處理
  return { status: STATUS[error.code] ?? 200, body: { ok: false, error } };
}

/** 解析 request body：{ "target": "example.com" } */
export function readTargetFromBody(text: string): { ok: true; target: string } | { ok: false; error: ApiError } {
  if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) {
    return { ok: false, error: { code: "INVALID_TARGET", message: "請求內容過大" } };
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return {
      ok: false,
      error: { code: "INVALID_TARGET", message: '請求格式錯誤，必須是 JSON：{ "target": "example.com" }' },
    };
  }
  const target = (json as { target?: unknown } | null)?.target;
  if (typeof target !== "string") {
    return { ok: false, error: { code: "INVALID_TARGET", message: "缺少 target 欄位" } };
  }
  return { ok: true, target };
}

export async function runCheck(rawTarget: string, deps: CheckDeps): Promise<CheckOutcome> {
  const parsed = parseTarget(rawTarget, { allowPrivate: deps.allowPrivate });
  if (!parsed.ok) return errorOutcome(parsed.error);
  const { target } = parsed;

  const fetched = await fetchCertificateChain(target, deps.connect, deps.timeoutMs);
  if (!fetched.ok) return errorOutcome(fetched.error);

  try {
    const result = await evaluate(fetched.certificates, { mode: "server" });
    return { status: 200, body: { ok: true, target: target.display, ...result } };
  } catch {
    return errorOutcome({ code: "PARSE_ERROR", message: "伺服器送出的憑證格式錯誤，無法解析" });
  }
}
