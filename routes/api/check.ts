import { connect } from "cloudflare:sockets";
import { defineHandler } from "void";
import { env } from "void/env";
import { errorOutcome, readTargetFromBody, runCheck, type CheckOutcome } from "../../server/check";

interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

/**
 * 只在本機開發時放寬限制（允許 localhost、私有位址、任意連接埠），供整合測試使用。
 * import.meta.env.DEV 在正式建置時是 false，整段會被移除，正式環境無法開啟。
 */
const allowPrivate = import.meta.env.DEV && env.DEV_ALLOW_PRIVATE_TARGETS === true;

function send(
  c: { json: (body: unknown, status: number, headers: Record<string, string>) => Response },
  out: CheckOutcome,
) {
  return c.json(out.body, out.status, { "Cache-Control": "no-store" });
}

export const POST = defineHandler(async (c) => {
  // 速率限制：每個用戶端 IP 每分鐘 10 次（Cloudflare Workers Rate Limiting binding）
  const limiter = (c.env as { RATE_LIMITER?: RateLimiter }).RATE_LIMITER;
  if (limiter) {
    const ip = c.req.header("CF-Connecting-IP") ?? "unknown";
    const { success } = await limiter.limit({ key: ip });
    if (!success) {
      return send(c, errorOutcome({ code: "RATE_LIMITED", message: "查詢次數過多，請稍候一分鐘再試" }));
    }
  } else if (!import.meta.env.DEV) {
    return send(c, errorOutcome({ code: "INTERNAL_ERROR", message: "服務設定錯誤（缺少速率限制）" }));
  }

  const body = readTargetFromBody(await c.req.text());
  if (!body.ok) return send(c, errorOutcome(body.error));

  try {
    return send(c, await runCheck(body.target, { connect, allowPrivate }));
  } catch {
    // 不記錄查詢的網域（隱私）
    return send(c, errorOutcome({ code: "INTERNAL_ERROR", message: "發生未預期的錯誤" }));
  }
});

const methodNotAllowed = defineHandler((c) =>
  c.json({ ok: false, error: { code: "METHOD_NOT_ALLOWED", message: "只接受 POST" } }, 405, {
    "Allow": "POST",
    "Cache-Control": "no-store",
  }),
);
export const GET = methodNotAllowed;
export const PUT = methodNotAllowed;
export const DELETE = methodNotAllowed;
export const PATCH = methodNotAllowed;
