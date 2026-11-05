import type { ApiError, EvaluationResult } from "../shared/types";

export type CardStatus = "needs_update" | "ok" | "not_applicable" | "error" | "pending";

export interface CardData {
  id: string;
  title: string;
  status: CardStatus;
  result?: EvaluationResult;
  error?: ApiError;
  /** 因速率限制等待中，剩餘秒數 */
  waitSeconds?: number;
}
