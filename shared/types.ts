export type Verdict = "needs_update" | "ok" | "not_applicable";
export type FindingLevel = "affected" | "warning" | "info";

export type FindingCode =
  | "AFFECTED_INTERMEDIATE"
  | "LEAF_BEFORE_REISSUE"
  | "CHAIN_INCOMPLETE"
  | "NOT_TWCA"
  | "NO_LEAF"
  | "ORDER_ADJUSTED"
  | "ORDER_UNCERTAIN"
  | "LOOKS_UPDATED"
  | "INPUT_SKIPPED";

export interface Finding {
  level: FindingLevel;
  code: FindingCode;
  message: string;
}

export interface ChainEntry {
  role: "leaf" | "intermediate";
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  sha256: string;
  /** 受影響清單中的名稱（若符合） */
  affected?: string;
}

export interface EvaluationResult {
  chain: ChainEntry[];
  verdict: Verdict;
  findings: Finding[];
  listUpdated: string;
}

export type ApiErrorCode =
  | "INVALID_TARGET"
  | "PORT_NOT_ALLOWED"
  | "BLOCKED_ADDRESS"
  | "RATE_LIMITED"
  | "CONNECT_FAILED"
  | "TIMEOUT"
  | "TLS13_ONLY"
  | "TLS_ALERT"
  | "UNSUPPORTED_VERSION"
  | "PARSE_ERROR"
  | "NO_CERTIFICATE"
  | "METHOD_NOT_ALLOWED"
  | "INTERNAL_ERROR";

export interface ApiError {
  code: ApiErrorCode;
  message: string;
}

export type CheckResponse = ({ ok: true; target: string } & EvaluationResult) | { ok: false; error: ApiError };
