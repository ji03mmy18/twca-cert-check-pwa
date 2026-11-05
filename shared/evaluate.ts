/**
 * 判斷邏輯（與 check_twca.sh 一致），前後端共用。
 *
 * 1. 網站憑證的 issuer 不含 TAIWAN-CA / TWCA（不分大小寫）→ 不適用。
 * 2. 中繼憑證的 SHA-256 指紋在受影響清單中 → 受影響（中繼憑證）。
 * 3. 網站憑證 notBefore（UTC 日期）早於 REISSUE_AFTER → 受影響（網站憑證為舊版）。
 * 4. 只有網站憑證、沒有中繼憑證 → 警告：憑證鏈不完整。
 * 5. 有任何「受影響」→ needs_update，否則 ok。
 */
import { AFFECTED_INTERMEDIATES, AFFECTED_LIST_UPDATED, REISSUE_AFTER } from "./affected";
import type { ChainEntry, EvaluationResult, Finding } from "./types";
import { parseCertificate, type ParsedCertificate } from "./x509";

export interface EvaluateOptions {
  /**
   * "server"：伺服器送出的順序（第 0 張為網站憑證），與 check_twca.sh 相同。
   * "paste"：使用者貼上的憑證，依 basicConstraints 分辨網站憑證與中繼憑證。
   */
  mode?: "server" | "paste";
}

const TWCA_RE = /TAIWAN-CA|TWCA/i;

export function isoSeconds(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function utcDate(d: Date): string {
  return d.toISOString().slice(0, 10);
}

interface Ordered {
  leaf: ParsedCertificate | null;
  intermediates: ParsedCertificate[];
  findings: Finding[];
}

function orderForPaste(certs: ParsedCertificate[]): Ordered {
  const nonCA = certs.filter((c) => c.isCA !== true);
  const ca = certs.filter((c) => c.isCA === true);
  if (nonCA.length === 1) {
    const leaf = nonCA[0];
    const findings: Finding[] = [];
    if (certs[0] !== leaf) {
      findings.push({
        level: "info",
        code: "ORDER_ADJUSTED",
        message: "已依 basicConstraints 自動辨識網站憑證，並調整憑證順序",
      });
    }
    return { leaf, intermediates: ca, findings };
  }
  if (nonCA.length === 0) {
    return {
      leaf: null,
      intermediates: ca,
      findings: [
        {
          level: "warning",
          code: "NO_LEAF",
          message: "沒有找到網站憑證（全部都是 CA 憑證），只檢查中繼憑證",
        },
      ],
    };
  }
  return {
    leaf: certs[0],
    intermediates: certs.slice(1),
    findings: [
      {
        level: "warning",
        code: "ORDER_UNCERTAIN",
        message: `有 ${nonCA.length} 張憑證看起來都是網站憑證，無法自動分辨，已依貼上的順序處理（第 1 張視為網站憑證）`,
      },
    ],
  };
}

function toEntry(c: ParsedCertificate, role: ChainEntry["role"]): ChainEntry {
  const entry: ChainEntry = {
    role,
    subject: c.subject,
    issuer: c.issuer,
    notBefore: isoSeconds(c.notBefore),
    notAfter: isoSeconds(c.notAfter),
    sha256: c.sha256,
  };
  const affected = AFFECTED_INTERMEDIATES[c.sha256];
  if (affected) entry.affected = affected;
  return entry;
}

/** 對已解析的憑證做判斷。 */
export function evaluateParsed(certs: ParsedCertificate[], options: EvaluateOptions = {}): EvaluationResult {
  if (certs.length === 0) throw new Error("沒有憑證");
  const ordered: Ordered =
    options.mode === "paste" ? orderForPaste(certs) : { leaf: certs[0], intermediates: certs.slice(1), findings: [] };
  const { leaf, intermediates } = ordered;
  const findings: Finding[] = [...ordered.findings];

  const chain: ChainEntry[] = [];
  if (leaf) chain.push(toEntry(leaf, "leaf"));
  for (const c of intermediates) chain.push(toEntry(c, "intermediate"));

  // 1. 是否為 TWCA 簽發
  const applicable = leaf
    ? TWCA_RE.test(leaf.issuer)
    : intermediates.some((c) => TWCA_RE.test(c.issuer) || TWCA_RE.test(c.subject));
  if (!applicable) {
    findings.push({
      level: "info",
      code: "NOT_TWCA",
      message: leaf ? `網站憑證不是由 TWCA 簽發（簽發者：${leaf.issuer}）` : "這些憑證不是 TWCA 的憑證",
    });
    return { chain, verdict: "not_applicable", findings, listUpdated: AFFECTED_LIST_UPDATED };
  }

  // 2. 中繼憑證指紋比對（網站憑證本身不可能在清單中，一併比對也不影響結果）
  for (const entry of chain) {
    if (entry.affected) {
      findings.push({
        level: "affected",
        code: "AFFECTED_INTERMEDIATE",
        message: `中繼憑證 ${entry.affected} 在受影響清單中`,
      });
    }
  }

  // 3. 網站憑證簽發日期
  if (leaf && utcDate(leaf.notBefore) < REISSUE_AFTER) {
    findings.push({
      level: "affected",
      code: "LEAF_BEFORE_REISSUE",
      message: `網站憑證在 ${REISSUE_AFTER} 之前簽發（${utcDate(leaf.notBefore)}），應是舊憑證`,
    });
  }

  // 4. 憑證鏈完整性
  if (leaf && intermediates.length === 0) {
    findings.push({
      level: "warning",
      code: "CHAIN_INCOMPLETE",
      message:
        options.mode === "paste"
          ? "只有網站憑證、沒有中繼憑證，無法檢查中繼憑證是否已更新"
          : "警告：憑證鏈不完整，伺服器只送出網站憑證、沒有中繼憑證",
    });
  }

  const needsUpdate = findings.some((f) => f.level === "affected");
  if (!needsUpdate) {
    findings.push({
      level: "info",
      code: "LOOKS_UPDATED",
      message: "沒有發現受影響的憑證",
    });
  }
  return {
    chain,
    verdict: needsUpdate ? "needs_update" : "ok",
    findings,
    listUpdated: AFFECTED_LIST_UPDATED,
  };
}

/** 輸入 DER 憑證陣列，回傳判斷結果。格式錯誤時拋出例外。 */
export async function evaluate(ders: Uint8Array[], options: EvaluateOptions = {}): Promise<EvaluationResult> {
  const parsed = await Promise.all(ders.map((d) => parseCertificate(d)));
  return evaluateParsed(parsed, options);
}
