/**
 * 受影響的 TWCA 中繼憑證清單。
 *
 * 更新清單時只需要修改這個檔案：
 *   1. 在 AFFECTED_INTERMEDIATES 新增 / 移除項目（key 為 DER 的 SHA-256，小寫 hex、無冒號）。
 *   2. 更新 AFFECTED_LIST_UPDATED。
 *
 * 前端（貼上模式）與後端（/api/check）共用這份資料。
 */

export const AFFECTED_LIST_UPDATED = "2026-11-05";
export const AFFECTED_LIST_SOURCE = "https://bugzilla.mozilla.org/show_bug.cgi?id=2087236";

/** 在此日期（UTC）之前簽發的 TWCA 網站憑證視為舊憑證。 */
export const REISSUE_AFTER = "2026-10-30";

export const AFFECTED_INTERMEDIATES: Record<string, string> = {
  "01af2324d098098f5e0cdf6faabada430b21cce777f47eacb26248b2fda3e531": "TWCA SSL Certification Authority (2023-02-23)",
  "f76e3339a6773dc5922da154628c8d22b5c915edcb15270db8fb3d8d24959e98": "TWCA EVSSL Certification Authority (2023-02-23)",
  "c6e96a1745707099f02279472fa28a99bae447d77511e19e86baf3047651c1eb":
    "TWCA Secure SSL Certification Authority (2023-08-18)",
  "1a2c75fd096e0499e9ff6ac74e526f61eaae3edfc8c2ea4436fee0c24d8b7d0e":
    "TWCA Secure SSL Certification Authority (2023-10-16)",
  "815c549c6976bf163eb54710ffc7806b1e7541c688313312b606837767164094": "TWCA SSL Certification Authority (2024-09-06)",
  "cac9fd0cd35aa5c480cd03fdd6edf0ca1a41fd02ac290ec83d83ceedf8ec245c": "TWCA EVSSL Certification Authority (2024-09-06)",
};
