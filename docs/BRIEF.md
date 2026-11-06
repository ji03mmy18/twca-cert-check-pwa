# TWCA 憑證影響檢查 PWA：開發規格

> 給 Claude Code 的開發說明。請先完整讀完本文件，再依「開發順序」實作。
> 遇到本文件沒寫到、或與官方文件衝突的地方，以官方文件為準，並在 PR 說明中註記。

## 1. 專案目標

做一個可安裝的 PWA，讓使用者檢查網站是否仍受 TWCA 中繼憑證序號隨機性不足事件影響（Mozilla Bugzilla 2087236）。

提供兩種檢查模式：

1. **輸入網址**：後端連到目標網站，取得伺服器實際送出的憑證鏈並判斷。
2. **貼上或上傳憑證**：完全在瀏覽器內完成，可離線使用。

部署目標：使用 **Void**（VoidZero 與 Cloudflare 推出的 Vite 全端框架），部署到 **Cloudflare Workers**。

介面語言：**繁體中文（台灣）**。

## 2. 事件背景（讓你理解判斷邏輯）

- TWCA 的 CA 憑證序號名義上有 128 bits，但只有約 24 bits 是隨機的，未達 CA/B Forum Baseline Requirements 要求的 64 bits CSPRNG 輸出。
- 受影響的中繼憑證在 **2026-11-06 00:00（UTC+8）** 前廢止。底下的網站憑證由 TWCA 用新中繼憑證重新簽發，**使用原金鑰**，網站管理者只要換上新憑證和新憑證鏈。
- 新舊中繼憑證的**名稱可能相同**，所以一定要用 **SHA-256 指紋**比對，不能只看 CN。

## 3. 判斷邏輯（必須與現有 shell 腳本 `check_twca.sh` 一致）

輸入：憑證鏈（第 0 張是網站憑證，其後是中繼憑證）。

1. 解析網站憑證的 issuer。若 issuer 不含 `TAIWAN-CA` 或 `TWCA`（不分大小寫），結果為 **不適用**。
2. 對第 1 張以後的每張憑證計算 DER 的 SHA-256 指紋（小寫 hex、無冒號），比對受影響清單。符合任一張，標記 **受影響（中繼憑證）**。
3. 若網站憑證的 `notBefore` 早於 `2026-10-30`（UTC 日期比較），標記 **受影響（網站憑證為舊版）**。
4. 若鏈中只有網站憑證、沒有中繼憑證，額外顯示 **警告：憑證鏈不完整**。
5. 有任何「受影響」標記，結論為 **需要更新**；否則為 **看起來已更新完成**。

**貼上模式的特別處理**：使用者可能只貼網站憑證，或貼的順序不對。請用「`basicConstraints` CA=true 的是中繼憑證，CA=false 或沒有的是網站憑證」來分辨。不能分辨時，依貼上的順序處理，並在結果中提示。

## 4. 受影響憑證資料

放在共用模組（例如 `shared/affected.ts`），前後端共用同一份。要附上資料來源與更新日期，結果頁要顯示「清單更新日期」。

```ts
export const AFFECTED_LIST_UPDATED = "2026-11-05";
export const AFFECTED_LIST_SOURCE = "https://bugzilla.mozilla.org/show_bug.cgi?id=2087236";
export const REISSUE_AFTER = "2026-10-30";

export const AFFECTED_INTERMEDIATES: Record<string, string> = {
  "01af2324d098098f5e0cdf6faabada430b21cce777f47eacb26248b2fda3e531": "TWCA SSL Certification Authority (2023-02-23)",
  "f76e3339a6773dc5922da154628c8d22b5c915edcb15270db8fb3d8d24959e98": "TWCA EVSSL Certification Authority (2023-02-23)",
  "c6e96a1745707099f02279472fa28a99bae447d77511e19e86baf3047651c1eb": "TWCA Secure SSL Certification Authority (2023-08-18)",
  "1a2c75fd096e0499e9ff6ac74e526f61eaae3edfc8c2ea4436fee0c24d8b7d0e": "TWCA Secure SSL Certification Authority (2023-10-16)",
  "815c549c6976bf163eb54710ffc7806b1e7541c688313312b606837767164094": "TWCA SSL Certification Authority (2024-09-06)",
  "cac9fd0cd35aa5c480cd03fdd6edf0ca1a41fd02ac290ec83d83ceedf8ec245c": "TWCA EVSSL Certification Authority (2024-09-06)",
};
```

TWCA 預計 2026-11-12 在 Bugzilla 更新完整事件報告，清單可能增加。請讓更新清單只需要改這一個檔案。

## 5. 架構

```
┌──────────────── PWA（Vite 前端）────────────────┐
│  輸入網址模式 ──► POST /api/check                 │
│  貼上憑證模式 ──► 瀏覽器內解析 + Web Crypto        │
│  共用：shared/affected.ts、shared/evaluate.ts     │
└─────────────────────────────────────────────────┘
                     │
                     ▼
┌──────── Void 路由（Cloudflare Workers）──────────┐
│  /api/check：                                     │
│   1. 驗證輸入、防濫用                              │
│   2. cloudflare:sockets 開明文 TCP                │
│   3. 送出 TLS 1.2 ClientHello                     │
│   4. 讀回 Certificate 訊息後立即斷線               │
│   5. 回傳憑證鏈（DER base64）＋ 判斷結果            │
└─────────────────────────────────────────────────┘
```

判斷邏輯 `evaluate()` 放在 `shared/`，前後端共用，輸入是 DER 憑證陣列。

### 5.1 關於 Void

- 官方資源：https://void.cloud 、https://github.com/voidzero-dev/void 、Cloudflare 部落格文章〈Deploy with Void〉。
- Void 在 2026 年 10 月才公開，**請以官方文件為準，不要憑印象寫 API**。路由與 handler 的寫法（例如 `defineHandler`）、專案結構、`void deploy` 流程都請先查文件。若 Void 產生了 `AGENTS.md`，請先讀。
- 本專案**不需要**資料庫、儲存或 AI 等 Cloudflare 服務，不要引入。

## 6. 後端：為什麼要自己做 TLS 握手

Cloudflare Workers 的 `node:tls` 不支援 `getPeerCertificate()`（會丟 not implemented），`cloudflare:sockets` 的 `startTls()` 也拿不到對方憑證。

但在 **TLS 1.2** 中，伺服器的 Certificate 訊息是**明文**傳送的。所以做法是：

1. `connect({ hostname, port }, { secureTransport: "off" })` 開明文 TCP。
2. 自己組一個**只支援 TLS 1.2** 的 ClientHello 送出。
3. 讀取伺服器回應，重組握手訊息，取出 Certificate（type 11）。
4. 拿到 Certificate 後**立即關閉 socket**，不用完成握手，也不需要任何金鑰交換。

### 6.1 ClientHello 格式

**Record layer**
- content type `0x16`（handshake）
- legacy version `0x03 0x01`（相容性較好）
- length（2 bytes）

**Handshake**
- type `0x01`（ClientHello）
- length（3 bytes）
- client_version `0x03 0x03`（TLS 1.2）
- random：32 bytes，用 `crypto.getRandomValues`
- session_id：長度 `0x00`
- cipher_suites：2 bytes 長度 + 清單。至少包含：
  `c02f c030 c02b c02c cca8 cca9 c013 c014 009c 009d 002f 0035`
- compression_methods：`0x01 0x00`
- extensions：2 bytes 總長度 + 各 extension

**Extensions（必要）**

| Extension | type | 內容 |
|---|---|---|
| server_name (SNI) | `0x0000` | list len(2) + name_type `0x00` + host len(2) + host（ASCII） |
| supported_groups | `0x000a` | x25519 `001d`、secp256r1 `0017`、secp384r1 `0018` |
| ec_point_formats | `0x000b` | `01 00` |
| signature_algorithms | `0x000d` | `0401 0501 0601 0403 0503 0603 0804 0805 0806 0201` |
| renegotiation_info | `0xff01` | `01 00` |

**不要**送 `supported_versions`（`0x002b`），否則伺服器可能選 TLS 1.3，憑證就會被加密。

SNI 必須用使用者輸入的網域。如果輸入的是 IP，就不送 SNI。

### 6.2 解析伺服器回應

- 依 TLS record 讀取：type(1) + version(2) + length(2) + payload。
- **handshake 訊息可能跨多個 record，一個 record 也可能包含多個 handshake 訊息**。請把所有 type `0x16` record 的 payload 串成一條 handshake 串流，再依 type(1) + length(3) 切出訊息。
- 依序會遇到 ServerHello（2）、Certificate（11）、ServerKeyExchange（12）、ServerHelloDone（14）。讀到 Certificate 就停止。
- Certificate 訊息內容：certificate_list 總長度（3 bytes），之後每張是長度（3 bytes）+ DER。
- 收到 Alert record（type `0x15`）時，解析 level 和 description。`protocol_version`（70）或 `handshake_failure`（40）通常代表**伺服器只支援 TLS 1.3**，或不接受我們的 cipher suite，要回傳明確的錯誤代碼（見 §8），讓前端引導使用者改用貼上模式。
- ServerHello 的 server_version 不是 `0x0303` 時，視同上述錯誤。

### 6.3 安全與資源限制（必做）

- **總逾時 10 秒**（連線＋讀取）。逾時就關閉 socket，回傳錯誤。
- **最多讀 64 KB**，超過就中止。
- 所有長度欄位都要做邊界檢查，**不能信任伺服器送來的長度**。parser 必須能安全處理截斷、過長或格式錯誤的資料，不能拋出未處理的例外。
- 拿到 Certificate、出錯或逾時後，一律在 `finally` 關閉 socket。

## 7. 防濫用（必做）

這個 API 會讓任何人叫 Worker 去連任意主機，必須限制：

1. **連接埠白名單**：只允許 `443` 和 `8443`。
2. **主機名驗證**：只接受合法網域名稱（字元、長度、label 規則）或 IPv4/IPv6 字面值。拒絕 `localhost`、`*.local`、`*.internal`，以及私有與保留位址（`10/8`、`172.16/12`、`192.168/16`、`127/8`、`169.254/16`、`100.64/10`、`0/8`、`::1`、`fc00::/7`、`fe80::/10` 等）。
3. **速率限制**：每個用戶端 IP 每分鐘最多 10 次。優先使用 Cloudflare Workers 的 Rate Limiting binding。若 Void 不支援設定該 binding，請在 PR 說明替代方案，不要自己用全域變數實作（Workers isolate 不共享記憶體）。
4. **只接受 `POST /api/check`**，request body 為 JSON：`{ "target": "example.com" }` 或 `"example.com:8443"`。也接受使用者貼上完整網址（`https://example.com/path`），後端自行取出 host 和 port。
5. **隱私**：不要把查詢的網域寫進持久化的 log。

注意：Cloudflare 對 Workers 連到 Cloudflare 自家 IP 有限制，遇到這種網站會連線失敗。請查官方文件確認目前的行為，並回傳明確的錯誤訊息。

## 8. API 規格

`POST /api/check`

成功：

```json
{
  "ok": true,
  "target": "www.example.gov.tw:443",
  "chain": [
    {
      "role": "leaf",
      "subject": "CN=www.example.gov.tw",
      "issuer": "C=TW, O=TAIWAN-CA, CN=TWCA SSL Certification Authority",
      "notBefore": "2025-05-20T00:00:00Z",
      "notAfter": "2026-06-20T23:59:59Z",
      "sha256": "..."
    },
    { "role": "intermediate", "subject": "...", "issuer": "...", "notBefore": "...", "notAfter": "...", "sha256": "...", "affected": "TWCA SSL Certification Authority (2024-09-06)" }
  ],
  "verdict": "needs_update",
  "findings": [
    { "level": "affected", "code": "AFFECTED_INTERMEDIATE", "message": "中繼憑證 TWCA SSL Certification Authority (2024-09-06) 在受影響清單中" },
    { "level": "affected", "code": "LEAF_BEFORE_REISSUE", "message": "網站憑證在 2026-10-30 之前簽發，應是舊憑證" }
  ],
  "listUpdated": "2026-11-05"
}
```

`verdict` 的值：`needs_update`、`ok`、`not_applicable`。

`findings[].level` 的值：`affected`、`warning`、`info`。

失敗：

```json
{ "ok": false, "error": { "code": "TLS13_ONLY", "message": "此網站可能只支援 TLS 1.3，無法從伺服器取得憑證，請改用「貼上憑證」模式" } }
```

錯誤代碼至少要有：
- `INVALID_TARGET`
- `PORT_NOT_ALLOWED`
- `BLOCKED_ADDRESS`
- `RATE_LIMITED`（HTTP 429）
- `CONNECT_FAILED`
- `TIMEOUT`
- `TLS13_ONLY`
- `TLS_ALERT`
- `PARSE_ERROR`
- `NO_CERTIFICATE`

## 9. 憑證解析

需要從 DER 取出：subject、issuer（至少要有 CN、O、C）、notBefore、notAfter、basicConstraints 的 CA 旗標，以及 SHA-256 指紋。

- 建議使用 `@peculiar/x509`。它以 Web Crypto 為基礎，瀏覽器和 Workers 都能用。導入前請先確認在 Workers 能正常打包與執行。不能用的話，就自己寫最小的 DER 解析器（只需處理上述欄位，時間格式要同時支援 UTCTime 與 GeneralizedTime）。
- SHA-256 一律用 `crypto.subtle.digest("SHA-256", der)`。

**前端貼上模式**要支援：
- 一或多段 PEM（`-----BEGIN CERTIFICATE-----`），例如 `openssl s_client -showcerts` 的完整輸出，請忽略 PEM 以外的文字。
- 上傳 `.pem`、`.crt`、`.cer` 檔案，DER 和 PEM 都要支援。
- 也可上傳多個檔案。

## 10. PWA 要求

- `manifest.webmanifest`：名稱「TWCA 憑證檢查」、短名稱「TWCA 檢查」、`display: standalone`、`lang: zh-TW`，附 192 與 512 px 圖示（簡單的盾牌或鎖頭圖形即可，不要使用 TWCA 的商標）。
- Service Worker：預快取 app shell。**貼上模式必須能離線使用**。輸入網址模式在離線時要顯示「需要網路連線」。
- API 回應不要快取。
- 可評估使用 `vite-plugin-pwa`，但請先確認它與 Void 和 Vite+ 相容。

## 11. 介面

- 首頁：兩個分頁「輸入網址」和「貼上憑證」。
- 輸入網址：一個輸入框，可輸入多個網址（一行一個，最多 20 個，依序查詢，不要同時送出）。
- 結果卡片：每個網站一張，大字顯示結論（需要更新／看起來已更新完成／不適用／錯誤），下面列出 findings 與憑證鏈明細（可展開）。指紋使用等寬字型，並提供複製按鈕。
- 頁尾：受影響清單更新日期、Bugzilla 連結，以及一句說明：「本工具僅比對已公開的受影響憑證清單，結果不代表 TWCA 官方認定。」
- 支援深色模式，手機版面優先。

## 12. 測試

**單元測試**
- ClientHello 產生器：檢查各長度欄位正確、SNI 正確編碼、沒有 `supported_versions`。
- Record／handshake 解析器：handshake 跨多個 record、一個 record 含多個訊息、截斷資料、長度欄位造假、Alert record。
- `evaluate()`：用固定憑證測試所有結論分支。
- 主機名與 IP 驗證：各種私有位址、IPv6、格式錯誤的輸入。
- 貼上解析：openssl 輸出、多段 PEM、DER 檔案、夾雜文字。

**整合測試（本機）**

用 openssl 產生測試 CA 和網站憑證，啟動本機測試伺服器：

```bash
# 只開 TLS 1.2：應成功取得憑證鏈
openssl s_server -accept 14433 -cert leaf.crt -key leaf.key -cert_chain ca.crt -tls1_2
# 只開 TLS 1.3：應回傳 TLS13_ONLY
openssl s_server -accept 14434 -cert leaf.crt -key leaf.key -cert_chain ca.crt -tls1_3
```

本機測試需要暫時允許連到 localhost 與測試用連接埠。請用**只在開發環境生效**的設定開關，不要讓正式環境放寬限制。

**部署後手動測試**：挑幾個實際使用 TWCA 憑證的公開網站，結果要跟 `check_twca.sh` 的輸出一致。

## 13. 開發順序

1. 查 Void 官方文件，建立專案骨架（Vite 前端 + 一個 API 路由），確認能在本機跑起來。
2. `shared/affected.ts`、`shared/evaluate.ts`、憑證解析，加單元測試。
3. 貼上模式前端（純前端，先做這個，因為不依賴後端）。
4. TLS 1.2 ClientHello 與回應解析器，加單元測試。
5. `/api/check` 路由：輸入驗證、防濫用、socket 連線、逾時，接上 parser 和 `evaluate()`。
6. 輸入網址模式前端。
7. PWA（manifest、service worker、離線）。
8. 本機整合測試，然後用 `void deploy` 部署。

每完成一步就 commit 一次，commit 訊息請用英文。

## 14. 驗收標準

- [ ] 輸入使用 TWCA 憑證的 TLS 1.2 網站，結果與 `check_twca.sh` 一致。
- [ ] 只支援 TLS 1.3 的網站回傳 `TLS13_ONLY`，前端引導使用者改用貼上模式。
- [ ] 私有 IP、localhost、非白名單連接埠都會被擋下。
- [ ] 超過速率限制回傳 429。
- [ ] 任何格式錯誤的伺服器回應都不會讓 Worker 崩潰，且 socket 一定會關閉。
- [ ] 貼上模式在離線狀態下可用。
- [ ] 可在 iOS Safari 與 Android Chrome「加入主畫面」，以獨立 App 形式開啟。
- [ ] 更新受影響清單只需要修改 `shared/affected.ts`。
- [ ] README 說明部署方式、清單更新方式與工具限制。

## 15. 參考資料

- Bugzilla 2087236（受影響清單來源）：https://bugzilla.mozilla.org/show_bug.cgi?id=2087236
- TLS 1.2：RFC 5246（ClientHello §7.4.1.2、Certificate §7.4.2）
- TLS Extensions：RFC 6066（SNI）、RFC 8422（EC groups / point formats）
- X.509：RFC 5280
- Cloudflare Workers TCP sockets：https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/
- Void：https://void.cloud 、https://github.com/voidzero-dev/void
- 既有的 shell 版本：`check_twca.sh`（判斷邏輯的參考實作）
