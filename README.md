# TWCA 憑證檢查 PWA

檢查網站是否仍受 TWCA 中繼憑證序號隨機性不足事件影響（[Mozilla Bugzilla 2087236](https://bugzilla.mozilla.org/show_bug.cgi?id=2087236)）的可安裝 PWA。

- **輸入網址**：由 Cloudflare Worker 連到目標網站，取得伺服器實際送出的憑證鏈並判斷。
- **貼上 / 上傳憑證**：完全在瀏覽器內完成，不會上傳任何資料，可離線使用。

> 本工具僅比對已公開的受影響憑證清單，結果不代表 TWCA 官方認定。

## 技術架構

| 部分        | 技術                                                                |
| ----------- | ------------------------------------------------------------------- |
| 框架 / 部署 | [Void](https://void.cloud) 1.6（Vite 全端框架）→ Cloudflare Workers |
| 建置工具    | Vite+（Vite 8 / Rolldown、Vitest、Oxlint、Oxfmt）                   |
| 前端        | Vue 3 + TypeScript（SPA，`src/`）                                   |
| API         | Void 檔案路由 `routes/api/check.ts`（Hono），`cloudflare:sockets`   |
| 共用邏輯    | `shared/`：受影響清單、DER/X.509 解析、`evaluate()`，前後端共用     |

```
shared/affected.ts     受影響清單（更新清單只改這個檔案）
shared/evaluate.ts     判斷邏輯（輸入 DER 陣列）
shared/x509.ts, der.ts 最小化 X.509 / DER 解析器
shared/pem.ts          貼上模式的 PEM / DER 輸入解析
server/tls.ts          TLS 1.2 ClientHello 產生器與回應解析器
server/target.ts       目標驗證（連接埠白名單、私有 / 保留位址封鎖）
server/fetch-chain.ts  socket 連線、10 秒總逾時、finally 關閉 socket
server/check.ts        /api/check 核心流程
routes/api/check.ts    Void 路由：速率限制、request 處理
build/sw-plugin.ts     產生 Service Worker（預快取 app shell）
src/                   Vue 前端
```

### 為什麼自己做 TLS 握手

Workers 的 `node:tls` 不支援 `getPeerCertificate()`，`cloudflare:sockets` 的 `startTls()` 也拿不到對方憑證。但 TLS 1.2 的 Certificate 訊息是明文，所以 Worker 用明文 TCP 送出只支援 TLS 1.2 的 ClientHello（不送 `supported_versions`），讀到 Certificate 訊息就立即斷線，不需要完成握手。

## 本機開發

需要 **Node.js 24.22+ 或 26.12+**（Void 的要求）與 OpenSSL 3.4+（產生測試憑證用）。

```bash
npm install
npm run dev          # http://localhost:5173
npm test             # 單元測試
npm run typecheck    # vue-tsc 型別檢查
npx vp check         # 格式、lint
```

npm 11 預設會擋套件的 install script；`package.json` 的 `allowScripts` 已允許 `esbuild` 與 `workerd`（Void 本機執行 Worker 需要）。

### 本機整合測試

開發伺服器預設也會封鎖 localhost 與私有位址。要連到本機 openssl 測試伺服器時，在專案根目錄的 `.env`（不會進 Git、也不會部署）加入：

```ini
DEV_ALLOW_PRIVATE_TARGETS=true
```

這個開關需要同時符合 `import.meta.env.DEV`，正式建置時該段程式碼會被移除，所以**正式環境無法開啟**。

```bash
npm run dev                  # 終端機 1
npm run test:integration     # 終端機 2：啟動 TLS 1.2 / 1.3 測試伺服器並呼叫 /api/check
npm run gen:certs            # （選用）重新產生 test/fixtures 內的測試憑證
```

## 部署到 Cloudflare

```bash
npx void deploy --platform cloudflare   # 第一次：開瀏覽器登入 Cloudflare、選擇帳號
npx void deploy                          # 之後
```

Void 會建置前端與 Worker，並依 `void.config.ts` 建立 Rate Limiting binding（`RATE_LIMITER`，每個 IP 每分鐘 10 次）。本專案不使用 D1、KV、R2、AI 等服務。`void.lock.json` 產生後請一起 commit。

部署後請挑幾個實際使用 TWCA 憑證的公開網站手動測試，結果應與 `check_twca.sh` 一致。

## 更新受影響清單

只需要修改 `shared/affected.ts`：

1. 在 `AFFECTED_INTERMEDIATES` 新增項目，key 為中繼憑證 DER 的 SHA-256（小寫 hex、無冒號），value 為顯示名稱。可用以下指令取得指紋：
   ```bash
   openssl x509 -in ca.crt -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr A-F a-f
   ```
2. 更新 `AFFECTED_LIST_UPDATED`。
3. `npm test` 後重新部署。前端（含離線快取）與後端會一起更新。

TWCA 預計 2026-11-12 在 Bugzilla 更新完整事件報告，清單可能增加。

## 判斷邏輯

輸入憑證鏈（第 0 張為網站憑證）：

1. 網站憑證 issuer 不含 `TAIWAN-CA` / `TWCA`（不分大小寫）→ **不適用**。
2. 中繼憑證的 SHA-256 指紋在清單中 → **受影響（中繼憑證）**。新舊中繼憑證名稱可能相同，所以只比對指紋。
3. 網站憑證 `notBefore`（UTC 日期）早於 `2026-10-30` → **受影響（網站憑證為舊版）**。
4. 只有網站憑證、沒有中繼憑證 → **警告：憑證鏈不完整**。
5. 有任何「受影響」→ **需要更新**，否則 **看起來已更新完成**。

貼上模式會依 `basicConstraints` 分辨：CA=true 是中繼憑證，CA=false 或沒有這個擴充的是網站憑證，並依 issuer → subject 排序。無法分辨（例如貼了兩張網站憑證）時，依貼上順序處理並提示。

## API

`POST /api/check`，body：`{ "target": "example.com" }`（也接受 `example.com:8443` 或完整網址 `https://example.com/path`）。

回應格式見 `shared/types.ts`。錯誤代碼：

| code                  | HTTP | 說明                                                                    |
| --------------------- | ---- | ----------------------------------------------------------------------- |
| `INVALID_TARGET`      | 400  | 格式錯誤                                                                |
| `PORT_NOT_ALLOWED`    | 400  | 只允許 443、8443                                                        |
| `BLOCKED_ADDRESS`     | 403  | localhost、`.local`、`.internal`、私有 / 保留位址                       |
| `RATE_LIMITED`        | 429  | 每個 IP 每分鐘超過 10 次                                                |
| `METHOD_NOT_ALLOWED`  | 405  | 只接受 POST                                                             |
| `CONNECT_FAILED`      | 200  | 連線失敗（含 Cloudflare 自家 IP 的網站）                                |
| `TIMEOUT`             | 200  | 超過 10 秒                                                              |
| `TLS13_ONLY`          | 200  | 伺服器回 `protocol_version` / `handshake_failure` alert，或選了 TLS 1.3 |
| `UNSUPPORTED_VERSION` | 200  | 伺服器選了 TLS 1.0 / 1.1                                                |
| `TLS_ALERT`           | 200  | 其他 TLS alert                                                          |
| `PARSE_ERROR`         | 200  | 回應或憑證格式錯誤、超過 64 KB                                          |
| `NO_CERTIFICATE`      | 200  | 伺服器沒有送出憑證                                                      |
| `INTERNAL_ERROR`      | 500  | 未預期的錯誤                                                            |

連線 / TLS 類錯誤屬於「檢查結果」，所以用 HTTP 200 + `ok: false` 回傳。

## 工具限制

- **只支援 TLS 1.2 的網站**。只支援 TLS 1.3 的網站會回 `TLS13_ONLY`，請改用貼上模式（例如 `openssl s_client -connect 網站:443 -showcerts </dev/null` 的輸出）。
- **使用 Cloudflare CDN 的網站無法用網址模式檢查**：Workers 不能用 TCP socket 連到 Cloudflare 自家 IP，會回 `CONNECT_FAILED`。
- **速率限制是近似值**：Cloudflare Rate Limiting 是各資料中心各自計數、最終一致。另外 Cloudflare 文件不建議用 IP 當 key（多人可能共用 IP），這裡依需求仍以 `CF-Connecting-IP` 為 key。前端一次可查 20 個網址，超過上限時會等待 60 秒後自動繼續。
- **DNS 解析到私有位址的網域**：Worker 只驗證使用者輸入的主機名 / IP 字面值，不會先做 DNS 解析。正式環境中，Cloudflare 本身會拒絕 Workers 連到私有位址。本機開發時沒有這層保護。
- 查詢的網域不會寫進 log。
- 只比對已公開的受影響清單，不驗證憑證簽章或信任鏈。

## 與原始規格（BRIEF.md）不同之處

- **X.509 解析**：沒有使用 `@peculiar/x509`，改寫一個只處理所需欄位的 DER 解析器（`shared/der.ts`、`shared/x509.ts`），支援 UTCTime 與 GeneralizedTime。這樣可以減少依賴與打包大小，也不用處理 polyfill 在 Workers 上的相容性。
- **Service Worker**：`vite-plugin-pwa` 2.0 雖然支援 Vite 8，但在 Void 的多環境建置中，它在 `closeBundle` 寫出的 `sw.js` 不會出現在部署目錄。所以改用 `build/sw-plugin.ts`，在 client 環境的 `generateBundle` 把 `sw.js` 當成一般 asset 輸出。
- **額外的錯誤代碼**：`UNSUPPORTED_VERSION`（TLS 1.0/1.1，規格要求視為錯誤，但用 `TLS13_ONLY` 描述不正確）、`METHOD_NOT_ALLOWED`、`INTERNAL_ERROR`。
- **`check_twca.sh` 不在此 repo 中**，判斷邏輯依 BRIEF.md §3 實作。部署後請用實際網站與該腳本對照。
