import { defineConfig } from "void/config";

export default defineConfig({
  worker: {
    compatibility_date: "2026-02-24",
  },
  cloudflare: {
    name: "twca-cert-check",
    // 只使用自訂網域；關閉 workers.dev 與 Preview URLs，讓 PWA 只有一個正式網址
    // （Service Worker、離線快取與「加入主畫面」都綁定網址）
    routes: [{ pattern: "twca-check.yomin.info", custom_domain: true }],
    workers_dev: false,
    preview_urls: false,
    // 每個用戶端 IP 每分鐘最多 10 次 /api/check
    ratelimits: [{ name: "RATE_LIMITER", namespace_id: "20872361", simple: { limit: 10, period: 60 } }],
  },
  routing: {
    headers: {
      "/api/*": ["Cache-Control: no-store"],
      "/sw.js": ["Cache-Control: no-cache"],
      "/manifest.webmanifest": ["Cache-Control: no-cache"],
      "/*": ["X-Content-Type-Options: nosniff", "Referrer-Policy: strict-origin-when-cross-origin"],
    },
  },
});
