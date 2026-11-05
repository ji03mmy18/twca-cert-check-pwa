import { defineConfig } from "void/config";

export default defineConfig({
  worker: {
    compatibility_date: "2026-02-24",
  },
  cloudflare: {
    name: "twca-cert-check",
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
