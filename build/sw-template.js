// TWCA 憑證檢查 Service Worker（由 build/sw-plugin.ts 產生，請勿直接修改 dist 內的 sw.js）
/* eslint-disable */
const VERSION = __CACHE_VERSION__;
const PRECACHE_URLS = __PRECACHE_URLS__;
const CACHE = `twca-shell-${VERSION}`;

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) => cache.addAll(PRECACHE_URLS.map((u) => new Request(u, { cache: "reload" }))))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith("twca-shell-") && k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  // API 回應一律不快取，直接走網路
  if (url.pathname.startsWith("/api/")) return;

  if (req.mode === "navigate") {
    // App shell：先用網路（取得最新版），失敗（離線）時用快取的首頁
    event.respondWith(
      fetch(req).catch(() => caches.open(CACHE).then((c) => c.match("/")).then((r) => r || Response.error())),
    );
    return;
  }

  event.respondWith(
    caches.open(CACHE).then((c) =>
      c.match(req, { ignoreSearch: true }).then((hit) => hit || fetch(req)),
    ),
  );
});
