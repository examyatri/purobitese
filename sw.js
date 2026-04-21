/* ─────────────────────────────────────────────────────────
   PuroBite / Tiffo — Service Worker (sw.js)
   Version : v18.0  |  Updated : 2026-04-22
   ───────────────────────────────────────────────────────── */

/* ─── Tiffo Service Worker — tiffo-v5 ──────────────────────────────────── */

const CACHE = 'tiffo-v5';
const PRECACHE = ['/', '/index.html', '/manifest.json'];

const OFFLINE_HTML = `<!DOCTYPE html>
<html><head><title>Tiffo Offline</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8f5f2}
h1{color:#e63946;font-size:24px}p{color:#6b7280}button{background:#e63946;color:white;border:none;border-radius:12px;padding:12px 24px;font-size:16px;cursor:pointer;margin-top:16px}</style>
</head><body>
<div style="font-size:48px">🍱</div>
<h1>Tiffo is offline</h1>
<p>Check your internet connection</p>
<button onclick="location.reload()">Try Again</button>
</body></html>`;

/* ─── INSTALL ────────────────────────────────────────────────────────────── */
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(cache => cache.addAll(PRECACHE))
  );
  self.skipWaiting();
});

/* ─── ACTIVATE ───────────────────────────────────────────────────────────── */
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

/* ─── FETCH ──────────────────────────────────────────────────────────────── */
self.addEventListener('fetch', e => {
  const { request } = e;
  const url = new URL(request.url);

  /* Strategy 1 — API: network-only, never cache */
  if (
    url.hostname === 'purobitese-api.onrender.com' ||
    url.pathname.startsWith('/api/')
  ) {
    return; /* let browser handle it normally */
  }

  /* Strategy 2 — HTML navigation: network-first with offline fallback */
  if (request.mode === 'navigate') {
    e.respondWith(
      fetch(request)
        .then(res => {
          const clone = res.clone();
          caches.open(CACHE).then(cache => cache.put(request, clone));
          return res;
        })
        .catch(async () => {
          const cached = await caches.match('/index.html');
          if (cached) return cached;
          return new Response(OFFLINE_HTML, {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        })
    );
    return;
  }

  /* Strategy 3 — All other assets: stale-while-revalidate */
  e.respondWith(
    caches.open(CACHE).then(async cache => {
      const cached = await cache.match(request);

      const fetchPromise = fetch(request)
        .then(res => {
          if (res && res.status === 200 && res.type !== 'opaque') {
            cache.put(request, res.clone());
          }
          return res;
        })
        .catch(() => null);

      return cached || fetchPromise;
    })
  );
});
