/* ─────────────────────────────────────────────────────────
   Tiffo — Rider Service Worker (sw-rider.js)
   Version : v2.0  |  Updated : 2026-04-23

   Dedicated SW for Rider PWA — installs separately from
   main Tiffo app so rider.html appears as its own app
   on home screen with name "Tiffo Rider".
   ───────────────────────────────────────────────────────── */

const CACHE      = 'tiffo-rider-v2';
const FONT_CACHE = 'tiffo-fonts-v1';

/* Only rider assets — keeps this PWA lightweight */
const PRECACHE = ['./rider.html', './manifest-rider.json'];

const CDN_ORIGINS = [
  'https://fonts.googleapis.com',
  'https://fonts.gstatic.com',
  'https://cdnjs.cloudflare.com'
];

const ASSET_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const OFFLINE_HTML = `<!DOCTYPE html>
<html><head><title>Tiffo Rider Offline</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f4f6f9}
h1{color:#e63946;font-size:24px}p{color:#6b7280}button{background:#e63946;color:white;border:none;border-radius:12px;padding:12px 24px;font-size:16px;cursor:pointer;margin-top:16px}</style>
</head><body>
<div style="font-size:48px">🛵</div>
<h1>Tiffo Rider Offline</h1>
<p>Check your internet connection</p>
<button onclick="location.reload()">Try Again</button>
</body></html>`;

/* ─── MESSAGE ────────────────────────────────────────────── */
self.addEventListener('message', e => {
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting();
});

/* ─── INSTALL ────────────────────────────────────────────── */
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(cache => cache.addAll(PRECACHE))
  );
});

/* ─── ACTIVATE ───────────────────────────────────────────── */
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(k => k !== CACHE && k !== FONT_CACHE)
          .map(k => caches.delete(k))
      )
    )
  );
  self.clients.claim();
});

/* ─── FETCH ──────────────────────────────────────────────── */
self.addEventListener('fetch', e => {
  const { request } = e;
  const url = new URL(request.url);

  /* API — network only */
  if (
    url.hostname === 'purobitese-api.onrender.com' ||
    url.pathname.startsWith('/api/')
  ) return;

  /* CDN — cache first */
  if (CDN_ORIGINS.some(o => url.href.startsWith(o))) {
    e.respondWith(
      caches.open(FONT_CACHE).then(async cache => {
        const cached = await cache.match(request);
        if (cached) return cached;
        const res = await fetch(request);
        if (res && res.status === 200) cache.put(request, res.clone());
        return res;
      })
    );
    return;
  }

  /* HTML navigation — network first, offline fallback */
  if (request.mode === 'navigate') {
    e.respondWith(
      fetch(request)
        .then(res => {
          caches.open(CACHE).then(cache => cache.put(request, res.clone()));
          return res;
        })
        .catch(async () => {
          const cached = await caches.match('./rider.html');
          if (cached) return cached;
          return new Response(OFFLINE_HTML, {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        })
    );
    return;
  }

  /* All other assets — stale-while-revalidate */
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

      if (!cached) return fetchPromise;

      const cachedDate = cached.headers.get('date');
      if (cachedDate) {
        const ageMs = Date.now() - new Date(cachedDate).getTime();
        if (ageMs > ASSET_MAX_AGE_MS) return fetchPromise.catch(() => cached);
      }

      fetchPromise; // background revalidate
      return cached;
    })
  );
});
