/* ─────────────────────────────────────────────────────────
   PuroBite / Tiffo — Service Worker (sw.js)
   Version : v24.0  |  Updated : 2026-04-24

   ARCHITECTURE:
   ┌──────────────────────────────────────────────────────────┐
   │  Single GitHub repo — two consumers                      │
   │                                                          │
   │  examyatri/purobitese (GitHub repo)                      │
   │   ├── index.html  ─┐                                     │
   │   ├── admin.html   ├── GitHub Pages (auto on push)       │
   │   ├── rider.html   │   https://examyatri.github.io/      │
   │   ├── sw.js      ──┘         purobitese/                 │
   │   │                                                      │
   │   └── server.js ────── Render (auto-deploy backend)      │
   │                        Node.js + Express + Supabase      │
   └──────────────────────────────────────────────────────────┘

   IMPORTANT — GitHub Pages subfolder scope:
   All paths in PRECACHE and SW registration MUST be relative
   ('./sw.js', './index.html') NOT absolute ('/sw.js', '/index.html')
   because the site lives at /purobitese/, not at root /.

   DEPLOY FLOW (frontend — GitHub Pages):
   1. git push → GitHub Pages serves new files within ~1 min
   2. Browser always re-fetches sw.js (browser spec: SW bypasses cache)
   3. New byte in sw.js → new SW installs in background
   4. install: precaches ./index.html, ./admin.html, ./rider.html
   5. SKIP_WAITING message → new SW activates immediately
   6. activate: deletes old tiffo-* caches
   7. clients.claim() → takes control of all open pages
   8. All 3 panels fire controllerchange → location.reload()
   9. Users get fresh code — no manual cache clear needed ✅

   DEPLOY FLOW (backend — Render):
   1. git push → Render detects server.js change, redeploys
   2. All API calls (purobitese-api.onrender.com) are network-only
      — SW never caches them — clients always hit live backend ✅
   3. No frontend change needed for backend-only deploys

   NOTE: /ping endpoint kept alive by UptimeRobot every 5 min.
   ───────────────────────────────────────────────────────── */

const CACHE      = 'tiffo-v14';
const FONT_CACHE = 'tiffo-fonts-v1';

/* Core app shell — cached on install.
   NOTE: rider/ and admin/ are separate PWA scopes with their own SWs.
   Do NOT add rider.html / admin.html here — that caused cross-app
   clients.claim() reloads and icon mixing in v53. */
const PRECACHE = ['./', './index.html', './manifest.json'];

/* CDN origins — fonts & icons cached with long TTL */
const CDN_ORIGINS = [
  'https://fonts.googleapis.com',
  'https://fonts.gstatic.com',
  'https://cdnjs.cloudflare.com'
];

/* Max age for stale-while-revalidate assets (non-HTML, non-CDN).
   Assets older than this will block on network rather than serve stale. */
const ASSET_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

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

/* ─── MESSAGE (SKIP_WAITING for hot deploy) ─────────────────────────────── */
self.addEventListener('message', e => {
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting();
});

/* ─── INSTALL ────────────────────────────────────────────────────────────── */
self.addEventListener('install', e => {
  // waitUntil keeps the SW in 'installing' state until precache is complete.
  // skipWaiting is intentionally NOT called here — activation is triggered by
  // the SKIP_WAITING message above, which the app sends only after the new
  // worker reaches 'installed' state (precache done). Calling skipWaiting()
  // here races with the cache.addAll() and can activate before assets are ready.
  e.waitUntil(
    caches.open(CACHE).then(cache => cache.addAll(PRECACHE))
  );
});

/* ─── ACTIVATE ───────────────────────────────────────────────────────────── */
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

/* ─── FETCH ──────────────────────────────────────────────────────────────── */
self.addEventListener('fetch', e => {
  const { request } = e;
  const url = new URL(request.url);

  /* Strategy 1 — API: network-only, never cache */
  if (
    url.hostname === 'purobitese-api.onrender.com' ||
    url.pathname.startsWith('/api/')
  ) {
    return; /* let browser handle normally */
  }

  /* Strategy 2 — CDN fonts & icons: cache-first with long TTL
     First visit fetches from CDN and caches. Every visit after = instant. */
  if (CDN_ORIGINS.some(o => url.href.startsWith(o))) {
    e.respondWith(
      caches.open(FONT_CACHE).then(async cache => {
        const cached = await cache.match(request);
        if (cached) return cached; /* instant from cache */
        const res = await fetch(request);
        if (res && res.status === 200) {
          cache.put(request, res.clone());
        }
        return res;
      })
    );
    return;
  }

  /* Strategy 3 — HTML navigation: network-first with offline fallback */
  if (request.mode === 'navigate') {
    e.respondWith(
      fetch(request)
        .then(res => {
          const clone = res.clone();
          caches.open(CACHE).then(cache => cache.put(request, clone));
          return res;
        })
        .catch(async () => {
          // Serve the correct cached page based on which portal was requested
          const path = url.pathname;
          const cacheKey = path.includes('admin') ? './admin.html'
                         : path.includes('rider') ? './rider.html'
                         : './index.html';
          const cached = await caches.match(cacheKey);
          if (cached) return cached;
          return new Response(OFFLINE_HTML, {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        })
    );
    return;
  }

  /* Strategy 4 — All other assets: stale-while-revalidate, capped at 7 days */
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

      // If no cached version, wait for network
      if (!cached) return fetchPromise;

      // If cached version is too old (>7d), wait for network (block on fresh)
      const cachedDate = cached.headers.get('date');
      if (cachedDate) {
        const ageMs = Date.now() - new Date(cachedDate).getTime();
        if (ageMs > ASSET_MAX_AGE_MS) return fetchPromise.catch(() => cached);
      }

      // Serve stale immediately, update cache in background
      fetchPromise; // fire-and-forget revalidation
      return cached;
    })
  );
});
