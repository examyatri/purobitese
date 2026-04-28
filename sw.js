/* ─────────────────────────────────────────────────────────
   Tiffo — Service Worker (sw.js)
   Version : v25.0  |  Updated : 2026-04-28

   ARCHITECTURE:
   ┌──────────────────────────────────────────────────────────┐
   │  Single GitHub repo — two consumers                      │
   │                                                          │
   │  tiffo.online (GitHub repo)                              │
   │   ├── index.html  ─┐                                     │
   │   ├── admin.html   ├── GitHub Pages (auto on push)       │
   │   ├── rider.html   │   https://examyatri.github.io/      │
   │   ├── sw.js      ──┘         tiffo/                      │
   │   │                                                      │
   │   └── server.js ────── Render (auto-deploy backend)      │
   │                        Node.js + Express + Supabase      │
   └──────────────────────────────────────────────────────────┘

   IMPORTANT — GitHub Pages subfolder scope:
   All paths in PRECACHE and SW registration MUST be relative
   ('./sw.js', './index.html') NOT absolute ('/sw.js', '/index.html')
   because the site lives at /, not at root /.

   DEPLOY FLOW (frontend — GitHub Pages):
   1. git push → GitHub Pages serves new files within ~1 min
   2. Browser always re-fetches sw.js (browser spec: SW bypasses cache)
   3. New byte in sw.js → new SW installs in background
   4. install: precaches ./index.html, ./manifest.json
   5. SKIP_WAITING message → new SW activates immediately
   6. activate: deletes old tiffo-* caches
   7. clients.claim() → takes control of all open pages
   8. controllerchange → location.reload()
   9. Users get fresh code — no manual cache clear needed ✅

   DEPLOY FLOW (backend — Render):
   1. git push → Render detects server.js change, redeploys
   2. All API calls (purobitese-api.onrender.com) are network-only
      — SW never caches them — clients always hit live backend ✅
   3. No frontend change needed for backend-only deploys

   NOTE: /ping kept alive by self-ping (12 min) + UptimeRobot (5 min).
   ───────────────────────────────────────────────────────── */

const CACHE      = 'tiffo-v15';        /* ← bumped: forces fresh install */
const FONT_CACHE = 'tiffo-fonts-v1';

/* Core app shell — cached on install.
   NOTE: rider/ and admin/ are separate PWA scopes with their own SWs.
   Do NOT add rider.html / admin.html here. */
const PRECACHE = ['./', './index.html', './manifest.json'];

/* CDN origins — fonts & icons cached with long TTL */
const CDN_ORIGINS = [
  'https://fonts.googleapis.com',
  'https://fonts.gstatic.com',
  'https://cdnjs.cloudflare.com'
];

/* Network-only: API calls — never cache, always live */
const NETWORK_ONLY_ORIGINS = [
  'purobitese-api.onrender.com',
  'supabase.co',
  'supabase.com'
];

/* Max age for stale-while-revalidate assets (non-HTML, non-CDN). */
const ASSET_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const OFFLINE_HTML = `<!DOCTYPE html>
<html><head><title>Tiffo Offline</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>*{box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8f5f2;padding:24px;text-align:center}
h1{color:#e63946;font-size:22px;margin:12px 0 8px}p{color:#6b7280;font-size:14px;margin:0 0 20px}button{background:#e63946;color:white;border:none;border-radius:12px;padding:14px 28px;font-size:16px;font-weight:600;cursor:pointer;-webkit-tap-highlight-color:transparent}button:active{opacity:.85}</style>
</head><body>
<div style="font-size:52px">🍱</div>
<h1>Tiffo is offline</h1>
<p>Check your internet connection and try again.</p>
<button onclick="location.reload()">Try Again</button>
</body></html>`;

/* ─── MESSAGE (SKIP_WAITING for instant deploy) ─────────────────────────── */
self.addEventListener('message', e => {
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting();
});

/* ─── INSTALL ────────────────────────────────────────────────────────────── */
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(cache => cache.addAll(PRECACHE))
    // skipWaiting intentionally deferred — triggered by SKIP_WAITING message
    // after precache completes, avoiding race conditions.
  );
});

/* ─── ACTIVATE ───────────────────────────────────────────────────────────── */
self.addEventListener('activate', e => {
  e.waitUntil(
    Promise.all([
      // Delete all old tiffo-* caches (except current and font cache)
      caches.keys().then(keys =>
        Promise.all(
          keys
            .filter(k => k.startsWith('tiffo-') && k !== CACHE && k !== FONT_CACHE)
            .map(k => caches.delete(k))
        )
      ),
      // Take control of all open clients immediately
      self.clients.claim()
    ])
  );
});

/* ─── FETCH ──────────────────────────────────────────────────────────────── */
self.addEventListener('fetch', e => {
  const { request } = e;

  // Ignore non-GET requests (POST, PUT, etc.)
  if (request.method !== 'GET') return;

  const url = new URL(request.url);

  /* Strategy 1 — Network-only: API + Supabase — never cache */
  if (NETWORK_ONLY_ORIGINS.some(o => url.hostname.includes(o)) ||
      url.pathname.startsWith('/api/')) {
    return; /* let browser handle normally */
  }

  /* Strategy 2 — CDN fonts & icons: cache-first, very long TTL */
  if (CDN_ORIGINS.some(o => url.href.startsWith(o))) {
    e.respondWith(
      caches.open(FONT_CACHE).then(async cache => {
        const cached = await cache.match(request);
        if (cached) return cached;
        try {
          const res = await fetch(request);
          if (res && res.status === 200) cache.put(request, res.clone());
          return res;
        } catch {
          return cached || new Response('', { status: 503 });
        }
      })
    );
    return;
  }

  /* Strategy 3 — HTML navigation: network-first, fallback to cache or offline */
  if (request.mode === 'navigate') {
    e.respondWith(
      fetch(request, { cache: 'no-cache' })
        .then(res => {
          if (res && res.status === 200) {
            const clone = res.clone();
            caches.open(CACHE).then(cache => cache.put(request, clone));
          }
          return res;
        })
        .catch(async () => {
          const path = url.pathname;
          if (path.includes('admin') || path.includes('rider')) {
            return new Response(OFFLINE_HTML, {
              headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
          }
          const cached = await caches.match('./index.html');
          if (cached) return cached;
          return new Response(OFFLINE_HTML, {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        })
    );
    return;
  }

  /* Strategy 4 — All other assets: stale-while-revalidate, max 7 days */
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

      // If stale beyond 7 days, wait for network (block on fresh)
      const cachedDate = cached.headers.get('date');
      if (cachedDate) {
        const ageMs = Date.now() - new Date(cachedDate).getTime();
        if (ageMs > ASSET_MAX_AGE_MS) return fetchPromise.catch(() => cached);
      }

      // Serve stale, revalidate in background
      fetchPromise; // fire-and-forget
      return cached;
    })
  );
});
