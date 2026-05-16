/* ─────────────────────────────────────────────────────────
   Tiffo — Admin Service Worker (admin/sw.js)
   Version : v7.2  |  Updated : 2026-05-16

   CHANGES v7.2:
   - Version bump for v63 release
   - Cache bumped → tiffo-admin-v9 (performance indexes migration)
   - skipWaiting() called immediately in install (faster PWA launch)
   - Fixed fire-and-forget fetchPromise (was silently dropped)
   - Manifest id fixed to absolute URL
   ───────────────────────────────────────────────────────── */

const CACHE      = 'tiffo-admin-v9';
const FONT_CACHE = 'tiffo-fonts-v1';

/* Only admin assets */
const PRECACHE = ['./index.html', './manifest.json', './sw.js'];

const CDN_ORIGINS = [
  'https://fonts.googleapis.com',
  'https://fonts.gstatic.com',
  'https://cdnjs.cloudflare.com'
];

/* Network-only: API + Supabase — never cache */
const NETWORK_ONLY_ORIGINS = [
  'purobitese-api.onrender.com',
  'supabase.co',
  'supabase.com'
];

const ASSET_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const OFFLINE_HTML = `<!DOCTYPE html>
<html><head><title>Tiffo Admin Offline</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>*{box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#0f172a;padding:24px;text-align:center}
h1{color:#e63946;font-size:22px;margin:12px 0 8px}p{color:#94a3b8;font-size:14px;margin:0 0 20px}button{background:#e63946;color:white;border:none;border-radius:12px;padding:14px 28px;font-size:16px;font-weight:600;cursor:pointer;-webkit-tap-highlight-color:transparent}button:active{opacity:.85}</style>
</head><body>
<div style="font-size:52px">⚙️</div>
<h1 style="color:#e63946">Tiffo Admin Offline</h1>
<p>Check your internet connection and try again.</p>
<button onclick="location.reload()">Try Again</button>
</body></html>`;

/* ─── MESSAGE ────────────────────────────────────────────── */
self.addEventListener('message', e => {
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting();
});

/* ─── INSTALL ────────────────────────────────────────────── */
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(cache => cache.addAll(PRECACHE))
      .then(() => self.skipWaiting()) // activate immediately — faster PWA launch
  );
});

/* ─── ACTIVATE ───────────────────────────────────────────── */
self.addEventListener('activate', e => {
  e.waitUntil(
    Promise.all([
      caches.keys().then(keys =>
        Promise.all(
          keys
            .filter(k => k.startsWith('tiffo-admin-') && k !== CACHE)
            .map(k => caches.delete(k))
        )
      ),
      self.clients.claim()
    ])
  );
});

/* ─── FETCH ──────────────────────────────────────────────── */
self.addEventListener('fetch', e => {
  const { request } = e;

  if (request.method !== 'GET') return;

  const url = new URL(request.url);

  /* Network-only: API + Supabase */
  if (NETWORK_ONLY_ORIGINS.some(o => url.hostname.includes(o)) ||
      url.pathname.startsWith('/api/')) return;

  /* CDN — cache first */
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

  /* HTML navigation — network first, offline fallback */
  if (request.mode === 'navigate') {
    e.respondWith(
      fetch(request, { cache: 'no-cache' })
        .then(res => {
          if (res && res.status === 200) {
            caches.open(CACHE).then(cache => cache.put(request, res.clone()));
          }
          return res;
        })
        .catch(async () => {
          const cached = await caches.match('./index.html');
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

      fetchPromise.catch(() => {}); // background revalidate, prevent unhandled rejection
      return cached;
    })
  );
});
