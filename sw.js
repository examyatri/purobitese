/* ─────────────────────────────────────────────────────────
   Tiffo — Service Worker (sw.js)
   Version : v32.0  |  Updated : 2026-05-24

   CHANGES v32.0:
   - Cache bumped to tiffo-v31 — ported from v40: navigate strategy changed
     from network-first → stale-while-revalidate with 3s network timeout.
     Cached index.html now serves INSTANTLY on every app open — user sees
     content in ~0ms instead of waiting 5-15s for 356KB over network.
     Background update happens silently; next open gets fresh HTML.
   - Added SW→page BroadcastChannel message on background HTML update so
     the app can trigger a silent menu refresh when app shell changes.
   - All other strategies unchanged.

   CHANGES v29.8:
   - Cache bumped → tiffo-v26 (signup location mandatory fix)
   - Location detection now required to create account
   - Improved signup validation messages

   CHANGES v29.7:
   - Version bump for v71 release (PTR freshness fix,
     settings cache reset on PTR and visibility return)

   CHANGES v29.0 (was v28.0):
   - Cache bumped → tiffo-v24 (performance indexes migration)
   - Added sw.js itself to PRECACHE for offline reliability
   - skipWaiting() called immediately in install (faster PWA launch)
   - Fixed fire-and-forget fetchPromise (was silently dropped)
   - display_override added in manifest for instant standalone launch
   ───────────────────────────────────────────────────────── */

const CACHE      = 'tiffo-v31'; // bumped — navigate strategy fix
const FONT_CACHE = 'tiffo-fonts-v1';

/* Core app shell — cached on install. */
const PRECACHE = ['./', './index.html', './manifest.json', './sw.js', './robots.txt', './llms.txt', './sitemap.xml', './humans.txt'];

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
  'supabase.com',
  'googletagmanager.com',
  'google-analytics.com',
  'gc.zgo.at',
  'goatcounter.com',
  'clarity.ms'
];

/* How long to wait for a network response before falling back to cache (navigate only) */
const NAVIGATE_NETWORK_TIMEOUT_MS = 3000; // 3s — matches perceived UX threshold

/* Max age for stale-while-revalidate assets (non-HTML, non-CDN). */
const ASSET_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const OFFLINE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<title>Tiffo – Fresh Tiffin in Varanasi | Offline</title>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="Tiffo – Daily home-cooked tiffin delivery in Varanasi. Mess alternative for BHU students and hostellers.">
<style>
*{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8f5f2;padding:24px;text-align:center}
h1{color:#e63946;font-size:22px;margin:12px 0 6px}
p{color:#6b7280;font-size:14px;margin:0 0 8px;line-height:1.5}
.tag{font-size:12px;color:#94a3b8;margin-bottom:20px}
button{background:#e63946;color:white;border:none;border-radius:12px;padding:14px 28px;font-size:16px;font-weight:600;cursor:pointer;-webkit-tap-highlight-color:transparent}
button:active{opacity:.85}
</style>
</head>
<body>
<div style="font-size:52px">🍱</div>
<h1>Tiffo is offline</h1>
<p>Check your internet connection and try again.</p>
<div class="tag">Fresh tiffin delivery · Varanasi · BHU · Hostels</div>
<button onclick="location.reload()">Try Again</button>
</body>
</html>`;

/* ─── MESSAGE (SKIP_WAITING for instant deploy) ─────────────────────────── */
self.addEventListener('message', e => {
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting();
});

/* ─── INSTALL ────────────────────────────────────────────────────────────── */
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(cache => cache.addAll(PRECACHE))
      .then(() => self.skipWaiting()) // activate immediately — faster PWA launch
  );
});

/* ─── ACTIVATE ───────────────────────────────────────────────────────────── */
self.addEventListener('activate', e => {
  e.waitUntil(
    Promise.all([
      // Delete old CUSTOMER-ONLY caches (tiffo-v* prefix).
      // IMPORTANT: Cache Storage is shared across the entire origin — SW scopes
      // do NOT restrict caches.keys(). Using startsWith('tiffo-') would also
      // delete tiffo-admin-v* and tiffo-rider-v* caches. Use 'tiffo-v' prefix
      // so we only touch our own versioned caches. Font cache is permanent.
      caches.keys().then(keys =>
        Promise.all(
          keys
            .filter(k => k.startsWith('tiffo-v') && k !== CACHE)
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

  /* Strategy 3 — HTML navigation: cache-first with network timeout fallback.
   *
   * WHY THIS CHANGE:
   * The old network-first strategy forced a 356KB download of index.html on
   * EVERY app open, even when a perfectly good cached copy existed.  On slow
   * Indian 4G this was the dominant cause of the 20-30s skeleton:
   *   network-first: wait for 356KB → parse JS → wait for config.js → getHomeData
   *
   * New strategy (stale-while-revalidate + 3s network timeout):
   *   cache hit  → serve cached HTML instantly (~0ms) → app boots → data loads
   *   cache miss → wait up to 3s for network, then serve what we have
   *
   * The background revalidation keeps the cached HTML fresh.  If the app shell
   * actually changed (new deploy), the next open will get the fresh version.
   * We also broadcast a 'SW_HTML_UPDATED' message so the app can handle it.
   */
  if (request.mode === 'navigate') {
    e.respondWith((async () => {
      const cache = await caches.open(CACHE);
      const cached = await cache.match(request);

      // Race: network vs 3s timeout
      const networkWithTimeout = new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('timeout')), NAVIGATE_NETWORK_TIMEOUT_MS);
        fetch(request, { cache: 'no-cache' })
          .then(res => { clearTimeout(timer); resolve(res); })
          .catch(err => { clearTimeout(timer); reject(err); });
      });

      if (cached) {
        // ── CACHE HIT: serve instantly, revalidate in background ──────────
        networkWithTimeout
          .then(async res => {
            if (res && res.status === 200) {
              const oldEtag = cached.headers.get('etag') || cached.headers.get('last-modified');
              const newEtag = res.headers.get('etag') || res.headers.get('last-modified');
              await cache.put(request, res.clone());
              // Notify page only if content actually changed
              if (oldEtag !== newEtag) {
                self.clients.matchAll({ type: 'window' }).then(clients =>
                  clients.forEach(c => c.postMessage({ type: 'SW_HTML_UPDATED' }))
                );
              }
            }
          })
          .catch(() => {}); // background — never block the user

        return cached;
      }

      // ── CACHE MISS: wait for network, fallback to offline page ───────────
      try {
        const res = await networkWithTimeout;
        if (res && res.status === 200) {
          await cache.put(request, res.clone());
          return res;
        }
        return res;
      } catch {
        // Network failed and no cache — show offline page
        const path = url.pathname;
        if (path.includes('admin') || path.includes('rider')) {
          return new Response(OFFLINE_HTML, {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        }
        return new Response(OFFLINE_HTML, {
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      }
    })());
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

      // Serve stale, revalidate in background (fire-and-forget correctly)
      fetchPromise.catch(() => {}); // prevent unhandled rejection
      return cached;
    })
  );
});
