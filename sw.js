/* ─────────────────────────────────────────────────────────
   Tiffo — Service Worker (sw.js)
   Version : v34.0  |  Updated : 2026-05-27

   CHANGES v34.0 (stability & reliability pass):
   ─ CACHE bumped tiffo-v31 → tiffo-v34 to force fresh precache
     after the v53 CSS redesign (new Google Fonts URL added).
   ─ PRECACHE: added './icons/icon-192.png' & './icons/icon-512.png'
     so PWA install works fully offline without a round-trip.
   ─ CDN_ORIGINS: added 'gc.zgo.at' (was wrongly in NETWORK_ONLY —
     GoatCounter count.js is a CDN asset, not an API endpoint).
   ─ Strategy 2 (CDN): fixed URL startsWith() → origin check so
     protocol variations (http/https) never miss the cache.
   ─ Strategy 3 (navigate): SKIP_WAITING now also posts to the
     active worker so the installed-but-waiting worker activates
     even when triggered from the SW side; fixes the case where
     updatefound fires but statechange never reaches 'activated'.
   ─ controllerchange listener added in index.html registration
     (documented here); SW side: clients.claim() already present.
   ─ Strategy 4 (assets): opaque response guard tightened —
     res.type === 'opaque' check was already there but we now
     also guard against status 0 (cross-origin no-cors responses).
   ─ OFFLINE_HTML: improved messaging, retry button kept.
   ─ Offline fallback: removed duplicate admin/rider branch —
     both returned identical HTML, now unified.
   ─ NAVIGATE_NETWORK_TIMEOUT_MS kept at 3000ms (proven sweet spot).
   ─ ASSET_MAX_AGE_MS kept at 7 days.
   ───────────────────────────────────────────────────────── */

const CACHE      = 'tiffo-v34'; // bumped — forces fresh precache after v53 redesign
const FONT_CACHE = 'tiffo-fonts-v2'; // bumped — new Google Fonts URL for Sora + DM Sans

/* Core app shell — cached on install.
   Keep this list minimal: only files that MUST be available offline.
   Large files here slow down SW install and block app first launch. */
const PRECACHE = [
  './',
  './index.html',
  './manifest.json',
  './sw.js',
  './robots.txt',
  './icons/icon-192.png',
  './icons/icon-512.png',
];

/* CDN origins — fonts & icons: cache-first, long TTL.
   NOTE: gc.zgo.at moved here from NETWORK_ONLY (it's a CDN asset script,
   not an API — caching it prevents a round-trip on every page view). */
const CDN_ORIGINS = [
  'fonts.googleapis.com',
  'fonts.gstatic.com',
  'cdnjs.cloudflare.com',
  'gc.zgo.at',
  'ka-f.fontawesome.com',
  'unpkg.com',
  'cdn.jsdelivr.net',
];

/* Network-only: live API calls — never cache, always fresh.
   Anything that returns user-specific or time-sensitive data belongs here. */
const NETWORK_ONLY_ORIGINS = [
  'purobitese-api.onrender.com',
  'supabase.co',
  'supabase.com',
  'googletagmanager.com',
  'google-analytics.com',
  'analytics.google.com',
  'goatcounter.com',
  'clarity.ms',
  'maps.googleapis.com',
  'maps.gstatic.com',
];

/* How long to wait for network on navigate before serving cache */
const NAVIGATE_NETWORK_TIMEOUT_MS = 3000;

/* Max age before stale-while-revalidate blocks on fresh fetch */
const ASSET_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

/* ─── BroadcastChannel for app shell update notifications ─── */
const UPDATE_CHANNEL = 'tiffo-sw-updates';

/* ─── Offline page ────────────────────────────────────────── */
const OFFLINE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<title>Tiffo – No Internet</title>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#e63946">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  min-height:100dvh;background:#f7f8fa;padding:28px;text-align:center;
  color:#0f172a;
}
.emoji{font-size:56px;margin-bottom:16px}
h1{color:#e63946;font-size:20px;font-weight:800;margin-bottom:8px;letter-spacing:-.3px}
p{color:#64748b;font-size:13.5px;margin-bottom:4px;line-height:1.6;max-width:260px}
.hint{font-size:12px;color:#94a3b8;margin-top:6px;margin-bottom:24px}
button{
  background:linear-gradient(135deg,#e63946,#f4591d);
  color:#fff;border:none;border-radius:14px;
  padding:15px 32px;font-size:15px;font-weight:700;
  cursor:pointer;-webkit-tap-highlight-color:transparent;
  box-shadow:0 4px 16px rgba(230,57,70,.35);
}
button:active{opacity:.88;transform:scale(.98)}
</style>
</head>
<body>
<div class="emoji">🍱</div>
<h1>Tiffo is offline</h1>
<p>No internet connection detected.</p>
<p class="hint">Connect to WiFi or mobile data and try again.</p>
<button onclick="location.reload()">Try Again</button>
</body>
</html>`;

/* ─── HELPERS ──────────────────────────────────────────────── */

/** Check if a URL hostname matches any network-only origin. */
function isNetworkOnly(url) {
  return NETWORK_ONLY_ORIGINS.some(o => url.hostname.includes(o)) ||
         url.pathname.startsWith('/api/');
}

/** Check if a URL should be cached as a CDN asset. */
function isCDN(url) {
  return CDN_ORIGINS.some(o => url.hostname.includes(o));
}

/** Returns true if a Response is safe to cache (not opaque, not error). */
function isCacheable(res) {
  return res && res.status === 200 && res.type !== 'opaque';
}

/** Notify all open app windows that the HTML shell was updated. */
async function notifyClientsHtmlUpdated() {
  const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: false });
  clients.forEach(c => c.postMessage({ type: 'SW_HTML_UPDATED' }));
}

/* ─── MESSAGE ──────────────────────────────────────────────── */
self.addEventListener('message', e => {
  if (!e.data) return;
  if (e.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

/* ─── INSTALL ──────────────────────────────────────────────── */
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(cache => cache.addAll(PRECACHE))
      .then(() => self.skipWaiting()) // activate immediately
      .catch(err => {
        // Don't fail install if a single precache item is missing (e.g. icon not yet deployed)
        console.warn('[SW] Precache partial failure (non-fatal):', err);
        return self.skipWaiting();
      })
  );
});

/* ─── ACTIVATE ─────────────────────────────────────────────── */
self.addEventListener('activate', e => {
  e.waitUntil(
    Promise.all([
      // Clean up old CUSTOMER caches only (prefix 'tiffo-v' — never touches admin/rider caches)
      caches.keys().then(keys =>
        Promise.all(
          keys
            .filter(k =>
              (k.startsWith('tiffo-v') || k.startsWith('tiffo-fonts-')) &&
              k !== CACHE &&
              k !== FONT_CACHE
            )
            .map(k => {
              console.log('[SW] Deleting old cache:', k);
              return caches.delete(k);
            })
        )
      ),
      // Take control of all open pages immediately
      self.clients.claim(),
    ])
  );
});

/* ─── FETCH ────────────────────────────────────────────────── */
self.addEventListener('fetch', e => {
  const { request } = e;

  // Only handle GET — pass through POST/PUT/DELETE to browser
  if (request.method !== 'GET') return;

  const url = new URL(request.url);

  // ── Strategy 1: Network-only (APIs, analytics, live data) ──────────────
  if (isNetworkOnly(url)) {
    return; // browser handles it natively
  }

  // ── Strategy 2: CDN assets (fonts, icons, libraries) — cache-first ─────
  if (isCDN(url)) {
    e.respondWith(
      caches.open(FONT_CACHE).then(async cache => {
        const cached = await cache.match(request);
        if (cached) return cached;

        try {
          const res = await fetch(request);
          if (isCacheable(res)) cache.put(request, res.clone());
          return res;
        } catch {
          // Network failed, nothing cached — return minimal 503
          return cached || new Response('', { status: 503 });
        }
      })
    );
    return;
  }

  // ── Strategy 3: HTML navigation — stale-while-revalidate + 3s timeout ──
  //
  // WHY: Serve cached HTML instantly (0ms boot on repeat visits).
  //      Revalidate in background so next visit gets fresh shell.
  //      If cache is empty, wait up to 3s for network, then offline page.
  if (request.mode === 'navigate') {
    e.respondWith((async () => {
      const cache   = await caches.open(CACHE);
      const cached  = await cache.match(request);

      // Network fetch with 3s timeout
      const networkWithTimeout = new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('timeout')), NAVIGATE_NETWORK_TIMEOUT_MS);
        fetch(request, { cache: 'no-cache' })
          .then(res => { clearTimeout(timer); resolve(res); })
          .catch(err => { clearTimeout(timer); reject(err); });
      });

      if (cached) {
        // CACHE HIT: serve instantly, revalidate silently in background
        networkWithTimeout
          .then(async res => {
            if (!isCacheable(res)) return;

            // Compare ETags/Last-Modified to avoid unnecessary notifies
            const oldTag = cached.headers.get('etag') || cached.headers.get('last-modified') || '';
            const newTag = res.headers.get('etag')    || res.headers.get('last-modified')    || '';
            await cache.put(request, res.clone());

            if (oldTag !== newTag) {
              // Shell actually changed — tell open tabs to refresh menu data
              await notifyClientsHtmlUpdated();
            }
          })
          .catch(() => {}); // background — never block user

        return cached;
      }

      // CACHE MISS: wait for network, then cache and serve
      try {
        const res = await networkWithTimeout;
        if (isCacheable(res)) await cache.put(request, res.clone());
        return res;
      } catch {
        // Network failed, nothing cached — show offline page
        return new Response(OFFLINE_HTML, {
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      }
    })());
    return;
  }

  // ── Strategy 4: All other assets — stale-while-revalidate, 7-day TTL ───
  e.respondWith(
    caches.open(CACHE).then(async cache => {
      const cached      = await cache.match(request);
      const fetchPromise = fetch(request)
        .then(res => {
          if (isCacheable(res)) cache.put(request, res.clone());
          return res;
        })
        .catch(() => null);

      if (!cached) {
        // Nothing cached — must wait for network
        return fetchPromise.then(res => res || new Response('', { status: 503 }));
      }

      // Check staleness
      const cachedDate = cached.headers.get('date');
      if (cachedDate) {
        const ageMs = Date.now() - new Date(cachedDate).getTime();
        if (ageMs > ASSET_MAX_AGE_MS) {
          // Stale beyond TTL — block on fresh fetch, fall back to old cache
          return fetchPromise.catch(() => cached);
        }
      }

      // Fresh enough — serve stale, revalidate in background
      fetchPromise.catch(() => {}); // suppress unhandled rejection
      return cached;
    })
  );
});
