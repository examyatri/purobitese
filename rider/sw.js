/* ─────────────────────────────────────────────────────────
   Tiffo — Rider Service Worker (rider/sw.js)
   Version : v4.0  |  Updated : 2026-04-24

   Lives at /rider/sw.js so its scope is ONLY /rider/
   — completely isolated from the main Tiffo PWA at /
   and the admin PWA at /admin/.

   v4.0 changes:
   - Bumped cache name → tiffo-rider-v4 (forces fresh
     index.html after OSRM routing + marker updates)
   - Added router.project-osrm.org to NETWORK_ONLY
     (routing responses must always be live, never cached)
   - Added tile.openstreetmap.org to TILE_CACHE with
     aggressive 30-day caching (rider re-uses same roads daily)
   - Added TILE_CACHE cleanup on activate
   ───────────────────────────────────────────────────────── */

const CACHE      = 'tiffo-rider-v4';   // ← bumped from v3
const FONT_CACHE = 'tiffo-fonts-v1';
const TILE_CACHE = 'tiffo-osm-tiles-v1'; // NEW: OSM map tiles

/* Only rider assets */
const PRECACHE = ['./index.html', './manifest.json'];

/* CDN assets — cache-first (fonts, leaflet JS/CSS) */
const CDN_ORIGINS = [
  'https://fonts.googleapis.com',
  'https://fonts.gstatic.com',
  'https://cdnjs.cloudflare.com'
];

/* OSM tile servers — cached aggressively (30 days) */
const TILE_ORIGINS = [
  'https://a.tile.openstreetmap.org',
  'https://b.tile.openstreetmap.org',
  'https://c.tile.openstreetmap.org'
];
const TILE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const TILE_CACHE_LIMIT = 500; // max tiles to store

/* Network-only: never cache these */
const NETWORK_ONLY_ORIGINS = [
  'purobitese-api.onrender.com',        // backend GAS API
  'router.project-osrm.org',            // OSRM routing — must be live
  'maps.googleapis.com',                // Google Maps API calls
  'maps.google.com'
];

const ASSET_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const OFFLINE_HTML = `<!DOCTYPE html>
<html><head><title>Tiffo Rider Offline</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f4f6f9}
h1{color:#2a9d8f;font-size:24px}p{color:#6b7280}button{background:#2a9d8f;color:white;border:none;border-radius:12px;padding:12px 24px;font-size:16px;cursor:pointer;margin-top:16px}</style>
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
          .filter(k => k !== CACHE && k !== FONT_CACHE && k !== TILE_CACHE)
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

  /* ── Network-only: API + OSRM routing + Google Maps ── */
  if (NETWORK_ONLY_ORIGINS.some(o => url.hostname.includes(o))) return;
  if (url.pathname.startsWith('/api/')) return;

  /* ── OSM map tiles — cache-first, 30-day TTL, 500 tile cap ── */
  if (TILE_ORIGINS.some(o => url.href.startsWith(o))) {
    e.respondWith(
      caches.open(TILE_CACHE).then(async cache => {
        const cached = await cache.match(request);
        if (cached) {
          const cachedDate = cached.headers.get('date');
          const ageMs = cachedDate ? Date.now() - new Date(cachedDate).getTime() : 0;
          if (ageMs < TILE_MAX_AGE_MS) return cached; // fresh tile — serve from cache
        }
        // Fetch fresh tile
        try {
          const res = await fetch(request);
          if (res && res.status === 200) {
            cache.put(request, res.clone());
            // Trim cache if over limit (evict oldest)
            cache.keys().then(keys => {
              if (keys.length > TILE_CACHE_LIMIT) {
                keys.slice(0, keys.length - TILE_CACHE_LIMIT).forEach(k => cache.delete(k));
              }
            });
          }
          return res;
        } catch {
          return cached || new Response('', { status: 503 });
        }
      })
    );
    return;
  }

  /* ── CDN — cache-first (fonts, Leaflet JS/CSS) ── */
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

  /* ── HTML navigation — network-first, offline fallback ── */
  if (request.mode === 'navigate') {
    e.respondWith(
      fetch(request)
        .then(res => {
          caches.open(CACHE).then(cache => cache.put(request, res.clone()));
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

  /* ── All other assets — stale-while-revalidate ── */
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
