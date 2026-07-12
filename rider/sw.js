/* ─────────────────────────────────────────────────────────
   Tiffo — Rider Service Worker (rider/sw.js)
   Version : v12.8  |  Updated : 2026-07-12

   CHANGES v12.8 (v206 — Phase 7):
   - Cache bumped → tiffo-rider-v37 (v206 — NRP See Map: fixed silent
     failure when OSRM is unreachable mid-route. Map now always shows a
     dashed straight-line placeholder immediately and keeps it on screen
     if the road route can't be fetched, plus a one-time toast, instead
     of a blank map with no line and no warning. Force refresh so riders
     get this today.)

   CHANGES v12.7 (v201):
   - Cache bumped → tiffo-rider-v36 (v201 — Orders "PDF" button
     replaced with "Share PDF": now generates a real PDF via
     jsPDF/html2canvas and opens the native Share sheet so the
     rider can send it directly to WhatsApp/Telegram/etc. Falls
     back to file download on desktop.)

   CHANGES v12.6 (v199):
   - Cache bumped → tiffo-rider-v35 (v199 — release sync only. v199
     was a customer-app-only release: cold-boot plan restore fix +
     Join Auto Tiffin/Monthly Plan carousel. No rider panel logic
     changed; bump keeps all three portals' cache versions aligned.)

   CHANGES v12.5 (v187):
   - Cache bumped → tiffo-rider-v34 (v187 — Map/Optimize Route stop
     cards now show the same Wallet/Paid/Unpaid payment tag as home
     and start-delivery, previously missing there entirely. Force
     refresh so riders see payment status on the map view too.)

   CHANGES v12.4 (v186):
   - Cache bumped → tiffo-rider-v33 (v186 — Unpaid/Udhar payment
     workflow: real payment-status tags (Wallet/Paid/blinking
     UNPAID) instead of hardcoded Cash, Collect Payment popup
     before marking unpaid orders delivered, new Cash Collected
     stat + day-summary. Force refresh so riders get this today.)

   CHANGES v12.3:
   - Cache bumped → tiffo-rider-v32 (v185 — release sync; version bump)
   - Cache bumped → tiffo-rider-v31 (v184 sync — admin fixed real
     root cause of blank User Map: missing </div> caused #p-usermap
     to nest inside display:none #p-analytics)

   CHANGES v12.2:
   - Cache bumped → tiffo-rider-v30 (v183 — fresh global bump across
     all three portals)
   - FONT_CACHE bumped: tiffo-fonts-v1 → tiffo-fonts-v3 (unified
     version string with admin/customer sw.js — this cache is shared
     origin-wide across all portals regardless of which SW writes it)
   - TILE_CACHE bumped: tiffo-osm-tiles-v1 → tiffo-osm-tiles-v2
   - activate() handler fixed: stale tiffo-fonts-* caches were
     previously NOT cleaned up here (only rider + tile caches were) —
     same root-cause bug found and fixed in admin/sw.js v182. Now
     properly versioned and cleaned up like every other cache.

   CHANGES v12.1:
   - Cache bumped → tiffo-rider-v29 (v176 — version headers updated
     to v176 across all panels; no rider-specific logic changes)

   CHANGES v12.0:
   - Cache bumped → tiffo-rider-v28 (v168 — Route bug fix:
     Morning 🗺 Route now opens ONLY morning orders, Evening
     opens ONLY evening orders. Fixed &quot; JSON corruption
     in onclick attrs via sessionStorage key approach.
     Removed "Plan & Go — Optimized Route" button — redundant,
     was also broken for same reason.)

   CHANGES v11.9:
   - Cache bumped → tiffo-rider-v27 (v166 — "Resume Delivery" banner:
     if Android kills the tab while rider is in Google Maps mid-route,
     app now offers to resume the exact same filter/batch/GMaps-mode
     state on next load instead of losing delivery-in-progress context)

   CHANGES v11.8:
   - Cache bumped → tiffo-rider-v23 (v161 — bug fixes: updateOrderStatus
     rejected guard, checkSession brute-force fix, manualRefund
     negative wallet floor guard)

   CHANGES v11.7:
   - Cache bumped → tiffo-rider-v22 (v158 release — no rider-panel
     UI code changes this release; bumped to stay aligned with the
     unified v158 backend/admin/rider release. Backend fix this
     release: new-subscriber rows now default to opt-in/paused
     auto-tiffin instead of opt-out — see server.js v158 notes.)

   CHANGES v11.6:
   - Cache bumped → tiffo-rider-v21 (v157 — CSP header + SIGTERM + security hardening)

   CHANGES v11.5:
   - Cache bumped → tiffo-rider-v20 (v154 deploy — cache sync)

   CHANGES v11.3:
   - Cache bumped → tiffo-rider-v18 (v145 — BHU Campus area filter
     fix, Edit button on home card, GPS fix for home screen modal)

   CHANGES v11.2:
   - Cache bumped → tiffo-rider-v16 (v131 — rider Set Location +
     GPS coverage banner)

   CHANGES v11.1:
   - Cache bumped → tiffo-rider-v15 (v130 — version alignment release)

   CHANGES v11.0:
   - Cache bumped → tiffo-rider-v14 (v121 release)

   CHANGES v10.0:
   - Cache bumped → tiffo-rider-v13 (v114 rider panel update)

   CHANGES v9.0:
   - Cache bumped → tiffo-rider-v12

   CHANGES v8.6:
   - Version bump for v84 clean release (2026-05-27)

   CHANGES v8.4:
   - Version bump for v71 release
   - Cache bumped → tiffo-rider-v10 (performance indexes migration)
   - skipWaiting() called immediately in install (faster PWA launch)
   - Fixed fire-and-forget fetchPromise (was silently dropped)
   - Manifest id fixed to absolute URL
   ───────────────────────────────────────────────────────── */

const CACHE      = 'tiffo-rider-v37'; // v206: NRP See Map OSRM-failure fallback fix
const FONT_CACHE = 'tiffo-fonts-v3'; // v183: unified version across all three portals' sw.js
const TILE_CACHE = 'tiffo-osm-tiles-v2'; // v183: fresh bump

/* Only rider assets */
const PRECACHE = ['./index.html', './manifest.json', './sw.js'];

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
const TILE_MAX_AGE_MS  = 30 * 24 * 60 * 60 * 1000; // 30 days
const TILE_CACHE_LIMIT = 500; // max tiles to store

/* Network-only: never cache these */
const NETWORK_ONLY_ORIGINS = [
  'purobitese-api.onrender.com',
  'router.project-osrm.org',
  'maps.googleapis.com',
  'maps.google.com',
  'supabase.co',
  'supabase.com'
];

const ASSET_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const OFFLINE_HTML = `<!DOCTYPE html>
<html><head><title>Tiffo Rider Offline</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>*{box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f4f6f9;padding:24px;text-align:center}
h1{color:#2a9d8f;font-size:22px;margin:12px 0 8px}p{color:#6b7280;font-size:14px;margin:0 0 20px}button{background:#2a9d8f;color:white;border:none;border-radius:12px;padding:14px 28px;font-size:16px;font-weight:600;cursor:pointer;-webkit-tap-highlight-color:transparent}button:active{opacity:.85}</style>
</head><body>
<div style="font-size:52px">🛵</div>
<h1>Tiffo Rider Offline</h1>
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
      // Scoped cleanup: only delete OLD rider/tile/font caches — never touch main or admin
      // BUG FIX: font cache was previously never cleaned up here either — same
      // root-cause class of bug found and fixed in admin/sw.js v182.
      caches.keys().then(keys =>
        Promise.all(
          keys
            .filter(k =>
              (k.startsWith('tiffo-rider-') && k !== CACHE) ||
              (k.startsWith('tiffo-osm-tiles-') && k !== TILE_CACHE) ||
              (k.startsWith('tiffo-fonts-') && k !== FONT_CACHE)
            )
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

  /* ── Network-only: API + OSRM routing + Google Maps + Supabase ── */
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
          if (ageMs < TILE_MAX_AGE_MS) return cached; // fresh tile
        }
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

  /* ── HTML navigation — network-first, offline fallback ── */
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

      fetchPromise.catch(() => {}); // background revalidate, prevent unhandled rejection
      return cached;
    })
  );
});
