// ═══════════════════════════════════════════════════════════
// Puro Bite — Service Worker
// Hosting: GitHub Pages (subfolder) + Render API
//
// Strategy:
//   • App shell (HTML, icons) → Cache First
//   • API calls (onrender.com) → Network Only (always fresh)
//   • Google Fonts / CDN assets → Cache First with long TTL
//   • Everything else → Network First with cache fallback
//
// Uses relative URLs — works on any origin or subfolder
// (GitHub Pages /purobitese/ or a future custom domain /)
// ═══════════════════════════════════════════════════════════

const SW_VERSION  = 'pb-v2';
const SHELL_CACHE = `${SW_VERSION}-shell`;
const ASSET_CACHE = `${SW_VERSION}-assets`;

// Relative paths — resolve correctly regardless of subfolder depth
const SHELL_URLS = [
  './',
  './index.html',
  './admin.html',
  './rider.html',
  './manifest.json',
  './manifest-admin.json',
  './manifest-rider.json',
  './icons/icon-192.png',
  './icons/icon-512.png'
];

// ── INSTALL — pre-cache app shell ────────────────────────────
self.addEventListener('install', e => {
  self.skipWaiting();
  e.waitUntil(
    caches.open(SHELL_CACHE).then(cache =>
      Promise.allSettled(
        SHELL_URLS.map(url =>
          cache.add(url).catch(() => console.warn('[SW] Could not cache:', url))
        )
      )
    )
  );
});

// ── ACTIVATE — purge old caches ──────────────────────────────
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys
          .filter(k => k !== SHELL_CACHE && k !== ASSET_CACHE)
          .map(k => { console.log('[SW] Removing old cache:', k); return caches.delete(k); })
      ))
      .then(() => self.clients.claim())
  );
});

// ── FETCH ─────────────────────────────────────────────────────
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // 1. Render API — NETWORK ONLY (never cache API responses)
  if (url.hostname.includes('onrender.com') ||
      url.pathname.endsWith('/api')) {
    return;
  }

  // 2. Google Fonts + CDN — CACHE FIRST
  if (url.hostname.includes('fonts.googleapis.com') ||
      url.hostname.includes('fonts.gstatic.com') ||
      url.hostname.includes('cdnjs.cloudflare.com')) {
    e.respondWith(
      caches.open(ASSET_CACHE).then(cache =>
        cache.match(e.request).then(cached => {
          if (cached) return cached;
          return fetch(e.request).then(res => {
            if (res.ok) cache.put(e.request, res.clone());
            return res;
          });
        })
      )
    );
    return;
  }

  // 3. HTML navigation — STALE WHILE REVALIDATE
  if (e.request.mode === 'navigate' ||
      url.pathname.endsWith('.html') ||
      url.pathname.endsWith('/')) {
    e.respondWith(
      caches.open(SHELL_CACHE).then(cache =>
        cache.match(e.request).then(cached => {
          const networkFetch = fetch(e.request)
            .then(res => { if (res.ok) cache.put(e.request, res.clone()); return res; })
            .catch(() => cached);
          return cached || networkFetch;
        })
      )
    );
    return;
  }

  // 4. Icons, manifests, images — CACHE FIRST
  if (url.pathname.includes('/icons/') ||
      url.pathname.endsWith('.json')   ||
      url.pathname.endsWith('.png')    ||
      url.pathname.endsWith('.jpg')    ||
      url.pathname.endsWith('.svg')    ||
      url.pathname.endsWith('.ico')) {
    e.respondWith(
      caches.open(ASSET_CACHE).then(cache =>
        cache.match(e.request).then(cached => {
          if (cached) return cached;
          return fetch(e.request).then(res => {
            if (res.ok) cache.put(e.request, res.clone());
            return res;
          });
        })
      )
    );
    return;
  }

  // 5. Anything else — NETWORK FIRST with cache fallback
  e.respondWith(
    fetch(e.request)
      .then(res => {
        if (res.ok) caches.open(ASSET_CACHE).then(c => c.put(e.request, res.clone()));
        return res;
      })
      .catch(() =>
        caches.match(e.request).then(cached =>
          cached || new Response('Offline — please check your internet connection.', {
            status: 503, headers: { 'Content-Type': 'text/plain' }
          })
        )
      )
  );
});

// ── MESSAGE — force update from app ──────────────────────────
self.addEventListener('message', e => {
  if (e.data === 'SKIP_WAITING') self.skipWaiting();
});
