/* ─── Tiffo Service Worker — tiffo-v5 ──────────────────────────────────── */
/* WHAT CHANGED vs v4:
   1. Google Fonts & Font Awesome pre-cached on install → no FOUT / render block
   2. index.html now uses cache-first (not network-first) — loads from cache
      instantly, then background-revalidates so next open gets the latest.
   3. Admin & rider HTML use the same instant-cache strategy.
   4. Separate STATIC cache (fonts/css — rarely changes) from SHELL cache
      (html/icons — changes more often). Fonts never need re-fetching.
   5. Offline fallback is served from cache; no hardcoded inline HTML to bloat sw.js.
*/

const VER       = 'tiffo-v5';
const CACHE_SHELL  = `${VER}-shell`;   // HTML + manifests + icons
const CACHE_STATIC = `${VER}-static`;  // Fonts, FA CSS, other CDN assets
const API_HOST  = 'purobitese-api.onrender.com';

/* ── Assets to pre-cache on install ─────────────────────────────────────── */
const SHELL_URLS = [
  './',
  './index.html',
  './admin.html',
  './rider.html',
  './manifest.json',
  './manifest-admin.json',
  './manifest-rider.json',
  './404.html',
];

/* Fonts & icon CSS — these basically never change; cache them permanently */
const STATIC_URLS = [
  'https://fonts.googleapis.com/css2?family=Sora:wght@400;500;600;700;800&family=DM+Sans:wght@400;500;600;700&display=swap',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/webfonts/fa-solid-900.woff2',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/webfonts/fa-regular-400.woff2',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/webfonts/fa-brands-400.woff2',
];

/* ─── INSTALL ────────────────────────────────────────────────────────────── */
self.addEventListener('install', e => {
  e.waitUntil(
    Promise.all([
      /* Shell: fail silently on any one missing file (icons may not exist yet) */
      caches.open(CACHE_SHELL).then(cache =>
        Promise.allSettled(SHELL_URLS.map(url => cache.add(url)))
      ),
      /* Static: pre-warm fonts & FA so first render has no network round-trips */
      caches.open(CACHE_STATIC).then(cache =>
        Promise.allSettled(STATIC_URLS.map(url =>
          cache.add(new Request(url, { mode: 'cors', credentials: 'omit' }))
        ))
      ),
    ])
  );
  self.skipWaiting(); // activate immediately
});

/* ─── ACTIVATE ───────────────────────────────────────────────────────────── */
self.addEventListener('activate', e => {
  const KEEP = [CACHE_SHELL, CACHE_STATIC];
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(k => !KEEP.includes(k))
          .map(k => caches.delete(k))
      )
    )
  );
  self.clients.claim(); // take over open tabs immediately
});

/* ─── FETCH ──────────────────────────────────────────────────────────────── */
self.addEventListener('fetch', e => {
  const { request } = e;
  const url = new URL(request.url);

  /* ── 1. API calls: always network-only, never cache ─────────────────── */
  if (url.hostname === API_HOST || url.pathname.startsWith('/api/')) {
    return; // fall through to browser
  }

  /* ── 2. Google Fonts / CDN static assets: cache-first, long-lived ───── */
  if (
    url.hostname === 'fonts.googleapis.com' ||
    url.hostname === 'fonts.gstatic.com'    ||
    url.hostname === 'cdnjs.cloudflare.com'
  ) {
    e.respondWith(cacheFirst(request, CACHE_STATIC));
    return;
  }

  /* ── 3. HTML navigation: stale-while-revalidate ──────────────────────
     Return cached HTML immediately (instant open), then fetch a fresh
     copy in the background so the *next* launch has the latest version.
     No more 300-500ms wait for the network on every cold open.           */
  if (request.mode === 'navigate') {
    e.respondWith(staleWhileRevalidate(request, CACHE_SHELL));
    return;
  }

  /* ── 4. Icons / manifests / other same-origin assets: SWR ───────────── */
  e.respondWith(staleWhileRevalidate(request, CACHE_SHELL));
});

/* ─── Strategies ─────────────────────────────────────────────────────────── */

/**
 * cache-first — serve from cache; only hit network if not cached.
 * Best for fonts / versioned CDN assets that don't change.
 */
async function cacheFirst(request, cacheName) {
  const cache  = await caches.open(cacheName);
  const cached = await cache.match(request);
  if (cached) return cached;

  try {
    const fresh = await fetch(request);
    if (fresh && fresh.status === 200) cache.put(request, fresh.clone());
    return fresh;
  } catch {
    return new Response('Network error', { status: 503 });
  }
}

/**
 * stale-while-revalidate — serve cache instantly, refresh in background.
 * Best for HTML shells: user sees the app immediately, gets updates next open.
 */
async function staleWhileRevalidate(request, cacheName) {
  const cache  = await caches.open(cacheName);
  const cached = await cache.match(request);

  // Always kick off a background revalidation
  const revalidate = fetch(request)
    .then(res => {
      if (res && res.status === 200 && res.type !== 'opaque') {
        cache.put(request, res.clone());
      }
      return res;
    })
    .catch(() => null);

  // If we have a cached copy, return it right away (instant)
  if (cached) return cached;

  // No cache yet (first visit) — wait for network
  const fresh = await revalidate;
  if (fresh) return fresh;

  // True offline + no cache — serve 404 page if available, else generic message
  const fallback = await cache.match('./404.html');
  return fallback || new Response(
    '<h2>You are offline</h2><p>Open Tiffo once with internet to enable offline mode.</p>',
    { headers: { 'Content-Type': 'text/html; charset=utf-8' }, status: 503 }
  );
}
