// ═══════════════════════════════════════════════════════════════
// sw.js — Tiffo PWA Service Worker  (production-grade)
// Strategy:
//   • HTML / navigation  → Network-first, fallback to /index.html
//   • API calls          → Network-only (never cache)
//   • Assets (JS/CSS/img)→ Cache-first, with background revalidation
// ═══════════════════════════════════════════════════════════════

const CACHE_NAME = 'tiffo-v3';

// Assets worth caching (adjust as your build evolves)
const PRECACHE_URLS = [
  '/',
  '/index.html',
  '/manifest.json',
  // Add versioned CSS / JS bundles here if you have them
];

// ── Install ─────────────────────────────────────────────────────
self.addEventListener('install', event => {
  // Take control immediately — don't wait for old SW to die
  self.skipWaiting();

  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(PRECACHE_URLS))
  );
});

// ── Activate ────────────────────────────────────────────────────
self.addEventListener('activate', event => {
  // Claim all open tabs instantly
  event.waitUntil(
    Promise.all([
      self.clients.claim(),
      // Delete every cache that isn't the current version
      caches.keys().then(keys =>
        Promise.all(
          keys
            .filter(k => k !== CACHE_NAME)
            .map(k => {
              console.log('[SW] Deleting old cache:', k);
              return caches.delete(k);
            })
        )
      ),
    ])
  );
});

// ── Fetch ───────────────────────────────────────────────────────
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // 1. Never intercept API calls — always go to network
  if (
    url.hostname === 'purobitese-api.onrender.com' ||
    url.pathname.startsWith('/api/')
  ) {
    return; // let browser handle it natively
  }

  // 2. HTML navigation requests → Network-first, fallback to /index.html
  if (request.mode === 'navigate') {
    event.respondWith(networkFirstHtml(request));
    return;
  }

  // 3. Everything else (JS, CSS, images, fonts) → Cache-first
  event.respondWith(cacheFirst(request));
});

// ── Strategies ──────────────────────────────────────────────────

async function networkFirstHtml(request) {
  try {
    const networkRes = await fetch(request);
    // Refresh the cache copy
    const cache = await caches.open(CACHE_NAME);
    cache.put(request, networkRes.clone());
    return networkRes;
  } catch {
    // Offline — return cached index.html for SPA routing
    const cached = await caches.match('/index.html');
    if (cached) return cached;
    // Last resort: bare offline page
    return new Response(
      '<html><body style="font-family:sans-serif;text-align:center;padding:40px">' +
      '<h2>Tiffo is offline</h2><p>Check your internet and try again.</p>' +
      '<button onclick="location.reload()">Retry</button></body></html>',
      { headers: { 'Content-Type': 'text/html' } }
    );
  }
}

async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) {
    // Revalidate in background so next load is fresh
    revalidateInBackground(request);
    return cached;
  }
  // Not in cache → fetch and store
  try {
    const networkRes = await fetch(request);
    if (networkRes.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, networkRes.clone());
    }
    return networkRes;
  } catch {
    return new Response('', { status: 503, statusText: 'Offline' });
  }
}

function revalidateInBackground(request) {
  fetch(request)
    .then(res => {
      if (res.ok) {
        caches.open(CACHE_NAME).then(c => c.put(request, res));
      }
    })
    .catch(() => {}); // silently ignore
}
