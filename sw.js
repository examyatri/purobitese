// Tiffo Service Worker
const CACHE_VERSION = ‘v4’;
const STATIC_CACHE = `tiffo-static-${CACHE_VERSION}`;
const DYNAMIC_CACHE = `tiffo-dynamic-${CACHE_VERSION}`;
const API_CACHE = `tiffo-api-${CACHE_VERSION}`;

// Files to pre-cache on install
const STATIC_FILES = [
‘./index.html’,
‘./admin.html’,
‘./rider.html’,
‘./manifest.json’,
‘./manifest-admin.json’,
‘./manifest-rider.json’,
‘./icons/icon-72.png’,
‘./icons/icon-96.png’,
‘./icons/icon-128.png’,
‘./icons/icon-144.png’,
‘./icons/icon-152.png’,
‘./icons/icon-192.png’,
‘./icons/icon-384.png’,
‘./icons/icon-512.png’,
];

// Install: pre-cache static files
self.addEventListener(‘install’, event => {
event.waitUntil(
caches.open(STATIC_CACHE).then(cache => {
console.log(’[SW] Pre-caching static files’);
return cache.addAll(STATIC_FILES);
}).then(() => self.skipWaiting())
);
});

// Activate: clean up old caches
self.addEventListener(‘activate’, event => {
event.waitUntil(
caches.keys().then(keys => {
return Promise.all(
keys
.filter(k => ![STATIC_CACHE, DYNAMIC_CACHE, API_CACHE].includes(k))
.map(k => {
console.log(’[SW] Deleting old cache:’, k);
return caches.delete(k);
})
);
}).then(() => self.clients.claim())
);
});

// Fetch: smart caching strategy
self.addEventListener(‘fetch’, event => {
const url = new URL(event.request.url);

// Skip non-GET and chrome-extension requests
if (event.request.method !== ‘GET’) return;
if (url.protocol === ‘chrome-extension:’) return;

// FIX: Strip hash from URL — never cache #pg-khata or any hash variant separately
url.hash = ‘’;
const cleanRequest = url.href === event.request.url ? event.request : new Request(url.href, { headers: event.request.headers });

// API calls (Render backend) → Network first, fallback to cache
if (url.hostname.includes(‘onrender.com’) || url.hostname.includes(‘supabase.co’)) {
event.respondWith(networkFirst(cleanRequest, API_CACHE));
return;
}

// Google Fonts, CDN → Stale while revalidate
if (
url.hostname.includes(‘fonts.googleapis.com’) ||
url.hostname.includes(‘fonts.gstatic.com’) ||
url.hostname.includes(‘cdnjs.cloudflare.com’)
) {
event.respondWith(staleWhileRevalidate(cleanRequest, DYNAMIC_CACHE));
return;
}

// Same-origin static files → Cache first
if (url.origin === self.location.origin) {
event.respondWith(cacheFirst(cleanRequest, STATIC_CACHE));
return;
}

// Everything else → Network first
event.respondWith(networkFirst(cleanRequest, DYNAMIC_CACHE));
});

// ── Strategies ──────────────────────────────────────

async function cacheFirst(request, cacheName) {
const cached = await caches.match(request);
if (cached) return cached;
try {
const response = await fetch(request);
if (response.ok) {
const cache = await caches.open(cacheName);
cache.put(request, response.clone());
}
return response;
} catch {
return new Response(‘Offline – please check your connection.’, {
status: 503,
headers: { ‘Content-Type’: ‘text/plain’ }
});
}
}

async function networkFirst(request, cacheName) {
try {
const response = await fetch(request);
if (response.ok) {
const cache = await caches.open(cacheName);
cache.put(request, response.clone());
}
return response;
} catch {
const cached = await caches.match(request);
if (cached) return cached;
return new Response(JSON.stringify({ error: ‘Offline’ }), {
status: 503,
headers: { ‘Content-Type’: ‘application/json’ }
});
}
}

async function staleWhileRevalidate(request, cacheName) {
const cache = await caches.open(cacheName);
const cached = await cache.match(request);
const fetchPromise = fetch(request).then(response => {
if (response.ok) cache.put(request, response.clone());
return response;
}).catch(() => cached);
return cached || fetchPromise;
}

// ── Push Notifications ───────────────────────────────

self.addEventListener(‘push’, event => {
let data = { title: ‘Puro Bite’, body: ‘You have a new update!’, icon: ‘./icons/icon-192.png’ };
if (event.data) {
try { data = { ...data, ...event.data.json() }; } catch {}
}
event.waitUntil(
self.registration.showNotification(data.title, {
body: data.body,
icon: data.icon || ‘./icons/icon-192.png’,
badge: ‘./icons/icon-72.png’,
vibrate: [200, 100, 200],
data: data.url || ‘/’,
})
);
});

self.addEventListener(‘notificationclick’, event => {
event.notification.close();
event.waitUntil(
clients.openWindow(event.notification.data || ‘/’)
);
});

// ── Background Sync ──────────────────────────────────

self.addEventListener(‘sync’, event => {
if (event.tag === ‘sync-orders’) {
event.waitUntil(syncPendingOrders());
}
});

async function syncPendingOrders() {
// Placeholder: implement IndexedDB-based offline order queue if needed
console.log(’[SW] Background sync triggered for orders’);
}
