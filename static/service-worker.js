/**
 * NetShield service worker
 * - Precaches the app shell (pages, CSS, JS, icons) for offline/repeat visits
 * - Network-first for HTML navigations, falling back to cache, then an offline page
 * - Stale-while-revalidate for static assets (css/js/img)
 * - NEVER caches /predict (file upload) or /socket.io/* (live WebSocket traffic)
 */

const VERSION = 'v3.4.2';
const STATIC_CACHE = `netshield-static-${VERSION}`;
const RUNTIME_CACHE = `netshield-runtime-${VERSION}`;

// Bump VERSION above whenever you deploy changed assets so old caches are dropped.
// Do not precache HTML pages here. Navigations are network-first and cached in the
// runtime cache, so a stale app shell can never shadow a newer server-rendered page.
const APP_SHELL = [
  '/offline.html',
  '/static/manifest.json',
  '/static/css/console.css?v=10',
  '/static/css/workbench.css?v=5',
  '/static/js/console.js?v=9',
  '/static/js/theme.js?v=4',
  '/static/js/workbench.js?v=3',
  '/static/js/pwa-register.js',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE).then((cache) =>
      // addAll fails the whole install if one URL 404s — cache individually so
      // one missing file (e.g. you haven't added responsive.css yet) doesn't
      // break the rest of the shell.
      Promise.all(
        APP_SHELL.map((url) =>
          cache.add(url).catch((err) => console.warn('[SW] skip precache', url, err))
        )
      )
    )
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => key !== STATIC_CACHE && key !== RUNTIME_CACHE)
            .map((key) => caches.delete(key))
        )
      )
      .then(() => self.clients.claim())
  );
});

function isNeverCache(url) {
  return (
    url.pathname.startsWith('/socket.io') || // live console websocket/polling
    url.pathname.startsWith('/api/') || // live state must not be served stale
    url.pathname === '/predict' // CSV upload + inference, must always hit the server
  );
}

self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Only handle same-origin GET requests; let everything else pass through untouched.
  if (request.method !== 'GET' || url.origin !== self.location.origin) return;
  if (isNeverCache(url)) return;

  // HTML navigations: network-first so users always get fresh pages when online,
  // with cache and then an offline fallback when they're not.
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const copy = response.clone();
          caches.open(RUNTIME_CACHE).then((cache) => cache.put(request, copy));
          return response;
        })
        .catch(
          () =>
            caches.match(request).then((cached) => cached || caches.match('/offline.html'))
        )
    );
    return;
  }

  // Static assets (css/js/images/fonts): stale-while-revalidate.
  if (['style', 'script', 'image', 'font'].includes(request.destination)) {
    event.respondWith(
      caches.match(request).then((cached) => {
        const network = fetch(request)
          .then((response) => {
            const copy = response.clone();
            caches.open(STATIC_CACHE).then((cache) => cache.put(request, copy));
            return response;
          })
          .catch(() => cached);
        return cached || network;
      })
    );
    return;
  }

  // Everything else: try network, fall back to cache.
  event.respondWith(fetch(request).catch(() => caches.match(request)));
});

// Allows the page to trigger an immediate SW update (see pwa-register.js "Update available" flow)
self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') self.skipWaiting();
});
