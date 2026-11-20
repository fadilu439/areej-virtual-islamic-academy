const CACHE_NAME = "areej-static-v1";
const STATIC_ASSETS = [
  "/static/css/public.css",
  "/static/css/style.css",
  "/static/js/public.js",
  "/static/js/script.js",
  "/static/images/areej-app-icon.svg",
  "/static/images/academy-logo.jpg"
];
self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", event => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin) return;
  if (url.pathname.startsWith("/static/")) {
    event.respondWith(caches.match(request).then(cached => cached || fetch(request).then(response => {
      if (response.ok) {
        const copy = response.clone();
        caches.open(CACHE_NAME).then(cache => cache.put(request, copy));
      }
      return response;
    })));
  }
  // HTML pages, logins, dashboards and form submissions remain network-only.
  // This avoids caching private portal information on shared devices.
});