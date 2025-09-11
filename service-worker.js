const CACHE_NAME = 'schomart-cache-v1';
const urlsToCache = [
  '/',
  '/templates/index.html',
  '/static/css/styles.css',
  '/static/js/app.js',
  '/static/assets/icon-192x192.png'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        return cache.addAll(urlsToCache);
      })
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        return response || fetch(event.request);
      })
  );
});
