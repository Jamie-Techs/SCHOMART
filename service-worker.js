const CACHE_NAME = 'schomart-cache-v1';
const urlsToCache = [
  '/',
  '/sell.html',
  '/advert_detail.html',
  '/seller_profile_view.html',
  '/profile.html',
  '/static/css/main.css',
  '/static/js/app.js',
  '/static/images/default_profile.png',
  
  '/static/images/icon-512x512.png',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Opened cache');
        return cache.addAll(urlsToCache);
      })
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        if (response) {
          return response;
        }
        return fetch(event.request);
      })
  );
});
