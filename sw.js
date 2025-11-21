// Service Worker للتطبيق
const CACHE_NAME = 'inventory-manager-v1';
const urlsToCache = [
  '/',
  '/index.html',
  '/manifest.json'
];

// تثبيت Service Worker
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        return cache.addAll(urlsToCache);
      })
      .catch(err => {
        console.log('Cache addAll error:', err);
      })
  );
  self.skipWaiting();
});

// تفعيل Service Worker
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// استراتيجية التخزين المؤقت
self.addEventListener('fetch', event => {
  // تخطي الطلبات غير GET
  if (event.request.method !== 'GET') {
    return;
  }

  // تخطي الطلبات API
  if (event.request.url.includes('/api/')) {
    event.respondWith(
      fetch(event.request)
        .catch(() => {
          // إذا فشل الطلب وكان بدون إنترنت
          return new Response(
            JSON.stringify({ error: 'Offline' }),
            { status: 503, statusText: 'Service Unavailable' }
          );
        })
    );
    return;
  }

  // استراتيجية Cache First للملفات الثابتة
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        if (response) {
          return response;
        }
        return fetch(event.request)
          .then(response => {
            // لا نخزن الاستجابات غير الناجحة
            if (!response || response.status !== 200 || response.type === 'error') {
              return response;
            }
            // نسخ الاستجابة
            const responseToCache = response.clone();
            caches.open(CACHE_NAME)
              .then(cache => {
                cache.put(event.request, responseToCache);
              });
            return response;
          })
          .catch(() => {
            // إذا فشل الطلب، حاول الحصول على نسخة مخزنة
            return caches.match(event.request);
          });
      })
  );
});

// معالجة الرسائل من العميل
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
