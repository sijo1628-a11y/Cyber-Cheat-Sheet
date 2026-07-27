/* Cyber Cheat Sheet — service worker
   Caches the app shell + data on install so the dashboard keeps
   working offline after the first successful visit. */

var CACHE_NAME = "cyber-cheat-sheet-v1";

var CORE_ASSETS = [
  "./",
  "./index.html",
  "./style.css",
  "./script.js",
  "./manifest.json",
  "./assets/logo.png",
  "./assets/favicon.png",
  "./data/linux.json",
  "./data/windows.json",
  "./data/powershell.json",
  "./data/nmap.json",
  "./data/wireshark.json",
  "./data/splunk.json",
  "./data/kql.json",
  "./data/sigma.json",
  "./data/yara.json"
];

self.addEventListener("install", function (event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function (cache) {
      return cache.addAll(CORE_ASSETS).catch(function (err) {
        // Don't fail install if one optional asset is missing.
        console.warn("Service worker: some assets failed to precache", err);
      });
    }).then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(
        keys.filter(function (k) { return k !== CACHE_NAME; }).map(function (k) { return caches.delete(k); })
      );
    }).then(function () { return self.clients.claim(); })
  );
});

// Cache-first for same-origin GET requests, falling back to the network,
// and updating the cache with anything new we fetch along the way.
self.addEventListener("fetch", function (event) {
  var req = event.request;
  if (req.method !== "GET" || new URL(req.url).origin !== location.origin) return;

  event.respondWith(
    caches.match(req).then(function (cached) {
      var networkFetch = fetch(req).then(function (res) {
        if (res && res.ok) {
          var copy = res.clone();
          caches.open(CACHE_NAME).then(function (cache) { cache.put(req, copy); });
        }
        return res;
      }).catch(function () { return cached; });
      return cached || networkFetch;
    })
  );
});
