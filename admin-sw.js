// Service minimal pour rendre l'administration installable ; aucune donnée n'est mise en cache.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', () => {});
