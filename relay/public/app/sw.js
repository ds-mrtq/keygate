// KeyGate service worker: only shows the (content-free) push notification and focuses the app on tap.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

self.addEventListener("push", (e) => {
  e.waitUntil(
    self.registration.showNotification("KeyGate", {
      body: "Có yêu cầu chờ duyệt",
      tag: "kg-pending",
      icon: "/app/icon-192.png",
    }),
  );
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
      for (const c of list) if (c.url.includes("/app/") && "focus" in c) return c.focus();
      return self.clients.openWindow("/app/");
    }),
  );
});
