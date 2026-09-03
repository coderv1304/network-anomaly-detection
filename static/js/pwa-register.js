/**
 * Registers the service worker, surfaces "Install app" and "Update available"
 * UI hooks. Include this on every page with:
 *   <script src="{{ url_for('static', filename='js/pwa-register.js') }}" defer></script>
 */
(function () {
  if (!('serviceWorker' in navigator)) return;

  let deferredInstallPrompt = null;
  const installBtn = document.getElementById('pwa-install-btn');
  const updateToast = document.getElementById('pwa-update-toast');
  const updateReloadBtn = document.getElementById('pwa-update-reload');

  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register('/service-worker.js', { scope: '/' })
      .then((registration) => {
        console.log('[PWA] Service worker registered', registration.scope);

        // Detect a waiting worker (new version deployed) and prompt to refresh.
        registration.addEventListener('updatefound', () => {
          const newWorker = registration.installing;
          if (!newWorker) return;
          newWorker.addEventListener('statechange', () => {
            if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
              if (updateToast) updateToast.hidden = false;
              console.log('[PWA] New version available — reload to update.');
            }
          });
        });
      })
      .catch((err) => console.error('[PWA] Service worker registration failed:', err));
  });

  // Reload once the new worker takes control.
  let refreshing = false;
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (refreshing) return;
    refreshing = true;
    window.location.reload();
  });

  if (updateReloadBtn) {
    updateReloadBtn.addEventListener('click', () => {
      navigator.serviceWorker.getRegistration().then((reg) => {
        if (reg && reg.waiting) reg.waiting.postMessage('SKIP_WAITING');
      });
    });
  }

  // --- "Add to Home Screen" custom install button (Android/desktop Chrome/Edge) ---
  window.addEventListener('beforeinstallprompt', (event) => {
    event.preventDefault();
    deferredInstallPrompt = event;
    if (installBtn) installBtn.hidden = false;
  });

  if (installBtn) {
    installBtn.addEventListener('click', async () => {
      if (!deferredInstallPrompt) return;
      installBtn.hidden = true;
      deferredInstallPrompt.prompt();
      const { outcome } = await deferredInstallPrompt.userChoice;
      console.log('[PWA] Install prompt outcome:', outcome);
      deferredInstallPrompt = null;
    });
  }

  window.addEventListener('appinstalled', () => {
    console.log('[PWA] App installed');
    if (installBtn) installBtn.hidden = true;
  });

  // --- Online/offline indicator (optional UI hook: <span id="pwa-net-status">) ---
  const netStatus = document.getElementById('pwa-net-status');
  function updateNetStatus() {
    if (!netStatus) return;
    netStatus.textContent = navigator.onLine ? 'Online' : 'Offline';
    netStatus.classList.toggle('is-offline', !navigator.onLine);
  }
  window.addEventListener('online', updateNetStatus);
  window.addEventListener('offline', updateNetStatus);
  updateNetStatus();
})();
