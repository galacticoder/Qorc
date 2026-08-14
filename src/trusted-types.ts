(function initTrustedTypesPolicy() {
  if (typeof window === 'undefined') return;
  try {
    const tt = (window as any).trustedTypes;
    if (!tt) return;

    const workerPolicy = tt.createPolicy('worker-policy', {
      createScriptURL(input: string) {
        const url = new URL(input, window.location.href);
        const isSameAppOrigin =
          url.protocol === window.location.protocol &&
          url.host === window.location.host;
        const isProductionWorker = /^\/assets\/post-quantum-worker-[A-Za-z0-9_-]+\.js$/.test(url.pathname);
        const isDevelopmentWorker = import.meta.env.DEV &&
          url.pathname === '/src/lib/cryptography/post-quantum-worker.ts';

        if (isSameAppOrigin && (isProductionWorker || isDevelopmentWorker)) {
          return input;
        }

        console.error('[TrustedTypes] Blocked unauthorized worker script URL');
        throw new TypeError('Blocked by Trusted Types worker-policy.');
      }
    });

    (window as any)._workerPolicy = workerPolicy;
  } catch {}
})();
