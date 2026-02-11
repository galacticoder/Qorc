(function initTrustedTypesPolicy() {
  if (typeof window === 'undefined') return;
  try {
    const tt = (window as any).trustedTypes;
    if (!tt) return;
    const policyName = 'default';
    if (typeof tt.getPolicyNames === 'function' && tt.getPolicyNames().includes(policyName)) return;

    tt.createPolicy(policyName, {
      createHTML(input: string) {
        return input;
      },
      createScript() {
        throw new TypeError('Blocked by Trusted Types policy.');
      },
      createScriptURL(input: string) {
        const url = new URL(input, window.location.href);
        const isAllowedOrigin = 
          url.origin === window.location.origin || 
          url.origin === 'tauri://localhost' ||
          url.origin === 'http://localhost:5173';
        
        if (isAllowedOrigin) {
          return input;
        }
        
        console.error('[TrustedTypes] Blocked unauthorized script URL:', input);
        throw new TypeError('Blocked by Trusted Types default policy.');
      },
    });

    // Worker policy for spawning Web Workers
    const workerPolicy = tt.createPolicy('worker-policy', {
      createScriptURL(input: string) {
        const url = new URL(input, window.location.href);
        const isAllowedOrigin = 
          url.origin === window.location.origin || 
          url.origin === 'tauri://localhost' ||
          url.origin === 'http://localhost:5173';
        
        const isWorkerScript = url.pathname.includes('post-quantum-worker');
        const isAsset = url.pathname.includes('/assets/') || url.pathname.includes('/src/');
        
        if (isAllowedOrigin && isWorkerScript && isAsset) {
          return input;
        }
        
        console.error('[TrustedTypes] Blocked unauthorized worker script URL:', input);
        throw new TypeError('Blocked by Trusted Types worker-policy.');
      }
    });

    (window as any)._workerPolicy = workerPolicy;
  } catch {}
})();
