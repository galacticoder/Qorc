(function initTrustedTypesPolicy() {
  if (typeof window === 'undefined') return;
  try {
    const tt = (window as any).trustedTypes;
    if (!tt) return;
    const policyName = 'default';
    if (typeof tt.getPolicyNames === 'function' && tt.getPolicyNames().includes(policyName)) return;

    // Default policy: do not strip or mutate HTML, otherwise React's internal
    // use of innerHTML + removeChild(<firstChild>) can end up with a null
    // child (e.g. when <script> tags are removed), which breaks DOM invariants
    // and causes "removeChild: parameter 1 is not of type 'Node'" errors.
    // We still block direct script/scriptURL creation.
    tt.createPolicy(policyName, {
      createHTML(input: string) {
        return input;
      },
      createScript() {
        throw new TypeError('Blocked by Trusted Types policy.');
      },
      createScriptURL() {
        throw new TypeError('Blocked by Trusted Types policy.');
      },
    });
  } catch {}
})();
