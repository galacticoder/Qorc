export function installPressFeedback(): void {
  let pressed: Element | null = null;
  let pointer: number | null = null;
  let origin = { x: 0, y: 0 };
  const clear = () => {
    pressed?.removeAttribute('data-qorc-pressed');
    pressed = null;
    pointer = null;
  };
  document.addEventListener('pointerdown', event => {
    clear();
    if (!event.isPrimary || event.button !== 0 || !(event.target instanceof Element)) return;
    const control = event.target.closest('button, [role="button"], [role="option"], a[href]');
    if (!control || control.matches(':disabled, [aria-disabled="true"]') || control.closest('[inert]')) return;
    pressed = control;
    pointer = event.pointerId;
    origin = { x: event.clientX, y: event.clientY };
    control.setAttribute('data-qorc-pressed', '');
  }, { capture: true, passive: true });
  document.addEventListener('pointermove', event => {
    if (event.pointerId === pointer && Math.hypot(event.clientX - origin.x, event.clientY - origin.y) > 8) clear();
  }, { capture: true, passive: true });
  document.addEventListener('pointerup', clear, true);
  document.addEventListener('pointercancel', clear, true);
  document.addEventListener('lostpointercapture', clear, true);
  document.addEventListener('scroll', clear, { capture: true, passive: true });
  document.addEventListener('visibilitychange', clear);
  window.addEventListener('blur', clear);
  document.addEventListener('keydown', event => {
    if (event.repeat || !['Enter', ' '].includes(event.key) || !(event.target instanceof Element)) return;
    const control = event.target.closest('button, [role="button"], [role="option"], a[href]');
    if (!control || control.matches(':disabled, [aria-disabled="true"]') || control.closest('[inert]')) return;
    clear();
    pressed = control;
    control.setAttribute('data-qorc-pressed', '');
  }, true);
  document.addEventListener('keyup', clear, true);
  document.addEventListener('focusout', event => {
    if (pointer === null || event.target === pressed) clear();
  }, true);
}
