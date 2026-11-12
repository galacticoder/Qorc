/** Keep reverse scrolling thread attached to the composer across IME and
 * native image layout changes without pulling readers out of older history. */
export function attachChatViewport(root: HTMLElement, viewport: HTMLElement, composer: HTMLElement) {
  const stack = root.querySelector<HTMLElement>('.qorc-message-stack');
  let pinned = true;
  let focusPin = false;
  let viewportHeight = viewport.clientHeight;
  let frame = 0;
  let disposed = false;
  let opening = true;
  let stableFrames = 0;
  let lastGeometry = '';
  const deadline = performance.now() + 5000;
  const previousAnchor = viewport.style.overflowAnchor;
  root.dataset.chatLayout = 'preparing';

  const pin = () => {
    if (pinned) viewport.scrollTop = 0;
    viewport.style.overflowAnchor = pinned ? 'none' : previousAnchor;
  };
  const measure = () => {
    const height = `${composer.getBoundingClientRect().height}px`;
    if (root.style.getPropertyValue('--qorc-composer-height') !== height) {
      root.style.setProperty('--qorc-composer-height', height);
    }
    viewportHeight = viewport.clientHeight;
    pin();
  };
  const tick = () => {
    frame = 0;
    if (disposed) return;
    measure();
    if (!opening) return;

    const bounds = viewport.getBoundingClientRect();
    const geometry = `${viewport.clientWidth}:${viewport.clientHeight}:${stack?.getBoundingClientRect().height}`;
    const ready = Array.from(stack?.querySelectorAll<HTMLElement>('.secure-canvas-text') ?? []).every(node => {
      const rect = node.getBoundingClientRect();
      return rect.bottom <= bounds.top || rect.top >= bounds.bottom || node.dataset.privateRendered === 'true';
    });
    stableFrames = ready && geometry === lastGeometry ? stableFrames + 1 : 0;
    lastGeometry = geometry;
    if (stableFrames >= 2 || performance.now() >= deadline) {
      opening = false;
      root.dataset.chatLayout = 'ready';
    } else {
      schedule();
    }
  };
  const schedule = () => {
    if (!disposed && !frame) frame = requestAnimationFrame(tick);
  };
  const onResize = () => {
    measure();
    schedule();
  };
  const onScroll = () => {
    if (focusPin) {
      pin();
      return;
    }
    if (viewport.clientHeight !== viewportHeight) {
      onResize();
      return;
    }
    pinned = Math.max(0, -viewport.scrollTop) <= 24;
    viewport.style.overflowAnchor = pinned ? 'none' : previousAnchor;
  };
  
  const onComposerPointer = () => {
    pinned = Math.max(0, -viewport.scrollTop) <= 24;
    focusPin = pinned;
  };
  const onFocus = () => { focusPin = pinned; measure(); schedule(); };
  const onBlur = (event: FocusEvent) => {
    if (!(event.relatedTarget instanceof Node) || !composer.contains(event.relatedTarget)) focusPin = false;
  };
  const onReadHistory = () => { focusPin = false; };
  const observer = new ResizeObserver(onResize);
  observer.observe(viewport);
  observer.observe(composer);
  if (stack) observer.observe(stack);
  viewport.addEventListener('scroll', onScroll, { passive: true });
  for (const type of ['pointerdown', 'touchstart', 'wheel', 'keydown']) {
    viewport.addEventListener(type, onReadHistory, { passive: true });
  }
  composer.addEventListener('pointerdown', onComposerPointer, { passive: true });
  composer.addEventListener('focusin', onFocus);
  composer.addEventListener('focusout', onBlur);
  window.visualViewport?.addEventListener('resize', onResize);
  measure();
  schedule();

  return () => {
    disposed = true;
    cancelAnimationFrame(frame);
    observer.disconnect();
    viewport.removeEventListener('scroll', onScroll);
    for (const type of ['pointerdown', 'touchstart', 'wheel', 'keydown']) {
      viewport.removeEventListener(type, onReadHistory);
    }
    composer.removeEventListener('pointerdown', onComposerPointer);
    composer.removeEventListener('focusin', onFocus);
    composer.removeEventListener('focusout', onBlur);
    window.visualViewport?.removeEventListener('resize', onResize);
    viewport.style.overflowAnchor = previousAnchor;
    root.style.removeProperty('--qorc-composer-height');
    delete root.dataset.chatLayout;
  };
}
