const guardedTargets = new WeakSet<EventTarget>();

const suppressWebviewContextMenu = (event: Event): void => {
  event.preventDefault();
};

/**
 * Suppress the webview's browser-style context menu without stopping event
 * propagation. React context-menu handlers still receive the event and can
 * render the application's own menus.
 */
export function installNativeContextMenuGuard(target: EventTarget): void {
  if (guardedTargets.has(target)) return;
  guardedTargets.add(target);
  target.addEventListener('contextmenu', suppressWebviewContextMenu, { capture: true });
}
