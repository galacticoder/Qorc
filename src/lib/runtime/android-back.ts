export const ANDROID_BACK_EVENT = 'qorc:android-back';
type BackHandler = { callback: () => boolean; priority: number };
const handlers: BackHandler[] = [];
let installed = false;

export function installAndroidBackNavigation(): void {
  if (installed) return;
  installed = true;
  window.addEventListener(ANDROID_BACK_EVENT, dispatchBack);
}

function dispatchBack(event: Event): void {
  if (event.defaultPrevented) return;
  const ordered = [...handlers].reverse().sort((a, b) => b.priority - a.priority);
  const overlay = [...document.querySelectorAll<HTMLElement>(
    '[role="dialog"], [role="alertdialog"], [role="listbox"], [role="menu"]',
  )].some(element => element.getClientRects().length > 0 && element.dataset.state !== 'closed');
  if (overlay && (!ordered.length || ordered[0].priority < 90)) {
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true, cancelable: true }));
    event.preventDefault();
    return;
  }
  for (const handler of ordered) {
    if (!handlers.includes(handler) || !handler.callback()) continue;
    event.preventDefault();
    return;
  }
}

export function registerAndroidBackHandler(callback: () => boolean, priority = 0): () => void {
  const handler = { callback, priority };
  installAndroidBackNavigation();
  handlers.push(handler);
  return () => {
    const index = handlers.indexOf(handler);
    if (index >= 0) handlers.splice(index, 1);
  };
}
