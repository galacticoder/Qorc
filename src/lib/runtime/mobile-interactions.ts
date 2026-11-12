import { isAndroidPlatform } from './platform';

export function installMobileInteractions(): void {
  const media = window.matchMedia('(max-width: 760px)');
  let mobile = false;
  const update = () => {
    mobile = isAndroidPlatform() || media.matches;
    document.documentElement.classList.toggle('qorc-mobile', mobile);
    if (mobile) window.getSelection?.()?.removeAllRanges();
  };
  const preventNativeSelection = (event: Event) => {
    if (!mobile || (event.target instanceof Element && event.target.closest('input, textarea, [contenteditable="true"]'))) return;
    event.preventDefault();
  };
  document.addEventListener('selectstart', preventNativeSelection);
  document.addEventListener('contextmenu', preventNativeSelection);
  update();
  media.addEventListener('change', update);
}
