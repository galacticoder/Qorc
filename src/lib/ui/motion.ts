export type ViewMotionDirection = 'forward' | 'back';

export function animateView(
  element: HTMLElement | null,
  direction: ViewMotionDirection = 'forward',
  leaving = false,
): Animation | null {
  if (!element?.animate || window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return null;
  const offset = direction === 'forward' ? 18 : -18;
  return element.animate(leaving ? [
    { opacity: 1, transform: 'translateX(0)' },
    { opacity: 0, transform: `translateX(${-offset}px)` },
  ] : [
    { opacity: .45, transform: `translateX(${offset}px)` },
    { opacity: 1, transform: 'translateX(0)' },
  ], { duration: leaving ? 140 : 180, easing: 'cubic-bezier(.2,.8,.2,1)', fill: leaving ? 'forwards' : 'none' });
}
