import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useAppBack } from '../../hooks/useAppBack';
import { animateView } from '../../lib/ui/motion';
import { useMobileLayout } from '../../hooks/useMobileLayout';

export const ScreenContext = createContext<((id: symbol, open: boolean) => void) | null>(null);

interface StandaloneScreenProps {
  open: boolean;
  onBack: () => void;
  className?: string;
  labelledBy: string;
  describedBy?: string;
  children: React.ReactNode;
}

export function StandaloneScreen({ open, onBack, className = '', labelledBy, describedBy, children }: StandaloneScreenProps) {
  const register = useContext(ScreenContext);
  const mobile = useMobileLayout();
  const id = useRef(Symbol('screen'));
  const content = useRef<HTMLElement>(null);
  const exit = useRef<Animation | null>(null);
  const closing = useRef(false);
  const latestBack = useRef(onBack);
  useLayoutEffect(() => { latestBack.current = onBack; });
  const goBack = useCallback(() => {
    if (closing.current) return;
    const animation = register && !mobile ? null : animateView(content.current, 'back', true);
    if (!animation) { latestBack.current(); return; }
    closing.current = true;
    exit.current = animation;
    const finish = () => {
      if (exit.current !== animation) return;
      latestBack.current();
    };
    void animation.finished.then(finish, finish);
  }, [register, mobile]);
  useAppBack(open, goBack, 80);

  useLayoutEffect(() => {
    if (!open) return;
    register?.(id.current, true);
    const root = !register ? document.getElementById('root') : null;
    const wasInert = root?.inert;
    if (root) root.inert = true;
    const previousFocus = document.activeElement;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    content.current?.querySelector<HTMLButtonElement>('button')?.focus();
    const entrance = register && !mobile ? null : animateView(content.current);
    return () => {
      entrance?.cancel();
      const animation = exit.current;
      exit.current = null;
      animation?.cancel();
      closing.current = false;
      register?.(id.current, false);
      if (root) root.inert = !!wasInert;
      document.body.style.overflow = overflow;
      queueMicrotask(() => {
        if (previousFocus instanceof HTMLElement && previousFocus.isConnected) previousFocus.focus({ preventScroll: true });
      });
    };
  }, [open, register, mobile]);

  useEffect(() => {
    if (!open) return;
    const keydown = (event: KeyboardEvent) => {
      if (event.defaultPrevented || document.querySelector('.qorc-screen-overlay[data-state="open"]')) return;
      if (event.key === 'Escape') { event.preventDefault(); goBack(); return; }
      if (event.key !== 'Tab' || (register && !mobile)) return;
      const items = Array.from(content.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), [tabindex="0"]') ?? [])
        .filter(element => element.getClientRects().length > 0);
      if (!items.length) return;
      const index = items.indexOf(document.activeElement as HTMLElement);
      if (index < 0 || (event.shiftKey ? index === 0 : index === items.length - 1)) {
        event.preventDefault();
        items[event.shiftKey ? items.length - 1 : 0].focus();
      }
    };
    document.addEventListener('keydown', keydown);
    return () => document.removeEventListener('keydown', keydown);
  }, [open, goBack, mobile, register]);

  if (!open) return null;
  const host = register ? document.querySelector('.qorc-main-pane') : null;
  return createPortal(
    <section ref={content} role="region" aria-labelledby={labelledBy} aria-describedby={describedBy}
      onClickCapture={event => {
        if (!(event.target instanceof Element) || !event.target.closest('[data-screen-back]')) return;
        event.preventDefault();
        event.stopPropagation();
        goBack();
      }}
      className={`qorc-standalone-screen${host ? '' : ' is-root-screen'} ${className}`}>
      {children}
    </section>, host ?? document.body,
  );
}
