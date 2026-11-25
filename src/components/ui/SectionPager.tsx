import {
  SECTION_PAGER_FINISH_COMPLETE_TIMEOUT_MS,
  SECTION_PAGER_MATH_MAX_MINIMUM,
} from '../../lib/constants';
import React, { useCallback, useContext, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { SectionNavigationContext } from '../../lib/ui/section-navigation';

export type AppSection = 'chats' | 'calls' | 'settings';
const sections: readonly AppSection[] = ['chats', 'calls', 'settings'];
const idle = { phase: 'idle', offset: 0, target: null } as const;
type Motion = { phase: 'idle' | 'dragging' | 'settling'; offset: number; target: AppSection | null };
type Gesture = { id: number; x: number; y: number; width: number; horizontal: boolean; lastX: number; lastTime: number; velocity: number };

interface SectionPagerProps {
  activeTab: AppSection;
  mobile: boolean;
  swipeEnabled?: boolean;
  onTabChange: (tab: AppSection) => void;
  panels: Record<AppSection, React.ReactNode>;
}

export function SectionPager({ activeTab, mobile, swipeEnabled = true, onTabChange, panels }: SectionPagerProps) {
  const [motion, setMotion] = useState<Motion>(idle);
  const motionRef = useRef<Motion>(idle);
  const gesture = useRef<Gesture | null>(null);
  const suppressClick = useRef(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const destination = useRef<AppSection | null>(null);
  const onTabChangeRef = useRef(onTabChange);
  onTabChangeRef.current = onTabChange;
  const activeIndex = sections.indexOf(activeTab);
  const reportNavigationMotion = useContext(SectionNavigationContext);
  const pageWidth = useRef(0);
  const enabled = mobile && swipeEnabled;

  const update = useCallback((next: Motion) => {
    motionRef.current = next;
    setMotion(next);
    reportNavigationMotion?.(next.phase === 'idle' ? null : { index: activeIndex - next.offset / (pageWidth.current || 1), phase: next.phase });
  }, [activeIndex, reportNavigationMotion]);
  const clearTimer = useCallback(() => {
    if (timer.current !== null) clearTimeout(timer.current);
    timer.current = null;
  }, []);
  const reset = useCallback(() => {
    clearTimer();
    gesture.current = null;
    destination.current = null;
    update(idle);
  }, [clearTimer, update]);
  useLayoutEffect(reset, [activeTab, enabled, reset]);
  useEffect(() => {
    window.addEventListener('resize', reset);
    return () => { window.removeEventListener('resize', reset); clearTimer(); };
  }, [clearTimer, reset]);

  const complete = useCallback(() => {
    if (motionRef.current.phase !== 'settling') return;
    const next = destination.current;
    reset();
    if (next) onTabChangeRef.current(next);
  }, [reset]);
  const finish = (event: React.PointerEvent, cancelled = false) => {
    const current = gesture.current;
    if (!current || event.pointerId !== current.id) return;
    gesture.current = null;
    if (!current.horizontal) return;
    if (event.currentTarget.hasPointerCapture(current.id)) event.currentTarget.releasePointerCapture(current.id);
    const now = event.timeStamp || performance.now();
    const offset = motionRef.current.offset;
    const velocity = now - current.lastTime <= 100 ? current.velocity : 0;
    const commit = !cancelled && (Math.abs(offset) >= Math.min(current.width * .25, 112) ||
      (Math.abs(offset) >= 24 && Math.sign(velocity) === Math.sign(offset) && Math.abs(velocity) >= .5));
    destination.current = commit ? motionRef.current.target : null;
    update({ ...motionRef.current, phase: 'settling', offset: commit ? Math.sign(offset) * current.width : 0 });
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) complete();
    else timer.current = setTimeout(complete, SECTION_PAGER_FINISH_COMPLETE_TIMEOUT_MS);
  };

  return (
    <div
      className={`qorc-section-pager${enabled ? ' can-swipe' : ''}${motion.phase === 'settling' ? ' is-settling' : ''}`}
      data-section-active={activeTab}
      data-section-motion={motion.phase}
      onPointerDown={event => {
        if (motionRef.current.phase !== 'idle' || !event.isPrimary || event.button !== 0) return;
        suppressClick.current = false;
        if (!enabled) return;
        if (!event.currentTarget.contains(event.target as Node)) return;
        if ((event.target as Element).closest('input, textarea, select, [contenteditable="true"], [role="slider"], [role="switch"], [role="dialog"], [data-no-section-swipe], .qorc-unblock-overlay, .qorc-conversation-swipe.is-open')) return;
        const width = event.currentTarget.getBoundingClientRect().width;
        if (width <= 0) return;
        pageWidth.current = width;
        gesture.current = { id: event.pointerId, x: event.clientX, y: event.clientY, width, horizontal: false, lastX: event.clientX, lastTime: event.timeStamp || performance.now(), velocity: 0 };
      }}
      onPointerMove={event => {
        const current = gesture.current;
        if (!current || current.id !== event.pointerId) return;
        const dx = event.clientX - current.x, dy = event.clientY - current.y;
        if (!current.horizontal) {
          if (Math.max(Math.abs(dx), Math.abs(dy)) < SECTION_PAGER_MATH_MAX_MINIMUM) return;
          if (Math.abs(dy) >= Math.abs(dx)) { gesture.current = null; return; }
          
          if (dx > 0 && (event.target as Element).closest('.qorc-conversation-swipe')) { gesture.current = null; return; }
          if (!sections[activeIndex - Math.sign(dx)]) {
            suppressClick.current = true;
            gesture.current = null;
            event.preventDefault();
            return;
          }
          current.horizontal = true;
          suppressClick.current = true;
          event.currentTarget.setPointerCapture(event.pointerId);
        }
        event.preventDefault();
        const now = event.timeStamp || performance.now();
        if (now > current.lastTime) current.velocity = (event.clientX - current.lastX) / (now - current.lastTime);
        current.lastTime = now;
        current.lastX = event.clientX;
        const target = sections[activeIndex - Math.sign(dx)];
        const offset = target ? Math.sign(dx) * Math.min(Math.abs(dx), current.width) : 0;
        update({ phase: 'dragging', offset, target: target ?? null });
      }}
      onPointerUp={event => finish(event)}
      onPointerCancel={event => finish(event, true)}
      onLostPointerCapture={event => {
        
        if (event.target === event.currentTarget && gesture.current?.horizontal) finish(event, true);
      }}
      onClickCapture={event => {
        const suppress = suppressClick.current && event.detail !== 0;
        suppressClick.current = false;
        if (suppress) { event.preventDefault(); event.stopPropagation(); }
      }}
      onTransitionEnd={event => {
        if (event.propertyName === 'transform' && (event.target as HTMLElement).dataset.sectionPage === activeTab) complete();
      }}
    >
      {sections.map((tab, index) => {
        const active = tab === activeTab;
        const visible = active || tab === motion.target;
        return (
          <div
            key={tab}
            data-section-page={tab}
            className="qorc-section-page"
            hidden={!visible}
            inert={!active}
            aria-hidden={!active}
            style={{ transform: mobile && motion.phase !== 'idle' ? `translate3d(calc(${index - activeIndex} * 100% + ${motion.offset}px), 0, 0)` : undefined }}
          >
            {(visible || tab === 'chats') ? panels[tab] : null}
          </div>
        );
      })}
    </div>
  );
}
