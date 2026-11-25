import {
  CONVERSATION_SWIPE_ROW_ACTION_WIDTH,
  CONVERSATION_SWIPE_ROW_MATH_MAX_MINIMUM,
} from '../../../lib/constants';
import React, { useEffect, useRef, useState } from 'react';
import { useAppBack } from '../../../hooks/useAppBack';

interface ConversationSwipeRowProps {
  enabled: boolean;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  actions: React.ReactNode;
  children: React.ReactNode;
  actionWidth?: number;
  allowButtonSwipes?: boolean;
  popoverSelector?: string;
  className?: string;
}

export function ConversationSwipeRow({ enabled, open, onOpenChange, actions, children, actionWidth = CONVERSATION_SWIPE_ROW_ACTION_WIDTH,
  allowButtonSwipes = false, popoverSelector = '.qorc-conversation-options-popover', className = '' }: ConversationSwipeRowProps) {
  const shellRef = useRef<HTMLDivElement>(null);
  const gesture = useRef<{ id: number; x: number; y: number; start: number; horizontal: boolean } | null>(null);
  const suppressClick = useRef(false);
  const [offset, setOffset] = useState<number | null>(null);
  const reveal = offset ?? (open ? actionWidth : 0);

  useAppBack(enabled && open, () => onOpenChange(false), 10);
  useEffect(() => {
    gesture.current = null;
    suppressClick.current = false;
    setOffset(null);
  }, [enabled, actionWidth]);
  useEffect(() => {
    if (!enabled || !open) return;
    const dismiss = (event: PointerEvent) => {
      const target = event.target;
      if (!(target instanceof Element) || shellRef.current?.contains(target) || target.closest(popoverSelector)) return;
      onOpenChange(false);
    };
    document.addEventListener('pointerdown', dismiss);
    return () => document.removeEventListener('pointerdown', dismiss);
  }, [enabled, open, onOpenChange, popoverSelector]);

  if (!enabled) return <>{children}</>;

  const finish = (event: React.PointerEvent, cancelled = false) => {
    const current = gesture.current;
    if (!current || current.id !== event.pointerId) return;
    gesture.current = null;
    if (current.horizontal) {
      onOpenChange(cancelled ? open : Math.max(0, Math.min(actionWidth, current.start + (event.clientX - current.x))) >= actionWidth / 2);
    }
    setOffset(null);
  };

  return (
    <div
      ref={shellRef}
      className={`qorc-conversation-swipe${open ? ' is-open' : ''}${offset !== null ? ' is-dragging' : ''}${className ? ` ${className}` : ''}`}
      style={{ '--qorc-swipe-action-width': `${actionWidth}px` } as React.CSSProperties}
      onKeyDown={event => {
        const target = event.target as Element;
        const overlay = target.closest('[role="menu"], [role="dialog"]');
        if ((event.key === 'ArrowLeft' || event.key === 'ArrowRight' || event.key === 'Escape') &&
            !(overlay && event.currentTarget.contains(overlay)) && !target.closest('.qorc-conversation-swipe-actions') &&
            (allowButtonSwipes || !target.closest('button'))) {
          event.preventDefault();
          event.stopPropagation();
          onOpenChange(event.key === 'ArrowRight');
        }
      }}
    >
      <div className="qorc-conversation-swipe-actions" inert={!open} aria-hidden={!open}>
        {actions}
      </div>
      <div
        className="qorc-conversation-swipe-content"
        style={{ transform: `translateX(${reveal}px)` }}
        onPointerDown={event => {
          if (!event.isPrimary || event.button !== 0 || (!allowButtonSwipes && (event.target as Element).closest('button'))) return;
          suppressClick.current = false;
          gesture.current = { id: event.pointerId, x: event.clientX, y: event.clientY, start: open ? actionWidth : 0, horizontal: false };
        }}
        onPointerMove={event => {
          const current = gesture.current;
          if (!current || current.id !== event.pointerId) return;
          const dx = event.clientX - current.x;
          const dy = event.clientY - current.y;
          if (!current.horizontal) {
            if (Math.max(Math.abs(dx), Math.abs(dy)) < CONVERSATION_SWIPE_ROW_MATH_MAX_MINIMUM) return;
            if (Math.abs(dy) >= Math.abs(dx)) { gesture.current = null; return; }
            
            if (dx < 0 && !open) { gesture.current = null; return; }
            current.horizontal = true;
            suppressClick.current = true;
            event.currentTarget.setPointerCapture(event.pointerId);
          }
          setOffset(Math.max(0, Math.min(actionWidth, current.start + dx)));
        }}
        onPointerUp={event => finish(event)}
        onPointerCancel={event => finish(event, true)}
        onClickCapture={event => {
          const afterSwipe = suppressClick.current && event.detail !== 0;
          suppressClick.current = false;
          if (afterSwipe || open) {
            event.preventDefault();
            event.stopPropagation();
            if (!afterSwipe) onOpenChange(false);
          }
        }}
      >
        {children}
      </div>
    </div>
  );
}
