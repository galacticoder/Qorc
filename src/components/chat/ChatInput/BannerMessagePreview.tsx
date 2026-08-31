import { useCallback, useLayoutEffect, useRef, useState } from 'react';
import { SecureCanvasText } from '../messaging/SecureCanvasText';

interface BannerMessagePreviewProps {
  readonly messageId: string;
  readonly contentVersion?: string;
  readonly maxWidth?: number;
  readonly fontSize?: number;
  readonly color?: string;
  readonly className?: string;
  readonly maxLines?: number;
}

export function BannerMessagePreview({
  messageId,
  contentVersion,
  maxWidth = 800,
  fontSize = 11,
  color = 'var(--qorc-reply-banner-preview-text)',
  className,
  maxLines = 1,
}: BannerMessagePreviewProps) {
  const previewRef = useRef<HTMLDivElement>(null);
  const resizeTimerRef = useRef<number | null>(null);
  const [renderWidth, setRenderWidth] = useState(maxWidth);

  const measure = useCallback(() => {
    const host = previewRef.current;
    if (!host || host.clientWidth < 20) return;
    const nextWidth = Math.max(20, Math.min(maxWidth, Math.floor(host.clientWidth)));
    setRenderWidth((currentWidth) => currentWidth === nextWidth ? currentWidth : nextWidth);
  }, [maxWidth]);

  const scheduleMeasure = useCallback(() => {
    if (resizeTimerRef.current !== null) window.clearTimeout(resizeTimerRef.current);
    resizeTimerRef.current = window.setTimeout(() => {
      resizeTimerRef.current = null;
      measure();
    }, 100);
  }, [measure]);

  useLayoutEffect(() => {
    const host = previewRef.current;
    if (!host || typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(scheduleMeasure);
    observer.observe(host);
    measure();
    return () => {
      if (resizeTimerRef.current !== null) {
        window.clearTimeout(resizeTimerRef.current);
        resizeTimerRef.current = null;
      }
      observer.disconnect();
    };
  }, [contentVersion, measure, messageId, scheduleMeasure]);

  return (
    <div
      ref={previewRef}
      className={`qorc-reply-banner-secure-preview${className ? ` ${className}` : ''}`}
    >
      <SecureCanvasText
        messageId={messageId}
        contentVersion={contentVersion}
        maxWidth={renderWidth}
        fontSize={fontSize}
        color={color}
        singleLine={maxLines === 1}
        maxLines={maxLines}
      />
    </div>
  );
}
