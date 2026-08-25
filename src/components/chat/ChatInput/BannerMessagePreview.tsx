import { useCallback, useLayoutEffect, useRef, useState } from 'react';
import { SecureCanvasText } from '../messaging/SecureCanvasText';

interface BannerMessagePreviewProps {
  readonly messageId: string;
  readonly contentVersion?: string;
  readonly maxWidth?: number;
  readonly fontSize?: number;
  readonly color?: string;
  readonly className?: string;
}

export function BannerMessagePreview({
  messageId,
  contentVersion,
  maxWidth = 360,
  fontSize = 11,
  color = 'var(--qor-reply-banner-preview-text)',
  className,
}: BannerMessagePreviewProps) {
  const previewRef = useRef<HTMLDivElement>(null);
  const [truncated, setTruncated] = useState(false);

  const measure = useCallback(() => {
    const host = previewRef.current;
    const preview = host?.querySelector<HTMLElement>('.secure-canvas-text');
    if (!host || !preview) {
      setTruncated(false);
      return;
    }
    const bounds = preview.getBoundingClientRect();
    setTruncated(bounds.width > host.clientWidth + 1 || bounds.height > host.clientHeight + 1);
  }, []);

  useLayoutEffect(() => {
    const host = previewRef.current;
    if (!host || typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(measure);
    observer.observe(host);
    const preview = host.querySelector<HTMLElement>('.secure-canvas-text');
    if (preview) observer.observe(preview);
    const frame = window.requestAnimationFrame(measure);
    return () => {
      window.cancelAnimationFrame(frame);
      observer.disconnect();
    };
  }, [measure, messageId, contentVersion]);

  return (
    <div
      ref={previewRef}
      className={`qor-reply-banner-secure-preview${truncated ? ' is-truncated' : ''}${className ? ` ${className}` : ''}`}
    >
      <SecureCanvasText
        messageId={messageId}
        contentVersion={contentVersion}
        maxWidth={maxWidth}
        fontSize={fontSize}
        color={color}
        onRendered={measure}
      />
    </div>
  );
}
