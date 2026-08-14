/**
 * Displays a Rust rendered private message image
 */

import React, { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { nativeMessageContent } from '../../../lib/tauri-bindings';

export interface SecureCanvasTextProps {
    messageId: string;
    maxWidth?: number;
    fontSize?: number;
    color?: string;
    fontFamily?: string;
    isCurrentUser?: boolean;
    onCopy?: () => void;
    onRendered?: () => void;
    onContextMenu?: (e: React.MouseEvent) => void;
}

const cssColorToHex = (
    requestedColor: string,
    element: HTMLElement | null,
    isCurrentUser: boolean,
): string => {
    const fallback = isCurrentUser ? '#ffffff' : '#0f172a';
    if (!element || typeof window === 'undefined') return fallback;
    const probe = document.createElement('span');
    probe.style.position = 'absolute';
    probe.style.visibility = 'hidden';
    probe.style.pointerEvents = 'none';
    probe.style.color = requestedColor === 'inherit' ? 'currentColor' : requestedColor;
    element.appendChild(probe);
    const computed = window.getComputedStyle(probe).color;
    probe.remove();
    const match = computed.match(/^rgba?\(\s*(\d+)\s*[, ]\s*(\d+)\s*[, ]\s*(\d+)/i);
    if (!match) return fallback;
    const toHex = (value: string) => Math.max(0, Math.min(255, Number(value)))
        .toString(16)
        .padStart(2, '0');
    return `#${toHex(match[1])}${toHex(match[2])}${toHex(match[3])}`;
};

export const SecureCanvasText = memo(function SecureCanvasText({
    messageId,
    maxWidth = 400,
    fontSize = 14,
    color = 'inherit',
    isCurrentUser = false,
    onCopy,
    onRendered,
    onContextMenu,
}: SecureCanvasTextProps) {
    const containerRef = useRef<HTMLDivElement>(null);
    const initialDimensions = useMemo(
        () => ({ width: 40, height: Math.ceil(fontSize * 1.4) }),
        [fontSize],
    );
    const [dimensions, setDimensions] = useState(initialDimensions);
    const [imageSource, setImageSource] = useState<string | null>(null);
    const [isVisible, setIsVisible] = useState(false);

    const onRenderedRef = useRef(onRendered);
    useEffect(() => { onRenderedRef.current = onRendered; });

    useEffect(() => {
        const node = containerRef.current;
        if (!node || typeof IntersectionObserver === 'undefined') {
            setIsVisible(true);
            return;
        }
        const observer = new IntersectionObserver(
            (entries) => setIsVisible(entries[0]?.isIntersecting === true),
            { threshold: 0.1, rootMargin: '100px' },
        );
        observer.observe(node);
        return () => observer.disconnect();
    }, []);

    useEffect(() => {
        if (!isVisible) {
            setImageSource(null);
            return;
        }
        let cancelled = false;
        const render = async (): Promise<void> => {
            const resolvedColor = cssColorToHex(color, containerRef.current, isCurrentUser);
            for (let attempt = 0; attempt < 5 && !cancelled; attempt += 1) {
                try {
                    const rendered = await nativeMessageContent.render(
                        messageId,
                        Math.max(20, Math.min(800, Math.floor(maxWidth))),
                        Math.max(10, Math.min(32, fontSize)),
                        resolvedColor,
                    );
                    if (cancelled) return;
                    setDimensions({ width: rendered.width, height: rendered.height });
                    setImageSource(`data:image/png;base64,${rendered.pngBase64}`);
                    onRenderedRef.current?.();
                    return;
                } catch {
                    if (attempt === 4) return;
                    await new Promise((resolve) => window.setTimeout(resolve, 50 * (attempt + 1)));
                }
            }
        };
        void render();
        return () => {
            cancelled = true;
            setImageSource(null);
        };
    }, [isVisible, messageId, maxWidth, fontSize, color, isCurrentUser]);

    const handleCopy = useCallback(async () => {
        await nativeMessageContent.copy(messageId);
        onCopy?.();
    }, [messageId, onCopy]);

    const handleKeyDown = useCallback((event: React.KeyboardEvent) => {
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'c') {
            event.preventDefault();
            void handleCopy().catch(() => { });
        }
    }, [handleCopy]);

    return (
        <div
            ref={containerRef}
            className="secure-canvas-text"
            style={{
                width: dimensions.width,
                height: dimensions.height,
                position: 'relative',
                display: 'block',
                overflow: 'hidden',
            }}
            onKeyDown={handleKeyDown}
            onContextMenu={onContextMenu}
            tabIndex={0}
        >
            {imageSource ? (
                <img
                    src={imageSource}
                    alt=""
                    aria-hidden="true"
                    draggable={false}
                    width={dimensions.width}
                    height={dimensions.height}
                    style={{ display: 'block', width: '100%', height: '100%', userSelect: 'none' }}
                />
            ) : null}
        </div>
    );
});
