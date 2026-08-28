/**
 * Displays a Rust rendered private message image
 */

import React, { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { nativeMessageContent } from '../../../lib/tauri-bindings';

export interface SecureCanvasTextProps {
    messageId: string;
    contentVersion?: string;
    maxWidth?: number;
    fontSize?: number;
    color?: string;
    singleLine?: boolean;
    maxLines?: number;
    fontFamily?: string;
    isCurrentUser?: boolean;
    onCopy?: () => void;
    onRendered?: () => void;
    onContextMenu?: (e: React.MouseEvent) => void;
}

export const SecureCanvasText = memo(function SecureCanvasText({
    messageId,
    contentVersion,
    maxWidth = 400,
    fontSize = 14,
    color = 'inherit',
    singleLine = false,
    maxLines = 0,
    onCopy,
    onRendered,
    onContextMenu,
}: SecureCanvasTextProps) {
    const containerRef = useRef<HTMLDivElement>(null);
    const initialDimensions = useMemo(
        () => ({ width: 40, height: Math.ceil(fontSize * 1.4) }),
        [fontSize],
    );
    const [renderedFrame, setRenderedFrame] = useState(() => ({
        ...initialDimensions,
        imageSource: null as string | null,
    }));
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
            setRenderedFrame((current) => current.imageSource === null
                ? current
                : { ...current, imageSource: null });
            return;
        }
        let cancelled = false;
        const render = async (): Promise<void> => {
            for (let attempt = 0; attempt < 5 && !cancelled; attempt += 1) {
                try {
                    const rendered = await nativeMessageContent.render(
                        messageId,
                        Math.max(20, Math.min(800, Math.floor(maxWidth))),
                        Math.max(10, Math.min(32, fontSize)),
                        '#ffffff',
                        singleLine,
                        Math.max(0, Math.min(8, Math.floor(maxLines))),
                    );
                    if (cancelled) return;
                    const nextImageSource = `data:image/png;base64,${rendered.pngBase64}`;
                    const decodedMask = new Image();
                    decodedMask.src = nextImageSource;
                    try {
                        await decodedMask.decode();
                    } catch { }
                    if (cancelled) return;
                    setRenderedFrame({
                        width: rendered.width,
                        height: rendered.height,
                        imageSource: nextImageSource,
                    });
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
        };
    }, [isVisible, messageId, contentVersion, maxWidth, fontSize, singleLine, maxLines]);

    const { width, height, imageSource } = renderedFrame;

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
                width,
                height,
                position: 'relative',
                display: 'block',
                overflow: 'hidden',
            }}
            onKeyDown={handleKeyDown}
            onContextMenu={onContextMenu}
            tabIndex={0}
        >
            {imageSource ? (
                <span
                    aria-hidden="true"
                    style={{
                        display: 'block',
                        width: '100%',
                        height: '100%',
                        backgroundColor: color === 'inherit' ? 'currentColor' : color,
                        maskImage: `url("${imageSource}")`,
                        maskPosition: 'center',
                        maskRepeat: 'no-repeat',
                        maskSize: '100% 100%',
                        WebkitMaskImage: `url("${imageSource}")`,
                        WebkitMaskPosition: 'center',
                        WebkitMaskRepeat: 'no-repeat',
                        WebkitMaskSize: '100% 100%',
                        userSelect: 'none',
                    }}
                />
            ) : null}
        </div>
    );
});
