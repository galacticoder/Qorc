/**
 * Renders text onto a canvas element so the DOM never contains actual text
 */

import React, { useEffect, useRef, useCallback, useState, memo, useMemo } from 'react';
import { messageVault } from '../../../lib/security/message-vault';

export interface SecureCanvasTextProps {
    messageId: string;
    maxWidth?: number;
    fontSize?: number;
    color?: string;
    fontFamily?: string;
    isCurrentUser?: boolean;
    onCopy?: () => void;
    onContextMenu?: (e: React.MouseEvent) => void;
}

// Word wrap text for canvas
const wrapText = (ctx: CanvasRenderingContext2D, text: string, maxWidth: number): string[] => {
    const words = text.split(' ');
    const lines: string[] = [];
    let currentLine = '';

    for (const word of words) {
        const testLine = currentLine ? `${currentLine} ${word}` : word;
        const metrics = ctx.measureText(testLine);

        if (metrics.width > maxWidth && currentLine) {
            lines.push(currentLine);
            currentLine = word;
        } else {
            currentLine = testLine;
        }
    }

    if (currentLine) {
        lines.push(currentLine);
    }

    return lines;
};

// Measurement context for synchronous dimension calculation
let measurementCanvas: HTMLCanvasElement | null = null;
let measurementContext: CanvasRenderingContext2D | null = null;

const getMeasurementContext = () => {
    if (typeof document === 'undefined') return null;
    if (!measurementContext) {
        measurementCanvas = document.createElement('canvas');
        measurementContext = measurementCanvas.getContext('2d');
    }
    return measurementContext;
};

// Renders text to a canvas element
export const SecureCanvasText = memo(function SecureCanvasText({
    messageId,
    maxWidth = 400,
    fontSize = 14,
    color = 'inherit',
    fontFamily = 'Inter, system-ui, sans-serif',
    isCurrentUser = false,
    onCopy,
    onContextMenu,
}: SecureCanvasTextProps) {
    const containerRef = useRef<HTMLDivElement>(null);
    const canvasRef = useRef<HTMLCanvasElement>(null);

    // Initial dimension estimation
    const initialDimensions = useMemo(() => {
        return { width: 40, height: fontSize + 8 };
    }, [fontSize]);

    const [dimensions, setDimensions] = useState(initialDimensions);
    const [isVisible, setIsVisible] = useState(false);
    const [selectableText, setSelectableText] = useState('');
    const renderedRef = useRef(false);

    useEffect(() => {
        if (!containerRef.current) return;

        const observer = new IntersectionObserver(
            (entries) => {
                if (entries[0]?.isIntersecting) {
                    setIsVisible(true);
                    observer.disconnect();
                }
            },
            { threshold: 0.1, rootMargin: '100px' }
        );

        observer.observe(containerRef.current);
        return () => observer.disconnect();
    }, []);

    // Render to canvas when visible
    useEffect(() => {
        if (!isVisible || !canvasRef.current || renderedRef.current) return;

        let cancelled = false;

        const renderSecureContent = async () => {
            let plaintext: string | null = null;
            let retries = 0;
            const maxRetries = 10;

            while (!plaintext && retries < maxRetries) {
                plaintext = await messageVault.retrieve(messageId);
                if (plaintext) break;

                if (cancelled) return;

                await new Promise(r => setTimeout(r, 50 * (retries + 1)));
                retries++;
            }

            if (cancelled || !plaintext || !canvasRef.current) {
                return;
            }

            const canvas = canvasRef.current;
            const ctx = canvas.getContext('2d');
            if (!ctx) return;

            // Set font for measurement
            const resolvedColor = color === 'inherit' ? (isCurrentUser ? '#ffffff' : '#e5e5e5') : color;
            ctx.font = `${fontSize}px ${fontFamily}`;

            // Word wrap
            const lines = wrapText(ctx, plaintext, maxWidth - 4);
            const lineHeight = fontSize * 1.4;

            // Calculate dimensions
            let maxLineWidth = 0;
            for (const line of lines) {
                const metrics = ctx.measureText(line);
                maxLineWidth = Math.max(maxLineWidth, metrics.width);
            }

            const textWidth = Math.ceil(Math.max(maxLineWidth + 4, 20));
            const textHeight = Math.ceil(Math.max(lines.length * lineHeight + 4, fontSize + 4));

            // Update dimensions
            setDimensions({ width: textWidth, height: textHeight });

            // Set canvas size
            const dpr = window.devicePixelRatio || 1;
            canvas.width = textWidth * dpr;
            canvas.height = textHeight * dpr;
            canvas.style.width = `${textWidth}px`;
            canvas.style.height = `${textHeight}px`;
            ctx.scale(dpr, dpr);

            // Clear and draw
            ctx.clearRect(0, 0, textWidth, textHeight);
            ctx.font = `${fontSize}px ${fontFamily}`;
            ctx.fillStyle = resolvedColor;
            ctx.textBaseline = 'top';

            // Draw each line
            lines.forEach((line, i) => {
                ctx.fillText(line, 2, 2 + i * lineHeight);
            });

            // Store text for selection overlay
            setSelectableText(plaintext);

            renderedRef.current = true;

            // @ts-ignore
            plaintext = null;
        };

        renderSecureContent();

        return () => {
            cancelled = true;
        };
    }, [isVisible, messageId, maxWidth, fontSize, color, fontFamily, isCurrentUser]);

    // Handle copy
    const handleCopy = useCallback(async () => {
        const selection = window.getSelection();
        if (selection && selection.toString()) {
            return;
        }

        // Copy full content from vault
        const content = await messageVault.retrieve(messageId);
        if (content) {
            await navigator.clipboard.writeText(content);
            onCopy?.();
        }
    }, [messageId, onCopy]);

    // Keyboard shortcuts
    const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'c') {
            handleCopy();
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
            <canvas
                ref={canvasRef}
                style={{
                    display: 'block',
                    width: '100%',
                    height: '100%',
                }}
            />
            {/* Transparent overlay */}
            {selectableText && (
                <div
                    style={{
                        position: 'absolute',
                        top: 0,
                        left: 0,
                        width: dimensions.width,
                        height: dimensions.height,
                        color: 'transparent',
                        fontSize: fontSize,
                        fontFamily: fontFamily,
                        lineHeight: `${fontSize * 1.4}px`,
                        padding: '2px',
                        userSelect: 'text',
                        cursor: 'text',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word',
                        overflow: 'hidden',
                    }}
                >
                    {selectableText}
                </div>
            )}
        </div>
    );
});

export default SecureCanvasText;
