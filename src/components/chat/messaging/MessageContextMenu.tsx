import React, { useLayoutEffect, useRef, useState } from 'react';
import { Pencil, Reply, Trash2, Download, SmilePlus, Copy } from 'lucide-react';
import { createPortal } from 'react-dom';

interface MessageContextMenuProps {
    x: number;
    y: number;
    onClose: () => void;
    onCopy?: () => void;
    onEdit?: () => void;
    onReply?: () => void;
    onDelete?: () => void;
    onReact?: () => void;
    onReactionSelect?: (emoji: string) => void;
    onDownload?: () => void;
    canEdit: boolean;
    canDelete: boolean;
    isFile: boolean;
}

export const MessageContextMenu: React.FC<MessageContextMenuProps> = ({
    x,
    y,
    onClose,
    onCopy,
    onEdit,
    onReply,
    onDelete,
    onReact,
    onReactionSelect,
    onDownload,
    canEdit,
    canDelete,
    isFile,
}) => {
    const menuRef = useRef<HTMLDivElement>(null);
    const [position, setPosition] = useState({ top: y, left: x });

    const QUICK_REACTIONS = ['👍', '👎', '❤️', '😂', '😮', '😢'];

    useLayoutEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
                onClose();
            }
        };

        const handleScroll = () => {
            onClose();
        };

        document.addEventListener('mousedown', handleClickOutside);
        window.addEventListener('scroll', handleScroll, true);
        window.addEventListener('resize', handleScroll);

        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
            window.removeEventListener('scroll', handleScroll, true);
            window.removeEventListener('resize', handleScroll);
        };
    }, [onClose]);

    useLayoutEffect(() => {
        if (menuRef.current) {
            const rect = menuRef.current.getBoundingClientRect();
            const viewportWidth = window.innerWidth;
            const viewportHeight = window.innerHeight;

            let newTop = y;
            let newLeft = x;

            // Check right edge
            if (x + rect.width > viewportWidth) {
                newLeft = x - rect.width;
            }

            // Check bottom edge
            if (y + rect.height > viewportHeight) {
                newTop = y - rect.height;
            }

            setPosition({ top: newTop, left: newLeft });
        }
    }, [x, y]);

    return createPortal(
        <div
            ref={menuRef}
            className="fixed z-50 min-w-[200px] rounded-xl overflow-hidden shadow-xl border text-card-foreground flex flex-col"
            style={{
                top: position.top,
                left: position.left,
                backgroundColor: 'hsl(var(--card))',
                borderColor: 'hsl(var(--border))',
                animation: 'in 0.1s ease-out'
            }}
        >
            {/* Reaction Strip */}
            <div className="flex items-center justify-between p-2 bg-muted/30 border-b border-border/50 gap-1">
                {QUICK_REACTIONS.map((emoji) => (
                    <button
                        key={emoji}
                        onClick={(e) => {
                            e.stopPropagation();
                            onReactionSelect?.(emoji);
                            onClose();
                        }}
                        className="p-1.5 hover:bg-background rounded-full transition-transform hover:scale-125 focus:outline-none text-lg leading-none"
                    >
                        {emoji}
                    </button>
                ))}
                <div className="w-px h-6 bg-gray-300 mx-1" />
                <button
                    onClick={(e) => {
                        e.stopPropagation();
                        onReact?.();
                        onClose();
                    }}
                    className="p-1.5 hover:bg-background rounded-full transition-colors text-muted-foreground hover:text-foreground"
                    title="Add Reaction"
                >
                    <SmilePlus className="w-5 h-5" />
                </button>
            </div>

            {/* Action Bar */}
            <div className="flex items-center justify-around p-2">
                <button
                    onClick={(e) => { e.stopPropagation(); onReply?.(); onClose(); }}
                    className="p-2 hover:bg-muted rounded-lg transition-colors text-muted-foreground hover:text-foreground group"
                    title="Reply"
                >
                    <Reply className="w-5 h-5 group-hover:text-indigo-500" />
                </button>

                {onCopy && (
                    <>
                        <div className="w-px h-5 bg-gray-300" />
                        <button
                            onClick={(e) => { e.stopPropagation(); onCopy?.(); onClose(); }}
                            className="p-2 hover:bg-muted rounded-lg transition-colors text-muted-foreground hover:text-foreground group"
                            title="Copy"
                        >
                            <Copy className="w-5 h-5 group-hover:text-indigo-500" />
                        </button>
                    </>
                )}

                {canEdit && (
                    <>
                        <div className="w-px h-5 bg-gray-300" />
                        <button
                            onClick={(e) => { e.stopPropagation(); onEdit?.(); onClose(); }}
                            className="p-2 hover:bg-muted rounded-lg transition-colors text-muted-foreground hover:text-foreground group"
                            title="Edit"
                        >
                            <Pencil className="w-5 h-5 group-hover:text-indigo-500" />
                        </button>
                    </>
                )}

                {isFile && (
                    <>
                        <div className="w-px h-5 bg-gray-300" />
                        <button
                            onClick={(e) => { e.stopPropagation(); onDownload?.(); onClose(); }}
                            className="p-2 hover:bg-muted rounded-lg transition-colors text-muted-foreground hover:text-foreground group"
                            title="Download"
                        >
                            <Download className="w-5 h-5 group-hover:text-indigo-500" />
                        </button>
                    </>
                )}

                {canDelete && (
                    <>
                        <div className="w-px h-5 bg-gray-300" />
                        <button
                            onClick={(e) => { e.stopPropagation(); onDelete?.(); onClose(); }}
                            className="p-2 hover:bg-muted rounded-lg transition-colors text-muted-foreground hover:text-foreground group"
                            title="Delete"
                        >
                            <Trash2 className="w-5 h-5 group-hover:text-red-600" />
                        </button>
                    </>
                )}
            </div>
        </div>,
        document.body
    );
};
