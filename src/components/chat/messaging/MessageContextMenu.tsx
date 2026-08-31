import React, { useLayoutEffect, useRef, useState } from 'react';
import { Pencil, Reply, Trash2, Download, SmilePlus, Copy } from 'lucide-react';
import { createPortal } from 'react-dom';

interface MessageAnchorRect {
    readonly top: number;
    readonly right: number;
    readonly bottom: number;
    readonly left: number;
}

interface MenuPosition {
    readonly top: number;
    readonly left: number;
}

interface MessageContextMenuProps {
    anchorRect: MessageAnchorRect;
    triggerId: string;
    isCurrentUser: boolean;
    onClose: () => void;
    onCopy?: () => void;
    onEdit?: () => void;
    onReply?: () => void;
    onDelete?: () => void;
    onReact?: (position: MenuPosition) => void;
    onReactionSelect?: (emoji: string) => void;
    onDownload?: () => void;
    canEdit: boolean;
    canDelete: boolean;
    isFile: boolean;
}

export const MessageContextMenu: React.FC<MessageContextMenuProps> = ({
    anchorRect,
    triggerId,
    isCurrentUser,
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
    const [position, setPosition] = useState<MenuPosition | null>(null);

    const QUICK_REACTIONS = ['👍', '👎', '❤️', '😂', '😮', '😢'];

    useLayoutEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            const target = event.target instanceof Element ? event.target : null;
            const targetTriggerId = target?.closest('[data-emoji-trigger]')?.getAttribute('data-emoji-trigger');
            if (event.button === 2 && targetTriggerId === triggerId) return;
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
    }, [onClose, triggerId]);

    useLayoutEffect(() => {
        const menu = menuRef.current;
        if (!menu) return;

        const margin = 8;
        const gap = 6;
        const menuRect = menu.getBoundingClientRect();
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;
        const clamp = (value: number, minimum: number, maximum: number) => (
            Math.min(Math.max(value, minimum), Math.max(minimum, maximum))
        );
        const alignedLeft = isCurrentUser
            ? anchorRect.right - menuRect.width
            : anchorRect.left;
        const belowTop = anchorRect.bottom + gap;
        const preferredSideLeft = isCurrentUser
            ? anchorRect.left - menuRect.width - gap
            : anchorRect.right + gap;
        const alternateSideLeft = isCurrentUser
            ? anchorRect.right + gap
            : anchorRect.left - menuRect.width - gap;
        const sideFits = (left: number) => (
            left >= margin && left + menuRect.width <= viewportWidth - margin
        );

        let top: number;
        let left: number;
        if (belowTop + menuRect.height <= viewportHeight - margin) {
            top = belowTop;
            left = alignedLeft;
        } else if (sideFits(preferredSideLeft)) {
            top = anchorRect.top;
            left = preferredSideLeft;
        } else if (sideFits(alternateSideLeft)) {
            top = anchorRect.top;
            left = alternateSideLeft;
        } else {
            top = anchorRect.top - menuRect.height - gap;
            left = alignedLeft;
        }

        setPosition({
            top: Math.round(clamp(top, margin, viewportHeight - menuRect.height - margin)),
            left: Math.round(clamp(left, margin, viewportWidth - menuRect.width - margin)),
        });
    }, [anchorRect, isCurrentUser]);

    return createPortal(
        <div
            ref={menuRef}
            className="qorc-message-context-menu fixed z-50 rounded-xl overflow-hidden shadow-xl flex flex-col"
            style={{
                top: position?.top ?? 0,
                left: position?.left ?? 0,
                visibility: position ? 'visible' : 'hidden',
            }}
        >
            {(onReactionSelect || onReact) && (
            <div className="qorc-message-context-reactions">
                {QUICK_REACTIONS.map((emoji) => (
                    <button
                        key={emoji}
                        type="button"
                        onClick={(e) => {
                            e.stopPropagation();
                            onReactionSelect?.(emoji);
                            onClose();
                        }}
                        className="qorc-message-context-reaction"
                        aria-label={`React with ${emoji}`}
                    >
                        {emoji}
                    </button>
                ))}
                <button
                    type="button"
                        onClick={(e) => {
                            e.stopPropagation();
                            onReact?.(position ?? { top: anchorRect.top, left: anchorRect.left });
                            onClose();
                        }}
                    className="qorc-message-context-more-reactions"
                    title="Add Reaction"
                    aria-label="Add reaction"
                >
                    <SmilePlus className="w-5 h-5" />
                </button>
            </div>
            )}

            <div className="qorc-message-context-actions">
                {onReply && (
                <button
                    type="button"
                    onClick={(e) => { e.stopPropagation(); onReply?.(); onClose(); }}
                    className="qorc-message-context-action"
                    title="Reply"
                    aria-label="Reply"
                >
                    <Reply className="w-5 h-5" />
                </button>
                )}

                {onCopy && (
                    <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); onCopy?.(); onClose(); }}
                        className="qorc-message-context-action"
                        title="Copy"
                        aria-label="Copy"
                    >
                        <Copy className="w-5 h-5" />
                    </button>
                )}

                {canEdit && (
                    <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); onEdit?.(); onClose(); }}
                        className="qorc-message-context-action"
                        title="Edit"
                        aria-label="Edit"
                    >
                        <Pencil className="w-5 h-5" />
                    </button>
                )}

                {isFile && (
                    <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); onDownload?.(); onClose(); }}
                        className="qorc-message-context-action"
                        title="Download"
                        aria-label="Download"
                    >
                        <Download className="w-5 h-5" />
                    </button>
                )}

                {canDelete && (
                    <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); onDelete?.(); onClose(); }}
                        className="qorc-message-context-action qorc-message-context-action--danger"
                        title="Delete"
                        aria-label="Delete"
                    >
                        <Trash2 className="w-5 h-5" />
                    </button>
                )}
            </div>
        </div>,
        document.body
    );
};
