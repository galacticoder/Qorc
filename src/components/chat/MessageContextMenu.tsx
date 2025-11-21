import React, { useLayoutEffect, useRef, useState } from 'react';
import { Pencil, Reply, Trash2, Download, SmilePlus } from 'lucide-react';
import { createPortal } from 'react-dom';

interface MessageContextMenuProps {
    x: number;
    y: number;
    onClose: () => void;
    onEdit?: () => void;
    onReply?: () => void;
    onDelete?: () => void;
    onReact?: () => void;
    onDownload?: () => void;
    canEdit: boolean;
    canDelete: boolean;
    isFile: boolean;
}

export const MessageContextMenu: React.FC<MessageContextMenuProps> = ({
    x,
    y,
    onClose,
    onEdit,
    onReply,
    onDelete,
    onReact,
    onDownload,
    canEdit,
    canDelete,
    isFile,
}) => {
    const menuRef = useRef<HTMLDivElement>(null);
    const [position, setPosition] = useState({ top: y, left: x });

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
            className="fixed z-50 min-w-[180px] rounded-xl overflow-hidden shadow-xl border text-card-foreground"
            style={{
                top: position.top,
                left: position.left,
                backgroundColor: 'hsl(var(--card))',
                borderColor: 'hsl(var(--border))',
            }}
        >
            <div className="p-1.5 flex flex-col gap-1">
                {canEdit && (
                    <button
                        onClick={(e) => {
                            e.stopPropagation();
                            onEdit?.();
                            onClose();
                        }}
                        className="flex items-center gap-3 px-3 py-2 text-sm font-medium text-gray-600 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-[#5353ff] hover:text-indigo-600 dark:hover:text-white rounded-lg transition-all duration-200 group w-full text-left"
                    >
                        <Pencil className="w-4 h-4 transition-colors group-hover:text-indigo-600 dark:group-hover:text-white" />
                        Edit
                    </button>
                )}

                <button
                    onClick={(e) => {
                        e.stopPropagation();
                        onReact?.();
                        onClose();
                    }}
                    className="flex items-center gap-3 px-3 py-2 text-sm font-medium text-gray-600 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-[#5353ff] hover:text-indigo-600 dark:hover:text-white rounded-lg transition-all duration-200 group w-full text-left"
                >
                    <SmilePlus className="w-4 h-4 transition-colors group-hover:text-indigo-600 dark:group-hover:text-white" />
                    Reaction
                </button>

                <button
                    onClick={(e) => {
                        e.stopPropagation();
                        onReply?.();
                        onClose();
                    }}
                    className="flex items-center gap-3 px-3 py-2 text-sm font-medium text-gray-600 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-[#5353ff] hover:text-indigo-600 dark:hover:text-white rounded-lg transition-all duration-200 group w-full text-left"
                >
                    <Reply className="w-4 h-4 transition-colors group-hover:text-indigo-600 dark:group-hover:text-white" />
                    Reply
                </button>

                {isFile && (
                    <button
                        onClick={(e) => {
                            e.stopPropagation();
                            onDownload?.();
                            onClose();
                        }}
                        className="flex items-center gap-3 px-3 py-2 text-sm font-medium text-gray-600 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-[#5353ff] hover:text-indigo-600 dark:hover:text-white rounded-lg transition-all duration-200 group w-full text-left"
                    >
                        <Download className="w-4 h-4 transition-colors group-hover:text-indigo-600 dark:group-hover:text-white" />
                        Download
                    </button>
                )}

                {canDelete && (
                    <button
                        onClick={(e) => {
                            e.stopPropagation();
                            onDelete?.();
                            onClose();
                        }}
                        className="flex items-center gap-3 px-3 py-2 text-sm font-medium text-gray-600 dark:text-gray-300 hover:bg-red-50 dark:hover:bg-[#8e2a2a] hover:text-red-600 dark:hover:text-white rounded-lg transition-all duration-200 group w-full text-left"
                    >
                        <Trash2 className="w-4 h-4 transition-colors group-hover:text-red-600 dark:group-hover:text-white" />
                        Delete
                    </button>
                )}
            </div>
        </div>,
        document.body
    );
};
