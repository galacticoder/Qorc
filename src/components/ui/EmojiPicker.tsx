import React, { useState, useRef, useEffect } from 'react';
import { getEmojiCategories, type EmojiCategory } from '../../lib/system-emoji';

interface EmojiPickerProps {
  onEmojiSelect: (emoji: string) => void;
  onClose: () => void;
  className?: string;
  triggerId?: string;
}

export function EmojiPicker({ onEmojiSelect, onClose, className = '', triggerId }: EmojiPickerProps) {
  const [categories] = useState<EmojiCategory[]>(getEmojiCategories());
  const [activeCategory, setActiveCategory] = useState(0);
  const [position, setPosition] = useState({ top: 0, left: 0 });
  const scrollRef = useRef<HTMLDivElement>(null);
  const pickerRef = useRef<HTMLDivElement>(null);

  // Position the picker relative to the trigger button
  useEffect(() => {
    if (pickerRef.current) {
      const trigger = triggerId
        ? document.querySelector(`[data-emoji-trigger="${triggerId}"]`) as HTMLElement
        : document.querySelector('[data-emoji-add-button]') as HTMLElement;
      if (trigger) {
        const triggerRect = trigger.getBoundingClientRect();
        const pickerWidth = 280;
        const pickerHeight = 320;

        // Calculate position to keep picker on screen and avoid overlapping message
        // Find the message container to get better positioning
        const messageContainer = trigger.closest('.mb-4') as HTMLElement;
        const messageRect = messageContainer ? messageContainer.getBoundingClientRect() : triggerRect;
        
        // Detect if this is a current user message (right side) or other user message (left side)
        // Current user messages have flex-row-reverse class
        const isCurrentUserMessage = messageContainer?.classList.contains('flex-row-reverse') || false;
        
        let left: number;
        let top = triggerRect.top - 10; // Position just slightly above the trigger button
        
        if (isCurrentUserMessage) {
          // For current user (right side): prefer left positioning
          left = triggerRect.left - pickerWidth - 8;
          // If going off left edge, position to the right instead
          if (left < 16) {
            left = triggerRect.right + 8;
          }
        } else {
          // For other users (left side): prefer right positioning  
          left = triggerRect.right + 8;
          // If going off right edge, position to the left instead
          if (left + pickerWidth > window.innerWidth - 16) {
            left = triggerRect.left - pickerWidth - 8;
          }
        }

        // Final fallback - ensure it's always on screen
        if (left < 16) {
          left = 16; // Minimum left margin
        }

        // Adjust if going off right edge
        if (left + pickerWidth > window.innerWidth) {
          left = window.innerWidth - pickerWidth - 16;
        }

        // If going off top, position below the trigger button instead
        if (top < 16) {
          top = triggerRect.bottom + 8; // Position below button
        }

        // If going off bottom, move up
        if (top + pickerHeight > window.innerHeight) {
          top = window.innerHeight - pickerHeight - 16;
        }

        setPosition({ top, left });
      }
    }
  }, [triggerId]);

  // Close on outside click
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (pickerRef.current && !pickerRef.current.contains(event.target as Node)) {
        onClose();
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [onClose]);

  // Close on escape key
  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        onClose();
      }
    }

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  const handleEmojiClick = (emoji: string) => {
    onEmojiSelect(emoji);
    onClose();
  };

  return (
    <div
      ref={pickerRef}
      className={`emoji-picker ${className}`}
      style={{
        position: 'fixed',
        top: position.top,
        left: position.left,
        width: '280px',
        height: '320px',
        backgroundColor: 'var(--color-surface)',
        border: '1px solid var(--color-border)',
        borderRadius: '8px',
        boxShadow: 'var(--shadow-elevation-medium)',
        zIndex: 1000,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden'
      }}
    >
      {/* Category tabs */}
      <div
        style={{
          display: 'flex',
          borderBottom: '1px solid var(--color-border)',
          backgroundColor: 'var(--color-muted-panel)'
        }}
      >
        {categories.map((category, index) => (
          <button
            key={category.name}
            onClick={() => setActiveCategory(index)}
            style={{
              flex: 1,
              padding: '8px 4px',
              border: 'none',
              backgroundColor: activeCategory === index ? 'var(--color-surface)' : 'transparent',
              color: activeCategory === index ? 'var(--color-text-primary)' : 'var(--color-text-secondary)',
              fontSize: '11px',
              fontWeight: activeCategory === index ? '600' : '400',
              cursor: 'pointer',
              borderBottom: activeCategory === index ? '2px solid var(--color-accent-primary)' : '2px solid transparent',
              transition: 'all 0.2s ease'
            }}
            onMouseEnter={(e) => {
              if (activeCategory !== index) {
                e.currentTarget.style.backgroundColor = 'var(--color-hover)';
              }
            }}
            onMouseLeave={(e) => {
              if (activeCategory !== index) {
                e.currentTarget.style.backgroundColor = 'transparent';
              }
            }}
          >
            {category.name}
          </button>
        ))}
      </div>

      {/* Emoji grid */}
      <div
        ref={scrollRef}
        style={{
          flex: 1,
          padding: '12px',
          overflowY: 'auto',
          overflowX: 'hidden'
        }}
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(8, 1fr)',
            gap: '4px'
          }}
        >
          {categories[activeCategory]?.emojis.map((emoji, index) => (
            <button
              key={`${emoji}-${index}`}
              onClick={() => handleEmojiClick(emoji)}
              style={{
                width: '28px',
                height: '28px',
                border: 'none',
                backgroundColor: 'transparent',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '18px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                transition: 'background-color 0.2s ease'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--color-hover)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'transparent';
              }}
              title={`React with ${emoji}`}
            >
              {emoji}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
