import React, { useState, useRef, useEffect, useCallback } from 'react';
import { getSystemEmojis, searchEmojis } from '../../lib/system-emoji';
import type { SecureDB } from '../../lib/secureDB';

interface EmojiPickerProps {
  onEmojiSelect: (emoji: string) => void;
  onClose: () => void;
  className?: string;
  triggerId?: string;
  isCurrentUser?: boolean;
  secureDB?: SecureDB;
}

export function EmojiPicker({ onEmojiSelect, onClose, className = '', triggerId, isCurrentUser = false, secureDB }: EmojiPickerProps) {
  const [allEmojis, setAllEmojis] = useState<string[]>([]);
  const [filteredEmojis, setFilteredEmojis] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [position, setPosition] = useState({ top: -9999, left: -9999 });
  const [isPositioned, setIsPositioned] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const pickerRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let mounted = true;
    getSystemEmojis(secureDB).then(emojis => {
      if (mounted) {
        setAllEmojis(emojis);
        setFilteredEmojis(emojis);
      }
    }).catch(error => {
      console.error('[EmojiPicker] Failed to load emojis:', error);
      if (mounted) {
        const fallback = ['😀', '😃', '😄', '😁', '😅', '😂', '🤣', '😊', '😍', '😎', '👍', '👎', '❤️', '✅', '❌'];
        setAllEmojis(fallback);
        setFilteredEmojis(fallback);
      }
    });
    return () => { mounted = false; };
  }, [secureDB]);

  useEffect(() => {
    if (!searchQuery.trim()) {
      setFilteredEmojis(allEmojis);
    } else {
      try {
        const results = searchEmojis(searchQuery, allEmojis);
        setFilteredEmojis(results);
      } catch {
        setFilteredEmojis(allEmojis);
      }
    }
  }, [searchQuery, allEmojis]);

  useEffect(() => {
    if (isPositioned && searchInputRef.current) {
      searchInputRef.current.focus();
    }
  }, [isPositioned]);

  const calculatePosition = useCallback(() => {
    const trigger = triggerId
      ? document.querySelector(`[data-emoji-trigger="${triggerId}"]`) as HTMLElement
      : document.querySelector('[data-emoji-add-button]') as HTMLElement;

    if (!trigger) {
      const pickerWidth = 280;
      const pickerHeight = 360;
      const left = (window.innerWidth - pickerWidth) / 2;
      const top = (window.innerHeight - pickerHeight) / 2;
      setPosition({ top, left });
      setIsPositioned(true);
      return;
    }

    const triggerRect = trigger.getBoundingClientRect();
    const pickerWidth = 280;
    const pickerHeight = 360;

    const isCurrentUserMessage = isCurrentUser;

    let left: number;
    let top: number;

    top = triggerRect.top - 10;

    if (isCurrentUserMessage) {
      left = triggerRect.left - pickerWidth - 8;
    } else {
      left = triggerRect.right + 8;
    }

    if (left < 16) {
      left = 16;
    }
    if (left + pickerWidth > window.innerWidth - 16) {
      left = window.innerWidth - pickerWidth - 16;
    }

    if (top < 16) {
      top = triggerRect.bottom + 8;
    }
    if (top + pickerHeight > window.innerHeight - 16) {
      top = window.innerHeight - pickerHeight - 16;
    }
    setPosition({ top, left });
    setIsPositioned(true);
  }, [triggerId, isCurrentUser]);

  useEffect(() => {
    const timer = setTimeout(() => {
      calculatePosition();
    }, 10);
    return () => clearTimeout(timer);
  }, [calculatePosition]);

  useEffect(() => {
    let scrollTimeout: ReturnType<typeof setTimeout>;

    const handleScroll = () => {
      clearTimeout(scrollTimeout);
      scrollTimeout = setTimeout(() => {
        calculatePosition();
      }, 16);
    };

    const handleResize = () => {
      calculatePosition();
    };

    window.addEventListener('scroll', handleScroll, true);
    window.addEventListener('resize', handleResize);

    return () => {
      clearTimeout(scrollTimeout);
      window.removeEventListener('scroll', handleScroll, true);
      window.removeEventListener('resize', handleResize);
    };
  }, [calculatePosition]);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (pickerRef.current && !pickerRef.current.contains(event.target as Node)) {
        setTimeout(() => {
          onClose();
        }, 100);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [onClose]);

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

  if (!isPositioned || allEmojis.length === 0) {
    return null;
  }

  return (
    <div
      ref={pickerRef}
      className={`emoji-picker ${className}`}
      style={{
        position: 'fixed',
        top: position.top,
        left: position.left,
        width: '280px',
        height: '360px',
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
      {/* Search input */}
      <div
        style={{
          padding: '8px',
          borderBottom: '1px solid var(--color-border)',
          backgroundColor: 'var(--color-muted-panel)'
        }}
      >
        <input
          ref={searchInputRef}
          type="text"
          placeholder="Search emoji..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          style={{
            width: '100%',
            padding: '8px 12px',
            border: '1px solid var(--color-border)',
            borderRadius: '6px',
            backgroundColor: 'var(--color-surface)',
            color: 'var(--color-text-primary)',
            fontSize: '14px',
            outline: 'none'
          }}
          onFocus={(e) => {
            e.currentTarget.style.borderColor = 'var(--color-accent-primary)';
          }}
          onBlur={(e) => {
            e.currentTarget.style.borderColor = 'var(--color-border)';
          }}
        />
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
        {filteredEmojis.length === 0 ? (
          <div
            style={{
              textAlign: 'center',
              color: 'var(--color-text-secondary)',
              padding: '20px',
              fontSize: '14px'
            }}
          >
            No emojis found
          </div>
        ) : (
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(8, 1fr)',
              gap: '4px'
            }}
          >
            {filteredEmojis.map((emoji, index) => (
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
        )}
      </div>
    </div>
  );
}
