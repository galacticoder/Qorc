import React, { useState, useRef, useEffect, useCallback } from 'react';
import { getEmojiCategories, type EmojiCategory } from '../../lib/system-emoji';

interface EmojiPickerProps {
  onEmojiSelect: (emoji: string) => void;
  onClose: () => void;
  className?: string;
  triggerId?: string;
  isCurrentUser?: boolean;
}

export function EmojiPicker({ onEmojiSelect, onClose, className = '', triggerId, isCurrentUser = false }: EmojiPickerProps) {
  const [categories, setCategories] = useState<EmojiCategory[]>([]);
  const [activeCategory, setActiveCategory] = useState(0);
  const [position, setPosition] = useState({ top: -9999, left: -9999 }); // Start off-screen to prevent flash
  const [isPositioned, setIsPositioned] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const pickerRef = useRef<HTMLDivElement>(null);
  
  // Load emoji categories asynchronously
  useEffect(() => {
    let mounted = true;
    getEmojiCategories().then(cats => {
      if (mounted) {
        setCategories(cats);
      }
    }).catch(error => {
      console.error('[EmojiPicker] Failed to load emoji categories:', error);
      // Set a minimal fallback
      if (mounted) {
        setCategories([{ name: 'Smileys', emojis: ['😀', '😃', '😄', '😁', '😅', '😂', '🤣', '😊', '😍', '😎'] }]);
      }
    });
    return () => { mounted = false; };
  }, []);

  // Function to calculate and set position
  const calculatePosition = useCallback(() => {
    const trigger = triggerId
      ? document.querySelector(`[data-emoji-trigger="${triggerId}"]`) as HTMLElement
      : document.querySelector('[data-emoji-add-button]') as HTMLElement;
    
    if (!trigger) {
      // Fallback positioning - center the picker on screen
      const pickerWidth = 280;
      const pickerHeight = 320;
      const left = (window.innerWidth - pickerWidth) / 2;
      const top = (window.innerHeight - pickerHeight) / 2;
      setPosition({ top, left });
      setIsPositioned(true);
      return;
    }

    const triggerRect = trigger.getBoundingClientRect();
    const pickerWidth = 280;
    const pickerHeight = 320;

    // Use the isCurrentUser prop for better detection
    const isCurrentUserMessage = isCurrentUser;
    
    let left: number;
    let top: number;
    
    // Position the picker relative to the trigger button
    top = triggerRect.top - 10; // Position just slightly above the trigger button
    
    if (isCurrentUserMessage) {
      // For current user (right side): position to the left of the button
      left = triggerRect.left - pickerWidth - 8;
    } else {
      // For other users (left side): position to the right of the button
      left = triggerRect.right + 8;
    }

    // Ensure the picker stays within screen bounds
    // Adjust horizontal position if going off screen
    if (left < 16) {
      left = 16; // Minimum left margin
    }
    if (left + pickerWidth > window.innerWidth - 16) {
      left = window.innerWidth - pickerWidth - 16; // Maximum right position
    }

    // Adjust vertical position if going off screen
    if (top < 16) {
      top = triggerRect.bottom + 8; // Position below button if too high
    }
    if (top + pickerHeight > window.innerHeight - 16) {
      top = window.innerHeight - pickerHeight - 16; // Position above if too low
    }
    setPosition({ top, left });
    setIsPositioned(true);
  }, [triggerId, isCurrentUser]);

  // Position the picker relative to the trigger button
  useEffect(() => {
    // Add a small delay to ensure the button is rendered and visible
    const timer = setTimeout(() => {
      calculatePosition();
    }, 10);
    
    return () => clearTimeout(timer);
  }, [calculatePosition]);

  // Recalculate position on scroll and resize
  useEffect(() => {
    let scrollTimeout: ReturnType<typeof setTimeout>;
    
    const handleScroll = () => {
      // Debounce scroll events to prevent excessive recalculations
      clearTimeout(scrollTimeout);
      scrollTimeout = setTimeout(() => {
        calculatePosition();
      }, 16); // ~60fps
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

  // Close on outside click
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (pickerRef.current && !pickerRef.current.contains(event.target as Node)) {
        // Add a small delay to prevent immediate closing when button is clicked
        setTimeout(() => {
          onClose();
        }, 100);
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

  // Don't render until positioned and categories are loaded to prevent flash
  if (!isPositioned || categories.length === 0) {
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
