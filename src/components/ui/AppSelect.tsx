import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react';
import { Check, ChevronDown } from 'lucide-react';
import { Popover, PopoverContent, PopoverTrigger } from './popover';

interface AppSelectProps {
  readonly id?: string;
  readonly className?: string;
  readonly label: string;
  readonly value: string;
  readonly options: readonly { value: string; label: string }[];
  readonly disabled?: boolean;
  readonly onValueChange: (value: string) => void;
}

export function AppSelect({ id, className = '', label, value, options, disabled = false, onValueChange }: AppSelectProps) {
  const [open, setOpen] = useState(false);
  const listId = useId();
  const triggerRef = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const tabbingRef = useRef(false);
  const searchRef = useRef({ text: '', time: 0 });
  const selected = options.find((option) => option.value === value);

  useEffect(() => {
    if (disabled) setOpen(false);
  }, [disabled]);

  const navigate = (event: KeyboardEvent<HTMLDivElement>) => {
    const items = Array.from(listRef.current?.querySelectorAll<HTMLButtonElement>('[role="option"]') ?? []);
    if (!items.length) return;
    const current = items.indexOf(document.activeElement as HTMLButtonElement);
    let next = -1;
    if (event.key === 'ArrowDown') next = (current + 1) % items.length;
    else if (event.key === 'ArrowUp') next = (current - 1 + items.length) % items.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = items.length - 1;
    else if (event.key === 'Tab') {
      tabbingRef.current = true;
      triggerRef.current?.focus();
      setOpen(false);
      return;
    }
    else if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey && event.key !== ' ') {
      const now = Date.now();
      const text = (now - searchRef.current.time < 700 ? searchRef.current.text : '') + event.key.toLowerCase();
      searchRef.current = { text, time: now };
      const query = [...text].every((character) => character === text[0]) ? text[0] : text;
      for (let offset = 1; offset <= items.length; offset++) {
        const index = (current + offset) % items.length;
        if (options[index].label.toLowerCase().startsWith(query)) { next = index; break; }
      }
    }
    if (next >= 0) { event.preventDefault(); items[next].focus(); }
  };

  return (
    <Popover open={open} onOpenChange={(next) => { if (!disabled) setOpen(next); }}>
      <PopoverTrigger asChild>
        <button
          ref={triggerRef}
          id={id}
          type="button"
          className={`qorc-select ${className}`}
          role="combobox"
          aria-label={label}
          aria-haspopup="listbox"
          aria-expanded={open}
          aria-controls={open ? listId : undefined}
          disabled={disabled}
          onKeyDown={(event) => {
            if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); setOpen(true); }
          }}
        >
          <span>{selected?.label ?? label}</span>
          <ChevronDown size={17} aria-hidden="true" />
        </button>
      </PopoverTrigger>
      <PopoverContent
        align="start"
        sideOffset={6}
        className="qorc-select-menu"
        style={{ backgroundColor: 'var(--qorc-select-menu-bg)', color: 'var(--qorc-text)', borderColor: 'var(--qorc-border)' }}
        onOpenAutoFocus={(event) => {
          event.preventDefault();
          tabbingRef.current = false;
          searchRef.current = { text: '', time: 0 };
          const items = listRef.current?.querySelectorAll<HTMLButtonElement>('[role="option"]');
          items?.[Math.max(0, options.findIndex((option) => option.value === value))]?.focus();
        }}
        onCloseAutoFocus={(event) => {
          if (tabbingRef.current) event.preventDefault();
        }}
      >
        <div id={listId} ref={listRef} role="listbox" aria-label={label} onKeyDown={navigate}>
          {options.map((option) => (
            <button
              type="button"
              key={option.value}
              role="option"
              aria-selected={option.value === value}
              tabIndex={-1}
              onClick={() => { onValueChange(option.value); setOpen(false); }}
            >
              <span>{option.label}</span>
              {option.value === value && <Check size={16} aria-hidden="true" />}
            </button>
          ))}
        </div>
      </PopoverContent>
    </Popover>
  );
}
