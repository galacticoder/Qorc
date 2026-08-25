import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { createPortal } from 'react-dom';
import {
  Clock3,
  Flag,
  Leaf,
  Lightbulb,
  LoaderCircle,
  PartyPopper,
  Plane,
  Search,
  Shapes,
  Smile,
  UserRound,
  Utensils,
  X,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import {
  getEmojiCatalog,
  searchEmojiCatalog,
} from '../../lib/system-emoji';
import type {
  EmojiCatalogView,
  EmojiRecord,
} from '../../lib/system-emoji';
import type { SecureDB } from '../../lib/database/secureDB';
import '../../styles/emoji-picker.css';

interface EmojiPickerProps {
  onEmojiSelect: (emoji: string) => void;
  onClose: () => void;
  className?: string;
  triggerId?: string;
  isCurrentUser?: boolean;
  secureDB?: SecureDB;
  origin?: PickerPosition | null;
}

interface PickerPosition {
  top: number;
  left: number;
}

interface PickerSection {
  id: string;
  label: string;
  emojis: readonly EmojiRecord[];
}

const CATEGORY_ICONS: Readonly<Record<string, LucideIcon>> = {
  frequent: Clock3,
  'smileys-and-emotion': Smile,
  'people-and-body': UserRound,
  'animals-and-nature': Leaf,
  'food-and-drink': Utensils,
  'travel-and-places': Plane,
  activities: PartyPopper,
  objects: Lightbulb,
  symbols: Shapes,
  flags: Flag,
};

const GRID_COLUMNS = 6;
const PAGE_SIZE = 160;

function findTrigger(triggerId?: string): HTMLElement | null {
  if (triggerId) {
    for (const element of document.querySelectorAll<HTMLElement>('[data-emoji-trigger]')) {
      if (element.dataset.emojiTrigger === triggerId) return element;
    }
  }
  return document.querySelector<HTMLElement>('[data-emoji-add-button]');
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(Math.max(value, minimum), Math.max(minimum, maximum));
}

export function EmojiPicker({
  onEmojiSelect,
  onClose,
  className = '',
  triggerId,
  isCurrentUser = false,
  secureDB,
  origin,
}: EmojiPickerProps) {
  const [catalog, setCatalog] = useState<EmojiCatalogView | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [activeCategory, setActiveCategory] = useState('frequent');
  const [searchQuery, setSearchQuery] = useState('');
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);
  const [position, setPosition] = useState<PickerPosition | null>(null);

  const pickerRef = useRef<HTMLDivElement>(null);
  const categoriesRef = useRef<HTMLDivElement>(null);
  const categoryWheelLockRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const gridRef = useRef<HTMLDivElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const sentinelRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let cancelled = false;
    setLoadFailed(false);

    void getEmojiCatalog(secureDB)
      .then((nextCatalog) => {
        if (!cancelled) setCatalog(nextCatalog);
      })
      .catch((error) => {
        console.error('[EmojiPicker] Unable to initialize local emoji catalog', error);
        if (!cancelled) setLoadFailed(true);
      });

    return () => {
      cancelled = true;
    };
  }, [secureDB]);

  const sections = useMemo<readonly PickerSection[]>(() => {
    if (!catalog) return [];
    return [
      { id: 'frequent', label: 'Frequently used', emojis: catalog.frequent },
      ...catalog.categories,
    ];
  }, [catalog]);

  const selectedSection = useMemo(
    () => sections.find((section) => section.id === activeCategory) ?? sections[0],
    [activeCategory, sections],
  );

  const isSearching = searchQuery.trim().length > 0;
  const matchingEmojis = useMemo(
    () => isSearching
      ? searchEmojiCatalog(searchQuery, secureDB)
      : (selectedSection?.emojis ?? []),
    [isSearching, searchQuery, secureDB, selectedSection],
  );
  const visibleEmojis = useMemo(
    () => matchingEmojis.slice(0, visibleCount),
    [matchingEmojis, visibleCount],
  );

  const calculatePosition = useCallback(() => {
    const picker = pickerRef.current;
    if (!picker) return;

    const margin = 8;
    const gap = 10;
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    const pickerRect = picker.getBoundingClientRect();
    const pickerWidth = pickerRect.width;
    const pickerHeight = pickerRect.height;

    if (origin) {
      setPosition({
        left: Math.round(clamp(origin.left, margin, viewportWidth - pickerWidth - margin)),
        top: Math.round(clamp(origin.top, margin, viewportHeight - pickerHeight - margin)),
      });
      return;
    }

    const trigger = findTrigger(triggerId);

    if (!trigger) {
      setPosition({
        left: Math.round(clamp((viewportWidth - pickerWidth) / 2, margin, viewportWidth - pickerWidth - margin)),
        top: Math.round(clamp((viewportHeight - pickerHeight) / 2, margin, viewportHeight - pickerHeight - margin)),
      });
      return;
    }

    const triggerRect = trigger.getBoundingClientRect();
    const preferredLeft = isCurrentUser
      ? triggerRect.left - pickerWidth - gap
      : triggerRect.right + gap;
    const alternateLeft = isCurrentUser
      ? triggerRect.right + gap
      : triggerRect.left - pickerWidth - gap;
    const preferredFits = preferredLeft >= margin && preferredLeft + pickerWidth <= viewportWidth - margin;
    const alternateFits = alternateLeft >= margin && alternateLeft + pickerWidth <= viewportWidth - margin;

    let left = preferredFits
      ? preferredLeft
      : alternateFits
        ? alternateLeft
        : triggerRect.left + (triggerRect.width - pickerWidth) / 2;
    let top = triggerRect.top - 48;

    left = clamp(left, margin, viewportWidth - pickerWidth - margin);
    top = clamp(top, margin, viewportHeight - pickerHeight - margin);
    setPosition({ left: Math.round(left), top: Math.round(top) });
  }, [isCurrentUser, origin, triggerId]);

  useLayoutEffect(() => {
    calculatePosition();
    const frame = window.requestAnimationFrame(calculatePosition);
    return () => window.cancelAnimationFrame(frame);
  }, [calculatePosition]);

  useEffect(() => {
    let frame = 0;
    const schedulePosition = () => {
      window.cancelAnimationFrame(frame);
      frame = window.requestAnimationFrame(calculatePosition);
    };

    window.addEventListener('resize', schedulePosition);
    window.addEventListener('scroll', schedulePosition, true);
    window.visualViewport?.addEventListener('resize', schedulePosition);
    window.visualViewport?.addEventListener('scroll', schedulePosition);

    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener('resize', schedulePosition);
      window.removeEventListener('scroll', schedulePosition, true);
      window.visualViewport?.removeEventListener('resize', schedulePosition);
      window.visualViewport?.removeEventListener('scroll', schedulePosition);
    };
  }, [calculatePosition]);

  useEffect(() => {
    if (!position) return;
    const frame = window.requestAnimationFrame(() => searchInputRef.current?.focus());
    return () => window.cancelAnimationFrame(frame);
  }, [position]);

  useEffect(() => {
    const handlePointerDown = (event: PointerEvent) => {
      if (pickerRef.current && !pickerRef.current.contains(event.target as Node)) onClose();
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };

    document.addEventListener('pointerdown', handlePointerDown);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('pointerdown', handlePointerDown);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [onClose]);

  useEffect(() => {
    setVisibleCount(PAGE_SIZE);
    scrollRef.current?.scrollTo({ top: 0 });
  }, [activeCategory, searchQuery]);

  useEffect(() => {
    const categories = categoriesRef.current;
    if (!categories) return;
    const handleWheel = (event: WheelEvent) => {
      const delta = Math.abs(event.deltaX) > Math.abs(event.deltaY)
        ? event.deltaX
        : event.deltaY;
      if (delta === 0) return;
      event.preventDefault();
      if (categoryWheelLockRef.current) return;
      const category = categories.querySelector<HTMLElement>('.emoji-picker__category');
      const gap = Number.parseFloat(window.getComputedStyle(categories).columnGap) || 0;
      const step = (category?.getBoundingClientRect().width ?? 0) + gap;
      if (step <= 0) return;
      const nextIndex = Math.round(categories.scrollLeft / step) + Math.sign(delta);
      categories.scrollTo({ left: nextIndex * step, behavior: 'smooth' });
      categoryWheelLockRef.current = setTimeout(() => {
        categoryWheelLockRef.current = null;
      }, 180);
    };
    categories.addEventListener('wheel', handleWheel, { passive: false });
    return () => {
      categories.removeEventListener('wheel', handleWheel);
      if (categoryWheelLockRef.current) clearTimeout(categoryWheelLockRef.current);
      categoryWheelLockRef.current = null;
    };
  }, []);

  useEffect(() => {
    const root = scrollRef.current;
    const sentinel = sentinelRef.current;
    if (!root || !sentinel || visibleCount >= matchingEmojis.length) return;

    if (typeof IntersectionObserver === 'undefined') {
      setVisibleCount(matchingEmojis.length);
      return;
    }

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setVisibleCount((current) => Math.min(current + PAGE_SIZE, matchingEmojis.length));
        }
      },
      { root, rootMargin: '160px 0px' },
    );
    observer.observe(sentinel);
    return () => observer.disconnect();
  }, [matchingEmojis.length, visibleCount]);

  const chooseCategory = useCallback((categoryId: string) => {
    setSearchQuery('');
    setActiveCategory(categoryId);
  }, []);

  const chooseEmoji = useCallback((record: EmojiRecord) => {
    onEmojiSelect(record.emoji);
    onClose();
  }, [onClose, onEmojiSelect]);

  const focusFirstEmoji = useCallback(() => {
    gridRef.current?.querySelector<HTMLButtonElement>('[data-emoji-option]')?.focus();
  }, []);

  const handleGridKeyDown = useCallback((event: React.KeyboardEvent<HTMLDivElement>) => {
    const target = event.target as HTMLElement;
    if (!target.hasAttribute('data-emoji-option')) return;

    const buttons = [...(gridRef.current?.querySelectorAll<HTMLButtonElement>('[data-emoji-option]') ?? [])];
    const currentIndex = buttons.indexOf(target as HTMLButtonElement);
    if (currentIndex < 0) return;

    let nextIndex = currentIndex;
    if (event.key === 'ArrowLeft') nextIndex -= 1;
    else if (event.key === 'ArrowRight') nextIndex += 1;
    else if (event.key === 'ArrowUp') nextIndex -= GRID_COLUMNS;
    else if (event.key === 'ArrowDown') nextIndex += GRID_COLUMNS;
    else if (event.key === 'Home') nextIndex = 0;
    else if (event.key === 'End') nextIndex = buttons.length - 1;
    else return;

    event.preventDefault();
    buttons[clamp(nextIndex, 0, buttons.length - 1)]?.focus();
  }, []);

  if (typeof document === 'undefined') return null;

  const sectionLabel = isSearching ? 'Search results' : (selectedSection?.label ?? 'Emoji');

  return createPortal(
    <div
      ref={pickerRef}
      className={`emoji-picker${className ? ` ${className}` : ''}`}
      style={{
        top: position?.top ?? -10_000,
        left: position?.left ?? -10_000,
        visibility: position ? 'visible' : 'hidden',
      }}
      role="dialog"
      aria-label="Emoji picker"
      aria-modal="false"
      data-positioned={position ? 'true' : 'false'}
    >
      <div
        ref={categoriesRef}
        className="emoji-picker__categories"
        role="tablist"
        aria-label="Emoji categories"
      >
        {sections.map((section) => {
          const Icon = CATEGORY_ICONS[section.id] ?? Shapes;
          const selected = !isSearching && selectedSection?.id === section.id;
          return (
            <button
              key={section.id}
              type="button"
              className="emoji-picker__category"
              role="tab"
              aria-selected={selected}
              aria-label={section.label}
              title={section.label}
              onClick={() => chooseCategory(section.id)}
            >
              <Icon size={17} strokeWidth={1.8} aria-hidden="true" />
            </button>
          );
        })}
      </div>

      <div ref={scrollRef} className="emoji-picker__scroll">
        <div className="emoji-picker__section-heading">
          <span>{sectionLabel}</span>
        </div>

        {!catalog && !loadFailed && (
          <div className="emoji-picker__state" role="status" aria-label="Loading emoji">
            <LoaderCircle size={22} className="emoji-picker__spinner" aria-hidden="true" />
          </div>
        )}

        {loadFailed && (
          <div className="emoji-picker__state" role="alert">
            <span>Emoji catalog unavailable</span>
          </div>
        )}

        {catalog && matchingEmojis.length === 0 && (
          <div className="emoji-picker__state" role="status">
            <Search size={22} aria-hidden="true" />
            <span>No emoji found</span>
          </div>
        )}

        {visibleEmojis.length > 0 && (
          <div
            ref={gridRef}
            className="emoji-picker__grid"
            role="grid"
            aria-label={sectionLabel}
            onKeyDown={handleGridKeyDown}
          >
            {visibleEmojis.map((record) => (
              <button
                key={record.emoji}
                type="button"
                className="emoji-picker__emoji"
                data-emoji-option
                onClick={() => chooseEmoji(record)}
                aria-label={`${record.name}, ${record.emoji}`}
              >
                <span aria-hidden="true">{record.emoji}</span>
              </button>
            ))}
          </div>
        )}
        <div ref={sentinelRef} className="emoji-picker__sentinel" aria-hidden="true" />
      </div>

      <div className="emoji-picker__search">
        <Search size={16} aria-hidden="true" />
        <input
          ref={searchInputRef}
          type="search"
          value={searchQuery}
          onChange={(event) => setSearchQuery(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'ArrowDown') {
              event.preventDefault();
              focusFirstEmoji();
            }
          }}
          placeholder="Search emoji"
          aria-label="Search emoji"
          autoComplete="off"
          spellCheck={false}
          maxLength={80}
        />
        {searchQuery && (
          <button
            type="button"
            className="emoji-picker__clear"
            onClick={() => {
              setSearchQuery('');
              searchInputRef.current?.focus();
            }}
            aria-label="Clear search"
            title="Clear search"
          >
            <X size={14} aria-hidden="true" />
          </button>
        )}
      </div>
    </div>,
    document.body,
  );
}
