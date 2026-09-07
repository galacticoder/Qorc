import { useCallback, useEffect, useRef, useState } from 'react';
import { blockStatusCache } from '@/lib/blocking/block-status-cache';
import { blockingSystem } from '@/lib/blocking/blocking-system';
import {
  DEFAULT_EVENT_RATE_MAX,
  DEFAULT_EVENT_RATE_WINDOW_MS,
} from '@/lib/constants';
import { exactEventDetail, isCanonicalAuthUsername } from '@/lib/sanitizers';
import { EventType } from '@/lib/types/event-types';

interface UseBlockStatusOptions {
  readonly eventRateMax?: number;
  readonly initialBlocked?: boolean;
  readonly load?: boolean;
  readonly refreshOnVisible?: boolean;
}

export const useBlockStatus = (
  peer: string | undefined,
  options: UseBlockStatusOptions = {},
): boolean => {
  const {
    eventRateMax = DEFAULT_EVENT_RATE_MAX,
    initialBlocked = false,
    load = true,
    refreshOnVisible = false,
  } = options;
  const [isBlocked, setIsBlocked] = useState(initialBlocked);
  const requestGenerationRef = useRef(0);
  const eventRateRef = useRef({ windowStart: Date.now(), count: 0 });

  const refresh = useCallback(async () => {
    const target = peer;
    const generation = ++requestGenerationRef.current;
    if (!isCanonicalAuthUsername(target)) {
      setIsBlocked(false);
      return;
    }

    if (!load) {
      setIsBlocked(blockStatusCache.get(target) === true);
      return;
    }

    try {
      const blocked = await blockingSystem.isUserBlocked(target);
      if (requestGenerationRef.current !== generation) return;
      setIsBlocked(blocked);
      blockStatusCache.set(target, blocked);
    } catch (error) {
      console.error('[Blocking] Failed to read block status:', error);
    }
  }, [load, peer]);

  useEffect(() => {
    requestGenerationRef.current += 1;
    setIsBlocked(initialBlocked);
    void refresh();
    return () => {
      requestGenerationRef.current += 1;
    };
  }, [initialBlocked, refresh]);

  useEffect(() => {
    const handleBlockStatusChange = (event: Event) => {
      const now = Date.now();
      const bucket = eventRateRef.current;
      if (now - bucket.windowStart > DEFAULT_EVENT_RATE_WINDOW_MS) {
        bucket.windowStart = now;
        bucket.count = 0;
      }
      bucket.count += 1;
      if (bucket.count > eventRateMax) return;

      const detail = exactEventDetail(event, ['isBlocked', 'username']);
      if (!detail || !isCanonicalAuthUsername(detail.username)) return;
      if (typeof detail.isBlocked !== 'boolean' || detail.username !== peer) return;
      setIsBlocked(detail.isBlocked);
    };

    window.addEventListener(EventType.BLOCK_STATUS_CHANGED, handleBlockStatusChange);
    return () => window.removeEventListener(EventType.BLOCK_STATUS_CHANGED, handleBlockStatusChange);
  }, [eventRateMax, peer]);

  useEffect(() => {
    if (!refreshOnVisible) return;
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') void refresh();
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, [refresh, refreshOnVisible]);

  return isBlocked;
};
