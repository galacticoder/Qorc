/**
 * Global block status cache
 */

import { EventType } from '../types/event-types';
import { BLOCK_STATUS_CACHE_TTL_MS } from '../constants';

interface BlockStatusCacheEntry {
  isBlocked: boolean;
  timestamp: number;
}

class BlockStatusManager {
  private readonly cache = new Map<string, BlockStatusCacheEntry>();
  private readonly CACHE_TTL = BLOCK_STATUS_CACHE_TTL_MS;

  // Get cached block status for a user
  get(username: string): boolean | null {
    const cached = this.cache.get(username);
    if (!cached) return null;

    if (Date.now() - cached.timestamp > this.CACHE_TTL) {
      this.cache.delete(username);
      return null;
    }

    return cached.isBlocked;
  }

  // Update block status in cache and dispatch event
  set(username: string, isBlocked: boolean): void {
    this.cache.set(username, {
      isBlocked,
      timestamp: Date.now()
    });

    window.dispatchEvent(new CustomEvent(EventType.BLOCK_STATUS_CHANGED, {
      detail: { username, isBlocked }
    }));
  }

  // Invalidate cache for a specific user
  invalidate(username: string): void {
    this.cache.delete(username);
  }

  // Clear entire cache
  clear(): void {
    this.cache.clear();
  }
}

export const blockStatusCache = new BlockStatusManager();
