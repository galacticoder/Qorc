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
  private cache: Record<string, BlockStatusCacheEntry> = {};
  private readonly CACHE_TTL = BLOCK_STATUS_CACHE_TTL_MS;

  // Get cached block status for a user
  get(username: string): boolean | null {
    const cached = this.cache[username];
    if (!cached) return null;

    if (Date.now() - cached.timestamp > this.CACHE_TTL) {
      delete this.cache[username];
      return null;
    }

    return cached.isBlocked;
  }

  // Update block status in cache and dispatch event
  set(username: string, isBlocked: boolean): void {
    this.cache[username] = {
      isBlocked,
      timestamp: Date.now()
    };

    window.dispatchEvent(new CustomEvent(EventType.BLOCK_STATUS_CHANGED, {
      detail: { username, isBlocked }
    }));
  }

  // Invalidate cache for a specific user
  invalidate(username: string): void {
    delete this.cache[username];
  }

  // Clear entire cache
  clear(): void {
    this.cache = {};
  }
}

export const blockStatusCache = new BlockStatusManager();
