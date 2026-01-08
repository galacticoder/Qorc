/**
 * Username Display Utilities
 */

import { UsernameDisplayConfig, DEFAULT_USERNAME_DISPLAY_CONFIG } from '../types/username-types';
import { isHashedUsername, sanitizeUsernameInput } from '../utils/username-utils';

export class UsernameDisplayConfiguration {
  private static config: Required<UsernameDisplayConfig> = { ...DEFAULT_USERNAME_DISPLAY_CONFIG };

  static configure(options: UsernameDisplayConfig = {}): void {
    if (!options || typeof options !== 'object') {
      return;
    }

    const next = { ...UsernameDisplayConfiguration.config, ...options } as Required<UsernameDisplayConfig>;

    next.cacheSize = Math.max(1, Math.min(10000, Math.floor(next.cacheSize)));
    next.cacheTTL = Math.max(1000, Math.floor(next.cacheTTL));
    next.maxUsernameLength = Math.max(1, Math.min(200, Math.floor(next.maxUsernameLength)));
    next.concurrentResolutionLimit = Math.max(1, Math.min(100, Math.floor(next.concurrentResolutionLimit)));
    next.hashPreviewLength = Math.max(4, Math.min(32, Math.floor(next.hashPreviewLength)));

    UsernameDisplayConfiguration.config = next;
  }

  static get(): Required<UsernameDisplayConfig> {
    return { ...UsernameDisplayConfiguration.config };
  }
}

// Resolve a username
export async function resolveDisplayUsername(
  username: string,
  getDisplayUsername?: (username: string) => Promise<string>
): Promise<string> {
  const sanitized = sanitizeUsernameInput(username);
  const config = UsernameDisplayConfiguration.get();

  if (!sanitized) {
    return '';
  }

  if (sanitized.length > config.maxUsernameLength) {
    return 'Unknown User';
  }

  let result = sanitized;

  try {
    if (!getDisplayUsername) {
      result = isHashedUsername(sanitized)
        ? formatUsernameForDisplay(sanitized, config.hashPreviewLength, true)
        : sanitized;
      return result;
    }

    const resolved = await getDisplayUsername(sanitized);
    result = isHashedUsername(resolved)
      ? formatUsernameForDisplay(resolved, config.hashPreviewLength, true)
      : resolved;
    return result;
  } catch {
    result = isHashedUsername(sanitized)
      ? formatUsernameForDisplay(sanitized, config.hashPreviewLength, true)
      : sanitized;
    return result;
  }
}


// Format usernames for display
export function formatUsernameForDisplay(
  username: string,
  maxLength?: number,
  showHashIndicator = false
): string {
  const sanitized = sanitizeUsernameInput(username);
  if (!sanitized) return 'Unknown User';

  const config = UsernameDisplayConfiguration.get();
  const limit = typeof maxLength === 'number' && maxLength > 0 ? maxLength : config.maxUsernameLength;
  const indicatorLength = config.hashPreviewLength;

  let displayName = sanitized;
  if (showHashIndicator && isHashedUsername(sanitized)) {
    displayName = `User (${sanitized.slice(0, indicatorLength)}...)`;
  }

  if (displayName.length > limit) {
    displayName = `${displayName.slice(0, Math.max(0, limit - 3))}...`;
  }

  return displayName;
}