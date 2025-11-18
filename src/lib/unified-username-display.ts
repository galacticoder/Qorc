/**
 * Username Display Utilities
 */

export interface UsernameDisplayConfig {
  cacheSize?: number;
  cacheTTL?: number;
  maxUsernameLength?: number;
  concurrentResolutionLimit?: number;
  hashPreviewLength?: number;
}

export type UsernameResolutionOperation =
  | 'resolve-single'
  | 'batch-resolve'
  | 'resolver-cache'
  | 'context-resolve'
  | 'context-batch'
  | 'validate-resolver'
  | 'ensure-mapping';

const DEFAULT_USERNAME_DISPLAY_CONFIG: Required<UsernameDisplayConfig> = {
  cacheSize: 1000,
  cacheTTL: 30 * 60 * 1000,
  maxUsernameLength: 50,
  concurrentResolutionLimit: 10,
  hashPreviewLength: 16
};

class UsernameResolutionMonitor {
  private static readonly MAX_SAMPLES = 1000;
  private static successDurations: number[] = [];
  private static totalSuccessCount = 0;
  private static totalFailureCount = 0;

  static recordResolution(duration: number, success: boolean): void {
    if (success) {
      UsernameResolutionMonitor.successDurations.push(duration);
      if (UsernameResolutionMonitor.successDurations.length > UsernameResolutionMonitor.MAX_SAMPLES) {
        UsernameResolutionMonitor.successDurations.shift();
      }
      UsernameResolutionMonitor.totalSuccessCount += 1;
    } else {
      UsernameResolutionMonitor.totalFailureCount += 1;
    }
  }
}

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

export function recordUsernameResolutionEvent(
  operation: UsernameResolutionOperation,
  username: string,
  result: string,
  duration: number,
  success: boolean
): void {
  UsernameResolutionMonitor.recordResolution(duration, success);
}

export function sanitizeUsernameInput(input: string): string {
  return typeof input === 'string' ? input.trim() : '';
}

/**
 * Resolve a username with robust error handling and metrics.
 */
export async function resolveDisplayUsername(
  username: string,
  getDisplayUsername?: (username: string) => Promise<string>
): Promise<string> {
  const startTime = Date.now();
  const sanitized = sanitizeUsernameInput(username);
  const config = UsernameDisplayConfiguration.get();

  if (!sanitized) {
    UsernameResolutionMonitor.recordResolution(Date.now() - startTime, true);
    return '';
  }

  if (sanitized.length > config.maxUsernameLength) {
    UsernameResolutionMonitor.recordResolution(Date.now() - startTime, false);
    return 'Unknown User';
  }

  let result = sanitized;
  let success = false;

  try {
    if (!getDisplayUsername) {
      result = isHashedUsername(sanitized)
        ? formatUsernameForDisplay(sanitized, config.hashPreviewLength, true)
        : sanitized;
      success = true;
      return result;
    }

    const resolved = await getDisplayUsername(sanitized);
    result = isHashedUsername(resolved)
      ? formatUsernameForDisplay(resolved, config.hashPreviewLength, true)
      : resolved;
    success = true;
    return result;
  } catch {
    result = isHashedUsername(sanitized)
      ? formatUsernameForDisplay(sanitized, config.hashPreviewLength, true)
      : sanitized;
    return result;
  } finally {
    UsernameResolutionMonitor.recordResolution(Date.now() - startTime, success);
  }
}

/**
 * Detect hashed usernames by matching against common hash formats.
 */
export function isHashedUsername(username: string): boolean {
  if (!username) return false;
  const trimmed = username.trim();
  if (trimmed.length < 32) return false;

  const hashPatterns = [
    /^[a-f0-9]{32}$/i,
    /^[a-f0-9]{40}$/i,
    /^[a-f0-9]{64}$/i,
    /^[a-f0-9]{128}$/i,
    /^[a-f0-9]{32,}$/i
  ];

  return hashPatterns.some(pattern => pattern.test(trimmed));
}

/**
 * Format usernames for display with optional truncation and hash indicators.
 */
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