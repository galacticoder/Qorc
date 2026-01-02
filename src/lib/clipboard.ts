import { MAX_CLIPBOARD_SIZE, MAX_INPUT_SIZE, RATE_LIMIT_ATTEMPTS, CLIPBOARD_CONTROL_CHARS_REGEX, RATE_LIMIT_WINDOW_MS } from './constants';

interface ClipboardResult {
  success: boolean;
  method: 'modern' | 'fallback' | 'failed';
  error?: string;
  bytesProcessed: number;
}

let lastWindowStart = 0;
let attemptsInWindow = 0;

function sanitizeForClipboard(text: string): string {
  return text.replace(CLIPBOARD_CONTROL_CHARS_REGEX, '').slice(0, MAX_CLIPBOARD_SIZE);
}

function enforceRateLimit(): void {
  const now = Date.now();
  if (now - lastWindowStart > RATE_LIMIT_WINDOW_MS) {
    lastWindowStart = now;
    attemptsInWindow = 0;
  }
  attemptsInWindow += 1;
  if (attemptsInWindow > RATE_LIMIT_ATTEMPTS) {
    throw new Error('Clipboard rate limit exceeded');
  }
}

async function checkClipboardPermission(): Promise<boolean> {
  if (typeof navigator === 'undefined' || !navigator.permissions) {
    return false;
  }
  try {
    const result = await navigator.permissions.query({ name: 'clipboard-write' as PermissionName });
    return result.state === 'granted' || result.state === 'prompt';
  } catch {
    return false;
  }
}

export async function copyTextToClipboard(text: unknown): Promise<ClipboardResult> {
  enforceRateLimit();

  if (typeof text !== 'string') {
    throw new Error('Invalid input type');
  }

  if (text.length > MAX_INPUT_SIZE) {
    throw new Error('Text exceeds maximum clipboard size');
  }

  const sanitized = sanitizeForClipboard(text);
  const permissionGranted = await checkClipboardPermission();

  let method: ClipboardResult['method'] = 'failed';
  let success = false;
  let error: string | undefined;

  try {
    if (typeof navigator !== 'undefined' && typeof window !== 'undefined') {
      const canUseAsyncClipboard = Boolean(window.isSecureContext || window.location.hostname === 'localhost') &&
        !!navigator.clipboard && typeof navigator.clipboard.writeText === 'function' && permissionGranted;

      if (canUseAsyncClipboard) {
        await navigator.clipboard.writeText(sanitized);
        method = 'modern';
        success = true;
      }
    }
  } catch (_err) {
    error = _err instanceof Error ? _err.message : String(_err);
  }

  if (!success) {
    try {
      await navigator.clipboard.writeText(sanitized);
      method = 'modern';
      success = true;
    } catch (fallbackError) {
      error = fallbackError instanceof Error ? fallbackError.message : String(fallbackError);
      success = false;
      method = 'failed';
    }
  }

  if (!success && error) {
    throw new Error(error);
  }

  return {
    success,
    method,
    error,
    bytesProcessed: sanitized.length
  };
}
