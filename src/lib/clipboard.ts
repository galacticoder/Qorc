interface ClipboardResult {
  success: boolean;
  method: 'modern' | 'fallback' | 'failed';
  error?: string;
  bytesProcessed: number;
}

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_ATTEMPTS = 10;
const MAX_CLIPBOARD_SIZE = 100 * 1024; // 100 KB
const MAX_INPUT_SIZE = 1024 * 1024;

let lastWindowStart = 0;
let attemptsInWindow = 0;

const CONTROL_CHARS_REGEX = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

async function containsSensitiveData(text: string): Promise<boolean> {
  const patterns = [/password/i, /secret/i, /private key/i];
  return patterns.some(pattern => pattern.test(text));
}

function sanitizeForClipboard(text: string): string {
  return text.replace(CONTROL_CHARS_REGEX, '').slice(0, MAX_CLIPBOARD_SIZE);
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

  if (await containsSensitiveData(text)) {
    throw new Error('Sensitive data cannot be copied to clipboard');
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
    let textarea: HTMLTextAreaElement | null = null;
    try {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));

      textarea = document.createElement('textarea');
      textarea.value = sanitized;
      textarea.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0;pointer-events:none;';
      textarea.setAttribute('tabindex', '-1');
      textarea.setAttribute('aria-hidden', 'true');
      document.body.appendChild(textarea);
      textarea.focus({ preventScroll: true });
      textarea.select();
      textarea.setSelectionRange(0, textarea.value.length);

      const supportsExec = typeof document.queryCommandSupported === 'function' && document.queryCommandSupported('copy');
      if (!supportsExec) {
        throw new Error('Clipboard operations not supported');
      }

      success = document.execCommand('copy');
      method = success ? 'fallback' : 'failed';
    } catch (fallbackError) {
      error = fallbackError instanceof Error ? fallbackError.message : String(fallbackError);
      success = false;
      method = 'failed';
    } finally {
      if (textarea && textarea.parentNode) {
        textarea.parentNode.removeChild(textarea);
      }
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


