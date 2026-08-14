import { MAX_CLIPBOARD_SIZE, MAX_INPUT_SIZE, RATE_LIMIT_ATTEMPTS, CLIPBOARD_CONTROL_CHARS_REGEX, RATE_LIMIT_WINDOW_MS } from './constants';

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

export async function copyTextToClipboard(text: unknown): Promise<void> {
  enforceRateLimit();

  if (typeof text !== 'string') {
    throw new Error('Invalid input type');
  }

  if (text.length > MAX_INPUT_SIZE) {
    throw new Error('Text exceeds maximum clipboard size');
  }

  const sanitized = sanitizeForClipboard(text);
  if (
    typeof navigator === 'undefined' ||
    !navigator.clipboard ||
    typeof navigator.clipboard.writeText !== 'function'
  ) {
    throw new Error('Secure clipboard API unavailable');
  }
  await navigator.clipboard.writeText(sanitized);
}
