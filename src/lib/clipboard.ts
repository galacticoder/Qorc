export async function copyTextToClipboard(text: string): Promise<boolean> {
  try {
    // Prefer modern async clipboard API when available and in a secure context
    if (typeof navigator !== 'undefined' && typeof window !== 'undefined') {
      const canUseAsyncClipboard = Boolean(window.isSecureContext || window.location.hostname === 'localhost') &&
        !!navigator.clipboard && typeof navigator.clipboard.writeText === 'function';

      if (canUseAsyncClipboard) {
        try {
          await navigator.clipboard.writeText(text);
          return true;
        } catch (err) {
          // Fall through to legacy copy below
        }
      }
    }
  } catch {
    // Ignore and try legacy fallback
  }

  // Legacy fallback using a temporary textarea and execCommand
  try {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    // Avoid scrolling to bottom
    textarea.style.position = 'fixed';
    textarea.style.top = '0';
    textarea.style.left = '0';
    textarea.style.opacity = '0';
    textarea.setAttribute('readonly', '');
    document.body.appendChild(textarea);
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);
    const successful = document.execCommand('copy');
    document.body.removeChild(textarea);
    return successful;
  } catch {
    return false;
  }
}


