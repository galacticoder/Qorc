/**
 * Markdown delimiter detection for chat messages
 * Uses react-markdown for rendering
 */

const MARKDOWN_BLOCK_REGEX = /\{\{\{([\s\S]*?)\}\}\}/g;
const SINGLE_MARKDOWN_BLOCK_REGEX = /\{\{\{([\s\S]*?)\}\}\}/;
const MAX_CONTENT_LENGTH = 100 * 1024;
const MAX_MARKDOWN_BLOCKS = 32;
const RATE_WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 60;

let rateWindowStart = 0;
let rateWindowCount = 0;

function enforceRateLimit(): void {
  const now = Date.now();
  if (now - rateWindowStart > RATE_WINDOW_MS) {
    rateWindowStart = now;
    rateWindowCount = 0;
  }

  rateWindowCount += 1;
  if (rateWindowCount > MAX_REQUESTS_PER_WINDOW) {
    throw new Error('Markdown parsing rate limit exceeded');
  }
}

function sanitizeMarkdown(text: string): string {
  return text
    .replace(/[\u0000-\u001F\u007F]+/g, '')
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')
    .replace(/javascript:/gi, '')
    .trim();
}

function normalizeIndentation(input: string): string {
  if (!input.includes('\n')) {
    return input.trim();
  }

  const lines = input.split('\n');
  const nonEmpty = lines.filter(line => line.trim() !== '');
  if (nonEmpty.length === 0) return '';

  const minIndent = Math.min(...nonEmpty.map(line => (line.match(/^(\s*)/)?.[1].length ?? 0)));

  if (minIndent > 0) {
    return lines.map(line => (line.trim() === '' ? '' : line.slice(minIndent))).join('\n').trim();
  }

  return input.trim();
}

export function isMarkdownMessage(content: string): boolean {
  if (!content || content.length > MAX_CONTENT_LENGTH) {
    return false;
  }

  if (MARKDOWN_BLOCK_REGEX.test(content)) {
    MARKDOWN_BLOCK_REGEX.lastIndex = 0;
    return true;
  }

  return /(^|\n)(```|~~~)/.test(content) ||
         /(^|\n)#{1,6}\s+\S/.test(content) ||
         /(^|\n)(?:-|\*|\+|\d+\.)\s+\S/.test(content) ||
         /\[[^\]]+\]\([^\)]+\)/.test(content) ||
         /(^|\n)>\s+\S/.test(content) ||
         /(^|\n)\|[^\n]+\|\n\|[\s:|-]+\|/.test(content);
}

export function parseMixedContent(content: string): Array<{ type: 'text' | 'markdown'; content: string; hasOriginalNewlines?: boolean }> {
  enforceRateLimit();
  if (!content) return [];
  if (content.length > MAX_CONTENT_LENGTH) {
    throw new Error('Content too large');
  }

  const segments: Array<{ type: 'text' | 'markdown'; content: string; hasOriginalNewlines?: boolean }> = [];
  let lastIndex = 0;
  let blockCount = 0;

  for (const match of content.matchAll(MARKDOWN_BLOCK_REGEX)) {
    if (!match || match.index === undefined || blockCount >= MAX_MARKDOWN_BLOCKS) continue;
    blockCount++;

    if (match.index > lastIndex) {
      const textSegment = content.slice(lastIndex, match.index).trim();
      if (textSegment) {
        segments.push({ type: 'text', content: sanitizeMarkdown(textSegment) });
      }
    }

    const rawMarkdown = match[1] ?? '';
    const normalized = sanitizeMarkdown(normalizeIndentation(rawMarkdown.replace(/^(#{1,6})([^\s#])/gm, '$1 $2')));
    if (normalized) {
      segments.push({ type: 'markdown', content: normalized, hasOriginalNewlines: rawMarkdown.includes('\n') });
    }

    lastIndex = match.index + match[0].length;
  }

  if (lastIndex < content.length) {
    const remaining = content.slice(lastIndex).trim();
    if (remaining) {
      segments.push({ type: 'text', content: sanitizeMarkdown(remaining) });
    }
  }

  return segments;
}

export function hasMixedContent(content: string): boolean {
  const segments = parseMixedContent(content);
  return segments.length > 1;
}

export function extractMarkdownContent(content: string): string {
  enforceRateLimit();
  if (!content) return '';
  if (content.length > MAX_CONTENT_LENGTH) {
    throw new Error('Content too large');
  }

  const match = content.match(SINGLE_MARKDOWN_BLOCK_REGEX);
  if (!match) {
    return sanitizeMarkdown(normalizeIndentation(content));
  }

  const extracted = match[1] ?? '';
  const normalized = normalizeIndentation(extracted.replace(/^(#{1,6})([^\s#])/gm, '$1 $2'));
  return sanitizeMarkdown(normalized);
}
