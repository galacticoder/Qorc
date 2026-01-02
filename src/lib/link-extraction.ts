import { URL_REGEX, SIMPLE_URL_REGEX, MAX_LINKS_PER_TEXT, COMMON_COMPOUND_TLDS, SUSPICIOUS_QUERY_PARAMS, COMMON_TLDS } from './constants';

export interface ExtractedLink {
  url: string;
  originalText: string;
  startIndex: number;
  endIndex: number;
}

export class LinkExtractor {
  static extractLinks(text: string): ExtractedLink[] {
    const links: ExtractedLink[] = [];

    for (const match of text.matchAll(URL_REGEX)) {
      if (!match[1] || match.index === undefined) continue;
      const normalized = this.normalizeUrl(match[1]);
      if (!normalized) continue;

      links.push({
        url: normalized,
        originalText: match[1],
        startIndex: match.index,
        endIndex: match.index + match[1].length
      });
      if (links.length >= MAX_LINKS_PER_TEXT) {
        return links;
      }
    }

    for (const match of text.matchAll(SIMPLE_URL_REGEX)) {
      if (!match[1] || match.index === undefined) continue;
      const startIndex = match.index + match[0].length - match[1].length;
      const endIndex = startIndex + match[1].length;

      const overlaps = links.some(link =>
        (startIndex >= link.startIndex && startIndex < link.endIndex) ||
        (endIndex > link.startIndex && endIndex <= link.endIndex) ||
        (startIndex <= link.startIndex && endIndex >= link.endIndex)
      );
      if (overlaps) continue;

      if (!this.isValidSimpleUrl(match[1])) continue;
      const normalized = this.normalizeUrl(match[1]);
      if (!normalized) continue;

      links.push({
        url: normalized,
        originalText: match[1],
        startIndex,
        endIndex
      });
      if (links.length >= MAX_LINKS_PER_TEXT) {
        break;
      }
    }

    links.sort((a, b) => a.startIndex - b.startIndex);
    return links.length > MAX_LINKS_PER_TEXT ? links.slice(0, MAX_LINKS_PER_TEXT) : links;
  }

  static extractUrlStrings(text: string): string[] {
    return this.extractLinks(text).map(link => link.url);
  }

  static isUrlOnlyMessage(text: string): boolean {
    const links = this.extractLinks(text);
    if (links.length === 0) return false;

    let previousEnd = 0;
    for (const link of links) {
      if (link.startIndex > previousEnd && text.slice(previousEnd, link.startIndex).trim() !== '') {
        return false;
      }
      previousEnd = link.endIndex;
    }

    return previousEnd >= text.length || text.slice(previousEnd).trim() === '';
  }

  static getFirstUrl(text: string): string | null {
    const links = this.extractLinks(text);
    return links.length > 0 ? links[0].url : null;
  }

  static replaceUrls(text: string, replaceFn: (url: string, originalText: string) => string): string {
    const links = this.extractLinks(text);
    if (links.length === 0) return text;

    let result = '';
    let previousEnd = 0;

    for (const link of links) {
      result += text.slice(previousEnd, link.startIndex) + replaceFn(link.url, link.originalText);
      previousEnd = link.endIndex;
    }

    return result + text.slice(previousEnd);
  }

  static removeUrls(text: string, replacement: string = ''): string {
    return this.replaceUrls(text, () => replacement);
  }

  static hasUrls(text: string): boolean {
    return this.extractLinks(text).length > 0;
  }

  static getTextWithoutUrls(text: string): string {
    return this.removeUrls(text, ' ').replace(/\s+/g, ' ').trim();
  }

  private static normalizeUrl(url: string): string | null {
    try {
      let normalized = url.trim();
      if (!normalized) return null;
      if (!/^https?:\/\//i.test(normalized)) {
        normalized = `https://${normalized}`;
      }

      normalized = normalized.replace(/[.,;!?]+$/, '');

      const urlObj = new URL(normalized);
      const protocol = urlObj.protocol.toLowerCase();
      if (protocol !== 'http:' && protocol !== 'https:') {
        return null;
      }

      const hostname = urlObj.hostname.trim();
      if (!this.isAllowedHostname(hostname)) {
        return null;
      }

      for (const param of SUSPICIOUS_QUERY_PARAMS) {
        if (urlObj.searchParams.has(param)) {
          return null;
        }
      }

      return urlObj.href;
    } catch {
      return null;
    }
  }

  private static isAllowedHostname(hostname: string): boolean {
    const lower = hostname.toLowerCase();
    if (!lower || lower.length > 255) return false;
    if (lower === 'localhost') return false;
    if (!lower.includes('.')) return false;

    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(lower)) {
      return false;
    }

    if (lower.startsWith('[') && lower.endsWith(']')) {
      return false;
    }

    return true;
  }

  private static isValidSimpleUrl(url: string): boolean {
    const domainPart = url.split(/[\/?#]/)[0];
    if (!domainPart.includes('.')) return false;

    const parts = domainPart.split('.');
    if (parts.length < 2 || parts[0].length < 2) return false;
    if (parts.some(part => part.length === 0 || part.length > 63)) return false;

    const compoundCandidate = parts.slice(-2).join('.').toLowerCase();
    const tld = COMMON_COMPOUND_TLDS.has(compoundCandidate)
      ? compoundCandidate
      : parts[parts.length - 1].toLowerCase();

    return COMMON_TLDS.has(tld) || COMMON_COMPOUND_TLDS.has(tld);
  }
}

export const extractLinks = (text: string) => LinkExtractor.extractLinks(text);
export const extractUrlStrings = (text: string) => LinkExtractor.extractUrlStrings(text);
export const isUrlOnlyMessage = (text: string) => LinkExtractor.isUrlOnlyMessage(text);
export const getFirstUrl = (text: string) => LinkExtractor.getFirstUrl(text);
export const hasUrls = (text: string) => LinkExtractor.hasUrls(text);
export const getTextWithoutUrls = (text: string) => LinkExtractor.getTextWithoutUrls(text);
