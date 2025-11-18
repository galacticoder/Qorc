export interface ExtractedLink {
  url: string;
  originalText: string;
  startIndex: number;
  endIndex: number;
}

export class LinkExtractor {
  private static readonly URL_REGEX = /(https?:\/\/(?:[-\w.]|%[0-9A-Fa-f]{2})+(?::[0-9]+)?(?:\/(?:[\w\/_~!$&'()*+,;=:@.-]|%[0-9A-Fa-f]{2})*)*(?:\?(?:[\w&=%._~!$'()*+,;:@/?-]|%[0-9A-Fa-f]{2})*)?(?:#(?:[\w._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})*)?)/gi;
  private static readonly SIMPLE_URL_REGEX = /(?:^|\s)((?:www\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?:\/(?:[\w\/_~!$&'()*+,;=:@.-]|%[0-9A-Fa-f]{2})*)*(?:\?(?:[\w&=%._~!$'()*+,;:@/?-]|%[0-9A-Fa-f]{2})*)?(?:#(?:[\w._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})*)?/gi;
  private static readonly MAX_LINKS_PER_TEXT = 50;
  private static readonly SUSPICIOUS_QUERY_PARAMS = new Set(['redirect', 'url', 'target', 'goto', 'dest', 'destination', 'location']);
  private static readonly COMMON_TLDS = new Set([
    'com','org','net','edu','gov','mil','int','biz','info','name','pro','aero','asia','cat','coop','jobs','mobi','museum','travel',
    'us','uk','ca','au','de','fr','jp','cn','in','br','ru','it','es','nl','se','no','fi','dk','ch','be','at','pl','cz','gr','pt','ie','hu','ro','bg','sk','hr','si','lt','lv','ee',
    'kr','hk','sg','nz','mx','ar','cl','co','za','ae','sa','tr','il','id','my','ph','th','vn','pk','bd','ng','ke','gh','tz','ug','zw',
    'io','ai','app','dev','tech','cloud','digital','software','systems','solutions','online','store','shop','blog','news','press','today','life','live','world','social','media',
    'xyz','top','club','site','space','fun','link','click','help','design','art','eco','one','plus','guru','global','agency','company','center',
    'tv','fm','cc','ly','me','io','ai','gg','gl','gs','la','md','nu','sh','su','to','ws'
  ]);
  private static readonly COMMON_COMPOUND_TLDS = new Set(['co.uk','com.au','com.br','com.cn','com.sg','com.tr','com.mx','com.sa','com.ar','com.pl','com.hk','com.tw']);

  static extractLinks(text: string): ExtractedLink[] {
    const links: ExtractedLink[] = [];

    for (const match of text.matchAll(this.URL_REGEX)) {
      if (!match[1] || match.index === undefined) continue;
      const normalized = this.normalizeUrl(match[1]);
      if (!normalized) continue;

      links.push({
        url: normalized,
        originalText: match[1],
        startIndex: match.index,
        endIndex: match.index + match[1].length
      });
      if (links.length >= this.MAX_LINKS_PER_TEXT) {
        return links;
      }
    }

    for (const match of text.matchAll(this.SIMPLE_URL_REGEX)) {
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
      if (links.length >= this.MAX_LINKS_PER_TEXT) {
        break;
      }
    }

    links.sort((a, b) => a.startIndex - b.startIndex);
    return links.length > this.MAX_LINKS_PER_TEXT ? links.slice(0, this.MAX_LINKS_PER_TEXT) : links;
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

      for (const param of this.SUSPICIOUS_QUERY_PARAMS) {
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
    const tld = this.COMMON_COMPOUND_TLDS.has(compoundCandidate)
      ? compoundCandidate
      : parts[parts.length - 1].toLowerCase();

    return this.COMMON_TLDS.has(tld) || this.COMMON_COMPOUND_TLDS.has(tld);
  }
}

export const extractLinks = (text: string) => LinkExtractor.extractLinks(text);
export const extractUrlStrings = (text: string) => LinkExtractor.extractUrlStrings(text);
export const isUrlOnlyMessage = (text: string) => LinkExtractor.isUrlOnlyMessage(text);
export const getFirstUrl = (text: string) => LinkExtractor.getFirstUrl(text);
export const hasUrls = (text: string) => LinkExtractor.hasUrls(text);
export const getTextWithoutUrls = (text: string) => LinkExtractor.getTextWithoutUrls(text);
