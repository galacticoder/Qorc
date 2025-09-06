/**
 * Link Extraction Utilities
 * Utilities for extracting and managing URLs in chat messages
 */

export interface ExtractedLink {
  url: string;
  originalText: string;
  startIndex: number;
  endIndex: number;
}

export class LinkExtractor {
  // Enhanced URL regex that handles complex URLs with query parameters, fragments, and special characters
  // This regex is more comprehensive and handles modern URL patterns including:
  // - Complex query parameters with encoded characters
  // - URL fragments (#)
  // - International domain names
  // - Various port numbers
  // - Complex path structures
  private static readonly URL_REGEX = /(https?:\/\/(?:[-\w.])+(?::[0-9]+)?(?:\/(?:[\w\/_.\-~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})*)*(?:\?(?:[\w&=%.\-~!$'()*+,;:@/?]|%[0-9A-Fa-f]{2})*)?(?:#(?:[\w.\-~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})*)?)/gi;

  // Simple URL pattern for basic detection (without protocol) - also enhanced
  private static readonly SIMPLE_URL_REGEX = /(?:^|\s)((?:www\.)?[-\w.]+\.(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9]+)(?::[0-9]+)?(?:\/(?:[\w\/_.\-~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})*)*(?:\?(?:[\w&=%.\-~!$'()*+,;:@/?]|%[0-9A-Fa-f]{2})*)?(?:#(?:[\w.\-~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})*)?)/gi;

  /**
   * Extract all URLs from text with their positions
   */
  static extractLinks(text: string): ExtractedLink[] {
    const links: ExtractedLink[] = [];

    // Find HTTP/HTTPS URLs first
    let match;
    this.URL_REGEX.lastIndex = 0; // Reset regex

    while ((match = this.URL_REGEX.exec(text)) !== null) {
      links.push({
        url: this.normalizeUrl(match[1]),
        originalText: match[1],
        startIndex: match.index,
        endIndex: match.index + match[1].length
      });
    }
    
    // Find simple URLs (without protocol) that don't overlap with existing matches
    this.SIMPLE_URL_REGEX.lastIndex = 0; // Reset regex
    
    while ((match = this.SIMPLE_URL_REGEX.exec(text)) !== null) {
      const startIndex = match.index + match[0].length - match[1].length; // Account for whitespace
      const endIndex = startIndex + match[1].length;
      
      // Check if this overlaps with existing HTTP/HTTPS URLs
      const overlaps = links.some(link => 
        (startIndex >= link.startIndex && startIndex < link.endIndex) ||
        (endIndex > link.startIndex && endIndex <= link.endIndex) ||
        (startIndex <= link.startIndex && endIndex >= link.endIndex)
      );
      
      if (!overlaps && this.isValidSimpleUrl(match[1])) {
        links.push({
          url: this.normalizeUrl(match[1]),
          originalText: match[1],
          startIndex,
          endIndex
        });
      }
    }
    
    // Sort by start index
    return links.sort((a, b) => a.startIndex - b.startIndex);
  }

  /**
   * Extract just the URL strings from text
   */
  static extractUrlStrings(text: string): string[] {
    return this.extractLinks(text).map(link => link.url);
  }

  /**
   * Check if message contains only URLs (no other meaningful content)
   */
  static isUrlOnlyMessage(text: string): boolean {
    const links = this.extractLinks(text);
    if (links.length === 0) return false;

    // Remove all URLs from text and check remaining content
    let textWithoutUrls = text;

    // Sort links by start index in reverse order to avoid index shifting
    const sortedLinks = [...links].sort((a, b) => b.startIndex - a.startIndex);

    for (const link of sortedLinks) {
      textWithoutUrls = textWithoutUrls.slice(0, link.startIndex) +
                       textWithoutUrls.slice(link.endIndex);
    }

    // Check if remaining text is just whitespace or very short
    const remainingText = textWithoutUrls.trim();
    return remainingText.length === 0; // Only consider URL-only if there's literally no other text
  }

  /**
   * Get the first URL from text
   */
  static getFirstUrl(text: string): string | null {
    const links = this.extractLinks(text);
    return links.length > 0 ? links[0].url : null;
  }

  /**
   * Replace URLs in text with a replacement function
   */
  static replaceUrls(text: string, replaceFn: (url: string, originalText: string) => string): string {
    const links = this.extractLinks(text);
    if (links.length === 0) return text;
    
    let result = text;
    let offset = 0;
    
    for (const link of links) {
      const replacement = replaceFn(link.url, link.originalText);
      const startIndex = link.startIndex + offset;
      const endIndex = link.endIndex + offset;
      
      result = result.slice(0, startIndex) + replacement + result.slice(endIndex);
      offset += replacement.length - (link.endIndex - link.startIndex);
    }
    
    return result;
  }

  /**
   * Remove URLs from text
   */
  static removeUrls(text: string, replacement: string = ''): string {
    return this.replaceUrls(text, () => replacement);
  }

  /**
   * Check if text contains any URLs
   */
  static hasUrls(text: string): boolean {
    return this.extractLinks(text).length > 0;
  }

  /**
   * Get text content without URLs
   */
  static getTextWithoutUrls(text: string): string {
    return this.removeUrls(text, ' ').replace(/\s+/g, ' ').trim();
  }

  /**
   * Normalize URL by adding protocol if missing and cleaning up
   * Enhanced to handle complex URLs better
   */
  private static normalizeUrl(url: string): string {
    try {
      let normalized = url.trim();

      // Add protocol if missing
      if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
        normalized = 'https://' + normalized;
      }

      // Only remove trailing punctuation if it's clearly not part of the URL
      // Be more conservative to preserve complex URLs with special characters
      normalized = normalized.replace(/[.,;!?]+$/, '');

      // Handle edge cases for complex URLs
      // Don't remove characters that might be part of encoded parameters

      // Validate and return
      const urlObj = new URL(normalized);
      return urlObj.href; // Use href to get the properly formatted URL
    } catch {
      // If URL is invalid, try to salvage it
      let fallback = url.trim();
      if (!fallback.startsWith('http')) {
        fallback = 'https://' + fallback;
      }
      return fallback;
    }
  }

  /**
   * Check if a simple URL (without protocol) looks valid
   * Enhanced to handle more complex domain patterns
   */
  private static isValidSimpleUrl(url: string): boolean {
    // Must contain at least one dot
    if (!url.includes('.')) return false;

    // Remove query parameters and fragments for domain validation
    const domainPart = url.split(/[?#]/)[0];
    const parts = domainPart.split('.');
    if (parts.length < 2) return false;

    // Each domain part should have reasonable length
    if (parts.some(part => part.length === 0 || part.length > 63)) return false;

    // Should not end with common sentence endings that got caught
    if (/\.(com|org|net|edu|gov|mil|info|biz|us|uk|ca|au|de|fr|jp|cn)\s*[.,;!?]$/.test(domainPart)) {
      return false;
    }

    // Should have a valid TLD (expanded list for modern domains)
    const tld = parts[parts.length - 1].toLowerCase().replace(/[.,;!?]+$/, '');
    const commonTlds = [
      'com', 'org', 'net', 'edu', 'gov', 'mil', 'info', 'biz',
      'us', 'uk', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'in', 'br',
      'co', 'io', 'ai', 'app', 'dev', 'tech', 'online', 'site',
      'me', 'tv', 'cc', 'ly', 'be', 'it', 'es', 'ru', 'pl',
      'xyz', 'top', 'club', 'shop', 'blog', 'news', 'today'
    ];

    return commonTlds.includes(tld) || tld.length >= 2;
  }
}

// Convenience functions for common operations
export const extractLinks = (text: string) => LinkExtractor.extractLinks(text);
export const extractUrlStrings = (text: string) => LinkExtractor.extractUrlStrings(text);
export const isUrlOnlyMessage = (text: string) => LinkExtractor.isUrlOnlyMessage(text);
export const getFirstUrl = (text: string) => LinkExtractor.getFirstUrl(text);
export const hasUrls = (text: string) => LinkExtractor.hasUrls(text);
export const getTextWithoutUrls = (text: string) => LinkExtractor.getTextWithoutUrls(text);
