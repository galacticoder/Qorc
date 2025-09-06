/**
 * Link Preview Service
 * Fetches link previews securely through Tor proxy to protect client IP addresses
 */

import { handleNetworkError } from './secure-error-handler';

export interface LinkPreview {
  url: string;
  title?: string;
  description?: string;
  image?: string;
  siteName?: string;
  faviconUrl?: string;
  isError?: boolean;
  errorMessage?: string;
}

export interface LinkPreviewOptions {
  timeout?: number;
  userAgent?: string;
  maxRedirects?: number;
}

class LinkPreviewService {
  private cache = new Map<string, { preview: LinkPreview; timestamp: number }>();
  private readonly CACHE_TTL = 5 * 60 * 1000; // 5 minutes
  private readonly DEFAULT_TIMEOUT = 10000; // 10 seconds
  private readonly DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';

  /**
   * Fetch link preview securely through Tor (Electron environment only)
   */
  async fetchPreview(url: string, options: LinkPreviewOptions = {}): Promise<LinkPreview> {
    try {
      // Validate URL
      const normalizedUrl = this.normalizeUrl(url);
      if (!this.isValidUrl(normalizedUrl)) {
        return this.createErrorPreview(url, 'Invalid URL');
      }

      // Check cache first
      const cached = this.getFromCache(normalizedUrl);
      if (cached) {
        return cached;
      }

      // Check if we're in Electron environment (required for Tor proxy)
      if (typeof window === 'undefined' || !(window as any).electronAPI) {
        console.log('[LINK-PREVIEW] Electron API not available, window:', typeof window, 'electronAPI:', !!(window as any)?.electronAPI);
        return this.createErrorPreview(url, 'Link preview requires secure proxy environment');
      }

      // Fetch through Electron main process (which handles Tor proxy)
      const preview = await this.fetchThroughElectron(normalizedUrl, options);

      // Cache successful results
      if (!preview.isError) {
        this.setCache(normalizedUrl, preview);
      }

      return preview;
    } catch (error) {
      console.error('[LINK-PREVIEW] Error fetching preview:', error);
      return this.createErrorPreview(url, 'Failed to fetch link preview');
    }
  }

  /**
   * Extract all URLs from text content - enhanced for complex URLs
   */
  extractUrls(text: string): string[] {
    // Enhanced regex that handles complex URLs with encoded parameters, fragments, etc.
    const urlRegex = /(https?:\/\/(?:[-\w.])+(?::[0-9]+)?(?:\/(?:[\w\/_.\-~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})*)*(?:\?(?:[\w&=%.\-~!$'()*+,;:@/?]|%[0-9A-Fa-f]{2})*)?(?:#(?:[\w.\-~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})*)?)/gi;
    const matches = text.match(urlRegex) || [];
    return matches.map(url => this.normalizeUrl(url));
  }

  /**
   * Check if message contains only a URL (no other meaningful text)
   */
  isUrlOnlyMessage(text: string): boolean {
    const urls = this.extractUrls(text);
    if (urls.length === 0) return false;
    
    // Remove URLs from text and check if anything meaningful remains
    let textWithoutUrls = text;
    urls.forEach(url => {
      textWithoutUrls = textWithoutUrls.replace(url, '').trim();
    });
    
    // Consider message as URL-only if remaining text is very short or just whitespace
    return textWithoutUrls.length <= 3;
  }

  /**
   * Fetch link preview through Electron main process
   */
  private async fetchThroughElectron(url: string, options: LinkPreviewOptions): Promise<LinkPreview> {
    try {
      const electronAPI = (window as any).electronAPI;
      console.log('[LINK-PREVIEW] Electron API check:', !!electronAPI, !!electronAPI?.fetchLinkPreview);
      if (!electronAPI || !electronAPI.fetchLinkPreview) {
        throw new Error('Electron API not available');
      }

      console.log('[LINK-PREVIEW] Calling fetchLinkPreview for:', url);
      const result = await electronAPI.fetchLinkPreview(url, {
        timeout: options.timeout || this.DEFAULT_TIMEOUT,
        userAgent: options.userAgent || this.DEFAULT_USER_AGENT,
        maxRedirects: options.maxRedirects || 5
      });

      console.log('[LINK-PREVIEW] Raw result from Electron:', result);

      if (result.error) {
        console.log('[LINK-PREVIEW] Error in result:', result.error);
        return this.createErrorPreview(url, result.error);
      }

      const preview = {
        url,
        title: result.title || undefined,
        description: result.description || undefined,
        image: result.image || undefined,
        siteName: result.siteName || undefined,
        faviconUrl: result.faviconUrl || undefined
      };

      console.log('[LINK-PREVIEW] Processed preview:', preview);
      return preview;
    } catch (error) {
      console.error('[LINK-PREVIEW] Electron API error:', error);
      return this.createErrorPreview(url, 'Failed to fetch through secure proxy');
    }
  }

  /**
   * Normalize URL for consistency - enhanced for complex URLs
   */
  private normalizeUrl(url: string): string {
    try {
      let normalized = url.trim();

      // Add protocol if missing
      if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
        normalized = 'https://' + normalized;
      }

      // Only remove trailing punctuation if it's clearly not part of the URL
      // Be more conservative to preserve complex URLs with special characters
      normalized = normalized.replace(/[.,;!?]+$/, '');

      // Use URL constructor to properly format and validate
      const urlObj = new URL(normalized);
      return urlObj.href;
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
   * Validate URL format
   */
  private isValidUrl(url: string): boolean {
    try {
      const parsed = new URL(url);
      return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  }

  /**
   * Create error preview object
   */
  private createErrorPreview(url: string, errorMessage: string): LinkPreview {
    return {
      url,
      isError: true,
      errorMessage
    };
  }

  /**
   * Get preview from cache if not expired
   */
  private getFromCache(url: string): LinkPreview | null {
    const cached = this.cache.get(url);
    if (cached && Date.now() - cached.timestamp < this.CACHE_TTL) {
      return cached.preview;
    }
    
    // Clean expired cache entry
    if (cached) {
      this.cache.delete(url);
    }
    
    return null;
  }

  /**
   * Store preview in cache
   */
  private setCache(url: string, preview: LinkPreview): void {
    this.cache.set(url, {
      preview,
      timestamp: Date.now()
    });

    // Limit cache size
    if (this.cache.size > 100) {
      const oldestKey = this.cache.keys().next().value;
      this.cache.delete(oldestKey);
    }
  }

  /**
   * Clear all cached previews
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; keys: string[] } {
    return {
      size: this.cache.size,
      keys: Array.from(this.cache.keys())
    };
  }
}

// Export singleton instance
export const linkPreviewService = new LinkPreviewService();
