/**
 * Enhanced Linkify Component with Link Previews
 * Uses @dhaiwat10/react-link-preview for beautiful link preview cards
 */

import React, { useMemo, useCallback } from 'react';
import Linkify from 'linkify-react';
import { LinkPreview } from '@dhaiwat10/react-link-preview';
import { LinkExtractor } from '../../lib/link-extraction';

// Cache for link preview data to prevent re-fetching
const linkPreviewCache = new Map<string, any>();

// Clean up old cache entries to prevent memory leaks
const MAX_CACHE_SIZE = 100;
const cleanupCache = () => {
  if (linkPreviewCache.size > MAX_CACHE_SIZE) {
    const entries = Array.from(linkPreviewCache.entries());
    // Remove oldest entries (first half)
    const toRemove = entries.slice(0, Math.floor(entries.length / 2));
    toRemove.forEach(([key]) => linkPreviewCache.delete(key));
  }
};

interface LinkifyWithPreviewsProps {
  children: string;
  options?: any;
  showPreviews?: boolean;
  isCurrentUser?: boolean;
  className?: string;
  previewsOnly?: boolean; // When true, only show previews, not the text
}

const LinkifyWithPreviewsComponent: React.FC<LinkifyWithPreviewsProps> = ({
  children,
  options = {},
  showPreviews = true,
  isCurrentUser = false,
  className,
  previewsOnly = false
}) => {

  const urls = useMemo(() => LinkExtractor.extractUrlStrings(children), [children]);
  const isUrlOnly = useMemo(() => LinkExtractor.isUrlOnlyMessage(children), [children]);

  // Memoized custom fetcher that uses caching to prevent re-fetches
  const customFetcher = useCallback(async (url: string) => {
    try {
      // Check cache first
      if (linkPreviewCache.has(url)) {
        console.log('[LINK-PREVIEW] Using cached preview for:', url);
        return linkPreviewCache.get(url);
      }

      // Check if we're in Electron environment
      if (typeof window === 'undefined' || !(window as any).electronAPI?.fetchLinkPreview) {
        console.log('[LINK-PREVIEW] Electron API not available');
        return null;
      }

      console.log('[LINK-PREVIEW] Fetching preview for:', url);
      const result = await (window as any).electronAPI.fetchLinkPreview(url, {
        timeout: 15000,
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        maxRedirects: 5
      });

      console.log('[LINK-PREVIEW] Raw result from Electron API:', result);

      if (result?.error) {
        console.log('[LINK-PREVIEW] Error in result:', result.error);
        return null;
      }

      // Transform the result to match the expected format
      const preview = {
        title: result?.title || null,
        description: result?.description || null,
        image: result?.image || null,
        siteName: result?.siteName || null,
        hostname: (() => {
          try {
            return new URL(url).hostname;
          } catch {
            return null;
          }
        })()
      };

      console.log('[LINK-PREVIEW] Successfully fetched preview:', preview);
      console.log('[LINK-PREVIEW] Image URL:', preview.image);
      console.log('[LINK-PREVIEW] Title:', preview.title);
      console.log('[LINK-PREVIEW] Description:', preview.description);

      // Cache the result to prevent re-fetching
      linkPreviewCache.set(url, preview);
      cleanupCache(); // Prevent memory leaks

      return preview;
    } catch (error) {
      console.error('[LINK-PREVIEW] Custom fetcher error:', error);
      return null;
    }
  }, []); // Empty dependency array since we don't want this to change

  // Enhanced linkify options that work with existing setup and match linkify's default styling
  const enhancedOptions = {
    // Remove target="_blank" since we handle clicks manually
    rel: "noopener noreferrer",
    ...options,
    // Custom render function for links
    render: {
      url: ({ attributes, content }: { attributes: any; content: string }) => {
        const url = attributes.href;

        return (
          <a
            href="javascript:void(0)" // Completely prevent navigation
            onClick={async (e) => {
              e.preventDefault();
              e.stopPropagation();
              if (e.stopImmediatePropagation) {
                e.stopImmediatePropagation();
              }

              // Always open in external browser
              if (typeof window !== 'undefined' && (window as any).electronAPI?.openExternal) {
                try {
                  await (window as any).electronAPI.openExternal(url);
                } catch (error) {
                  console.error('[LINK-CLICK] electronAPI failed:', error);
                  // Fallback to system default browser
                  window.open(url, '_blank', 'noopener,noreferrer');
                }
              } else {
                // Fallback to system default browser
                window.open(url, '_blank', 'noopener,noreferrer');
              }
              return false; // Extra prevention
            }}
            onAuxClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              return false;
            }}
            onContextMenu={(e) => {
              e.preventDefault();
              return false;
            }}
            className="underline decoration-1 underline-offset-2 transition-colors cursor-pointer"
            style={{
              // Use white color for links in both current user and other user messages for consistency
              color: isCurrentUser ? '#ffffff' : '#ffffff',
              textDecorationColor: isCurrentUser ? '#ffffff' : '#ffffff',
            }}
          >
            {content}
          </a>
        );
      }
    }
  };

  // Memoized preview components to prevent unnecessary re-renders
  const previewComponents = useMemo(() => {
    if (!isUrlOnly || !showPreviews || urls.length === 0) {
      return null;
    }

    return urls.slice(0, 3).map((url, index) => (
          <div
            key={url}
            onClick={async (e) => {
              e.preventDefault();
              e.stopPropagation();
              if (e.stopImmediatePropagation) {
                e.stopImmediatePropagation();
              }

              // Always open in external browser
              if (typeof window !== 'undefined' && (window as any).electronAPI?.openExternal) {
                try {
                  await (window as any).electronAPI.openExternal(url);
                } catch (error) {
                  console.error('[LINK-CLICK] electronAPI failed:', error);
                  // Fallback to system default browser
                  window.open(url, '_blank', 'noopener,noreferrer');
                }
              } else {
                // Fallback to system default browser
                window.open(url, '_blank', 'noopener,noreferrer');
              }
              return false;
            }}
            className="cursor-pointer link-preview-container"
            style={{ position: 'relative' }}
          >
            <div style={{ pointerEvents: 'none' }}>
              <LinkPreview
                url={url}
                width="400px"
                height="auto"
                borderRadius="12px"
                backgroundColor={isCurrentUser ? '#1c1c1e' : '#2d3748'}
                primaryTextColor={isCurrentUser ? '#ffffff' : '#ffffff'}
                secondaryTextColor={isCurrentUser ? '#d1d5db' : '#cbd5e0'}
                borderColor={isCurrentUser ? '#38383a' : '#4a5568'}
                showLoader={true}
                openInNewTab={false}
                fetcher={customFetcher}
                descriptionLength={120}
                imageHeight="160px"
                showPlaceholderIfNoImage={true}
                placeholderImageSrc="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 24 24' fill='none' stroke='%23666' stroke-width='1' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='3' y='3' width='18' height='18' rx='2' ry='2'/%3E%3Ccircle cx='8.5' cy='8.5' r='1.5'/%3E%3Cpolyline points='21,15 16,10 5,21'/%3E%3C/svg%3E"
              fallback={
              <div
                className="rounded-xl overflow-hidden max-w-md cursor-pointer hover:scale-[1.02] transition-all duration-200"
                style={{
                  backgroundColor: isCurrentUser ? '#1c1c1e' : '#2d3748',
                  border: `1px solid ${isCurrentUser ? '#38383a' : '#4a5568'}`,
                  boxShadow: '0 4px 16px rgba(0, 0, 0, 0.1)'
                }}
                onClick={async (e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  if (e.stopImmediatePropagation) {
                    e.stopImmediatePropagation();
                  }
                  // Always open in external browser
                  if (typeof window !== 'undefined' && (window as any).electronAPI?.openExternal) {
                    try {
                      await (window as any).electronAPI.openExternal(url);
                    } catch {
                      // Fallback to system default browser
                      window.open(url, '_blank', 'noopener,noreferrer');
                    }
                  } else {
                    // Fallback to system default browser
                    window.open(url, '_blank', 'noopener,noreferrer');
                  }
                  return false;
                }}
              >
                <div className="p-3">
                  <div className="flex items-center space-x-3">
                    <div
                      className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
                      style={{ backgroundColor: isCurrentUser ? '#374151' : '#4a5568' }}
                    >
                      <svg
                        className="w-4 h-4"
                        style={{ color: isCurrentUser ? '#9ca3af' : '#cbd5e0' }}
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                      </svg>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div
                        className="font-medium text-sm truncate"
                        style={{ color: isCurrentUser ? '#ffffff' : '#ffffff' }}
                      >
                        {url}
                      </div>
                      <div
                        className="text-xs truncate mt-0.5"
                        style={{ color: isCurrentUser ? '#d1d5db' : '#cbd5e0' }}
                      >
                        {new URL(url).hostname}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            }
            />
            </div>
          </div>
        ));
  }, [urls, isUrlOnly, showPreviews, isCurrentUser, customFetcher]);

  // For URL-only messages, show rich preview cards using react-link-preview
  if (previewComponents) {
    return (
      <div className="space-y-3">
        {previewComponents}
      </div>
    );
  }

  // If previewsOnly is true, only show the link previews without text
  if (previewsOnly && showPreviews && urls.length > 0) {
    return (
      <div className={className}>
        <div className="space-y-2">
          {urls.slice(0, 2).map((url, index) => (
            <div
              key={url}
              onClick={async (e) => {
                e.preventDefault();
                e.stopPropagation();
                if (e.stopImmediatePropagation) {
                  e.stopImmediatePropagation();
                }
                // Always open in external browser
                if (typeof window !== 'undefined' && (window as any).electronAPI?.openExternal) {
                  try {
                    await (window as any).electronAPI.openExternal(url);
                  } catch {
                    // Fallback to system default browser
                    window.open(url, '_blank', 'noopener,noreferrer');
                  }
                } else {
                  // Fallback to system default browser
                  window.open(url, '_blank', 'noopener,noreferrer');
                }
                return false;
              }}
              className="cursor-pointer link-preview-container"
            >
              <div style={{ pointerEvents: 'none' }}>
                <LinkPreview
                url={url}
                width="320px"
                height="auto"
                borderRadius="8px"
                backgroundColor={isCurrentUser ? '#1c1c1e' : '#2d3748'}
                primaryTextColor={isCurrentUser ? '#ffffff' : '#ffffff'}
                secondaryTextColor={isCurrentUser ? '#d1d5db' : '#cbd5e0'}
                borderColor={isCurrentUser ? '#38383a' : '#4a5568'}
                showLoader={true}
                openInNewTab={false}
                fetcher={customFetcher}
                descriptionLength={80}
                imageHeight="120px"
                showPlaceholderIfNoImage={true}
                placeholderImageSrc="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 24 24' fill='none' stroke='%23666' stroke-width='1' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='3' y='3' width='18' height='18' rx='2' ry='2'/%3E%3Ccircle cx='8.5' cy='8.5' r='1.5'/%3E%3Cpolyline points='21,15 16,10 5,21'/%3E%3C/svg%3E"
                fallback={
                <div
                  className="rounded-lg overflow-hidden max-w-sm cursor-pointer hover:scale-[1.01] transition-all duration-200"
                  style={{
                    backgroundColor: isCurrentUser ? '#1c1c1e' : '#2d3748',
                    border: `1px solid ${isCurrentUser ? '#38383a' : '#4a5568'}`,
                    boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)'
                  }}
                  onClick={async (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    if (e.stopImmediatePropagation) {
                      e.stopImmediatePropagation();
                    }
                    // Always open in external browser
                    if (typeof window !== 'undefined' && (window as any).electronAPI?.openExternal) {
                      try {
                        await (window as any).electronAPI.openExternal(url);
                      } catch {
                        // Fallback to system default browser
                        window.open(url, '_blank', 'noopener,noreferrer');
                      }
                    } else {
                      // Fallback to system default browser
                      window.open(url, '_blank', 'noopener,noreferrer');
                    }
                    return false;
                  }}
                >
                  <div className="p-2">
                    <div className="flex items-center space-x-2">
                      <div
                        className="w-6 h-6 rounded flex items-center justify-center flex-shrink-0"
                        style={{ backgroundColor: isCurrentUser ? '#374151' : '#4a5568' }}
                      >
                        <svg
                          className="w-3 h-3"
                          style={{ color: isCurrentUser ? '#9ca3af' : '#cbd5e0' }}
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                        </svg>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div
                          className="font-medium text-xs truncate"
                          style={{ color: isCurrentUser ? '#ffffff' : '#ffffff' }}
                        >
                          {url}
                        </div>
                        <div
                          className="text-xs truncate mt-0.5"
                          style={{ color: isCurrentUser ? '#d1d5db' : '#cbd5e0' }}
                        >
                          {new URL(url).hostname}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              }
              />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  // For regular messages with text + links, show preview above the message
  if (showPreviews && urls.length > 0) {
    return (
      <div className={className}>
        {/* Link previews above the message */}
        <div className="space-y-2 mb-3">
          {urls.slice(0, 2).map((url, index) => (
            <div
              key={url}
              onClick={async (e) => {
                e.preventDefault();
                e.stopPropagation();
                if (e.stopImmediatePropagation) {
                  e.stopImmediatePropagation();
                }
                // Always open in external browser
                if (typeof window !== 'undefined' && (window as any).electronAPI?.openExternal) {
                  try {
                    await (window as any).electronAPI.openExternal(url);
                  } catch {
                    // Fallback to system default browser
                    window.open(url, '_blank', 'noopener,noreferrer');
                  }
                } else {
                  // Fallback to system default browser
                  window.open(url, '_blank', 'noopener,noreferrer');
                }
                return false;
              }}
              className="cursor-pointer link-preview-container"
            >
              <div style={{ pointerEvents: 'none' }}>
                <LinkPreview
                url={url}
                width="320px"
                height="auto"
                borderRadius="8px"
                backgroundColor={isCurrentUser ? '#1c1c1e' : '#2d3748'}
                primaryTextColor={isCurrentUser ? '#ffffff' : '#ffffff'}
                secondaryTextColor={isCurrentUser ? '#d1d5db' : '#cbd5e0'}
                borderColor={isCurrentUser ? '#38383a' : '#4a5568'}
                showLoader={true}
                openInNewTab={false}
                fetcher={customFetcher}
                descriptionLength={80}
                imageHeight="120px"
                showPlaceholderIfNoImage={true}
                placeholderImageSrc="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 24 24' fill='none' stroke='%23666' stroke-width='1' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='3' y='3' width='18' height='18' rx='2' ry='2'/%3E%3Ccircle cx='8.5' cy='8.5' r='1.5'/%3E%3Cpolyline points='21,15 16,10 5,21'/%3E%3C/svg%3E"
                fallback={
                <div
                  className="rounded-lg overflow-hidden max-w-sm cursor-pointer hover:scale-[1.01] transition-all duration-200"
                  style={{
                    backgroundColor: isCurrentUser ? '#1c1c1e' : '#2d3748',
                    border: `1px solid ${isCurrentUser ? '#38383a' : '#4a5568'}`,
                    boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)'
                  }}
                  onClick={async (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    if (e.stopImmediatePropagation) {
                      e.stopImmediatePropagation();
                    }
                    // Always open in external browser
                    if (typeof window !== 'undefined' && (window as any).electronAPI?.openExternal) {
                      try {
                        await (window as any).electronAPI.openExternal(url);
                      } catch {
                        // Fallback to system default browser
                        window.open(url, '_blank', 'noopener,noreferrer');
                      }
                    } else {
                      // Fallback to system default browser
                      window.open(url, '_blank', 'noopener,noreferrer');
                    }
                    return false;
                  }}
                >
                  <div className="p-2">
                    <div className="flex items-center space-x-2">
                      <div
                        className="w-6 h-6 rounded flex items-center justify-center flex-shrink-0"
                        style={{ backgroundColor: isCurrentUser ? '#374151' : '#4a5568' }}
                      >
                        <svg
                          className="w-3 h-3"
                          style={{ color: isCurrentUser ? '#9ca3af' : '#cbd5e0' }}
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                        </svg>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div
                          className="font-medium text-xs truncate"
                          style={{ color: isCurrentUser ? '#ffffff' : '#ffffff' }}
                        >
                          {url}
                        </div>
                        <div
                          className="text-xs truncate mt-0.5"
                          style={{ color: isCurrentUser ? '#d1d5db' : '#cbd5e0' }}
                        >
                          {new URL(url).hostname}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              }
              />
              </div>
            </div>
          ))}
        </div>

        {/* Message text with clickable links */}
        <div>
          <Linkify options={enhancedOptions}>
            {children}
          </Linkify>
        </div>
      </div>
    );
  }

  // For messages without links or when previews are disabled
  return (
    <div className={className}>
      <Linkify options={enhancedOptions}>
        {children}
      </Linkify>
    </div>
  );
};

// Memoize the component to prevent unnecessary re-renders
export const LinkifyWithPreviews = React.memo(LinkifyWithPreviewsComponent, (prevProps, nextProps) => {
  // Custom comparison function to prevent re-renders when props haven't changed
  return (
    prevProps.children === nextProps.children &&
    prevProps.showPreviews === nextProps.showPreviews &&
    prevProps.isCurrentUser === nextProps.isCurrentUser &&
    prevProps.className === nextProps.className &&
    prevProps.previewsOnly === nextProps.previewsOnly &&
    JSON.stringify(prevProps.options) === JSON.stringify(nextProps.options)
  );
});