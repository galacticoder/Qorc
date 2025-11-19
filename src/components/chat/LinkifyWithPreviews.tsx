import React, { useMemo, useCallback } from 'react';
import Linkify from 'linkify-react';
import { LinkPreview } from '@dhaiwat10/react-link-preview';
import { LinkExtractor } from '../../lib/link-extraction';

interface CachedPreview {
  readonly title: string | null;
  readonly description: string | null;
  readonly image: string | null;
  readonly siteName: string | null;
  readonly hostname: string | null;
}

const linkPreviewCache = new Map<string, CachedPreview>();

const MAX_CACHE_SIZE = 100;
const MAX_URL_LENGTH = 2048;
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

const cleanupCache = (): void => {
  if (linkPreviewCache.size > MAX_CACHE_SIZE) {
    const entries = Array.from(linkPreviewCache.entries());
    const toRemove = entries.slice(0, Math.floor(entries.length / 2));
    toRemove.forEach(([key]) => linkPreviewCache.delete(key));
  }
};

const isValidUrl = (urlString: string): boolean => {
  if (typeof urlString !== 'string' || urlString.length === 0 || urlString.length > MAX_URL_LENGTH) {
    return false;
  }
  try {
    const url = new URL(urlString);
    return ALLOWED_PROTOCOLS.has(url.protocol);
  } catch {
    return false;
  }
};

const getHostname = (urlString: string): string | null => {
  try {
    const url = new URL(urlString);
    return url.hostname;
  } catch {
    return null;
  }
};

interface LinkifyWithPreviewsProps {
  readonly children: string;
  readonly options?: Record<string, unknown>;
  readonly showPreviews?: boolean;
  readonly isCurrentUser?: boolean;
  readonly className?: string;
  readonly previewsOnly?: boolean;
}

const LinkifyWithPreviewsComponent: React.FC<LinkifyWithPreviewsProps> = ({
  children,
  options = {},
  showPreviews = true,
  isCurrentUser = false,
  className,
  previewsOnly = false
}) => {
  const urls = useMemo(() => {
    const extracted = LinkExtractor.extractUrlStrings(children);
    return extracted.filter(isValidUrl);
  }, [children]);

  const isUrlOnly = useMemo(() => LinkExtractor.isUrlOnlyMessage(children), [children]);

  const customFetcher = useCallback(async (url: string): Promise<CachedPreview | null> => {
    if (!isValidUrl(url)) {
      return null;
    }

    if (linkPreviewCache.has(url)) {
      return linkPreviewCache.get(url) ?? null;
    }

    if (typeof window === 'undefined' || typeof (window as any).electronAPI?.fetchLinkPreview !== 'function') {
      return null;
    }

    try {
      const result = await (window as any).electronAPI.fetchLinkPreview(url, {
        timeout: 15000,
        maxRedirects: 5
      });

      if (result?.error) {
        return null;
      }

      const preview: CachedPreview = {
        title: typeof result?.title === 'string' ? result.title : null,
        description: typeof result?.description === 'string' ? result.description : null,
        image: typeof result?.image === 'string' ? result.image : null,
        siteName: typeof result?.siteName === 'string' ? result.siteName : null,
        hostname: getHostname(url)
      };

      linkPreviewCache.set(url, preview);
      cleanupCache();

      return preview;
    } catch {
      return null;
    }
  }, []);

  const handleLinkClick = useCallback(async (url: string, e: React.MouseEvent): Promise<void> => {
    e.preventDefault();
    e.stopPropagation();

    if (!isValidUrl(url)) {
      return;
    }

    try {
      await (window as any).electronAPI.openExternal(url);
    } catch {
      // In Electron-only mode, ignore if openExternal fails
    }
  }, []);

  const enhancedOptions = useMemo(() => ({
    rel: "noopener noreferrer",
    ...options,
    render: {
      url: ({ attributes, content }: { attributes: { href: string }; content: string }) => {
        const url = attributes.href;

        return (
          <a
            href="#"
            onClick={(e) => handleLinkClick(url, e)}
            onAuxClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
            }}
            onContextMenu={(e) => {
              e.preventDefault();
            }}
            className="underline decoration-1 underline-offset-2 transition-colors cursor-pointer"
            style={{
              color: isCurrentUser ? '#ffffff' : 'var(--color-accent-primary)',
              textDecorationColor: isCurrentUser ? '#ffffff' : 'var(--color-accent-primary)',
            }}
            role="link"
            tabIndex={0}
            aria-label={`Open link: ${url}`}
          >
            {content}
          </a>
        );
      }
    }
  }), [options, handleLinkClick, isCurrentUser]);

  const renderLinkPreview = useCallback((url: string, size: 'large' | 'small' = 'large') => {
    const hostname = getHostname(url);
    const width = size === 'large' ? '400px' : '320px';
    const imageHeight = size === 'large' ? '160px' : '120px';
    const descriptionLength = size === 'large' ? 120 : 80;
    const borderRadius = size === 'large' ? '12px' : '8px';

    return (
      <div
        key={url}
        onClick={(e) => handleLinkClick(url, e)}
        className="cursor-pointer link-preview-container"
        style={{ position: 'relative' }}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            handleLinkClick(url, e as any);
          }
        }}
        aria-label={`Open link: ${url}`}
      >
        <div style={{ pointerEvents: 'none' }}>
          <LinkPreview
            url={url}
            width={width}
            height="auto"
            borderRadius={borderRadius}
            backgroundColor={isCurrentUser ? '#1c1c1e' : 'transparent'}
            primaryTextColor={isCurrentUser ? '#ffffff' : 'inherit'}
            secondaryTextColor={isCurrentUser ? '#d1d5db' : 'inherit'}
            borderColor={isCurrentUser ? '#38383a' : 'transparent'}
            showLoader={true}
            openInNewTab={false}
            fetcher={customFetcher}
            descriptionLength={descriptionLength}
            imageHeight={imageHeight}
            showPlaceholderIfNoImage={true}
            placeholderImageSrc="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 24 24' fill='none' stroke='%23666' stroke-width='1' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='3' y='3' width='18' height='18' rx='2' ry='2'/%3E%3Ccircle cx='8.5' cy='8.5' r='1.5'/%3E%3Cpolyline points='21,15 16,10 5,21'/%3E%3C/svg%3E"
            fallback={
              <div
                className={`rounded-${size === 'large' ? 'xl' : 'lg'} overflow-hidden max-w-${size === 'large' ? 'md' : 'sm'} cursor-pointer hover:scale-[1.01] transition-all duration-200`}
                style={{
                  backgroundColor: isCurrentUser ? '#1c1c1e' : 'var(--color-surface)',
                  border: `1px solid ${isCurrentUser ? '#38383a' : 'var(--color-border)'}`,
                  boxShadow: size === 'large' ? '0 4px 16px rgba(0, 0, 0, 0.1)' : '0 2px 8px rgba(0, 0, 0, 0.1)'
                }}
                onClick={(e) => handleLinkClick(url, e)}
              >
                <div className={`p-${size === 'large' ? '3' : '2'}`}>
                  <div className="flex items-center space-x-${size === 'large' ? '3' : '2'}">
                    <div
                      className={`w-${size === 'large' ? '8' : '6'} h-${size === 'large' ? '8' : '6'} rounded${size === 'large' ? '-lg' : ''} flex items-center justify-center flex-shrink-0`}
                      style={{ backgroundColor: isCurrentUser ? '#374151' : 'var(--color-panel)' }}
                      aria-hidden="true"
                    >
                      <svg
                        className={`w-${size === 'large' ? '4' : '3'} h-${size === 'large' ? '4' : '3'}`}
                        style={{ color: isCurrentUser ? '#9ca3af' : 'var(--color-text-secondary)' }}
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                      </svg>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div
                        className={`font-medium text-${size === 'large' ? 'sm' : 'xs'} truncate`}
                        style={{ color: isCurrentUser ? '#ffffff' : 'var(--color-text-primary)' }}
                      >
                        {url}
                      </div>
                      {hostname && (
                        <div
                          className="text-xs truncate mt-0.5"
                          style={{ color: isCurrentUser ? '#d1d5db' : 'var(--color-text-secondary)' }}
                        >
                          {hostname}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            }
          />
        </div>
      </div>
    );
  }, [isCurrentUser, customFetcher, handleLinkClick]);

  const previewComponents = useMemo(() => {
    if (!isUrlOnly || !showPreviews || urls.length === 0) {
      return null;
    }
    return urls.slice(0, 3).map((url) => renderLinkPreview(url, 'large'));
  }, [urls, isUrlOnly, showPreviews, renderLinkPreview]);

  if (previewComponents) {
    return (
      <div className="space-y-3">
        {previewComponents}
      </div>
    );
  }

  if (previewsOnly && showPreviews && urls.length > 0) {
    return (
      <div className={className}>
        <div className="space-y-2">
          {urls.slice(0, 2).map((url) => renderLinkPreview(url, 'small'))}
        </div>
      </div>
    );
  }

  if (showPreviews && urls.length > 0) {
    return (
      <div className={className}>
        <div className="space-y-2 mb-3">
          {urls.slice(0, 2).map((url) => renderLinkPreview(url, 'small'))}
        </div>
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

export const LinkifyWithPreviews = React.memo(LinkifyWithPreviewsComponent, (prevProps, nextProps) => {
  return (
    prevProps.children === nextProps.children &&
    prevProps.showPreviews === nextProps.showPreviews &&
    prevProps.isCurrentUser === nextProps.isCurrentUser &&
    prevProps.className === nextProps.className &&
    prevProps.previewsOnly === nextProps.previewsOnly &&
    JSON.stringify(prevProps.options) === JSON.stringify(nextProps.options)
  );
});
