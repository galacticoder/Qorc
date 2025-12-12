import React, { useMemo, useCallback, useState, useEffect } from 'react';
import Linkify from 'linkify-react';
import { LinkExtractor } from '../../lib/link-extraction';

interface CachedPreview {
  readonly title: string | null;
  readonly description: string | null;
  readonly image: string | null;
  readonly siteName: string | null;
  readonly hostname: string | null;
  readonly url: string;
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
  readonly style?: React.CSSProperties;
  readonly previewsOnly?: boolean;
  readonly urls?: string[];
}

const CustomLinkPreview = React.memo(({ url, isCurrentUser, showFallbackLink }: { url: string; isCurrentUser: boolean; showFallbackLink?: boolean }) => {
  const [data, setData] = useState<CachedPreview | null>(linkPreviewCache.get(url) || null);
  const [loading, setLoading] = useState(!data);
  const [error, setError] = useState(false);

  useEffect(() => {
    if (data || !isValidUrl(url)) return;

    let mounted = true;

    if (linkPreviewCache.has(url)) {
      setData(linkPreviewCache.get(url)!);
      setLoading(false);
      return;
    }

    const fetchWithRedirects = async (targetUrl: string, attempt: number = 0): Promise<any> => {
      if (attempt >= 5) throw new Error('Too many redirects');

      if (typeof window === 'undefined' || typeof (window as any).electronAPI?.fetchLinkPreview !== 'function') {
        throw new Error('API unavailable');
      }

      const result = await (window as any).electronAPI.fetchLinkPreview(targetUrl, {
        timeout: 25000,
        maxRedirects: 5
      });

      if (result?.needsRedirect && result.redirectTo) {
        try {
          const nextUrl = new URL(result.redirectTo, targetUrl).href;
          return fetchWithRedirects(nextUrl, attempt + 1);
        } catch (e) {
          throw new Error('Invalid redirect URL');
        }
      }

      if (result?.error) throw new Error(result.error);

      return { ...result, originalUrl: url };
    };

    const fetchPreview = async () => {
      try {
        const result = await fetchWithRedirects(url);

        const preview: CachedPreview = {
          title: result.title || null,
          description: result.description || null,
          image: result.image || null,
          siteName: result.siteName || null,
          hostname: getHostname(result.url || url),
          url: url
        };

        if (mounted) {
          linkPreviewCache.set(url, preview);
          cleanupCache();
          setData(preview);
          setLoading(false);
        }
      } catch (err) {
        if (mounted) {
          setError(true);
          setLoading(false);
        }
      }
    };

    fetchPreview();

    return () => { mounted = false; };
  }, [url, data]);

  const handleClick = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if ((window as any).electronAPI?.openExternal) {
      (window as any).electronAPI.openExternal(url);
    } else {
      window.open(url, '_blank', 'noopener,noreferrer');
    }
  };

  if (error || (!loading && !data)) {
    if (showFallbackLink) {
      return (
        <div
          className="rounded-lg border overflow-hidden w-full"
          style={{
            borderColor: 'var(--color-border)',
            backgroundColor: 'var(--color-surface)',
            width: '100%',
            maxWidth: 'min(var(--message-bubble-max-width), 320px)',
            minWidth: '240px',
            userSelect: 'none'
          }}
        >
          <div className="p-3 flex flex-col gap-1">
            <a
              href={url}
              onClick={handleClick}
              className="underline decoration-1 underline-offset-2 transition-colors break-all cursor-pointer text-sm"
              style={{
                color: 'var(--color-accent-primary)'
              }}
            >
              {url}
            </a>
            <span className="text-[10px] uppercase tracking-wider text-muted-foreground/70 font-medium">
              {getHostname(url) ?? url}
            </span>
          </div>
        </div>
      );
    }
    return null;
  }

  if (loading) {
    return (
      <div
        className="animate-pulse rounded-lg border overflow-hidden w-full"
        style={{
          borderColor: 'var(--color-border)',
          backgroundColor: 'var(--color-surface)',
          width: '100%',
          maxWidth: 'min(var(--message-bubble-max-width), 320px)',
          minWidth: '240px',
          userSelect: 'none'
        }}
      >
        <div className="w-full h-32 md:h-40 bg-muted/20 border-b" style={{ borderColor: 'var(--color-border)' }} />
        <div className="p-3 flex flex-col gap-1">
          <div className="h-4 bg-muted/20 rounded w-3/4" />
          <div className="h-3 bg-muted/20 rounded w-full" />
          <div className="h-3 bg-muted/20 rounded w-1/2" />
          <div className="flex items-center gap-2 mt-1">
            <div className="h-2.5 bg-muted/20 rounded w-24" />
          </div>
        </div>
      </div>
    );
  }

  const { title, description, image, hostname } = data!;

  return (
    <div
      onClick={handleClick}
      className="group cursor-pointer rounded-lg border overflow-hidden transition-all hover:bg-muted/10 w-full"
      style={{
        borderColor: 'var(--color-border)',
        backgroundColor: 'var(--color-surface)',
        width: '100%',
        maxWidth: 'min(var(--message-bubble-max-width), 320px)',
        minWidth: '240px',
        userSelect: 'none'
      }}
    >
      {image && (
        <div
          className="w-full h-32 md:h-40 bg-cover bg-center bg-no-repeat relative border-b"
          style={{
            backgroundImage: `url('${image}')`,
            borderColor: 'var(--color-border)'
          }}
        />
      )}
      <div className="p-3 flex flex-col gap-1">
        {title && (
          <h3 className="font-semibold text-sm leading-tight text-foreground">
            {title}
          </h3>
        )}
        {description && (
          <p className="text-xs text-muted-foreground leading-relaxed">
            {description}
          </p>
        )}
        <div className="flex items-center gap-2 mt-1">
          {image && !title && !description && (
            <span className="text-xs text-muted-foreground break-all">{url}</span>
          )}
          <span className="text-[10px] uppercase tracking-wider text-muted-foreground/70 font-medium">
            {hostname}
          </span>
        </div>
      </div>
    </div>
  );
});

const LinkifyWithPreviewsComponent: React.FC<LinkifyWithPreviewsProps> = ({
  children,
  options = {},
  showPreviews = true,
  isCurrentUser = false,
  className,
  style,
  previewsOnly = false,
  urls: providedUrls
}) => {
  /* Restore URL decoding */
  const urls = useMemo(() => {
    const baseUrls = providedUrls ?? LinkExtractor.extractUrlStrings(children);
    return baseUrls
      .map(url => url.replace(/&amp;/g, '&'))
      .filter(isValidUrl);
  }, [children, providedUrls]);

  const isUrlOnly = useMemo(() => LinkExtractor.isUrlOnlyMessage(children), [children]);

  const handleLinkClick = useCallback((url: string, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if ((window as any).electronAPI?.openExternal) {
      (window as any).electronAPI.openExternal(url);
    } else {
      window.open(url, '_blank', 'noopener,noreferrer');
    }
  }, []);

  const enhancedOptions = useMemo(() => ({
    rel: "noopener noreferrer",
    ...options,
    render: {
      url: ({ attributes, content }: any) => {
        return (
          <a
            href={attributes.href}
            onClick={(e) => handleLinkClick(attributes.href, e)}
            className="underline decoration-1 underline-offset-2 transition-colors cursor-pointer"
            style={{
              color: isCurrentUser ? '#ffffff' : 'var(--color-accent-primary)',
              textDecorationColor: isCurrentUser ? '#ffffff' : 'var(--color-accent-primary)',
            }}
          >
            {content}
          </a>
        );
      }
    }
  }), [options, handleLinkClick, isCurrentUser]);

  if (previewsOnly && showPreviews && urls.length > 0) {
    return (
      <div className={className} style={style}>
        <div className="space-y-3">
          {urls.slice(0, 3).map(url => (
            <CustomLinkPreview key={url} url={url} isCurrentUser={!!isCurrentUser} showFallbackLink={true} />
          ))}
        </div>
      </div>
    );
  }

  if (isUrlOnly && showPreviews && urls.length > 0) {
    return (
      <div className={className} style={style}>
        <div className="space-y-3">
          {urls.map(url => (
            <CustomLinkPreview key={url} url={url} isCurrentUser={!!isCurrentUser} showFallbackLink={true} />
          ))}
        </div>
      </div>
    );
  }

  if (showPreviews && urls.length > 0) {
    return (
      <div className={className} style={style}>
        <div className="break-words whitespace-pre-wrap">
          <Linkify options={enhancedOptions}>
            {children}
          </Linkify>
        </div>
        <div className="mt-2 space-y-3">
          {urls.slice(0, 3).map(url => (
            <CustomLinkPreview key={url} url={url} isCurrentUser={!!isCurrentUser} />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className={className} style={style}>
      <Linkify options={enhancedOptions}>
        {children}
      </Linkify>
    </div>
  );
};

export const LinkifyWithPreviews = React.memo(LinkifyWithPreviewsComponent);
