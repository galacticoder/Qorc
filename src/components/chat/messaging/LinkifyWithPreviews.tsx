import React, { useMemo, useCallback, useState, useEffect } from 'react';
import Linkify from 'linkify-react';
import { LinkExtractor } from '../../../lib/link-extraction';
import { MAX_CACHE_SIZE, MAX_URL_LENGTH, ALLOWED_PROTOCOLS, IPV4_REGEX, IPV6_REGEX } from '@/lib/constants';
import { link, system } from '../../../lib/tauri-bindings';

// Cached preview metadata
interface CachedPreview {
  readonly title: string | null;
  readonly description: string | null;
  readonly image: string | null;
  readonly siteName: string | null;
  readonly hostname: string | null;
  readonly url: string;
}

const linkPreviewCache = new Map<string, CachedPreview>();

// Trim cache when it grows too large
const cleanupCache = (): void => {
  if (linkPreviewCache.size > MAX_CACHE_SIZE) {
    const entries = Array.from(linkPreviewCache.entries());
    const toRemove = entries.slice(0, Math.floor(entries.length / 2));
    toRemove.forEach(([key]) => linkPreviewCache.delete(key));
  }
};

// Detect localhost or private hosts to skip previews
const isPrivateOrLocalHost = (hostname: string): boolean => {
  const lower = hostname.toLowerCase();
  if (lower === 'localhost' || lower.endsWith('.local')) return true;
  if (IPV4_REGEX.test(lower)) return true;
  if (IPV6_REGEX.test(lower)) return true;
  return false;
};

// Validate URL protocol, length, and host
const isValidUrl = (urlString: string): boolean => {
  if (typeof urlString !== 'string' || urlString.length === 0 || urlString.length > MAX_URL_LENGTH) {
    return false;
  }
  try {
    const url = new URL(urlString);
    if (!ALLOWED_PROTOCOLS.has(url.protocol)) return false;
    const hostname = url.hostname || '';
    if (isPrivateOrLocalHost(hostname)) return false;
    return true;
  } catch {
    return false;
  }
};

// Extract hostname from URL
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
  readonly onRendered?: () => void;
}

// Open a URL
const openInBrowser = (url: string): void => {
  void (async () => {
    try {
      const ok = await system.openExternal(url);
      if (ok === false) window.open(url, '_blank', 'noopener,noreferrer');
    } catch {
      window.open(url, '_blank', 'noopener,noreferrer');
    }
  })();
};

const clamp2: React.CSSProperties = {
  display: '-webkit-box',
  WebkitLineClamp: 2,
  WebkitBoxOrient: 'vertical',
  overflow: 'hidden',
  overflowWrap: 'anywhere',
  wordBreak: 'break-word',
};

const cardBase: React.CSSProperties = {
  width: '100%',
  maxWidth: '100%',
  minWidth: 0,
  userSelect: 'none',
  borderColor: 'var(--qor-border)',
  backgroundColor: 'var(--color-surface)',
};

// Render a single link preview
const CustomLinkPreview = React.memo(({ url, isCurrentUser: _isCurrentUser, showFallbackLink }: { url: string; isCurrentUser: boolean; showFallbackLink?: boolean }) => {
  const [data, setData] = useState<CachedPreview | null>(linkPreviewCache.get(url) || null);
  const [loading, setLoading] = useState(!data);
  const [error, setError] = useState(false);
  const [imgError, setImgError] = useState(false);

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

      const result = await link.fetchPreview(targetUrl);

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
      } catch {
        if (mounted) {
          setError(true);
          setLoading(false);
        }
      }
    };

    fetchPreview();

    return () => { mounted = false; };
  }, [url, data]);

  const handleClick = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    openInBrowser(url);
  }, [url]);

  if (error || (!loading && !data)) {
    if (showFallbackLink) {
      return (
        <div className="rounded-lg border overflow-hidden" style={cardBase}>
          <a
            href={url}
            onClick={handleClick}
            className="block p-3 underline decoration-1 underline-offset-2 transition-colors cursor-pointer text-sm"
            style={{ color: 'var(--color-accent-primary)', overflowWrap: 'anywhere', wordBreak: 'break-word' }}
          >
            {url}
          </a>
        </div>
      );
    }
    return null;
  }

  if (loading) {
    return (
      <div className="animate-pulse rounded-lg border overflow-hidden" style={cardBase}>
        <div className="w-full border-b" style={{ height: '150px', backgroundColor: 'rgba(127,127,127,0.12)', borderColor: 'var(--qor-border)' }} />
        <div className="p-3 flex flex-col gap-2">
          <div className="h-4 rounded w-3/4" style={{ backgroundColor: 'rgba(127,127,127,0.14)' }} />
          <div className="h-3 rounded w-full" style={{ backgroundColor: 'rgba(127,127,127,0.12)' }} />
          <div className="h-2.5 rounded w-24 mt-1" style={{ backgroundColor: 'rgba(127,127,127,0.1)' }} />
        </div>
      </div>
    );
  }

  const { title, description, image, hostname } = data!;
  const showImage = !!image && !imgError;

  return (
    <div
      onClick={handleClick}
      role="link"
      tabIndex={0}
      onKeyDown={(e) => { if (e.key === 'Enter') openInBrowser(url); }}
      className="group cursor-pointer rounded-lg border overflow-hidden transition-colors hover:bg-white/[0.04]"
      style={cardBase}
    >
      {showImage && (
        <img
          src={image!}
          alt=""
          loading="lazy"
          referrerPolicy="no-referrer"
          onError={() => setImgError(true)}
          className="w-full object-cover border-b block"
          style={{ height: '160px', borderColor: 'var(--qor-border)' }}
        />
      )}
      <div className="p-3 flex flex-col gap-1 min-w-0">
        {title && (
          <h3 className="font-semibold text-sm leading-tight text-foreground" style={clamp2}>
            {title}
          </h3>
        )}
        {description && (
          <p className="text-xs text-muted-foreground leading-relaxed" style={clamp2}>
            {description}
          </p>
        )}
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground/70 font-medium mt-1 block truncate">
          {hostname ?? getHostname(url) ?? url}
        </span>
      </div>
    </div>
  );
});

// Main component that linkifies text and shows previews
const LinkifyWithPreviewsComponent: React.FC<LinkifyWithPreviewsProps> = ({
  children,
  options = {},
  showPreviews = true,
  isCurrentUser = false,
  className,
  style,
  previewsOnly = false,
  urls: providedUrls,
  onRendered
}) => {
  useEffect(() => {
    onRendered?.();
  }, [onRendered]);

  const urls = useMemo(() => {
    const baseUrls = providedUrls ?? LinkExtractor.extractUrlStrings(children);
    return baseUrls
      .map(url => url.replace(/&amp;/g, '&'))
      .filter(isValidUrl);
  }, [children, providedUrls]);

  const orderedUrls = useMemo(() => {
    return [...urls].reverse();
  }, [urls]);

  const isUrlOnly = useMemo(() => LinkExtractor.isUrlOnlyMessage(children), [children]);

  const handleLinkClick = useCallback((url: string, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    openInBrowser(url);
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
          {orderedUrls.slice(0, 3).map(url => (
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
          {orderedUrls.map(url => (
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
          {orderedUrls.slice(0, 3).map(url => (
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
