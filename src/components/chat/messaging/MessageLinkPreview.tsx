import { ExternalLink, Link2 } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import {
    nativeMessageContent,
    system,
    type NativeLinkPreview,
    type NativeMessageLinkTarget,
} from '../../../lib/tauri-bindings';
import type { SecureDB } from '../../../lib/database/secureDB';
import {
    loadLinkPreviewFromCache,
    saveLinkPreviewToCache,
} from '../../../lib/database/link-preview-cache';
import { SEGMENT_UNLOAD_IDLE_MS } from '../../../lib/constants';

interface MessageLinkPreviewsProps {
    messageId: string;
    contentVersion?: string;
    secureDB?: SecureDB | null;
    onContextMenu?: (event: React.MouseEvent) => void;
}

const previewRequests = new Map<string, Promise<NativeLinkPreview>>();
const MAX_CACHED_PREVIEWS = 16;
const MAX_CACHED_MESSAGE_TARGETS = 2048;
const MAX_CACHED_MESSAGE_PREVIEWS = 512;
const MESSAGE_PREVIEW_MEMORY_TTL_MS = SEGMENT_UNLOAD_IDLE_MS;

type ExpiringTargetRequest = {
    expiresAt: number;
    request: Promise<NativeMessageLinkTarget[]>;
};

type ExpiringMessagePreviews = {
    expiresAt: number;
    previews: NativeLinkPreview[];
};

const targetRequests = new Map<string, ExpiringTargetRequest>();
const messagePreviewCache = new Map<string, ExpiringMessagePreviews>();

const messageCacheKey = (
    messageId: string,
    contentVersion: string | undefined,
    secureDB?: SecureDB | null,
): string => {
    const scope = secureDB?.getAccountScope() || '';
    const version = contentVersion || '';
    return `${scope.length}:${scope}${messageId.length}:${messageId}${version.length}:${version}`;
};

const trimExpiredCache = <T,>(cache: Map<string, T & { expiresAt: number }>, maximum: number): void => {
    const now = Date.now();
    for (const [key, entry] of cache) {
        if (entry.expiresAt <= now) cache.delete(key);
    }
    while (cache.size >= maximum) {
        const oldest = cache.keys().next().value;
        if (!oldest) break;
        cache.delete(oldest);
    }
};

const cachedTargets = (cacheKey: string, messageId: string): Promise<NativeMessageLinkTarget[]> => {
    const now = Date.now();
    const cached = targetRequests.get(cacheKey);
    if (cached && cached.expiresAt > now) {
        targetRequests.delete(cacheKey);
        cached.expiresAt = now + MESSAGE_PREVIEW_MEMORY_TTL_MS;
        targetRequests.set(cacheKey, cached);
        return cached.request;
    }
    if (cached) targetRequests.delete(cacheKey);
    trimExpiredCache(targetRequests, MAX_CACHED_MESSAGE_TARGETS);

    const request = (async (): Promise<NativeMessageLinkTarget[]> => {
        let lastError: unknown;
        for (let attempt = 0; attempt < 5; attempt += 1) {
            try {
                return (await nativeMessageContent.linkTargets(messageId)).slice(0, 3);
            } catch (error) {
                lastError = error;
                if (attempt < 4) {
                    await new Promise((resolve) => window.setTimeout(resolve, 50 * (attempt + 1)));
                }
            }
        }
        throw lastError;
    })();
    const entry = {
        expiresAt: now + MESSAGE_PREVIEW_MEMORY_TTL_MS,
        request,
    };
    targetRequests.set(cacheKey, entry);
    void request.catch(() => {
        if (targetRequests.get(cacheKey) === entry) targetRequests.delete(cacheKey);
    });
    return request;
};

const readMessagePreviewCache = (cacheKey: string): NativeLinkPreview[] | undefined => {
    const cached = messagePreviewCache.get(cacheKey);
    if (!cached) return undefined;
    if (cached.expiresAt <= Date.now()) {
        messagePreviewCache.delete(cacheKey);
        return undefined;
    }
    messagePreviewCache.delete(cacheKey);
    cached.expiresAt = Date.now() + MESSAGE_PREVIEW_MEMORY_TTL_MS;
    messagePreviewCache.set(cacheKey, cached);
    return cached.previews;
};

const writeMessagePreviewCache = (cacheKey: string, previews: NativeLinkPreview[]): void => {
    trimExpiredCache(messagePreviewCache, MAX_CACHED_MESSAGE_PREVIEWS);
    messagePreviewCache.delete(cacheKey);
    messagePreviewCache.set(cacheKey, {
        expiresAt: Date.now() + MESSAGE_PREVIEW_MEMORY_TTL_MS,
        previews,
    });
};

const fetchCachedPreview = (
    target: NativeMessageLinkTarget,
    secureDB?: SecureDB | null,
): Promise<NativeLinkPreview> => {
    const requestKey = secureDB ? `${secureDB.getAccountScope()}:${target.url}` : target.url;
    const existing = previewRequests.get(requestKey);
    if (existing) return existing;
    if (previewRequests.size >= MAX_CACHED_PREVIEWS) {
        const oldest = previewRequests.keys().next().value;
        if (oldest) previewRequests.delete(oldest);
    }
    const request = (async () => {
        if (secureDB) {
            try {
                const cached = await loadLinkPreviewFromCache(secureDB, target.url);
                if (cached) return cached;
            } catch {
                console.warn('[LINK-PREVIEW] metadata cache read failed');
            }
        }
        const preview = await nativeMessageContent.fetchLinkPreview(target.url);
        if (secureDB && preview.metadataFetched) {
            void saveLinkPreviewToCache(secureDB, preview).catch(() => {
                console.warn('[LINK-PREVIEW] metadata cache write failed');
            });
        }
        return preview;
    })();
    previewRequests.set(requestKey, request);
    void request.then((preview) => {
        if (!preview.metadataFetched) previewRequests.delete(requestKey);
    }, () => {
        previewRequests.delete(requestKey);
    });
    return request;
};

const basicPreview = (target: NativeMessageLinkTarget): NativeLinkPreview => ({
    ...target,
    metadataFetched: false,
    title: null,
    description: null,
    imageDataUrl: null,
});

export function MessageLinkPreviews({
    messageId,
    contentVersion,
    secureDB,
    onContextMenu,
}: MessageLinkPreviewsProps) {
    const cacheKey = messageCacheKey(messageId, contentVersion, secureDB);
    const [previews, setPreviews] = useState<NativeLinkPreview[]>(() => (
        readMessagePreviewCache(cacheKey) || []
    ));

    useEffect(() => {
        const retained = readMessagePreviewCache(cacheKey);
        setPreviews(retained || []);
        let cancelled = false;
        const load = async (): Promise<void> => {
            let targets: NativeMessageLinkTarget[];
            try {
                targets = await cachedTargets(cacheKey, messageId);
            } catch {
                return;
            }
            if (cancelled) return;
            if (targets.length === 0) {
                writeMessagePreviewCache(cacheKey, []);
                setPreviews([]);
                return;
            }
            const previous = readMessagePreviewCache(cacheKey);
            const sameTargets = previous?.length === targets.length && previous.every((preview, index) => (
                preview.url === targets[index].url
            ));
            if (!sameTargets) {
                const basic = targets.map(basicPreview);
                writeMessagePreviewCache(cacheKey, basic);
                setPreviews(basic);
            } else if (previous) {
                setPreviews(previous);
            }
            const enrich = async (target: NativeMessageLinkTarget): Promise<void> => {
                for (let attempt = 0; attempt < 3 && !cancelled; attempt += 1) {
                    try {
                        const enriched = await fetchCachedPreview(target, secureDB);
                        if (cancelled) return;
                        setPreviews((current) => {
                            const next = current.map((preview) => (
                                preview.url === target.url ? enriched : preview
                            ));
                            writeMessagePreviewCache(cacheKey, next);
                            return next;
                        });
                        if (enriched.metadataFetched) return;
                    } catch {
                        console.warn('[LINK-PREVIEW] metadata invoke failed');
                    }
                    if (attempt < 2) {
                        await new Promise((resolve) => window.setTimeout(resolve, 1500 * (attempt + 1)));
                    }
                }
            };
            const targetsToEnrich = targets.filter((target) => !previous?.some((preview) => (
                preview.url === target.url && preview.metadataFetched
            )));
            await Promise.all(targetsToEnrich.map(enrich));
        };
        void load();
        return () => { cancelled = true; };
    }, [cacheKey, messageId, secureDB]);

    const openPreview = useCallback((url: string) => {
        void system.openExternal(url).catch(() => { });
    }, []);

    if (previews.length === 0) return null;

    return (
        <div className="qorc-message-link-previews" role="group" aria-label="Link previews">
            {previews.map((preview) => (
                <button
                    key={preview.url}
                    type="button"
                    className={`qorc-message-link-preview${preview.imageDataUrl ? ' has-image' : ''}`}
                    onClick={() => openPreview(preview.url)}
                    onContextMenu={onContextMenu}
                    aria-label={`Open link to ${preview.host}`}
                >
                    {preview.imageDataUrl ? (
                        <img
                            className="qorc-message-link-preview-image"
                            src={preview.imageDataUrl}
                            alt=""
                            aria-hidden="true"
                            draggable={false}
                        />
                    ) : (
                        <span className="qorc-message-link-preview-icon" aria-hidden="true">
                            <Link2 />
                        </span>
                    )}
                    <span className="qorc-message-link-preview-body">
                        <span className="qorc-message-link-preview-host">{preview.host}</span>
                        <span className="qorc-message-link-preview-title">
                            {preview.title || preview.displayUrl}
                        </span>
                        {preview.description ? (
                            <span className="qorc-message-link-preview-description">
                                {preview.description}
                            </span>
                        ) : null}
                    </span>
                    <ExternalLink className="qorc-message-link-preview-open" aria-hidden="true" />
                </button>
            ))}
        </div>
    );
}
