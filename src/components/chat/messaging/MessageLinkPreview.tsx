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

interface MessageLinkPreviewsProps {
    messageId: string;
    contentVersion?: string;
    enabled: boolean;
    secureDB?: SecureDB | null;
    onContextMenu?: (event: React.MouseEvent) => void;
}

const previewRequests = new Map<string, Promise<NativeLinkPreview>>();
const MAX_CACHED_PREVIEWS = 16;

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
    enabled,
    secureDB,
    onContextMenu,
}: MessageLinkPreviewsProps) {
    const [previews, setPreviews] = useState<NativeLinkPreview[]>([]);

    useEffect(() => {
        setPreviews([]);
        if (!enabled) return;
        let cancelled = false;
        const load = async (): Promise<void> => {
            let targets: NativeMessageLinkTarget[] = [];
            for (let attempt = 0; attempt < 5 && !cancelled; attempt += 1) {
                try {
                    targets = (await nativeMessageContent.linkTargets(messageId)).slice(0, 3);
                    break;
                } catch {
                    if (attempt === 4) return;
                    await new Promise((resolve) => window.setTimeout(resolve, 50 * (attempt + 1)));
                }
            }
            if (cancelled || targets.length === 0) return;
            setPreviews(targets.map(basicPreview));
            const enrich = async (target: NativeMessageLinkTarget): Promise<void> => {
                for (let attempt = 0; attempt < 3 && !cancelled; attempt += 1) {
                    try {
                        const enriched = await fetchCachedPreview(target, secureDB);
                        if (cancelled) return;
                        setPreviews((current) => current.map((preview) => (
                            preview.url === target.url ? enriched : preview
                        )));
                        if (enriched.metadataFetched) return;
                    } catch {
                        console.warn('[LINK-PREVIEW] metadata invoke failed');
                    }
                    if (attempt < 2) {
                        await new Promise((resolve) => window.setTimeout(resolve, 1500 * (attempt + 1)));
                    }
                }
            };
            await Promise.all(targets.map(enrich));
        };
        void load();
        return () => { cancelled = true; };
    }, [messageId, contentVersion, enabled, secureDB]);

    const openPreview = useCallback((url: string) => {
        void system.openExternal(url).catch(() => { });
    }, []);

    if (previews.length === 0) return null;

    return (
        <div className="qor-message-link-previews" role="group" aria-label="Link previews">
            {previews.map((preview) => (
                <button
                    key={preview.url}
                    type="button"
                    className={`qor-message-link-preview${preview.imageDataUrl ? ' has-image' : ''}`}
                    onClick={() => openPreview(preview.url)}
                    onContextMenu={onContextMenu}
                    aria-label={`Open link to ${preview.host}`}
                >
                    {preview.imageDataUrl ? (
                        <img
                            className="qor-message-link-preview-image"
                            src={preview.imageDataUrl}
                            alt=""
                            aria-hidden="true"
                            draggable={false}
                        />
                    ) : (
                        <span className="qor-message-link-preview-icon" aria-hidden="true">
                            <Link2 />
                        </span>
                    )}
                    <span className="qor-message-link-preview-body">
                        <span className="qor-message-link-preview-host">{preview.host}</span>
                        <span className="qor-message-link-preview-title">
                            {preview.title || preview.displayUrl}
                        </span>
                        {preview.description ? (
                            <span className="qor-message-link-preview-description">
                                {preview.description}
                            </span>
                        ) : null}
                    </span>
                    <ExternalLink className="qor-message-link-preview-open" aria-hidden="true" />
                </button>
            ))}
        </div>
    );
}
