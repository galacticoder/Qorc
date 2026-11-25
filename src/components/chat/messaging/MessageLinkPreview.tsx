import { ExternalLink, Link2 } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
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
import {
  SEGMENT_UNLOAD_IDLE_MS,
  MAX_LINK_PREVIEW_MESSAGE_TARGETS,
  MESSAGE_LINK_PREVIEW_ATTEMPT_MINIMUM,
  MESSAGE_LINK_PREVIEW_ATTEMPT_EXPECTED,
  NATIVE_MESSAGE_RENDER_RETRY_STEP_MS,
} from '../../../lib/constants';

interface MessageLinkPreviewsProps {
    messageId: string;
    contentVersion?: string;
    secureDB: SecureDB;
    onContextMenu?: (event: React.MouseEvent) => void;
}

type TargetRequest = {
    expiresAt: number;
    request: Promise<NativeMessageLinkTarget[]>;
};

const targetRequests = new WeakMap<SecureDB, Map<string, TargetRequest>>();

function cachedTargets(secureDB: SecureDB, cacheKey: string, messageId: string): Promise<NativeMessageLinkTarget[]> {
    const cache = targetRequests.get(secureDB) ?? new Map<string, TargetRequest>();
    targetRequests.set(secureDB, cache);
    const now = Date.now();
    const cached = cache.get(cacheKey);
    if (cached && cached.expiresAt > now) {
        cache.delete(cacheKey);
        cached.expiresAt = now + SEGMENT_UNLOAD_IDLE_MS;
        cache.set(cacheKey, cached);
        return cached.request;
    }
    for (const [key, entry] of cache) {
        if (entry.expiresAt <= now) cache.delete(key);
    }
    if (cache.size >= MAX_LINK_PREVIEW_MESSAGE_TARGETS) {
        const oldest = cache.keys().next().value;
        if (oldest !== undefined) cache.delete(oldest);
    }

    const request = (async () => {
        for (let attempt = 0; attempt < MESSAGE_LINK_PREVIEW_ATTEMPT_MINIMUM; attempt += 1) {
            if (!secureDB.isInitialized()) return [];
            try {
                return (await nativeMessageContent.linkTargets(messageId)).slice(0, 3);
            } catch (error) {
                if (attempt === MESSAGE_LINK_PREVIEW_ATTEMPT_EXPECTED) throw error;
                await new Promise((resolve) => window.setTimeout(resolve, NATIVE_MESSAGE_RENDER_RETRY_STEP_MS * (attempt + 1)));
            }
        }
        return [];
    })();
    const entry = { expiresAt: now + SEGMENT_UNLOAD_IDLE_MS, request };
    cache.set(cacheKey, entry);
    void request.catch(() => {
        if (cache.get(cacheKey) === entry) cache.delete(cacheKey);
    });
    return request;
}

function LinkPreviewCard({ target, secureDB, onContextMenu }: {
    target: NativeMessageLinkTarget;
    secureDB: SecureDB;
    onContextMenu: MessageLinkPreviewsProps['onContextMenu'];
}) {
    const [preview, setPreview] = useState<NativeLinkPreview | null>(null);
    const [status, setStatus] = useState<'idle' | 'loading' | 'failed'>('idle');
    const isMounted = useRef(false);
    const isLoading = useRef(false);

    useEffect(() => {
        isMounted.current = true;
        let cancelled = false;
        void loadLinkPreviewFromCache(secureDB, target.url).then((cached) => {
            if (!cancelled && cached) setPreview((current) => current ?? cached);
        }).catch(() => { });
        return () => {
            cancelled = true;
            isMounted.current = false;
        };
    }, [secureDB, target.url]);

    const loadPreview = async () => {
        if (isLoading.current || !secureDB.isInitialized()) return;
        isLoading.current = true;
        setStatus('loading');
        try {
            const loaded = await nativeMessageContent.fetchLinkPreview(target.url);
            if (!secureDB.isInitialized()) return;
            if (isMounted.current) {
                setPreview(loaded);
                setStatus('idle');
            }
            await saveLinkPreviewToCache(secureDB, loaded).catch(() => { });
        } catch {
            if (isMounted.current) setStatus('failed');
        } finally {
            isLoading.current = false;
        }
    };

    if (!preview) {
        const label = status === 'loading' ? 'Loading link preview…'
            : status === 'failed' ? 'Retry link preview'
            : 'Load link preview';
        return (
            <button
                type="button"
                className="qorc-message-link-preview"
                onClick={() => void loadPreview()}
                onContextMenu={onContextMenu}
                aria-label={`${label} for ${target.host}`}
                disabled={status === 'loading'}
            >
                <span className="qorc-message-link-preview-icon" aria-hidden="true"><Link2 /></span>
                <span className="qorc-message-link-preview-body">
                    <span className="qorc-message-link-preview-host">{target.host}</span>
                    <span className="qorc-message-link-preview-title">{label}</span>
                </span>
            </button>
        );
    }

    return (
        <button
            type="button"
            className={`qorc-message-link-preview${preview.imageDataUrl ? ' has-image' : ''}`}
            onClick={() => void system.openExternal(preview.url).catch(() => { })}
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
                <span className="qorc-message-link-preview-icon" aria-hidden="true"><Link2 /></span>
            )}
            <span className="qorc-message-link-preview-body">
                <span className="qorc-message-link-preview-host">{preview.host}</span>
                <span className="qorc-message-link-preview-title">{preview.title || preview.displayUrl}</span>
                {preview.description ? (
                    <span className="qorc-message-link-preview-description">{preview.description}</span>
                ) : null}
            </span>
            <ExternalLink className="qorc-message-link-preview-open" aria-hidden="true" />
        </button>
    );
}

export function MessageLinkPreviews({ messageId, contentVersion, secureDB, onContextMenu }: MessageLinkPreviewsProps) {
    const cacheKey = JSON.stringify([messageId, contentVersion]);
    const [resolved, setResolved] = useState<{
        secureDB: SecureDB;
        cacheKey: string;
        targets: NativeMessageLinkTarget[];
    } | null>(null);
    const targets = resolved?.secureDB === secureDB && resolved.cacheKey === cacheKey ? resolved.targets : [];

    useEffect(() => {
        let cancelled = false;
        void cachedTargets(secureDB, cacheKey, messageId).then((targets) => {
            if (!cancelled) setResolved({ secureDB, cacheKey, targets });
        }).catch(() => { });
        return () => { cancelled = true; };
    }, [cacheKey, messageId, secureDB]);

    if (targets.length === 0) return null;

    return (
        <div className="qorc-message-link-previews" role="group" aria-label="Link previews">
            {targets.map((target) => (
                <LinkPreviewCard
                    key={JSON.stringify([secureDB.getAccountScope(), cacheKey, target.url])}
                    target={target}
                    secureDB={secureDB}
                    onContextMenu={onContextMenu}
                />
            ))}
        </div>
    );
}
