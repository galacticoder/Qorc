type AvatarImageStatus = 'ready' | 'failed';

const MAX_TRACKED_IMAGES = 256;
const LOAD_TIMEOUT_MS = 8_000;
const statuses = new Map<string, AvatarImageStatus>();
const pending = new Map<string, Promise<boolean>>();

const remember = (url: string, status: AvatarImageStatus): void => {
    statuses.delete(url);
    statuses.set(url, status);
    while (statuses.size > MAX_TRACKED_IMAGES) {
        const oldest = statuses.keys().next().value;
        if (!oldest) break;
        statuses.delete(oldest);
    }
};

export const getAvatarImageStatus = (url: string | null): AvatarImageStatus | null => (
    url ? statuses.get(url) || null : null
);

export const markAvatarImageReady = (url: string): void => remember(url, 'ready');

export const markAvatarImageFailed = (url: string): void => remember(url, 'failed');

export const preloadAvatarImage = (url: string): Promise<boolean> => {
    const status = getAvatarImageStatus(url);
    if (status) return Promise.resolve(status === 'ready');
    const existing = pending.get(url);
    if (existing) return existing;
    if (typeof Image === 'undefined') return Promise.resolve(false);

    const operation = new Promise<boolean>((resolve) => {
        const image = new Image();
        let settled = false;
        const finish = (loaded: boolean) => {
            if (settled) return;
            settled = true;
            window.clearTimeout(timeout);
            image.onload = null;
            image.onerror = null;
            remember(url, loaded ? 'ready' : 'failed');
            resolve(loaded);
        };
        const timeout = window.setTimeout(() => finish(false), LOAD_TIMEOUT_MS);
        image.onload = () => finish(image.naturalWidth > 0 && image.naturalHeight > 0);
        image.onerror = () => finish(false);
        image.decoding = 'async';
        image.src = url;
        if (image.complete) finish(image.naturalWidth > 0 && image.naturalHeight > 0);
    });
    pending.set(url, operation);
    void operation.finally(() => {
        if (pending.get(url) === operation) pending.delete(url);
    });
    return operation;
};
