import { useState, useEffect, useRef } from 'react';
import type { SecureDB } from '../lib/secureDB';

interface UseFileUrlReturn {
    url: string | null;
    loading: boolean;
    error: string | null;
}

interface UseFileUrlOptions {
    secureDB: SecureDB | null;
    fileId: string | undefined;
    mimeType?: string;
    initialUrl?: string;
    originalBase64Data?: string | null; // For recovery if SecureDB doesn't have the file
}

const MAX_INLINE_BYTES = 10 * 1024 * 1024; // 10 MB 
const BASE64_SAFE_REGEX = /^[A-Za-z0-9+/=_-]+$/;

const validateAndDecodeBase64 = (input: string | null | undefined): Uint8Array | null => {
    if (!input || typeof input !== 'string') return null;
    let cleanBase64 = input.trim();

    const inlinePrefixIndex = cleanBase64.indexOf(',');
    if (inlinePrefixIndex > 0 && inlinePrefixIndex < 128) {
        cleanBase64 = cleanBase64.slice(inlinePrefixIndex + 1);
    }

    if (!BASE64_SAFE_REGEX.test(cleanBase64.replace(/=+$/, ''))) {
        return null;
    }

    const estimatedBytes = Math.floor((cleanBase64.length * 3) / 4) - (cleanBase64.endsWith('==') ? 2 : cleanBase64.endsWith('=') ? 1 : 0);
    if (estimatedBytes <= 0 || estimatedBytes > MAX_INLINE_BYTES) {
        return null;
    }

    try {
        return Uint8Array.from(atob(cleanBase64), char => char.charCodeAt(0));
    } catch {
        return null;
    }
};

/**
 * Hook to resolve file URLs from SecureDB storage.
 * Creates and manages Blob URLs for files stored in the encrypted database.
 * Falls back to originalBase64Data if file not found in SecureDB.
 * 
 * @param options - Object containing secureDB instance, fileId, mimeType, initialUrl, and originalBase64Data
 * @returns Object containing the resolved URL, loading state, and error state
 */
export function useFileUrl({
    secureDB,
    fileId,
    mimeType = 'application/octet-stream',
    initialUrl,
    originalBase64Data,
}: UseFileUrlOptions): UseFileUrlReturn {
    const safeInitialUrl = initialUrl && !initialUrl.startsWith('blob:') ? initialUrl : null;
    const [url, setUrl] = useState<string | null>(safeInitialUrl);
    const [loading, setLoading] = useState<boolean>(!safeInitialUrl);
    const [error, setError] = useState<string | null>(null);
    const urlRef = useRef<string | null>(null);

    useEffect(() => {
        // Cleanup function to revoke old blob URLs
        return () => {
            if (urlRef.current && urlRef.current.startsWith('blob:')) {
                try {
                    URL.revokeObjectURL(urlRef.current);
                } catch (e) {
                }
            }
        };
    }, []);

    useEffect(() => {
        if (!fileId) {
            setUrl(null);
            setLoading(false);
            setError('No file ID provided');
            return;
        }

        if (!secureDB) {
            if (originalBase64Data) {
                const decoded = validateAndDecodeBase64(originalBase64Data);
                if (decoded) {
                    try {
                        const buffer = new ArrayBuffer(decoded.length);
                        const copy = new Uint8Array(buffer);
                        copy.set(decoded);
                        const blob = new Blob([buffer], { type: mimeType });
                        const blobUrl = URL.createObjectURL(blob);
                        urlRef.current = blobUrl;
                        setUrl(blobUrl);
                        setLoading(false);
                        return;
                    } catch (e) {
                    }
                }
            }

            if (initialUrl && !initialUrl.startsWith('blob:')) {
                setUrl(initialUrl);
                setLoading(false);
            } else {
                setError('Database not initialized');
                setLoading(false);
            }
            return;
        }

        const loadFile = async () => {
            try {
                setLoading(true);
                setError(null);

                const blob = await secureDB.getFile(fileId);

                if (!blob) {
                    // Try to recover from originalBase64Data
                    if (originalBase64Data) {
                        const decoded = validateAndDecodeBase64(originalBase64Data);
                        if (decoded) {
                            try {
                                const buffer = new ArrayBuffer(decoded.length);
                                const copy = new Uint8Array(buffer);
                                copy.set(decoded);
                                const recoveredBlob = new Blob([buffer], { type: mimeType });

                                try {
                                    await secureDB.saveFile(fileId, recoveredBlob);
                                } catch (saveErr) {
                                    console.error('[useFileUrl] Failed to save recovered file to SecureDB:', saveErr);
                                }

                                const blobUrl = URL.createObjectURL(recoveredBlob);
                                if (urlRef.current && urlRef.current.startsWith('blob:')) {
                                    try {
                                        URL.revokeObjectURL(urlRef.current);
                                    } catch (e) { }
                                }
                                urlRef.current = blobUrl;
                                setUrl(blobUrl);
                                setLoading(false);
                                return;
                            } catch (e) {
                                console.error('[useFileUrl] Failed to recover from originalBase64Data:', e);
                            }
                        }
                    }

                    if (initialUrl && !initialUrl.startsWith('blob:')) {
                        setUrl(initialUrl);
                        setLoading(false);
                        return;
                    }
                    setError('File not found in storage');
                    setLoading(false);
                    return;
                }

                const typedBlob = new Blob([blob], { type: mimeType });
                const blobUrl = URL.createObjectURL(typedBlob);

                if (urlRef.current && urlRef.current.startsWith('blob:')) {
                    try {
                        URL.revokeObjectURL(urlRef.current);
                    } catch (e) { }
                }

                urlRef.current = blobUrl;
                setUrl(blobUrl);
                setLoading(false);
            } catch (err) {
                const message = err instanceof Error ? err.message : 'Failed to load file';
                setError(message);
                setLoading(false);
            }
        };

        loadFile();
    }, [fileId, mimeType, initialUrl, secureDB, originalBase64Data]);

    return { url, loading, error };
}
