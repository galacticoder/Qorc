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
}

/**
 * Hook to resolve file URLs from SecureDB storage.
 * Creates and manages Blob URLs for files stored in the encrypted database.
 * 
 * @param options - Object containing secureDB instance, fileId, mimeType, and initialUrl
 * @returns Object containing the resolved URL, loading state, and error state
 */
export function useFileUrl({
    secureDB,
    fileId,
    mimeType = 'application/octet-stream',
    initialUrl,
}: UseFileUrlOptions): UseFileUrlReturn {
    const [url, setUrl] = useState<string | null>(initialUrl || null);
    const [loading, setLoading] = useState<boolean>(false);
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
    }, [fileId, mimeType, initialUrl, secureDB]);

    return { url, loading, error };
}
