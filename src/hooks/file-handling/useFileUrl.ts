import { useState, useEffect, useRef } from 'react';
import { validateAndDecodeBase64 } from '../../lib/utils/file-utils';
import type { UseFileUrlOptions, UseFileUrlReturn } from '../../lib/types/file-types';

// Hook to resolve file URLs from SecureDB storage
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
    return () => {
      if (urlRef.current && urlRef.current.startsWith('blob:')) {
        try {
          URL.revokeObjectURL(urlRef.current);
        } catch { }
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
          } catch { }
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
                  } catch { }
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
          } catch { }
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
