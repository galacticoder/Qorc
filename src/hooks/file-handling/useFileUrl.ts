import { useState, useEffect, useRef } from 'react';
import type { UseFileUrlOptions, UseFileUrlReturn } from '../../lib/types/file-types';
import type { SecureDB } from '../../lib/database/secureDB';
import { validateFilePreview } from '../../lib/utils/file-utils';

// Hook to resolve file URLs from SecureDB storage
export function useFileUrl({
  secureDB,
  fileId,
  mimeType = 'application/octet-stream',
  enabled = true,
  previewKind,
}: UseFileUrlOptions): UseFileUrlReturn {
  const [url, setUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const urlRef = useRef<string | null>(null);
  const ownerRef = useRef<{
    secureDB: SecureDB;
    fileId: string;
    mimeType: string;
    previewKind: typeof previewKind;
    url: string;
  } | null>(null);

  useEffect(() => {
    let canceled = false;
    let ownedUrl: string | null = null;
    
    urlRef.current = null;
    ownerRef.current = null;
    setUrl(null);
    setError(null);

    if (!enabled) {
      setLoading(false);
      return () => { canceled = true; };
    }

    if (!fileId) {
      setLoading(false);
      setError('No file ID provided');
      return () => { canceled = true; };
    }

    const loadFile = async () => {
      try {
        setLoading(true);

        const blob = await secureDB.getFile(fileId);
        if (canceled) return;

        if (!blob) {
          setError('File not found in storage');
          setLoading(false);
          return;
        }

        const validatedMimeType = previewKind
          ? await validateFilePreview(blob, previewKind)
          : mimeType;
        if (canceled) return;
        if (!validatedMimeType) {
          setError('File preview was rejected');
          setLoading(false);
          return;
        }

        const typedBlob = new Blob([blob], { type: validatedMimeType });
        const blobUrl = URL.createObjectURL(typedBlob);
        if (canceled) {
          URL.revokeObjectURL(blobUrl);
          return;
        }

        ownedUrl = blobUrl;
        urlRef.current = blobUrl;
        ownerRef.current = { secureDB, fileId, mimeType, previewKind, url: blobUrl };
        setUrl(blobUrl);
        setLoading(false);
      } catch (err) {
        if (canceled) return;
        const message = err instanceof Error ? err.message : 'Failed to load file';
        setError(message);
        setLoading(false);
      }
    };

    void loadFile();
    return () => {
      canceled = true;
      if (ownedUrl) {
        try { URL.revokeObjectURL(ownedUrl); } catch { }
        if (urlRef.current === ownedUrl) urlRef.current = null;
        if (ownerRef.current?.url === ownedUrl) ownerRef.current = null;
        ownedUrl = null;
      }
    };
  }, [enabled, fileId, mimeType, previewKind, secureDB]);

  const owner = ownerRef.current;
  const currentUrl = enabled && owner && owner.secureDB === secureDB && owner.fileId === fileId &&
    owner.mimeType === mimeType && owner.previewKind === previewKind && owner.url === url
    ? url
    : null;
  return { url: currentUrl, loading, error };
}
