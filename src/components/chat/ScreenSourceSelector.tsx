import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { Monitor, Square, X } from 'lucide-react';
import { sanitizeTextInput } from '../../lib/sanitizers';

interface ScreenSource {
  readonly id: string;
  readonly name: string;
  readonly thumbnail?: string;
  readonly type: 'screen' | 'window';
}

interface ScreenSourceSelectorProps {
  readonly isOpen: boolean;
  readonly onClose: () => void;
  readonly onSelect: (source: ScreenSource) => void;
  readonly onCancel: () => void;
  readonly onGetAvailableScreenSources?: () => Promise<ReadonlyArray<{ 
    readonly id: string; 
    readonly name: string; 
    readonly type: 'screen' | 'window' 
  }>>;
}

export const ScreenSourceSelector = React.memo<ScreenSourceSelectorProps>(({ 
  isOpen, 
  onClose, 
  onSelect, 
  onCancel,
  onGetAvailableScreenSources 
}) => {
  const [sources, setSources] = useState<ReadonlyArray<ScreenSource>>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const isMountedRef = useRef<boolean>(false);
  const abortControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    isMountedRef.current = true;

    if (isOpen) {
      loadScreenSources();
    }

    return () => {
      isMountedRef.current = false;
      abortControllerRef.current?.abort();
      abortControllerRef.current = null;
    };
  }, [isOpen]);

  const loadScreenSources = useCallback(async () => {
    if (!isMountedRef.current) return;

    abortControllerRef.current?.abort();
    abortControllerRef.current = new AbortController();
    const signal = abortControllerRef.current.signal;

    setLoading(true);
    setError(null);

    try {
      if (onGetAvailableScreenSources) {
        const rawSources = await onGetAvailableScreenSources();

        if (signal.aborted) return;

        if (!rawSources || rawSources.length === 0) {
          throw new Error('No screen sources available');
        }

        const formattedSources: ScreenSource[] = rawSources.map((source) => ({
          id: sanitizeTextInput(source.id, { maxLength: 256, allowNewlines: false }),
          name: sanitizeTextInput(source.name, { maxLength: 128, allowNewlines: false }),
          thumbnail: undefined,
          type: source.type
        }));

        if (isMountedRef.current && !signal.aborted) {
          setSources(formattedSources);
        }
      } else {
        const electronApi = (window as any).electronAPI;
        const edgeApi = (window as any).edgeApi;

        const getScreenSourcesFn =
          (typeof electronApi?.getScreenSources === 'function' ? electronApi.getScreenSources : null) ||
          (typeof edgeApi?.getScreenSources === 'function' ? edgeApi.getScreenSources : null);

        if (getScreenSourcesFn) {
          const rawSources = await getScreenSourcesFn();

          if (signal.aborted) return;

          if (!rawSources || rawSources.length === 0) {
            throw new Error('No screen sources available');
          }

          const formattedSources: ScreenSource[] = rawSources.map((source: any) => {
            let thumbnail: string | undefined;

            if (source.thumbnail && typeof source.thumbnail.toDataURL === 'function') {
              try {
                thumbnail = source.thumbnail.toDataURL();
              } catch {
                thumbnail = undefined;
              }
            }

            const isScreen = typeof source.id === 'string' && source.id.startsWith('screen:');
            const originalName = typeof source.name === 'string' ? source.name : '';
            let displayName = originalName || source.id;
            
            if (isScreen) {
              if (!displayName || displayName.trim() === '') {
                const screenNum = source.id.split(':')[1] || '0';
                const num = parseInt(screenNum, 10);
                displayName = `Entire Screen ${Number.isFinite(num) ? num + 1 : 1}`;
              } else {
                displayName = `Screen: ${displayName}`;
              }
            } else {
              if (!displayName || displayName.trim() === '') {
                displayName = `Application Window ${source.id.split(':')[1] || ''}`;
              } else {
                displayName = `Window: ${displayName}`;
              }
            }

            return {
              id: sanitizeTextInput(String(source.id), { maxLength: 256, allowNewlines: false }),
              name: sanitizeTextInput(displayName, { maxLength: 128, allowNewlines: false }),
              thumbnail,
              type: isScreen ? 'screen' as const : 'window' as const
            };
          });

          formattedSources.sort((a, b) => {
            if (a.type === 'screen' && b.type !== 'screen') return -1;
            if (a.type !== 'screen' && b.type === 'screen') return 1;
            return 0;
          });

          if (isMountedRef.current && !signal.aborted) {
            setSources(formattedSources);
          }
        } else {
          throw new Error('Screen source selection not available in this environment');
        }
      }
    } catch (_err) {
      if (_err instanceof Error && _err.name === 'AbortError') return;
      if (isMountedRef.current && !signal.aborted) {
        setError(_err instanceof Error ? _err.message : 'Failed to load screen sources');
      }
    } finally {
      if (isMountedRef.current && !signal.aborted) {
        setLoading(false);
      }
      abortControllerRef.current = null;
    }
  }, [onGetAvailableScreenSources]);

  const handleSelect = useCallback((source: ScreenSource) => {
    onSelect(source);
    onClose();
  }, [onSelect, onClose]);

  const handleCancel = useCallback(() => {
    onCancel();
    onClose();
  }, [onCancel, onClose]);

  const sortedSources = useMemo(() => sources, [sources]);

  if (!isOpen) {
    return null;
  }

  return (
    <div 
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
      onClick={handleCancel}
      role="dialog"
      aria-modal="true"
      aria-labelledby="screen-share-title"
    >
      <div 
        className="bg-white rounded-lg shadow-xl max-w-4xl w-full mx-4 max-h-[80vh] overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-4 border-b">
          <h2 id="screen-share-title" className="text-lg font-semibold text-gray-900">
            Choose what to share
          </h2>
          <button
            onClick={handleCancel}
            className="p-1 hover:bg-gray-100 rounded-full transition-colors"
            aria-label="Close dialog"
          >
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        <div className="p-4">
          {loading && (
            <div className="flex items-center justify-center py-8" role="status">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" aria-hidden="true"></div>
              <span className="ml-3 text-gray-600">Loading screen sources...</span>
            </div>
          )}

          {error && (
            <div className="text-center py-8" role="alert">
              <div className="text-red-600 mb-4">{error}</div>
              <button
                onClick={loadScreenSources}
                className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
                aria-label="Retry loading screen sources"
              >
                Try Again
              </button>
            </div>
          )}

          {!loading && !error && sortedSources.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 max-h-96 overflow-y-auto">
              {sortedSources.map((source) => (
                <button
                  key={source.id}
                  onClick={() => handleSelect(source)}
                  className="border rounded-lg p-3 hover:border-blue-500 hover:bg-blue-50 cursor-pointer transition-colors text-left"
                  aria-label={`Select ${source.name}`}
                >
                  <div className="aspect-video bg-gray-100 rounded mb-2 flex items-center justify-center overflow-hidden">
                    {source.thumbnail ? (
                      <img
                        src={source.thumbnail}
                        alt=""
                        className="w-full h-full object-cover"
                        loading="lazy"
                      />
                    ) : (
                      <div className="text-gray-400" aria-hidden="true">
                        {source.type === 'screen' ? (
                          <Monitor className="w-8 h-8" />
                        ) : (
                          <Square className="w-8 h-8" />
                        )}
                      </div>
                    )}
                  </div>

                  <div className="flex items-center space-x-2">
                    {source.type === 'screen' ? (
                      <Monitor className="w-4 h-4 text-gray-500 flex-shrink-0" aria-hidden="true" />
                    ) : (
                      <Square className="w-4 h-4 text-gray-500 flex-shrink-0" aria-hidden="true" />
                    )}
                    <span className="text-sm font-medium text-gray-900 truncate">
                      {source.name}
                    </span>
                  </div>
                  
                  <div className="text-xs text-gray-500 mt-1 capitalize">
                    {source.type === 'screen' ? 'Entire Screen' : 'Application Window'}
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="flex justify-end space-x-3 p-4 border-t bg-gray-50">
          <button
            onClick={handleCancel}
            className="px-4 py-2 text-gray-700 border border-gray-300 rounded hover:bg-gray-100 transition-colors"
            aria-label="Cancel"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
});
