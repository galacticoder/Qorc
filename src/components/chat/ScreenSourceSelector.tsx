import React, { useState, useEffect, useRef } from 'react';
import { Monitor, Square, X } from 'lucide-react';

interface ScreenSource {
  id: string;
  name: string;
  thumbnail?: string;
  type: 'screen' | 'window';
}

interface ScreenSourceSelectorProps {
  isOpen: boolean;
  onClose: () => void;
  onSelect: (source: ScreenSource) => void;
  onCancel: () => void;
  onGetAvailableScreenSources?: () => Promise<Array<{ id: string; name: string; type: 'screen' | 'window' }>>;
}

export const ScreenSourceSelector: React.FC<ScreenSourceSelectorProps> = ({
  isOpen,
  onClose,
  onSelect,
  onCancel,
  onGetAvailableScreenSources
}) => {
  const [sources, setSources] = useState<ScreenSource[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isMountedRef = useRef(false);

  useEffect(() => {
    isMountedRef.current = true;

    if (isOpen) {
      loadScreenSources();
    }

    return () => {
      isMountedRef.current = false;
    };
  }, [isOpen]);

  const loadScreenSources = async () => {
    if (!isMountedRef.current) return;

    setLoading(true);
    setError(null);

    try {
      if (onGetAvailableScreenSources) {
        console.log('[ScreenSourceSelector] Loading screen sources...');
        const rawSources = await onGetAvailableScreenSources();

        if (!rawSources || rawSources.length === 0) {
          throw new Error('No screen sources available');
        }

        // Convert raw sources to our format
        const formattedSources: ScreenSource[] = rawSources.map((source) => ({
          id: source.id,
          name: source.name,
          thumbnail: undefined, // Will be handled separately with safe conversion
          type: source.type
        }));

        if (isMountedRef.current) {
          setSources(formattedSources);
          console.log('[ScreenSourceSelector] Loaded sources:', formattedSources.length);
        }
      } else {
        // Fallback to direct window API access with type safety
        const electronApi = (window as any).electronAPI;
        const edgeApi = (window as any).edgeApi;

        // Type-safe checks
        const getScreenSourcesFn =
          (typeof electronApi?.getScreenSources === 'function' ? electronApi.getScreenSources : null) ||
          (typeof edgeApi?.getScreenSources === 'function' ? edgeApi.getScreenSources : null);

        if (getScreenSourcesFn) {
          console.log('[ScreenSourceSelector] Loading screen sources via fallback...');
          const rawSources = await getScreenSourcesFn();

          if (!rawSources || rawSources.length === 0) {
            throw new Error('No screen sources available');
          }

          // Convert raw sources to our format with safe thumbnail handling
          const formattedSources: ScreenSource[] = rawSources.map((source: any) => {
            let thumbnail: string | undefined;

            // Safe thumbnail conversion
            if (source.thumbnail && typeof source.thumbnail.toDataURL === 'function') {
              try {
                thumbnail = source.thumbnail.toDataURL();
              } catch (error) {
                console.warn('[ScreenSourceSelector] Failed to convert thumbnail for source:', source.name, error);
                thumbnail = undefined;
              }
            }

            return {
              id: source.id,
              name: source.name,
              thumbnail,
              type: source.id.startsWith('screen:') ? 'screen' : 'window'
            };
          });

          if (isMountedRef.current) {
            setSources(formattedSources);
            console.log('[ScreenSourceSelector] Loaded sources:', formattedSources.length);
          }
        } else {
          throw new Error('Screen source selection not available in this environment');
        }
      }
    } catch (err) {
      console.error('[ScreenSourceSelector] Failed to load screen sources:', err);
      if (isMountedRef.current) {
        setError(err instanceof Error ? err.message : 'Failed to load screen sources');
      }
    } finally {
      if (isMountedRef.current) {
        setLoading(false);
      }
    }
  };

  const handleSelect = (source: ScreenSource) => {
    console.log('[ScreenSourceSelector] Selected source:', source.name);
    onSelect(source);
    onClose();
  };

  const handleCancel = () => {
    onCancel();
    onClose();
  };

  if (!isOpen) {
    return null;
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full mx-4 max-h-[80vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b">
          <h2 className="text-lg font-semibold text-gray-900">
            Choose what to share
          </h2>
          <button
            onClick={handleCancel}
            className="p-1 hover:bg-gray-100 rounded-full transition-colors"
          >
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        {/* Content */}
        <div className="p-4">
          {loading && (
            <div className="flex items-center justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              <span className="ml-3 text-gray-600">Loading screen sources...</span>
            </div>
          )}

          {error && (
            <div className="text-center py-8">
              <div className="text-red-600 mb-4">{error}</div>
              <button
                onClick={loadScreenSources}
                className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
              >
                Try Again
              </button>
            </div>
          )}

          {!loading && !error && sources.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 max-h-96 overflow-y-auto">
              {sources.map((source) => (
                <div
                  key={source.id}
                  onClick={() => handleSelect(source)}
                  className="border rounded-lg p-3 hover:border-blue-500 hover:bg-blue-50 cursor-pointer transition-colors"
                >
                  {/* Thumbnail */}
                  <div className="aspect-video bg-gray-100 rounded mb-2 flex items-center justify-center overflow-hidden">
                    {source.thumbnail ? (
                      <img
                        src={source.thumbnail}
                        alt={source.name}
                        className="w-full h-full object-cover"
                      />
                    ) : (
                      <div className="text-gray-400">
                        {source.type === 'screen' ? (
                          <Monitor className="w-8 h-8" />
                        ) : (
                          <Square className="w-8 h-8" />
                        )}
                      </div>
                    )}
                  </div>

                  {/* Source info */}
                  <div className="flex items-center space-x-2">
                    {source.type === 'screen' ? (
                      <Monitor className="w-4 h-4 text-gray-500 flex-shrink-0" />
                    ) : (
                      <Square className="w-4 h-4 text-gray-500 flex-shrink-0" />
                    )}
                    <span className="text-sm font-medium text-gray-900 truncate">
                      {source.name}
                    </span>
                  </div>
                  
                  <div className="text-xs text-gray-500 mt-1 capitalize">
                    {source.type === 'screen' ? 'Entire Screen' : 'Application Window'}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-end space-x-3 p-4 border-t bg-gray-50">
          <button
            onClick={handleCancel}
            className="px-4 py-2 text-gray-700 border border-gray-300 rounded hover:bg-gray-100 transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
};
