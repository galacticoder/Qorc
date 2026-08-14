import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Monitor, Square, X } from 'lucide-react';
import { sanitizeTextInput } from '../../../lib/sanitizers';
import { Dialog, DialogContent } from '../../ui/dialog';
import type { ScreenSource } from '../../../lib/types/screen-sharing-types';

interface ScreenSourceSelectorProps {
  readonly isOpen: boolean;
  readonly onClose: () => void;
  readonly onSelect: (source: ScreenSource) => void | Promise<void>;
  readonly onCancel: () => void;
  readonly onGetAvailableScreenSources: () => Promise<ReadonlyArray<ScreenSource>>;
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
  const [selecting, setSelecting] = useState<boolean>(false);
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
      const rawSources = await onGetAvailableScreenSources();

      if (signal.aborted) return;

      if (!rawSources || rawSources.length === 0) {
        throw new Error('No screen sources available');
      }

      const formattedSources: ScreenSource[] = rawSources.map((source) => ({
          id: sanitizeTextInput(source.id, { maxLength: 256, allowNewlines: false }),
          name: sanitizeTextInput(source.name, { maxLength: 128, allowNewlines: false }),
          type: source.type
      }));

      if (isMountedRef.current && !signal.aborted) {
        setSources(formattedSources);
      }
    } catch (_err) {
      if (_err instanceof Error && _err.name === 'AbortError') return;
      if (isMountedRef.current && !signal.aborted) {
        setError(_err instanceof Error ? _err.message : 'Failed to load screens');
      }
    } finally {
      if (isMountedRef.current && !signal.aborted) {
        setLoading(false);
      }
      abortControllerRef.current = null;
    }
  }, [onGetAvailableScreenSources]);

  const handleSelect = useCallback(async (source: ScreenSource) => {
    if (selecting) return;
    setSelecting(true);
    setError(null);
    try {
      await onSelect(source);
      onClose();
    } catch (selectionError) {
      if (isMountedRef.current) {
        setError(selectionError instanceof Error ? selectionError.message : 'Failed to share screen');
      }
    } finally {
      if (isMountedRef.current) setSelecting(false);
    }
  }, [onSelect, onClose, selecting]);

  const handleCancel = useCallback(() => {
    onCancel();
    onClose();
  }, [onCancel, onClose]);

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && handleCancel()}>
      <DialogContent className="max-w-3xl max-h-[85vh] p-0 gap-0 overflow-hidden flex flex-col border-border bg-background text-card-foreground">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border bg-background z-10 relative">
          <h2 className="text-sm font-semibold text-foreground tracking-wide">
            Share Screen
          </h2>
          <button
            onClick={handleCancel}
            className="p-1.5 hover:bg-muted rounded-md transition-colors text-muted-foreground hover:text-foreground"
            aria-label="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 overflow-y-auto custom-scrollbar bg-background flex-1">
          {loading && (
            <div className="flex flex-col items-center justify-center py-12 gap-3">
              <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin"></div>
              <span className="text-xs text-muted-foreground">Loading sources...</span>
            </div>
          )}

          {error && (
            <div className="flex flex-col items-center justify-center py-8 gap-4">
              <div className="text-destructive text-xs">{error}</div>
              <button
                onClick={loadScreenSources}
                className="px-3 py-1.5 bg-secondary hover:bg-muted text-secondary-foreground text-xs rounded transition-colors"
              >
                Retry
              </button>
            </div>
          )}

          {!loading && !error && sources.length > 0 && (
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              {sources.map((source) => (
                <button
                  key={source.id}
                  onClick={() => { void handleSelect(source); }}
                  disabled={selecting}
                  className="group flex flex-col gap-2 p-2 rounded-lg border border-transparent hover:border-border hover:bg-card transition-all text-left outline-none focus:ring-1 focus:ring-primary/50"
                  title={source.name}
                >
                  <div className="relative aspect-video bg-muted rounded overflow-hidden border border-border group-hover:border-primary/50 transition-colors flex items-center justify-center">
                    <div className="text-muted-foreground group-hover:text-foreground transition-colors">
                      {source.type === 'screen' ? <Monitor className="w-8 h-8" /> : <Square className="w-8 h-8" />}
                    </div>
                    {/* Hover overlay */}
                    <div className="absolute inset-0 bg-primary/0 group-hover:bg-primary/5 transition-colors" />
                  </div>

                  <div className="flex items-center gap-2 px-1">
                    {source.type === 'screen' ? (
                      <Monitor className="w-3 h-3 text-muted-foreground" />
                    ) : (
                      <Square className="w-3 h-3 text-muted-foreground" />
                    )}
                    <span className="text-xs text-foreground truncate font-medium">
                      {source.name}
                    </span>
                  </div>
                </button>
              ))}
            </div>
          )}

          {!loading && !error && sources.length === 0 && (
            <div className="text-center py-12 text-muted-foreground text-sm">
              No screens found
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
});
