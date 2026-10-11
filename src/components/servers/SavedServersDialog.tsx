import { useCallback, useEffect, useId, useRef } from 'react';
import { Server, X } from 'lucide-react';
import { Dialog, DialogContent, DialogTitle } from '../ui/dialog';
import { SavedServers } from './SavedServers';
import type { SavedServer } from '../../lib/servers/saved-servers';

interface SavedServersDialogProps {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly onSelect?: (server: SavedServer) => void;
  readonly selectedUrl?: string;
  readonly disabled?: boolean;
}

export function SavedServersDialog({ open, onOpenChange, onSelect, selectedUrl, disabled }: SavedServersDialogProps) {
  const titleId = useId();
  const contentRef = useRef<HTMLDivElement | null>(null);
  const mountContent = useCallback((element: HTMLDivElement | null) => {
    contentRef.current = element;
    element?.querySelector<HTMLButtonElement>('button')?.focus();
  }, []);

  useEffect(() => {
    if (!open) return;
    const previousFocus = document.activeElement;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const keydown = (event: KeyboardEvent) => {
      if (event.defaultPrevented || (event.target instanceof Element && event.target.closest('.saved-server-menu'))) return;
      if (event.key === 'Escape') { event.preventDefault(); onOpenChange(false); return; }
      if (event.key !== 'Tab') return;
      const items = Array.from(contentRef.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), [tabindex="0"]') ?? [])
        .filter((element) => element.getClientRects().length > 0);
      if (!items.length) return;
      const index = items.indexOf(document.activeElement as HTMLElement);
      if (index < 0 || (event.shiftKey ? index === 0 : index === items.length - 1)) {
        event.preventDefault();
        items[event.shiftKey ? items.length - 1 : 0].focus();
      }
    };
    const focusin = (event: FocusEvent) => {
      if (event.target instanceof Element && !contentRef.current?.contains(event.target) && !event.target.closest('.saved-server-menu')) {
        contentRef.current?.querySelector<HTMLButtonElement>('button')?.focus();
      }
    };
    document.addEventListener('keydown', keydown);
    document.addEventListener('focusin', focusin);
    return () => {
      document.body.style.overflow = overflow;
      document.removeEventListener('keydown', keydown);
      document.removeEventListener('focusin', focusin);
      if (previousFocus instanceof HTMLElement && previousFocus.isConnected) previousFocus.focus();
    };
  }, [open, onOpenChange]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="qorc-cm-dialog saved-servers-dialog" containerClassName="saved-servers-overlay" role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <div ref={mountContent} className="saved-servers-dialog-content">
          <header className="qorc-cm-head">
            <div className="saved-servers-dialog-title"><Server size={20} aria-hidden="true" /><DialogTitle id={titleId}>Saved servers</DialogTitle></div>
            <button type="button" className="qorc-cm-close" aria-label="Close saved servers" onClick={() => onOpenChange(false)}><X size={18} aria-hidden="true" /></button>
          </header>
          <SavedServers showTitle={false} selectedUrl={selectedUrl} disabled={disabled} onSelect={onSelect ? (server) => { onSelect(server); onOpenChange(false); } : undefined} />
        </div>
      </DialogContent>
    </Dialog>
  );
}
