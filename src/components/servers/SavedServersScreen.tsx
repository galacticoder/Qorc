import { useId } from 'react';
import { StandaloneScreen } from '../ui/StandaloneScreen';
import { SavedServers } from './SavedServers';
import type { SavedServer } from '../../lib/servers/saved-servers';

interface SavedServersScreenProps {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly onSelect?: (server: SavedServer) => void;
  readonly selectedUrl?: string;
  readonly disabled?: boolean;
}

export function SavedServersScreen({ open, onOpenChange, onSelect, selectedUrl, disabled }: SavedServersScreenProps) {
  const titleId = useId();
  return <StandaloneScreen open={open} onBack={() => onOpenChange(false)} className="saved-servers-screen" labelledBy={titleId}>
    <SavedServers showTitle={false} titleId={titleId} onClose={() => onOpenChange(false)}
      selectedUrl={selectedUrl} disabled={disabled}
      onSelect={onSelect ? server => { onSelect(server); onOpenChange(false); } : undefined} />
  </StandaloneScreen>;
}
