import { useId } from 'react';
import { StandaloneScreen } from '../ui/StandaloneScreen';
import { SavedServers } from './SavedServers';
import type { SavedServer } from '../../lib/servers/saved-servers';
import { useConnectedServer } from '../../hooks/useConnectedServer';

interface SavedServersScreenProps {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly onSelect?: (server: SavedServer) => void;
  readonly selectedUrl?: string;
  readonly disabled?: boolean;
}

export function SavedServersScreen({ open, onOpenChange, onSelect, selectedUrl, disabled }: SavedServersScreenProps) {
  const titleId = useId();
  const currentServer = useConnectedServer(open);
  return <StandaloneScreen open={open} onBack={() => onOpenChange(false)} className="saved-servers-screen" labelledBy={titleId}>
    <SavedServers showTitle={false} titleId={titleId} onClose={() => onOpenChange(false)}
      selectedUrl={selectedUrl} currentServer={currentServer} disabled={disabled}
      onSelect={onSelect ? server => { onSelect(server); onOpenChange(false); } : undefined} />
  </StandaloneScreen>;
}
