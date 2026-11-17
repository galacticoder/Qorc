import { useRef, useState } from 'react';
import { Server } from 'lucide-react';
import { savedServers, type ServerProfile } from '../../lib/servers/saved-servers';

interface SaveServerPromptProps {
  readonly url: string;
  readonly profile: ServerProfile;
  readonly onSaveStart: () => void;
  readonly onDismiss: () => void;
}

export function SaveServerPrompt({ url, profile, onSaveStart, onDismiss }: SaveServerPromptProps) {
  const [phase, setPhase] = useState<'offer' | 'saving'>('offer');
  const [error, setError] = useState('');
  const savingRef = useRef(false);

  const save = async () => {
    if (phase !== 'offer' || savingRef.current) return;
    savingRef.current = true;
    setPhase('saving');
    setError('');
    try {
      onSaveStart();
      await savedServers.save({ ...profile, url });
      onDismiss();
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Server could not be saved');
      setPhase('offer');
    } finally {
      savingRef.current = false;
    }
  };

  return (
    <div className="server-save-offer" role="status" aria-live="polite" aria-busy={phase === 'saving'}>
      <span className="server-save-icon" aria-hidden="true">{profile.icon ? <img src={profile.icon} alt="" draggable={false} /> : <Server size={20} />}</span>
      <div className="conn-sheet-text">
        <span className="conn-sheet-title">
          Save this server?
        </span>
        <span className="conn-sheet-detail server-save-server-name" title={profile.name}>{profile.name}</span>
        {error && <span className="conn-sheet-detail" role="alert">{error}</span>}
      </div>
      <div className="conn-sheet-actions">
        <button type="button" className="conn-sheet-btn" disabled={phase === 'saving'} onClick={onDismiss}>Don’t save</button>
        <button type="button" className="conn-sheet-btn is-primary" disabled={phase === 'saving'} onClick={() => void save()}>{phase === 'saving' ? 'Saving…' : 'Save server'}</button>
      </div>
    </div>
  );
}
