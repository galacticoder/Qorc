import { useEffect, useRef, useState } from 'react';
import { Server } from 'lucide-react';
import { savedServers, type ServerProfile } from '../../lib/servers/saved-servers';

interface SaveServerPromptProps {
  readonly url: string;
  readonly profile: ServerProfile;
  readonly onSaveStart: () => void;
  readonly onDismiss: () => void;
}

export function SaveServerPrompt({ url, profile, onSaveStart, onDismiss }: SaveServerPromptProps) {
  const [phase, setPhase] = useState<'offer' | 'saving' | 'saved'>('offer');
  const [error, setError] = useState('');
  const savingRef = useRef(false);

  useEffect(() => {
    if (phase !== 'saved') return;
    const timer = setTimeout(onDismiss, 3000);
    return () => clearTimeout(timer);
  }, [phase, onDismiss]);

  const save = async () => {
    if (phase !== 'offer' || savingRef.current) return;
    savingRef.current = true;
    setPhase('saving');
    setError('');
    try {
      onSaveStart();
      await savedServers.save({ ...profile, url });
      setPhase('saved');
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Server could not be saved');
      setPhase('offer');
    } finally {
      savingRef.current = false;
    }
  };

  return (
    <div className={`server-save-offer${phase === 'saved' ? ' is-saved' : ''}`} role="status" aria-live="polite" aria-busy={phase === 'saving'}>
      {phase !== 'saved' && <span className="server-save-icon" aria-hidden="true">{profile.icon ? <img src={profile.icon} alt="" draggable={false} /> : <Server size={20} />}</span>}
      <div className="conn-sheet-text">
        <span className="conn-sheet-title">
          {phase === 'saved' ? 'Server saved' : 'Save this server?'}
        </span>
        {phase !== 'saved' && <span className="conn-sheet-detail server-save-server-name" title={profile.name}>{profile.name}</span>}
        {error && <span className="conn-sheet-detail" role="alert">{error}</span>}
      </div>
      {phase !== 'saved' && (
        <div className="conn-sheet-actions">
          <button type="button" className="conn-sheet-btn" disabled={phase === 'saving'} onClick={onDismiss}>Don’t save</button>
          <button type="button" className="conn-sheet-btn is-primary" disabled={phase === 'saving'} onClick={() => void save()}>{phase === 'saving' ? 'Saving…' : 'Save server'}</button>
        </div>
      )}
    </div>
  );
}
