import { useId, useState } from 'react';
import { Check, MoreVertical, Pencil, Plus, Server, Trash2 } from 'lucide-react';
import { useSavedServers } from '../../hooks/useSavedServers';
import { savedServers, type SavedServer } from '../../lib/servers/saved-servers';
import { normalizeToWss } from '../../lib/servers/server-address';
import { SERVER_NAME_MAX_LENGTH } from '../../../shared/server-profile.js';
import { Popover, PopoverContent, PopoverTrigger } from '../ui/popover';

interface SavedServersProps {
  readonly onSelect?: (server: SavedServer) => void;
  readonly selectedUrl?: string;
  readonly disabled?: boolean;
  readonly showTitle?: boolean;
}

export function SavedServers({ onSelect, selectedUrl = '', disabled = false, showTitle = true }: SavedServersProps) {
  const { servers, loaded, error: loadError } = useSavedServers();
  const [editor, setEditor] = useState<{ previous?: SavedServer; name: string; url: string } | null>(null);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [openMenu, setOpenMenu] = useState<string | null>(null);
  const inputId = useId();
  const busy = disabled || saving;

  const startEditor = (previous?: SavedServer) => {
    setOpenMenu(null);
    setError('');
    setEditor({ previous, name: previous?.name ?? '', url: previous?.url ?? '' });
  };

  const save = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!editor || busy) return;
    setSaving(true);
    setError('');
    try {
      await savedServers.save({ name: editor.name, url: editor.url,
        icon: normalizeToWss(editor.url) === editor.previous?.url ? editor.previous.icon : null }, editor.previous?.url);
      setEditor(null);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Server could not be saved');
    } finally {
      setSaving(false);
    }
  };

  const remove = async (url: string) => {
    if (busy) return;
    setOpenMenu(null);
    setSaving(true);
    setError('');
    try {
      await savedServers.remove(url);
      if (editor?.previous?.url === url) setEditor(null);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Server could not be removed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="saved-servers">
      <div className="saved-servers-heading">
        {showTitle && <span>Saved servers</span>}
        <button type="button" className="saved-servers-action" disabled={busy || !loaded} onClick={() => startEditor()}>
          <Plus size={16} aria-hidden="true" /><span>Add server</span>
        </button>
      </div>
      {(error || loadError) && <p className="saved-servers-error" role="alert">{error || loadError}</p>}
      {!loaded && !loadError && <p className="saved-servers-empty" role="status">Loading saved servers…</p>}
      {loadError && <button type="button" className="saved-servers-action" onClick={() => void savedServers.load().catch(() => undefined)}>Try again</button>}
      {loaded && servers.length === 0 && !editor && <p className="saved-servers-empty">No saved servers yet.</p>}
      <div className="saved-servers-list">
        {servers.map((server) => {
          const selected = normalizeToWss(selectedUrl) === server.url;
          const details = <>
            <span className="saved-server-icon">{server.icon ? <img src={server.icon} alt="" draggable={false} /> : <Server size={20} aria-hidden="true" />}</span>
            <span className="saved-server-details"><span className="saved-server-name">{server.name}</span><span className="saved-server-url">{server.url}</span></span>
            {selected && <Check size={16} className="saved-server-check" aria-hidden="true" />}
          </>;
          return <div className={`saved-server-row${selected ? ' is-selected' : ''}`} key={server.url}>
            {onSelect ? <button type="button" className="saved-server-select" disabled={busy} onClick={() => onSelect(server)} aria-pressed={selected}>{details}</button>
              : <div className="saved-server-select">{details}</div>}
            <Popover open={openMenu === server.url && !busy} onOpenChange={(open) => setOpenMenu(open ? server.url : null)}>
              <PopoverTrigger asChild><button type="button" className="saved-server-options" disabled={busy} aria-label={`Options for ${server.name}`}><MoreVertical size={18} aria-hidden="true" /></button></PopoverTrigger>
              <PopoverContent align="end" className="saved-server-menu" sideOffset={6}>
                <button type="button" onClick={() => startEditor(server)}><Pencil size={16} aria-hidden="true" /><span>Edit server</span></button>
                <button type="button" className="is-danger" onClick={() => void remove(server.url)}><Trash2 size={16} aria-hidden="true" /><span>Remove server</span></button>
              </PopoverContent>
            </Popover>
          </div>;
        })}
      </div>
      {editor && <form className="saved-server-editor" onSubmit={save} aria-busy={saving}>
        <label htmlFor={`${inputId}-name`}>Name</label>
        <input id={`${inputId}-name`} value={editor.name} onChange={(event) => setEditor({ ...editor, name: event.target.value })} maxLength={SERVER_NAME_MAX_LENGTH} placeholder="Server name" autoComplete="off" disabled={busy} autoFocus required />
        <label htmlFor={`${inputId}-url`}>Server address</label>
        <input id={`${inputId}-url`} value={editor.url} onChange={(event) => setEditor({ ...editor, url: event.target.value })} maxLength={2048} placeholder="wss://your-server" spellCheck={false} autoComplete="off" disabled={busy} required />
        <div className="saved-server-editor-actions">
          <button type="button" className="saved-servers-action" disabled={busy} onClick={() => { setEditor(null); setError(''); }}>Cancel</button>
          <button type="submit" className="saved-servers-action" disabled={busy || !editor.name.trim() || !editor.url.trim()}>{saving ? 'Saving…' : 'Save server'}</button>
        </div>
      </form>}
    </div>
  );
}
