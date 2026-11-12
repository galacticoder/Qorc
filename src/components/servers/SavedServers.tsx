import { useEffect, useId, useState } from 'react';
import { ArrowLeft, Check, Loader2, MoreVertical, Pencil, Plus, Server, Trash2 } from 'lucide-react';
import { useSavedServers } from '../../hooks/useSavedServers';
import { SAVED_SERVER_LIMIT, savedServers, type SavedServer } from '../../lib/servers/saved-servers';
import { normalizeToWss } from '../../lib/servers/server-address';
import { SERVER_NAME_MAX_LENGTH } from '../../../shared/server-profile.js';
import { Popover, PopoverContent, PopoverTrigger } from '../ui/popover';
import { useAppBack } from '../../hooks/useAppBack';

interface SavedServersProps {
  readonly onSelect?: (server: SavedServer) => void;
  readonly selectedUrl?: string;
  readonly disabled?: boolean;
  readonly showTitle?: boolean;
  readonly onClose?: () => void;
  readonly titleId?: string;
}

export function SavedServers({ onSelect, selectedUrl = '', disabled = false, showTitle = true, onClose, titleId }: SavedServersProps) {
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

  const closeEditor = () => { setEditor(null); setError(''); };
  useAppBack(!!editor, () => { if (!saving) closeEditor(); }, 90);
  useAppBack(openMenu !== null, () => setOpenMenu(null), 95);
  useEffect(() => {
    if (!editor) return;
    const back = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || event.defaultPrevented) return;
      event.preventDefault();
      event.stopPropagation();
      if (!saving) { setEditor(null); setError(''); }
    };
    document.addEventListener('keydown', back, true);
    return () => document.removeEventListener('keydown', back, true);
  }, [!!editor, saving]);

  return (
    <div className="saved-servers" aria-busy={saving}>
      {onClose && <header className="saved-servers-screen-header">
        <button type="button" className="saved-server-back" data-screen-back={!editor ? '' : undefined} aria-label={editor ? 'Back to saved servers' : 'Back from manage servers'} disabled={saving} onClick={editor ? closeEditor : onClose}><ArrowLeft size={24} aria-hidden="true" /></button>
        <div><h1 id={titleId}>{editor ? editor.previous ? 'Edit server' : 'Add server' : 'Manage servers'}</h1>
          {editor && <p>Choose a name and add the server address.</p>}</div>
      </header>}
      <div className="saved-servers-screen-body">
      {editor ? <form className="saved-server-editor" onSubmit={save}>
        {!onClose && <div className="saved-server-editor-heading">
          <button type="button" className="saved-server-back" aria-label="Back to saved servers" disabled={saving} onClick={closeEditor}><ArrowLeft size={20} aria-hidden="true" /></button>
          <div><h3>{editor.previous ? 'Edit server' : 'Add a server'}</h3><p>Give this server a name you recognise.</p></div>
        </div>}
        <div className="saved-server-fields">
          <label htmlFor={`${inputId}-name`}>Server name</label>
          <input id={`${inputId}-name`} value={editor.name} onChange={(event) => setEditor({ ...editor, name: event.target.value })} maxLength={SERVER_NAME_MAX_LENGTH} placeholder="My server" autoComplete="off" disabled={busy} autoFocus required />
          <label htmlFor={`${inputId}-url`}>Server address</label>
          <input id={`${inputId}-url`} value={editor.url} onChange={(event) => setEditor({ ...editor, url: event.target.value })} maxLength={2048} placeholder="wss://your-server" spellCheck={false} autoCapitalize="none" autoComplete="off" inputMode="url" disabled={busy} required aria-describedby={`${inputId}-hint`} />
          <p id={`${inputId}-hint`} className="saved-server-hint">Paste the server address or Tor onion address.</p>
        </div>
        {(error || loadError) && <p className="saved-servers-error" role="alert">{error || loadError}</p>}
        <div className="saved-server-editor-actions">
          <button type="button" className="saved-servers-action" disabled={saving} onClick={closeEditor}>Cancel</button>
          <button type="submit" className="saved-servers-action is-primary" disabled={busy || !editor.name.trim() || !editor.url.trim()}>{saving && <Loader2 size={17} className="animate-spin" aria-hidden="true" />}{saving ? 'Saving…' : 'Save server'}</button>
        </div>
      </form> : <>
        <div className="saved-servers-heading">
          <span>{showTitle ? 'Saved servers' : 'Your servers'}{loaded && <span className="saved-servers-count">{servers.length}</span>}</span>
          <button type="button" className="saved-servers-action is-primary" disabled={busy || !loaded || servers.length >= SAVED_SERVER_LIMIT} onClick={() => startEditor()}><Plus size={18} aria-hidden="true" /><span>Add server</span></button>
        </div>
        {(error || loadError) && <p className="saved-servers-error" role="alert">{error || loadError}</p>}
        {!loaded && !loadError && <div className="saved-servers-empty" role="status"><Loader2 className="animate-spin" size={24} aria-hidden="true" /><p>Loading your servers…</p></div>}
        {loadError && <button type="button" className="saved-servers-action" onClick={() => void savedServers.load().catch(() => undefined)}>Try again</button>}
        {loaded && servers.length === 0 && <div className="saved-servers-empty"><span className="saved-servers-empty-icon"><Server size={28} aria-hidden="true" /></span><h3>A place for your servers</h3><p>Add a server to find it here whenever you need it.</p><button type="button" className="saved-servers-action" disabled={busy} onClick={() => startEditor()}><Plus size={18} aria-hidden="true" />Add your first server</button></div>}
        <div className="saved-servers-list">
          {servers.map((server) => {
            const selected = normalizeToWss(selectedUrl) === server.url;
            const details = <>
              <span className="saved-server-icon">{server.icon ? <img src={server.icon} alt="" draggable={false} /> : <Server size={23} aria-hidden="true" />}</span>
              <span className="saved-server-details"><span className="saved-server-name-line"><span className="saved-server-name">{server.name}</span>{selected && <span className="saved-server-status"><Check size={12} aria-hidden="true" />Selected</span>}</span><span className="saved-server-url" title={server.url}>{server.url}</span></span>
            </>;
            return <div className={`saved-server-row${selected ? ' is-selected' : ''}`} key={server.url}>
              {onSelect ? <button type="button" className="saved-server-select" disabled={busy} onClick={() => onSelect(server)} aria-pressed={selected}>{details}</button> : <div className="saved-server-select">{details}</div>}
              <Popover open={openMenu === server.url && !busy} onOpenChange={(open) => setOpenMenu(open ? server.url : null)}>
                <PopoverTrigger asChild><button type="button" className="saved-server-options" disabled={busy} aria-label={`Options for ${server.name}`}><MoreVertical size={20} aria-hidden="true" /></button></PopoverTrigger>
                <PopoverContent align="end" className="saved-server-menu qorc-screen-overlay" sideOffset={6}>
                  <button type="button" onClick={() => startEditor(server)}><Pencil size={18} aria-hidden="true" /><span>Edit server</span></button>
                  <button type="button" className="is-danger" onClick={() => void remove(server.url)}><Trash2 size={18} aria-hidden="true" /><span>Remove server</span></button>
                </PopoverContent>
              </Popover>
            </div>;
          })}
        </div>
        {loaded && servers.length >= SAVED_SERVER_LIMIT && <p className="saved-server-hint">You can save up to {SAVED_SERVER_LIMIT} servers.</p>}
      </>}
      </div>
    </div>
  );
}
