import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { ArrowLeft, Check, Loader2, MoreVertical, Pencil, Plus, Search, Server, Trash2, X } from 'lucide-react';
import { useSavedServers } from '../../hooks/useSavedServers';
import { SAVED_SERVER_LIMIT, savedServers, type SavedServer } from '../../lib/servers/saved-servers';
import { normalizeToWss } from '../../lib/servers/server-address';
import { SERVER_NAME_MAX_LENGTH } from '../../../shared/server-profile.js';
import { Popover, PopoverContent, PopoverTrigger } from '../ui/popover';
import { useAppBack } from '../../hooks/useAppBack';
import type { ConnectedServer } from '../../hooks/useConnectedServer';
import { ServerIdentityDetails } from './ServerIdentityDetails';

interface SavedServersProps {
  readonly onSelect?: (server: SavedServer) => void;
  readonly selectedUrl?: string;
  readonly currentServer?: ConnectedServer | null;
  readonly disabled?: boolean;
  readonly showTitle?: boolean;
  readonly onClose?: () => void;
  readonly titleId?: string;
}

function ServerMark({ name, url, icon }: { name: string; url: string; icon?: string | null }) {
  const words = name.trim().split(/\s+/u);
  const initials = words.length > 1
    ? `${Array.from(words[0])[0] ?? ''}${Array.from(words[words.length - 1])[0] ?? ''}`
    : Array.from(name.trim()).slice(0, 2).join('');
  const tone = Array.from(url || name).reduce((sum, character) => sum + character.codePointAt(0)!, 0) % 4;
  return <span className="saved-server-icon" data-tone={tone} aria-hidden="true">
    {icon ? <img src={icon} alt="" draggable={false} /> : initials.toLocaleUpperCase()}
  </span>;
}

export function SavedServers({ onSelect, selectedUrl = '', currentServer = null, disabled = false, showTitle = true, onClose, titleId }: SavedServersProps) {
  const { servers, loaded, error: loadError } = useSavedServers();
  const [editor, setEditor] = useState<{ previous?: SavedServer; name: string; url: string } | null>(null);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [openMenu, setOpenMenu] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [detailsUrl, setDetailsUrl] = useState<string | null>(null);
  const serverButtons = useRef(new Map<string, HTMLButtonElement>());
  const adding = !!editor && !editor.previous;
  const inputId = useId();
  const bodyRef = useRef<HTMLDivElement>(null);
  const nameInputRef = useRef<HTMLInputElement>(null);
  const addButtonRef = useRef<HTMLButtonElement>(null);
  useLayoutEffect(() => {
    if (!editor) return;
    const input = nameInputRef.current;
    input?.focus({ preventScroll: true });
    const body = bodyRef.current;
    const form = input?.closest('form');
    if (!body || !form) return;
    const viewport = body.getBoundingClientRect();
    const row = form.getBoundingClientRect();
    if (row.top < viewport.top || row.bottom > viewport.bottom) {
      body.scrollTop += row.top - viewport.top;
    }
  }, [editor?.previous?.url, adding]);
  const busy = disabled || saving;
  const search = query.trim().toLocaleLowerCase();
  const visibleServers = servers.filter(server => server.url === editor?.previous?.url || !search || `${server.name} ${server.url}`.toLocaleLowerCase().includes(search));
  const atLimit = servers.length >= SAVED_SERVER_LIMIT;
  const canSaveCurrent = currentServer && !servers.some(server => server.url === currentServer.url);

  const saveCurrent = async () => {
    if (!currentServer || !canSaveCurrent || busy || atLimit) return;
    setSaving(true);
    setError('');
    try {
      await savedServers.save(currentServer);
      setQuery('');
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Server could not be saved');
    } finally {
      setSaving(false);
    }
  };

  const saveCurrentButton = canSaveCurrent && <button type="button" className="saved-servers-action is-primary" disabled={busy || atLimit} onClick={() => void saveCurrent()}>Save current server</button>;

  const startEditor = (previous?: SavedServer) => {
    setOpenMenu(null);
    setError('');
    setDetailsUrl(null);
    if (!previous) setQuery('');
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
      setQuery('');
      requestAnimationFrame(() => serverButtons.current.get(normalizeToWss(editor.url))?.focus({ preventScroll: true }));
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
      if (detailsUrl === url) setDetailsUrl(null);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Server could not be removed');
    } finally {
      setSaving(false);
    }
  };

  const closeEditor = () => {
    const previousUrl = editor?.previous?.url;
    setEditor(null); setError('');
    requestAnimationFrame(() => {
      (previousUrl ? serverButtons.current.get(previousUrl) : addButtonRef.current)?.focus({ preventScroll: true });
    });
  };
  useAppBack(!!editor, () => { if (!saving) closeEditor(); }, 90);
  useAppBack(detailsUrl !== null, () => setDetailsUrl(null), 85);
  useAppBack(openMenu !== null, () => setOpenMenu(null), 95);
  useEffect(() => {
    if (!editor && !detailsUrl) return;
    const back = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || event.defaultPrevented || openMenu) return;
      event.preventDefault();
      event.stopPropagation();
      if (!saving) {
        if (editor) closeEditor();
        else { const url = detailsUrl; setDetailsUrl(null); serverButtons.current.get(url)?.focus({ preventScroll: true }); }
      }
    };
    document.addEventListener('keydown', back, true);
    return () => document.removeEventListener('keydown', back, true);
  }, [!!editor, saving, detailsUrl, openMenu]);

  const editorFields = editor && <div className="saved-server-fields">
    <div className="saved-server-field">
      <label htmlFor={`${inputId}-name`}>Server name</label>
      <input ref={nameInputRef} id={`${inputId}-name`} value={editor.name} onChange={(event) => setEditor({ ...editor, name: event.target.value })} maxLength={SERVER_NAME_MAX_LENGTH} placeholder="A name you recognise" autoComplete="off" disabled={busy} required aria-describedby={!editor.previous ? `${inputId}-name-hint` : undefined} />
      {!editor.previous && <p id={`${inputId}-name-hint`} className="saved-server-hint">This is how it will appear in your list.</p>}
    </div>
    <div className="saved-server-field">
      <label htmlFor={`${inputId}-url`}>Server address</label>
      <input id={`${inputId}-url`} value={editor.url} onChange={(event) => setEditor({ ...editor, url: event.target.value })} maxLength={2048} placeholder="wss://your-server" spellCheck={false} autoCapitalize="none" autoComplete="off" inputMode="url" disabled={busy} required aria-describedby={!editor.previous ? `${inputId}-hint` : undefined} />
      {!editor.previous && <p id={`${inputId}-hint`} className="saved-server-hint">Paste a server address or Tor .onion address.</p>}
    </div>
  </div>;
  const editorActions = <div className="saved-server-editor-actions">
    <button type="button" className="saved-servers-action" disabled={saving} onClick={closeEditor}>Cancel</button>
    <button type="submit" className="saved-servers-action is-primary" disabled={busy || !editor?.name.trim() || !editor?.url.trim()}>{saving && <Loader2 size={17} className="animate-spin" aria-hidden="true" />}{saving ? 'Saving…' : 'Save server'}</button>
  </div>;

  return (
    <div className="saved-servers" aria-busy={saving}>
      {onClose && <header className="saved-servers-screen-header">
        <button type="button" className="saved-server-back" data-screen-back={!editor ? '' : undefined} aria-label={editor ? 'Back to saved servers' : 'Back from saved servers'} disabled={saving} onClick={editor ? closeEditor : onClose}><ArrowLeft size={22} aria-hidden="true" /></button>
        <div><h1 id={titleId}>Saved servers</h1></div>
      </header>}
      <div ref={bodyRef} className="saved-servers-screen-body">
        {!onClose && showTitle && <div className="saved-servers-inline-heading"><h2>Saved servers</h2></div>}
        {(loadError || (!editor && error)) && <p className="saved-servers-error" role="alert">{loadError || error}</p>}
        {!loaded && !loadError && <div className="saved-servers-empty" role="status"><Loader2 className="animate-spin" size={24} aria-hidden="true" /><p>Loading your servers…</p></div>}
        {loadError && <button type="button" className="saved-servers-action is-primary" onClick={() => void savedServers.load().catch(() => undefined)}>Try again</button>}
        {loaded && servers.length === 0 && !loadError && !adding && <>
          <div className="saved-servers-empty is-first-use">
            <div className="saved-servers-empty-art" aria-hidden="true">
              <span className="saved-servers-empty-card is-back"><i /><b /><b /></span>
              <span className="saved-servers-empty-card is-front"><span><Server size={22} /></span><b /><b /></span>
            </div>
            <h2>Your servers, in one place</h2>
            <p>Save a server address and make your next visit a little easier.</p>
            <div className="saved-servers-empty-actions">
              <button ref={addButtonRef} type="button" className="saved-servers-action is-primary" disabled={busy} onClick={() => startEditor()}><Plus size={18} aria-hidden="true" />Add server</button>
              {saveCurrentButton}
            </div>
          </div>
        </>}
        {loaded && (servers.length > 0 || adding) && <>
          <div className="saved-servers-toolbar">
            <div className="qorc-search-field saved-servers-search">
              <span className="qorc-search-icon" aria-hidden="true"><Search /></span>
              <input className="qorc-search-input" type="search" placeholder="Find a server" aria-label="Search saved servers" value={query} onChange={event => { setQuery(event.target.value); setDetailsUrl(null); }} autoComplete="off" spellCheck={false} />
              {query && <button className="qorc-search-action" type="button" aria-label="Clear server search" onClick={() => setQuery('')}><X /></button>}
            </div>
            <button ref={addButtonRef} type="button" className="saved-servers-action is-primary" disabled={busy || atLimit || adding} onClick={() => startEditor()}><Plus size={18} aria-hidden="true" /><span>Add server</span></button>
            {saveCurrentButton}
          </div>
          <div className="saved-servers-heading">
            <h2>Your servers <span className="saved-servers-count">{servers.length}</span></h2>
          </div>
          <div className="saved-servers-list" role="list" aria-label="Saved servers">
          {adding && <div className="saved-server-row" role="listitem">
            <form className="saved-server-inline-editor" onSubmit={save} aria-label="Add server">
              <ServerMark name={editor.name.trim() || 'New server'} url={editor.url} />
              <div className="saved-server-inline-fields">{editorFields}</div>
              {error && <p className="saved-servers-error" role="alert">{error}</p>}
              {editorActions}
            </form>
          </div>}
          {visibleServers.map((server) => {
            const selected = normalizeToWss(selectedUrl) === server.url;
            const connected = currentServer?.url === server.url;
            const detailsId = `${inputId}-identity-${servers.indexOf(server)}`;
            if (editor?.previous?.url === server.url) return <div className="saved-server-row is-editing" role="listitem" key={server.url}>
              <form className="saved-server-inline-editor" onSubmit={save} aria-label={`Edit ${server.name}`}>
                <ServerMark name={server.name} url={server.url} icon={server.icon} />
                <div className="saved-server-inline-fields">{editorFields}</div>
                {normalizeToWss(editor.url) !== server.url && <p className="saved-server-hint saved-server-address-note">The identity is tied to the address. Changing the address does not transfer its saved identity.</p>}
                {error && <p className="saved-servers-error" role="alert">{error}</p>}
                {editorActions}
              </form>
            </div>;
            const details = <>
              <ServerMark name={server.name} url={server.url} icon={server.icon} />
              <span className="saved-server-details">
                <span className="saved-server-name">{server.name}</span>
                <span className="saved-server-url" title={server.url}>{server.url}</span>
                {connected ? <span className="saved-server-status is-connected" role="status">Connected</span> : selected && <span className="saved-server-status"><Check size={13} aria-hidden="true" />Selected</span>}
              </span>
            </>;
            return <div className="saved-server-row" role="listitem" key={server.url}>
              <div className="saved-server-summary">
              <button ref={element => { if (element) serverButtons.current.set(server.url, element); else serverButtons.current.delete(server.url); }}
                type="button" className="saved-server-select" disabled={busy}
                onClick={() => setDetailsUrl(detailsUrl === server.url ? null : server.url)}
                aria-label={`View identity for ${server.name}`} aria-expanded={detailsUrl === server.url} aria-controls={detailsId}>{details}</button>
              <Popover open={openMenu === server.url && !busy} onOpenChange={(open) => setOpenMenu(open ? server.url : null)}>
                <PopoverTrigger asChild><button type="button" className="saved-server-options qorc-more-btn" disabled={busy} aria-label={`Options for ${server.name}`}><MoreVertical size={20} aria-hidden="true" /></button></PopoverTrigger>
                <PopoverContent align="end" className="saved-server-menu qorc-screen-overlay" sideOffset={6} onCloseAutoFocus={event => { if (editor) event.preventDefault(); }}>
                  <button type="button" onClick={() => startEditor(server)}><Pencil size={18} aria-hidden="true" /><span>Edit server</span></button>
                  <button type="button" className="is-danger" onClick={() => void remove(server.url)}><Trash2 size={18} aria-hidden="true" /><span>Remove from saved</span></button>
                </PopoverContent>
              </Popover>
              </div>
              {detailsUrl === server.url && <div id={detailsId} className="saved-server-expanded-details">
                <ServerIdentityDetails key={server.url} server={server} connected={currentServer?.url === server.url ? currentServer : null}
                  headerAction={onSelect && <button type="button" className="saved-servers-action is-primary saved-server-use" disabled={busy} onClick={() => onSelect(server)}>Use this server</button>} />
              </div>}
            </div>;
          })}
          </div>
          {visibleServers.length === 0 && !adding && <div className="saved-servers-no-results" role="status"><Search size={24} aria-hidden="true" /><h3>No matching servers</h3><p>Try a different name or server address.</p><button type="button" className="saved-servers-action" onClick={() => setQuery('')}>Clear search</button></div>}
          <p className="saved-servers-footnote">{atLimit ? `You’ve saved all ${SAVED_SERVER_LIMIT} servers. Remove one to add another.` : onSelect ? 'Open a server to view its identity and choose its address.' : 'Select a server to view its identity.'}</p>
        </>}
      </div>
    </div>
  );
}
