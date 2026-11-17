import { useEffect, useState } from 'react';
import { Check, ChevronRight, Copy } from 'lucide-react';
import { readSavedServerIdentity, type SavedServerIdentity } from '../../lib/servers/server-identity';
import type { SavedServer } from '../../lib/servers/saved-servers';
import type { ConnectedServer } from '../../hooks/useConnectedServer';
import { copyTextToClipboard } from '../../lib/clipboard';
import { CopyIconButton } from '../ui/CopyIconButton';

const grouped = (fingerprint: string) => fingerprint.match(/.{1,8}/g)?.join(' ') ?? fingerprint;

function IdentityCodeBlock({ label, value, caption, fingerprint = false }: { label: string; value: string; caption?: string; fingerprint?: boolean }) {
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState(false);
  useEffect(() => { setCopied(false); setError(false); }, [value]);
  const copy = async () => {
    setError(false);
    try { await copyTextToClipboard(value); setCopied(true); }
    catch { setError(true); }
  };
  return <div className="server-identity-code-block">
    <h4>{label}{caption && <span>{caption}</span>}</h4>
    <div className="server-identity-code">
      <code>{fingerprint ? grouped(value) : value}</code>
      <CopyIconButton copied={copied} aria-label={copied ? `${label} copied` : `Copy ${label.toLowerCase()}`} title={copied ? 'Copied' : `Copy ${label.toLowerCase()}`}  onClick={() => void copy()} />
    </div>
    {error && <p className="saved-servers-error" role="alert">Could not copy this value. Try again.</p>}
  </div>;
}

export function ServerIdentityDetails({ server, connected }: { server: SavedServer; connected: ConnectedServer | null }) {
  const [result, setResult] = useState<{ identity: SavedServerIdentity | null; error: boolean } | null>(null);
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  useEffect(() => {
    let active = true;
    setResult(null);
    setCopied(false);
    setCopyError(false);
    void readSavedServerIdentity(server.url).then(identity => {
      if (active) setResult({ identity, error: false });
    }, () => { if (active) setResult({ identity: null, error: true }); });
    return () => { active = false; };
  }, [server.url, connected?.identity?.fingerprint]);

  const address = new URL(server.url);
  const live = connected?.url === server.url ? connected : null;
  const identity = result?.identity;
  const matches = !!identity && live?.identity?.fingerprint === identity.fingerprint;
  const mismatch = !!identity && !!live?.identity && !matches;
  const status = !result ? 'Reading saved identity…' : result.error ? 'Identity unavailable'
    : mismatch ? 'Identity mismatch' : matches ? 'Matches saved identity'
      : identity ? 'Saved identity' : 'No saved identity';
  const copyDetails = async () => {
    setCopyError(false);
    try {
      await copyTextToClipboard([
        `Saved name: ${server.name}`, `Address: ${server.url}`, `Status: ${status}`,
        ...(matches && live?.signedName ? [`Signed server name: ${live.signedName}`] : []),
        ...(matches && live?.identity?.serverId ? [`Signed server ID: ${live.identity.serverId}`] : []),
        ...(identity ? [`Server fingerprint (BLAKE3): ${identity.fingerprint}`,
          ...identity.keyFingerprints.map(key => `${key.purpose} (${key.algorithm}, BLAKE3): ${key.fingerprint}`)] : []),
        ...(mismatch ? [`Current connection fingerprint: ${live.identity.fingerprint}`] : []),
      ].join('\n'));
      setCopied(true);
    } catch { setCopyError(true); }
  };

  return <div className="server-identity-details">
    <div className="server-identity-heading"><h3>Server identity</h3>
      <span className={`server-identity-state${matches ? ' is-matched' : mismatch || result?.error ? ' is-error' : ''}`} role="status">{status}</span>
    </div>
    <IdentityCodeBlock label="Full address" value={server.url} />
    {identity && <>
      <IdentityCodeBlock fingerprint label="Server fingerprint" value={identity.fingerprint} caption="BLAKE3" />
      {mismatch && <>
        <p className="saved-servers-error" role="alert">The current connection does not match this saved identity. Do not treat it as verified.</p>
        <IdentityCodeBlock fingerprint label="Current connection fingerprint" value={live.identity.fingerprint} caption="BLAKE3" />
      </>}
      <p className="server-identity-explanation">Compare the full fingerprint with the server owner through another trusted channel. Names, images and server IDs can be copied.</p>
      {!live && <p className="server-identity-explanation">This is the identity stored on this device, not a live check. No connection was made to open these details.</p>}

    </>}
    {result && !identity && <p className="server-identity-explanation">{result.error
      ? 'The saved identity could not be read. This server is not being shown as verified.'
      : 'No cryptographic identity is stored for this address yet. The first connection pins the keys it receives and compares the resulting fingerprint with the server owner before trusting it.'}</p>}
    <button type="button" className="saved-servers-action server-identity-copy" disabled={!result || result.error} onClick={() => void copyDetails()}>
      {copied ? <Check size={16} aria-hidden="true" /> : <Copy size={16} aria-hidden="true" />}{copied ? 'Copied identity details' : 'Copy identity details'}
    </button>
    {copyError && <p className="saved-servers-error" role="alert">Could not copy the identity details. Try again.</p>}
    <details className="server-identity-connection"><summary><ChevronRight size={16} aria-hidden="true" /><span>Connection details</span></summary>
    <dl className="server-identity-facts">
      <div><dt>Hostname</dt><dd className="server-identity-mono">{address.hostname}</dd></div>
      <div><dt>Port</dt><dd>{address.port || '443'}</dd></div>
      <div><dt>Address type</dt><dd>{address.hostname.endsWith('.onion') ? 'Tor onion service' : 'WebSocket over TLS (wss)'}</dd></div>
      <div><dt>Connection</dt><dd>{live ? 'Connected' : 'Not connected to this server'}</dd></div>
      {matches && live?.signedName && <div><dt>Signed server name</dt><dd>{live.signedName}</dd></div>}
      {matches && live?.identity?.serverId && <div><dt>Signed server ID</dt><dd className="server-identity-mono">{live.identity.serverId}</dd></div>}
    </dl>
    </details>
    {identity && (<details className="server-identity-keys"><summary><ChevronRight size={16} aria-hidden="true" /><span>Key fingerprints</span></summary>
        {identity.keyFingerprints.map(key => <IdentityCodeBlock fingerprint key={key.algorithm} label={key.purpose} caption={key.algorithm} value={key.fingerprint} />)}
      </details>)}
  </div>;
}
