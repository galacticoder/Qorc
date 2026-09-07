import type { PeerCertificateBundle } from '../types/p2p-types';
import { storage } from '../tauri-bindings';
import { validatePeerCertificateBundle } from '../utils/peer-certificate-utils';
import { parseP2PEndpointUrl } from '../utils/p2p-endpoint';
import { PQ_SIG_PUBLIC_KEY_SIZE } from '../constants';
import { getCurrentLocalAccountScope } from '../security/local-account-scope';
import { canonicalAuthUsername } from '../sanitizers';
import { deriveScopedStorageKey } from '../security/scoped-storage-key';
import { STORAGE_KEY_DOMAINS, STORAGE_PREFIXES } from '../database/storage-keys';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

const MAX_PERSISTED_CERT_CHARS = 64 * 1024;
const PERSISTED_RECORD_KEYS = ['cert', 'endpoint', 'protocol'];
const PERSISTED_ENDPOINT_KEYS = new Set(['announcedAt', 'endpointUrl', 'signerPublicKeyBase64']);

export interface PersistedPeerEndpoint {
  endpointUrl: string;
  signerPublicKeyBase64: string;
  announcedAt: number;
}

export interface PersistedPeerRecord {
  cert: PeerCertificateBundle | null;
  endpoint: PersistedPeerEndpoint | null;
}

const persistedKey = async (owner: string, peer: string): Promise<string> => {
  const accountScope = await getCurrentLocalAccountScope(
    canonicalAuthUsername(owner, 'certificate owner')
  );
  return deriveScopedStorageKey(
    STORAGE_PREFIXES.PEER_CERTIFICATE,
    STORAGE_KEY_DOMAINS.PEER_CERTIFICATE,
    accountScope,
    canonicalAuthUsername(peer, 'certificate peer')
  );
};

const validatePersistedEndpoint = (value: unknown): PersistedPeerEndpoint | null => {
  if (value === null) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid persisted peer endpoint');
  }
  const candidate = value as Record<string, unknown>;
  if (Object.keys(candidate).some((key) => !PERSISTED_ENDPOINT_KEYS.has(key))) {
    throw new Error('Persisted peer endpoint contains unexpected fields');
  }
  const parsed = parseP2PEndpointUrl(
    typeof candidate.endpointUrl === 'string' ? candidate.endpointUrl : null
  );
  if (!parsed?.hasDirectAddress) throw new Error('Invalid persisted peer endpoint URL');
  if (
    typeof candidate.signerPublicKeyBase64 !== 'string' ||
    candidate.signerPublicKeyBase64.length !== 4 * Math.ceil(PQ_SIG_PUBLIC_KEY_SIZE / 3) ||
    !Number.isSafeInteger(candidate.announcedAt) ||
    (candidate.announcedAt as number) < 0
  ) throw new Error('Invalid persisted peer endpoint');
  return {
    endpointUrl: parsed.endpointUrl,
    signerPublicKeyBase64: candidate.signerPublicKeyBase64,
    announcedAt: candidate.announcedAt as number,
  };
};

const writeTails = new Map<string, Promise<void>>();

const MAX_WRITE_TAILS = 512;

async function updateRecord(
  owner: string,
  peer: string,
  mutate: (current: PersistedPeerRecord) => PersistedPeerRecord
): Promise<void> {
  const tailKey = `${owner}\0${peer}`;
  const previous = writeTails.get(tailKey) ?? Promise.resolve();
  const write = previous.catch(() => { }).then(async () => {
    const key = await persistedKey(owner, peer);
    const next = mutate(await readRecord(key, peer));
    const serialized = JSON.stringify({
      protocol: PROTOCOL_KEYS.PEER_CERTIFICATE_STORE,
      cert: next.cert,
      endpoint: next.endpoint,
    });
    if (serialized.length > MAX_PERSISTED_CERT_CHARS) throw new Error('Peer record is too large');
    if (!await storage.set(key, serialized)) {
      throw new Error('Peer record could not be persisted');
    }
    if (await storage.get(key) !== serialized) {
      throw new Error('Peer record update could not be verified');
    }
  });
  const tail = write.then(() => { }, () => { });
  writeTails.set(tailKey, tail);
  if (writeTails.size > MAX_WRITE_TAILS) {
    const oldest = writeTails.keys().next().value;
    if (oldest !== undefined && oldest !== tailKey) writeTails.delete(oldest);
  }
  try {
    await write;
  } finally {
    if (writeTails.get(tailKey) === tail) writeTails.delete(tailKey);
  }
}

async function readRecord(key: string, peer: string): Promise<PersistedPeerRecord> {
  const raw = await storage.get(key);
  if (raw === null) return { cert: null, endpoint: null };
  if (raw.length === 0) throw new Error('Invalid persisted peer record');
  if (raw.length > MAX_PERSISTED_CERT_CHARS) throw new Error('Persisted peer record is too large');
  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Invalid persisted peer record');
  }
  const candidate = parsed as Record<string, unknown>;
  if (Object.keys(candidate).sort().join(',') !== PERSISTED_RECORD_KEYS.join(',')) {
    throw new Error('Invalid persisted peer record shape');
  }
  if (candidate.protocol !== PROTOCOL_KEYS.PEER_CERTIFICATE_STORE) {
    throw new Error('Invalid persisted peer record protocol');
  }
  const cert = candidate.cert === null
    ? null
    : await validatePeerCertificateBundle(candidate.cert, peer, Date.now(), true);
  if (candidate.cert !== null && !cert) throw new Error('Invalid persisted peer certificate');
  return { cert, endpoint: validatePersistedEndpoint(candidate.endpoint) };
}

export async function loadPersistedPeerCert(
  owner: string,
  peer: string,
  allowExpired = false,
): Promise<PeerCertificateBundle | null> {
  const record = await readRecord(await persistedKey(owner, peer), peer);
  if (!record.cert) return null;
  return await validatePeerCertificateBundle(record.cert, peer, Date.now(), allowExpired);
}

export async function savePersistedPeerCert(owner: string, peer: string, cert: PeerCertificateBundle): Promise<void> {
  const validated = await validatePeerCertificateBundle(cert, peer, Date.now());
  if (!validated) throw new Error('Invalid peer certificate');
  await updateRecord(owner, peer, (current) => ({ ...current, cert: validated }));
}

export async function loadPersistedPeerEndpoint(owner: string, peer: string): Promise<PersistedPeerEndpoint | null> {
  return (await readRecord(await persistedKey(owner, peer), peer)).endpoint;
}

export async function savePersistedPeerEndpoint(
  owner: string,
  peer: string,
  endpoint: PersistedPeerEndpoint
): Promise<void> {
  const validated = validatePersistedEndpoint(endpoint);
  if (!validated) throw new Error('Invalid peer endpoint');
  await updateRecord(owner, peer, (current) => {
    if (current.endpoint && current.endpoint.announcedAt > validated.announcedAt) return current;
    return { ...current, endpoint: validated };
  });
}

export async function clearPersistedPeerEndpoint(owner: string, peer: string): Promise<void> {
  await updateRecord(owner, peer, (current) => ({ ...current, endpoint: null }));
}
