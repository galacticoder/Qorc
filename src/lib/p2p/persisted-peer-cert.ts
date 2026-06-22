import type { PeerCertificateBundle } from '../types/p2p-types';
import { storage } from '../tauri-bindings';
import { validatePeerCertificateBundle } from '../utils/peer-certificate-utils';

const PERSISTED_PEER_CERT_PREFIX = 'peercert:v1:';
const persistedKey = (peer: string): string => `${PERSISTED_PEER_CERT_PREFIX}${peer.trim().toLowerCase()}`;

export async function loadPersistedPeerCert(peer: string): Promise<PeerCertificateBundle | null> {
  try {
    if (!peer) return null;
    const raw = await storage.get(persistedKey(peer));
    if (!raw) return null;
    return await validatePeerCertificateBundle(JSON.parse(raw), peer);
  } catch {
    return null;
  }
}

export function savePersistedPeerCert(peer: string, cert: PeerCertificateBundle): void {
  try { void storage.set(persistedKey(peer), JSON.stringify(cert)); } catch { }
}

export function removePersistedPeerCert(peer: string): void {
  try { void storage.remove(persistedKey(peer)); } catch { }
}
