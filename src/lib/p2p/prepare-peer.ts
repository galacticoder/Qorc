import type { PeerCertificateBundle } from '../types/p2p-types';
import { p2pTransport } from '../transport/p2p-transport';
import { loadPersistedPeerEndpoint } from './persisted-peer-cert';

export async function preparePeerTransport(
  ownerUsername: string,
  peer: string,
  getPeerCertificate: (peer: string) => Promise<PeerCertificateBundle | null>,
  isCurrent: () => boolean,
): Promise<PeerCertificateBundle> {
  const assertCurrent = () => {
    if (!isCurrent()) throw new Error('Account changed while preparing peer transport');
  };
  assertCurrent();
  const cert = await getPeerCertificate(peer);
  assertCurrent();
  if (!cert) throw new Error('PEER_CERT_MISSING');
  await p2pTransport.registerPeerCertificate(peer, cert);
  assertCurrent();
  if (!p2pTransport.hasAuthenticatedEndpoint(peer)) {
    const endpoint = await loadPersistedPeerEndpoint(ownerUsername, peer);
    assertCurrent();
    if (endpoint) {
      p2pTransport.updateAuthenticatedEndpoint(
        peer,
        endpoint.endpointUrl,
        endpoint.signerPublicKeyBase64,
        endpoint.announcedAt,
      );
    }
  }
  return cert;
}
