import type { PeerCertificateBundle } from '../types/p2p-types';
import { loadPersistedPeerCert } from './persisted-peer-cert';
import { loadTrustedPersistedDiscoveryMaterial } from '../utils/signal-bundle-utils';
import { computePeerCertificateFingerprint } from '../utils/peer-certificate-utils';
import { isKeyTransparencyAuthorizedPeerCertificate } from '../key-transparency/verified-material';

export async function loadAuthorizedPeerCertificate(
  account: string,
  peer: string,
  isCurrent: () => boolean,
): Promise<PeerCertificateBundle | null> {
  if (!isCurrent()) return null;
  const isAuthorized = (cert: PeerCertificateBundle) => isKeyTransparencyAuthorizedPeerCertificate({
    account,
    peer,
    kyberPublicBase64: cert.kyberPublicKey,
    dilithiumPublicBase64: cert.dilithiumPublicKey,
    x25519PublicBase64: cert.x25519PublicKey,
    peerCertificateFingerprint: computePeerCertificateFingerprint(cert),
  });
  const persisted = await loadPersistedPeerCert(account, peer, true);
  if (!isCurrent()) return null;
  if (persisted && isAuthorized(persisted)) return persisted;
  const material = await loadTrustedPersistedDiscoveryMaterial(account, peer);
  if (!isCurrent()) return null;
  const cert = material?.peerCertificate;
  return cert && isAuthorized(cert) ? cert : null;
}
