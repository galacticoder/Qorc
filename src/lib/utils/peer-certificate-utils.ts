import { blake3 } from '@noble/hashes/blake3.js';
import type { PeerCertificateBundle } from '../types/p2p-types';
import { CryptoUtils } from './crypto-utils';
import { toUint8 } from './p2p-utils';
import { bytesToHex } from './byte-utils';
import { Base64, decodeCanonicalBase64 } from '../cryptography/base64';
import {
  AUTH_USERNAME_REGEX,
  CERT_CLOCK_SKEW_MS,
  P2P_PEER_CERT_TTL_MS,
  PQ_KEM_PUBLIC_KEY_SIZE,
  PQ_SIG_PUBLIC_KEY_SIZE,
  PQ_SIG_SIGNATURE_SIZE,
  X25519_PUBLIC_KEY_LENGTH
} from '../constants';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

const PEER_CERTIFICATE_KEYS = [
  'username',
  'dilithiumPublicKey',
  'kyberPublicKey',
  'x25519PublicKey',
  'proof',
  'issuedAt',
  'expiresAt',
  'signature'
] as const;

function hasExactCertificateShape(value: unknown): value is PeerCertificateBundle {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const keys = Object.keys(value as object).sort();
  const expected = [...PEER_CERTIFICATE_KEYS].sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function canonicalKey(value: unknown, length: number): Uint8Array | null {
  return toUint8(value, length);
}

// Fully validate a peer certificate bundle
export async function validatePeerCertificateBundle(
  fetched: PeerCertificateBundle | null | undefined,
  expectedUsername: string,
  now: number = Date.now()
): Promise<PeerCertificateBundle | null> {
  let dilithiumKey: Uint8Array | null = null;
  let kyberKey: Uint8Array | null = null;
  let x25519Key: Uint8Array | null = null;
  let signature: Uint8Array | null = null;
  let canonical: Uint8Array | null = null;
  try {
    if (!hasExactCertificateShape(fetched)) return null;
    if (
      !Number.isSafeInteger(now) ||
      !AUTH_USERNAME_REGEX.test(expectedUsername) ||
      fetched.username !== expectedUsername
    ) return null;
    const cert = normalizePeerCertificateBundle(fetched);
    if (cert.username !== fetched.username) return null;
    if (
      !Number.isSafeInteger(cert.issuedAt) ||
      !Number.isSafeInteger(cert.expiresAt) ||
      cert.expiresAt - cert.issuedAt !== P2P_PEER_CERT_TTL_MS
    ) return null;
    dilithiumKey = canonicalKey(cert.dilithiumPublicKey, PQ_SIG_PUBLIC_KEY_SIZE);
    kyberKey = canonicalKey(cert.kyberPublicKey, PQ_KEM_PUBLIC_KEY_SIZE);
    x25519Key = canonicalKey(cert.x25519PublicKey, X25519_PUBLIC_KEY_LENGTH);
    signature = canonicalKey(cert.signature, PQ_SIG_SIGNATURE_SIZE);
    if (!dilithiumKey || !kyberKey || !x25519Key || !signature) return null;
    if (!isSelfSignedPeerCertificate(cert)) return null;
    canonical = encodePeerCertificateSigningPayload(cert);
    const valid = await CryptoUtils.Dilithium.verify(signature, canonical, dilithiumKey);
    if (!valid) return null;
    const notYetValid = cert.issuedAt > (now + CERT_CLOCK_SKEW_MS);
    const alreadyExpired = cert.expiresAt <= (now - CERT_CLOCK_SKEW_MS);
    if (notYetValid || alreadyExpired) return null;
    return cert;
  } catch {
    return null;
  } finally {
    dilithiumKey?.fill(0);
    kyberKey?.fill(0);
    x25519Key?.fill(0);
    signature?.fill(0);
    canonical?.fill(0);
  }
}

export function computePeerCertificateFingerprint(cert: PeerCertificateBundle): string {
  const canonical = JSON.stringify({
    schema: PROTOCOL_KEYS.PEER_CERTIFICATE_IDENTITY,
    username: cert.username,
    dilithiumPublicKey: cert.dilithiumPublicKey,
    kyberPublicKey: cert.kyberPublicKey,
    x25519PublicKey: cert.x25519PublicKey,
    proof: cert.proof
  });
  const digest = blake3(new TextEncoder().encode(canonical), { dkLen: 32 });
  return bytesToHex(digest);
}

export function normalizePeerCertificateBundle(cert: PeerCertificateBundle): PeerCertificateBundle {
  return {
    username: typeof cert.username === 'string' ? cert.username.trim() : '',
    dilithiumPublicKey: cert.dilithiumPublicKey,
    kyberPublicKey: cert.kyberPublicKey,
    x25519PublicKey: cert.x25519PublicKey,
    proof: cert.proof,
    issuedAt: cert.issuedAt,
    expiresAt: cert.expiresAt,
    signature: cert.signature
  };
}

export function isSelfSignedPeerCertificate(cert: PeerCertificateBundle): boolean {
  return (
    typeof cert?.proof === 'string' &&
    typeof cert?.dilithiumPublicKey === 'string' &&
    cert.proof === cert.dilithiumPublicKey
  );
}

export function encodePeerCertificateSigningPayload(cert: PeerCertificateBundle): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      schema: PROTOCOL_KEYS.PEER_CERTIFICATE_ATTESTATION,
      version: 4,
      username: cert.username,
      dilithiumPublicKey: cert.dilithiumPublicKey,
      kyberPublicKey: cert.kyberPublicKey,
      x25519PublicKey: cert.x25519PublicKey,
      proof: cert.proof,
      issuedAt: cert.issuedAt,
      expiresAt: cert.expiresAt
    })
  );
}

export function extractX25519FromSignalBundle(fullBundle: unknown): string | undefined {
  if (!fullBundle || typeof fullBundle !== 'object' || Array.isArray(fullBundle)) return undefined;
  const bundle = fullBundle as Record<string, unknown>;

  if (
    typeof bundle.identityKeyBase64 === 'string' &&
    bundle.identityKeyBase64.length === 4 * Math.ceil(33 / 3) &&
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(bundle.identityKeyBase64)
  ) {
    let keyBytes: Uint8Array | null = null;
    try {
      keyBytes = decodeCanonicalBase64(
        bundle.identityKeyBase64,
        'Signal identity key',
        { exactBytes: 33 }
      );

      if (
        keyBytes[0] === 0x05 &&
        Base64.arrayBufferToBase64(keyBytes) === bundle.identityKeyBase64
      ) {
        const rawKey = keyBytes.slice(1);
        try {
          return Base64.arrayBufferToBase64(rawKey);
        } finally {
          rawKey.fill(0);
        }
      }
    } catch {
      return undefined;
    } finally {
      keyBytes?.fill(0);
    }
  }

  return undefined;
}

export function extractStaticMlKemFromSignalBundle(fullBundle: unknown): string | undefined {
  if (!fullBundle || typeof fullBundle !== 'object' || Array.isArray(fullBundle)) return undefined;
  const pqKey = (fullBundle as Record<string, unknown>).staticMlKem;
  if (!pqKey || typeof pqKey !== 'object' || Array.isArray(pqKey)) return undefined;
  const publicKey = (pqKey as Record<string, unknown>).publicKeyBase64;
  return typeof publicKey === 'string' ? publicKey : undefined;
}
