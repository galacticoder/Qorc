import { blake3 } from '@noble/hashes/blake3.js';

const textEncoder = new TextEncoder();
const ROUTE_ID_REGEX = /^[A-Za-z0-9_-]{64,128}$/;

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function deriveCommitment(domain: string, inboxId: string): string {
  const normalized = typeof inboxId === 'string' ? inboxId.trim() : '';
  if (!normalized) return '';
  const digest = blake3(new Uint8Array([
    ...textEncoder.encode(domain),
    0,
    ...textEncoder.encode(normalized)
  ]), { dkLen: 64 });
  return toBase64Url(digest);
}

export function isRendezvousRouteId(value: unknown): value is string {
  return typeof value === 'string' && ROUTE_ID_REGEX.test(value);
}

export function deriveRendezvousRouteId(inboxId: string): string {
  return deriveCommitment('qor-rendezvous-route-v1', inboxId);
}

export function deriveMailboxMetadataId(inboxId: string): string {
  return deriveCommitment('qor-mailbox-metadata-v1', inboxId);
}

export function deriveBundleLookupId(inboxId: string): string {
  return deriveCommitment('qor-libsignal-bundle-v1', inboxId);
}

export function deriveBlockListLookupId(inboxId: string): string {
  return deriveCommitment('qor-block-list-v1', inboxId);
}

export function deriveRendezvousLookups(inboxId: string): {
  routeId: string;
  mailboxLookupId: string;
  bundleLookupId: string;
  blockListLookupId: string;
} {
  const routeId = deriveRendezvousRouteId(inboxId);
  return {
    routeId,
    mailboxLookupId: deriveMailboxMetadataId(inboxId),
    bundleLookupId: deriveBundleLookupId(inboxId),
    blockListLookupId: deriveBlockListLookupId(inboxId)
  };
}
