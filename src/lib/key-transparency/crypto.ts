import { sha3_512 } from '@noble/hashes/sha3.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

import {
  KEY_TRANSPARENCY_EPOCH_MS,
  encodeKeyTransparencySignaturePayload,
  exactPlainObject,
  isKeyTransparencyHash,
  isKeyTransparencyLabel,
  keyTransparencyEpoch,
  keyTransparencyRecordHash,
  keyTransparencySignedUpdate,
} from '../../../shared/key-transparency-protocol.js';
import { Base64, decodeCanonicalBase64 } from '../cryptography/base64';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES } from '../../../shared/crypto-sizes.js';
import { KEY_TRANSPARENCY_PROTOCOL } from '../../../shared/protocol-keys.js';
import { bytesToHex, concatUint8Arrays } from '../../../shared/bytes.js';

const LABEL_DOMAIN = new TextEncoder().encode(PROTOCOL_KEYS.KEY_TRANSPARENCY_LABEL);
const EPOCH_LABEL_DOMAIN = new TextEncoder().encode(PROTOCOL_KEYS.KEY_TRANSPARENCY_EPOCH_LABEL);
const KEY_COMMITMENT_DOMAIN = new TextEncoder().encode(PROTOCOL_KEYS.KEY_TRANSPARENCY_KEY_COMMITMENT);
const SIGNER_KEY_ID_DOMAIN = new TextEncoder().encode(PROTOCOL_KEYS.KEY_TRANSPARENCY_SIGNER_KEY);

export type KeyTransparencyEventKind =
  | 'register'
  | 'rotate'
  | 'recovery-request'
  | 'recovery-cancel';

export interface KeyTransparencySignedUpdate {
  protocol: typeof KEY_TRANSPARENCY_PROTOCOL;
  kind: KeyTransparencyEventKind;
  label: string;
  version: number;
  rootCommitment: string;
  recoveryCommitment: string;
  previousRootCommitment: string | null;
  pendingRootCommitment: string | null;
  recoveryRequestEpoch: number | null;
  recoveryActivatesAt: number | null;
}

export interface KeyTransparencyAuthorization {
  previousRootPublicKey: string | null;
  previousRootSignature: string | null;
  recoveryPublicKey: string | null;
  recoverySignature: string | null;
  rootPublicKey: string | null;
  rootSignature: string | null;
}

const SIGNED_UPDATE_KEYS = [
  'kind',
  'label',
  'pendingRootCommitment',
  'previousRootCommitment',
  'protocol',
  'recoveryActivatesAt',
  'recoveryCommitment',
  'recoveryRequestEpoch',
  'rootCommitment',
  'version',
];

const AUTHORIZATION_KEYS = [
  'previousRootPublicKey',
  'previousRootSignature',
  'recoveryPublicKey',
  'recoverySignature',
  'rootPublicKey',
  'rootSignature',
];

function hashWithDomain(domain: Uint8Array, bytes: Uint8Array): Uint8Array {
  const hasher = sha3_512.create();
  hasher.update(domain);
  hasher.update(bytes);
  return hasher.digest();
}

function hashHex(domain: Uint8Array, bytes: Uint8Array): string {
  const digest = hashWithDomain(domain, bytes);
  try {
    return bytesToHex(digest);
  } finally {
    digest.fill(0);
  }
}

function canonicalBase64(bytes: Uint8Array): string {
  return Base64.arrayBufferToBase64(bytes);
}

function decodeOptional(value: string | null, expectedBytes: number): Uint8Array | null {
  return value === null ? null : decodeCanonicalBase64(
    value,
    'key-transparency base64 value',
    { exactBytes: expectedBytes }
  );
}

function assertSignedUpdate(value: unknown): asserts value is KeyTransparencySignedUpdate {
  const update = value as KeyTransparencySignedUpdate;
  if (
    !exactPlainObject(update, SIGNED_UPDATE_KEYS) ||
    update.protocol !== KEY_TRANSPARENCY_PROTOCOL ||
    !['register', 'rotate', 'recovery-request', 'recovery-cancel'].includes(update.kind) ||
    !isKeyTransparencyLabel(update.label) ||
    !Number.isSafeInteger(update.version) ||
    update.version < 1 ||
    !isKeyTransparencyHash(update.rootCommitment) ||
    !isKeyTransparencyHash(update.recoveryCommitment) ||
    !(update.previousRootCommitment === null || isKeyTransparencyHash(update.previousRootCommitment)) ||
    !(update.pendingRootCommitment === null || isKeyTransparencyHash(update.pendingRootCommitment)) ||
    !(update.recoveryRequestEpoch === null || Number.isSafeInteger(update.recoveryRequestEpoch)) ||
    !(update.recoveryActivatesAt === null || Number.isSafeInteger(update.recoveryActivatesAt))
  ) throw new Error('Invalid key-transparency signed update');
}

function assertAuthorization(value: unknown): asserts value is KeyTransparencyAuthorization {
  const authorization = value as KeyTransparencyAuthorization;
  if (
    !exactPlainObject(authorization, AUTHORIZATION_KEYS) ||
    Object.values(authorization).some((entry) => entry !== null && typeof entry !== 'string')
  ) throw new Error('Invalid key-transparency authorization');
}

export function deriveKeyTransparencyLabel(discoveryEncryptionKey: Uint8Array): string {
  if (!(discoveryEncryptionKey instanceof Uint8Array) || discoveryEncryptionKey.length !== 32) {
    throw new Error('Invalid key-transparency discovery key');
  }
  return hashHex(LABEL_DOMAIN, discoveryEncryptionKey);
}

export function keyTransparencyPublicKeyCommitment(publicKey: Uint8Array): string {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== ML_DSA_87_PUBLIC_KEY_BYTES) {
    throw new Error('Invalid key-transparency public key');
  }
  return hashHex(KEY_COMMITMENT_DOMAIN, publicKey);
}

export function keyTransparencySignerKeyId(publicKey: Uint8Array): string {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== ML_DSA_87_PUBLIC_KEY_BYTES) {
    throw new Error('Invalid key-transparency signer key');
  }
  return hashHex(SIGNER_KEY_ID_DOMAIN, publicKey);
}

export async function createKeyTransparencyAuthorizationWithSigners(
  signedUpdate: KeyTransparencySignedUpdate,
  keys: {
    previousRoot?: { publicKey: Uint8Array; sign: (payload: Uint8Array) => Promise<string> };
    recovery?: { publicKey: Uint8Array; sign: (payload: Uint8Array) => Promise<string> };
    root?: { publicKey: Uint8Array; sign: (payload: Uint8Array) => Promise<string> };
  },
): Promise<KeyTransparencyAuthorization> {
  assertSignedUpdate(signedUpdate);
  const payload = encodeKeyTransparencySignaturePayload('event-authorization', signedUpdate);
  const sign = async (
    key: { publicKey: Uint8Array; sign: (payload: Uint8Array) => Promise<string> } | undefined,
  ): Promise<string | null> => {
    if (!key) return null;
    if (key.publicKey.length !== ML_DSA_87_PUBLIC_KEY_BYTES) {
      throw new Error('Invalid key-transparency public key');
    }
    const signature = await key.sign(payload);
    const decoded = decodeCanonicalBase64(
      signature,
      'key-transparency base64 value',
      { exactBytes: ML_DSA_87_SIGNATURE_BYTES },
    );
    decoded.fill(0);
    return signature;
  };
  try {
    return {
      previousRootPublicKey: keys.previousRoot ? canonicalBase64(keys.previousRoot.publicKey) : null,
      previousRootSignature: await sign(keys.previousRoot),
      recoveryPublicKey: keys.recovery ? canonicalBase64(keys.recovery.publicKey) : null,
      recoverySignature: await sign(keys.recovery),
      rootPublicKey: keys.root ? canonicalBase64(keys.root.publicKey) : null,
      rootSignature: await sign(keys.root),
    };
  } finally {
    payload.fill(0);
  }
}

function verifySignature(
  signature: Uint8Array | null,
  payload: Uint8Array,
  publicKey: Uint8Array | null,
): boolean {
  return !!signature && !!publicKey && ml_dsa87.verify(signature, payload, publicKey);
}

export function verifyKeyTransparencyAuthorization(
  signedUpdate: KeyTransparencySignedUpdate,
  authorization: KeyTransparencyAuthorization,
): boolean {
  try {
    assertSignedUpdate(signedUpdate);
    assertAuthorization(authorization);
  } catch {
    return false;
  }
  let previousRootPublicKey: Uint8Array | null = null;
  let previousRootSignature: Uint8Array | null = null;
  let recoveryPublicKey: Uint8Array | null = null;
  let recoverySignature: Uint8Array | null = null;
  let rootPublicKey: Uint8Array | null = null;
  let rootSignature: Uint8Array | null = null;
  const payload = encodeKeyTransparencySignaturePayload(
    'event-authorization',
    keyTransparencySignedUpdate(signedUpdate),
  );
  try {
    previousRootPublicKey = decodeOptional(authorization.previousRootPublicKey, ML_DSA_87_PUBLIC_KEY_BYTES);
    previousRootSignature = decodeOptional(authorization.previousRootSignature, ML_DSA_87_SIGNATURE_BYTES);
    recoveryPublicKey = decodeOptional(authorization.recoveryPublicKey, ML_DSA_87_PUBLIC_KEY_BYTES);
    recoverySignature = decodeOptional(authorization.recoverySignature, ML_DSA_87_SIGNATURE_BYTES);
    rootPublicKey = decodeOptional(authorization.rootPublicKey, ML_DSA_87_PUBLIC_KEY_BYTES);
    rootSignature = decodeOptional(authorization.rootSignature, ML_DSA_87_SIGNATURE_BYTES);

    if (
      previousRootPublicKey &&
      keyTransparencyPublicKeyCommitment(previousRootPublicKey) !== signedUpdate.previousRootCommitment
    ) return false;

    if (signedUpdate.kind === 'register') {
      return signedUpdate.version === 1 &&
        signedUpdate.previousRootCommitment === null &&
        signedUpdate.pendingRootCommitment === null &&
        signedUpdate.recoveryRequestEpoch === null &&
        signedUpdate.recoveryActivatesAt === null &&
        previousRootPublicKey === null && previousRootSignature === null &&
        !!rootPublicKey && !!rootSignature && !!recoveryPublicKey && !!recoverySignature &&
        keyTransparencyPublicKeyCommitment(rootPublicKey) === signedUpdate.rootCommitment &&
        keyTransparencyPublicKeyCommitment(recoveryPublicKey) === signedUpdate.recoveryCommitment &&
        verifySignature(rootSignature, payload, rootPublicKey) &&
        verifySignature(recoverySignature, payload, recoveryPublicKey);
    }
    if (signedUpdate.kind === 'rotate') {
      return signedUpdate.previousRootCommitment !== null &&
        signedUpdate.pendingRootCommitment === null &&
        signedUpdate.recoveryRequestEpoch === null &&
        signedUpdate.recoveryActivatesAt === null &&
        !!previousRootPublicKey && !!previousRootSignature && !!rootPublicKey && !!rootSignature &&
        recoveryPublicKey === null && recoverySignature === null &&
        signedUpdate.rootCommitment !== signedUpdate.previousRootCommitment &&
        keyTransparencyPublicKeyCommitment(rootPublicKey) === signedUpdate.rootCommitment &&
        verifySignature(previousRootSignature, payload, previousRootPublicKey) &&
        verifySignature(rootSignature, payload, rootPublicKey);
    }
    if (signedUpdate.kind === 'recovery-request') {
      return signedUpdate.previousRootCommitment === signedUpdate.rootCommitment &&
        signedUpdate.pendingRootCommitment !== null &&
        signedUpdate.pendingRootCommitment !== signedUpdate.rootCommitment &&
        Number.isSafeInteger(signedUpdate.recoveryRequestEpoch) &&
        Number.isSafeInteger(signedUpdate.recoveryActivatesAt) &&
        previousRootPublicKey === null && previousRootSignature === null &&
        !!rootPublicKey && !!rootSignature && !!recoveryPublicKey && !!recoverySignature &&
        keyTransparencyPublicKeyCommitment(rootPublicKey) === signedUpdate.pendingRootCommitment &&
        keyTransparencyPublicKeyCommitment(recoveryPublicKey) === signedUpdate.recoveryCommitment &&
        verifySignature(rootSignature, payload, rootPublicKey) &&
        verifySignature(recoverySignature, payload, recoveryPublicKey);
    }
    return signedUpdate.previousRootCommitment === signedUpdate.rootCommitment &&
      signedUpdate.pendingRootCommitment === null &&
      signedUpdate.recoveryRequestEpoch === null &&
      signedUpdate.recoveryActivatesAt === null &&
      !!previousRootPublicKey && !!previousRootSignature &&
      rootPublicKey === null && rootSignature === null &&
      recoveryPublicKey === null && recoverySignature === null &&
      verifySignature(previousRootSignature, payload, previousRootPublicKey);
  } catch {
    return false;
  } finally {
    previousRootPublicKey?.fill(0);
    previousRootSignature?.fill(0);
    recoveryPublicKey?.fill(0);
    recoverySignature?.fill(0);
    rootPublicKey?.fill(0);
    rootSignature?.fill(0);
    payload.fill(0);
  }
}

export function deriveKeyTransparencyEpochLabel(
  discoveryEncryptionKey: Uint8Array,
  epoch: number,
): string {
  if (!(discoveryEncryptionKey instanceof Uint8Array) || discoveryEncryptionKey.length !== 32) {
    throw new Error('Invalid key-transparency discovery key');
  }
  if (!Number.isSafeInteger(epoch) || epoch < 0) {
    throw new Error('Invalid key-transparency epoch');
  }
  const suffix = new Uint8Array(8);
  new DataView(suffix.buffer).setBigUint64(0, BigInt(epoch), false);
  const input = concatUint8Arrays(discoveryEncryptionKey, suffix);
  try {
    return hashHex(EPOCH_LABEL_DOMAIN, input);
  } finally {
    input.fill(0);
    suffix.fill(0);
  }
}

export function keyTransparencyCurrentEpoch(now: number = Date.now()): number {
  return keyTransparencyEpoch(now);
}

export function keyTransparencyEpochStartMs(epoch: number): number {
  if (!Number.isSafeInteger(epoch) || epoch < 0) {
    throw new Error('Invalid key-transparency epoch');
  }
  return epoch * KEY_TRANSPARENCY_EPOCH_MS;
}

// Hash over the full signed transition
export function computeKeyTransparencyRecordHash(
  signedUpdate: KeyTransparencySignedUpdate,
  authorization: KeyTransparencyAuthorization,
): string {
  assertSignedUpdate(signedUpdate);
  assertAuthorization(authorization);
  return keyTransparencyRecordHash(sha3_512, signedUpdate, authorization);
}
