import { sha3_512 } from '@noble/hashes/sha3.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

import {
  KEY_TRANSPARENCY_DELTA_MAX_EPOCHS,
  KEY_TRANSPARENCY_DELTA_MAX_RECORDS,
  KEY_TRANSPARENCY_MAX_LOG_SIZE,
  KEY_TRANSPARENCY_ML_DSA_PUBLIC_KEY_BYTES,
  KEY_TRANSPARENCY_ML_DSA_SIGNATURE_BYTES,
  KEY_TRANSPARENCY_PROTOCOL,
  encodeKeyTransparencySignaturePayload,
  exactPlainObject,
  isKeyTransparencyHash,
  isKeyTransparencyRecord,
  keyTransparencyFoldRecords,
  keyTransparencyGenesisRoot,
  keyTransparencyHeadPayload,
  keyTransparencyRecoveryActivationEpoch,
} from '../../../shared/key-transparency-protocol.js';
import { decodeCanonicalBase64 as decodeBase64 } from '../cryptography/base64';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import {
  computeKeyTransparencyRecordHash,
  deriveKeyTransparencyEpochLabel,
  keyTransparencyPublicKeyCommitment,
  keyTransparencySignerKeyId,
  verifyKeyTransparencyAuthorization,
} from './crypto';
import type {
  KeyTransparencyCheckpoint,
  KeyTransparencyLogHead,
  KeyTransparencyRecord,
  KeyTransparencySyncResult,
  KeyTransparencyTransition,
  VerifiedKeyTransparencyContactState,
} from './types';

const HEAD_KEYS = ['entryCount', 'epoch', 'genesisEpoch', 'protocol', 'rootHash', 'signature', 'signerKeyId'];
const SYNC_KEYS = [
  'currentEpoch',
  'firstLogIndex',
  'fromEpoch',
  'head',
  'protocol',
  'records',
  'toEpoch',
];

export class KeyTransparencyGlobalVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyTransparencyGlobalVerificationError';
  }
}

function globalFailure(message: string): never {
  throw new KeyTransparencyGlobalVerificationError(message);
}

function decodeKeyTransparencyBase64(value: unknown, expectedBytes: number): Uint8Array {
  try {
    return decodeBase64(value, 'key-transparency base64 value', { exactBytes: expectedBytes });
  } catch {
    globalFailure('Invalid key-transparency base64 value');
  }
}

export function parseKeyTransparencyHead(value: unknown): KeyTransparencyLogHead {
  const head = value as KeyTransparencyLogHead;
  if (
    !exactPlainObject(head, HEAD_KEYS) ||
    head.protocol !== KEY_TRANSPARENCY_PROTOCOL ||
    !Number.isSafeInteger(head.epoch) ||
    head.epoch < 0 ||
    !Number.isSafeInteger(head.genesisEpoch) ||
    head.genesisEpoch < 0 ||
    head.genesisEpoch > head.epoch ||
    !Number.isSafeInteger(head.entryCount) ||
    head.entryCount < 0 ||
    head.entryCount > KEY_TRANSPARENCY_MAX_LOG_SIZE ||
    !isKeyTransparencyHash(head.rootHash) ||
    !isKeyTransparencyHash(head.signerKeyId) ||
    typeof head.signature !== 'string'
  ) globalFailure('Invalid key-transparency head');
  return head;
}

// Verify a heads ML-DSA-87 signature against the pinned signer.
export function verifyKeyTransparencyHead(
  value: unknown,
  signerPublicKey: Uint8Array,
): KeyTransparencyLogHead {
  const head = parseKeyTransparencyHead(value);
  if (
    !(signerPublicKey instanceof Uint8Array) ||
    signerPublicKey.length !== KEY_TRANSPARENCY_ML_DSA_PUBLIC_KEY_BYTES
  ) globalFailure('Invalid key-transparency signer key');
  if (keyTransparencySignerKeyId(signerPublicKey) !== head.signerKeyId) {
    globalFailure('Key-transparency head was signed by an unexpected signer');
  }
  const signature = decodeKeyTransparencyBase64(head.signature, KEY_TRANSPARENCY_ML_DSA_SIGNATURE_BYTES);
  const payload = encodeKeyTransparencySignaturePayload(
    'log-head',
    keyTransparencyHeadPayload(head),
  );
  try {
    if (!ml_dsa87.verify(signature, payload, signerPublicKey)) {
      globalFailure('Invalid key-transparency head signature');
    }
  } finally {
    signature.fill(0);
    payload.fill(0);
  }
  return head;
}

export function verifyKeyTransparencyGossipHead(
  value: unknown,
  signerPublicKey: Uint8Array,
): KeyTransparencyLogHead {
  return verifyKeyTransparencyHead(value, signerPublicKey);
}

//A cold client starts at the logs own genesis epoch
export function keyTransparencyGenesisCheckpoint(genesisEpoch = 0): KeyTransparencyCheckpoint {
  if (!Number.isSafeInteger(genesisEpoch) || genesisEpoch < 0) {
    globalFailure('Invalid key-transparency genesis epoch');
  }
  return {
    protocol: KEY_TRANSPARENCY_PROTOCOL,
    epoch: genesisEpoch,
    entryCount: 0,
    rootHash: keyTransparencyGenesisRoot(sha3_512),
  };
}

function parseSyncResult(value: unknown): KeyTransparencySyncResult {
  const sync = value as KeyTransparencySyncResult;
  if (
    !exactPlainObject(sync, SYNC_KEYS) ||
    sync.protocol !== KEY_TRANSPARENCY_PROTOCOL ||
    !Number.isSafeInteger(sync.currentEpoch) ||
    sync.currentEpoch < 0 ||
    !Number.isSafeInteger(sync.fromEpoch) ||
    sync.fromEpoch < 0 ||
    !Number.isSafeInteger(sync.toEpoch) ||
    sync.toEpoch < sync.fromEpoch ||
    sync.toEpoch - sync.fromEpoch >= KEY_TRANSPARENCY_DELTA_MAX_EPOCHS ||
    !Number.isSafeInteger(sync.firstLogIndex) ||
    sync.firstLogIndex < 0 ||
    sync.firstLogIndex > KEY_TRANSPARENCY_MAX_LOG_SIZE ||
    !Array.isArray(sync.records) ||
    sync.records.length > KEY_TRANSPARENCY_DELTA_MAX_RECORDS ||
    !sync.records.every((record) => isKeyTransparencyRecord(record))
  ) globalFailure('Invalid key-transparency sync result');
  return sync;
}

export interface VerifiedKeyTransparencyDelta {
  checkpoint: KeyTransparencyCheckpoint;
  records: KeyTransparencyRecord[];
  head: KeyTransparencyLogHead;
}

// Fold a delta onto a checkpoint and confirm the result is the head the server signed.
export function verifyKeyTransparencyDelta(
  previous: KeyTransparencyCheckpoint,
  value: unknown,
  signerPublicKey: Uint8Array,
): VerifiedKeyTransparencyDelta {
  const sync = parseSyncResult(value);
  const head = verifyKeyTransparencyHead(sync.head, signerPublicKey);

  if (sync.fromEpoch !== previous.epoch) {
    globalFailure('Key-transparency delta does not continue the stored checkpoint');
  }
  if (sync.firstLogIndex !== previous.entryCount) {
    globalFailure('Key-transparency delta does not start at the stored log position');
  }
  if (head.entryCount < previous.entryCount) {
    globalFailure('Key-transparency log shrank below a verified checkpoint');
  }
  if (head.epoch < previous.epoch) {
    globalFailure('Key-transparency log rolled back to an earlier epoch');
  }

  const entryCount = previous.entryCount + sync.records.length;
  if (entryCount > KEY_TRANSPARENCY_MAX_LOG_SIZE) {
    globalFailure('Key-transparency log exceeded its maximum size');
  }

  const rootHash = keyTransparencyFoldRecords(sha3_512, previous.rootHash, sync.records);

  if (sync.toEpoch >= head.epoch) {
    if (entryCount !== head.entryCount || rootHash !== head.rootHash) {
      globalFailure('Key-transparency records do not reproduce the signed head');
    }
  } else if (entryCount > head.entryCount) {
    globalFailure('Key-transparency delta exceeds the signed head');
  }

  return {
    checkpoint: {
      protocol: KEY_TRANSPARENCY_PROTOCOL,
      epoch: sync.toEpoch + 1,
      entryCount,
      rootHash,
    },
    records: sync.records,
    head,
  };
}

function stateFromTransition(
  previous: VerifiedKeyTransparencyContactState | null,
  transition: KeyTransparencyTransition,
  record: KeyTransparencyRecord,
  epoch: number,
): VerifiedKeyTransparencyContactState {
  const { signedUpdate } = transition;
  const base = {
    protocol: PROTOCOL_KEYS.KEY_TRANSPARENCY_CONTACT,
    label: signedUpdate.label,
    version: signedUpdate.version,
    kind: signedUpdate.kind,
    recordHash: record.recordHash,
    epoch,
    lastVerifiedEpoch: epoch,
  };

  if (signedUpdate.kind === 'register') {
    if (
      previous !== null ||
      signedUpdate.version !== 1 ||
      signedUpdate.previousRootCommitment !== null ||
      signedUpdate.pendingRootCommitment !== null
    ) throw new Error('Invalid key-transparency registration transition');
    return {
      ...base,
      state: 'active',
      rootCommitment: signedUpdate.rootCommitment,
      recoveryCommitment: signedUpdate.recoveryCommitment,
      pendingRootCommitment: null,
      recoveryActivatesAtEpoch: null,
    };
  }

  if (!previous || previous.label !== signedUpdate.label) {
    throw new Error('Key-transparency transition has no verified predecessor');
  }

  if (signedUpdate.kind === 'rotate') {
    if (
      previous.state !== 'active' ||
      signedUpdate.version !== previous.version + 1 ||
      signedUpdate.previousRootCommitment !== previous.rootCommitment ||
      signedUpdate.recoveryCommitment !== previous.recoveryCommitment
    ) throw new Error('Invalid key-transparency rotation transition');
    return {
      ...base,
      state: 'active',
      rootCommitment: signedUpdate.rootCommitment,
      recoveryCommitment: previous.recoveryCommitment,
      pendingRootCommitment: null,
      recoveryActivatesAtEpoch: null,
    };
  }

  if (signedUpdate.kind === 'recovery-request') {
    if (
      previous.state !== 'active' ||
      signedUpdate.version !== previous.version + 1 ||
      signedUpdate.rootCommitment !== previous.rootCommitment ||
      signedUpdate.previousRootCommitment !== previous.rootCommitment ||
      signedUpdate.recoveryCommitment !== previous.recoveryCommitment ||
      signedUpdate.pendingRootCommitment === null ||
      signedUpdate.recoveryRequestEpoch !== epoch
    ) throw new Error('Invalid key-transparency recovery request transition');
    return {
      ...base,
      state: 'recovery-pending',
      rootCommitment: previous.rootCommitment,
      recoveryCommitment: previous.recoveryCommitment,
      pendingRootCommitment: signedUpdate.pendingRootCommitment,
      recoveryActivatesAtEpoch: keyTransparencyRecoveryActivationEpoch(epoch),
    };
  }

  if (signedUpdate.kind === 'recovery-cancel') {
    if (
      previous.state !== 'recovery-pending' ||
      signedUpdate.version !== previous.version + 1 ||
      signedUpdate.rootCommitment !== previous.rootCommitment ||
      signedUpdate.previousRootCommitment !== previous.rootCommitment ||
      signedUpdate.recoveryCommitment !== previous.recoveryCommitment
    ) throw new Error('Invalid key-transparency recovery cancellation');
    return {
      ...base,
      state: 'active',
      rootCommitment: previous.rootCommitment,
      recoveryCommitment: previous.recoveryCommitment,
      pendingRootCommitment: null,
      recoveryActivatesAtEpoch: null,
    };
  }

  if (
    previous.state !== 'recovery-pending' ||
    previous.recoveryActivatesAtEpoch === null ||
    epoch < previous.recoveryActivatesAtEpoch ||
    signedUpdate.version !== previous.version + 1 ||
    signedUpdate.previousRootCommitment !== previous.rootCommitment ||
    signedUpdate.rootCommitment !== previous.pendingRootCommitment ||
    signedUpdate.recoveryCommitment !== previous.recoveryCommitment
  ) throw new Error('Invalid key-transparency recovery activation');
  return {
    ...base,
    state: 'active',
    rootCommitment: previous.pendingRootCommitment as string,
    recoveryCommitment: previous.recoveryCommitment,
    pendingRootCommitment: null,
    recoveryActivatesAtEpoch: null,
  };
}

export interface KeyTransparencyPublishedTransition {
  transition: KeyTransparencyTransition;
  record: KeyTransparencyRecord;
  epoch: number;
}

// Walk a contacts transitions in publication order.
export function verifyKeyTransparencyTransitions(
  previous: VerifiedKeyTransparencyContactState | null,
  published: KeyTransparencyPublishedTransition[],
  discoveryEncryptionKey: Uint8Array,
): VerifiedKeyTransparencyContactState | null {
  let state = previous;
  for (const entry of published) {
    const { transition, record, epoch } = entry;
    if (deriveKeyTransparencyEpochLabel(discoveryEncryptionKey, epoch) !== record.epochLabel) {
      throw new Error('Key-transparency record is not published under this contact label');
    }
    if (computeKeyTransparencyRecordHash(transition.signedUpdate, transition.authorization)
      !== record.recordHash) {
      throw new Error('Key-transparency transition does not match its published record');
    }
    if (transition.signedUpdate.version !== record.version) {
      throw new Error('Key-transparency transition version does not match its record');
    }
    if (!verifyKeyTransparencyAuthorization(transition.signedUpdate, transition.authorization)) {
      throw new Error('Invalid key-transparency transition authorization');
    }
    state = stateFromTransition(state, transition, record, epoch);
  }
  return state;
}

export function keyTransparencyRootMatches(
  contact: VerifiedKeyTransparencyContactState,
  accountRootPublicKeyBase64: string,
): boolean {
  let publicKey: Uint8Array | null = null;
  try {
    publicKey = decodeKeyTransparencyBase64(
      accountRootPublicKeyBase64,
      KEY_TRANSPARENCY_ML_DSA_PUBLIC_KEY_BYTES,
    );
    return keyTransparencyPublicKeyCommitment(publicKey) === contact.rootCommitment;
  } catch {
    return false;
  } finally {
    publicKey?.fill(0);
  }
}
