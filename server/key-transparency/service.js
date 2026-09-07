import crypto from 'node:crypto';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

import {
  KEY_TRANSPARENCY_DELTA_MAX_EPOCHS,
  KEY_TRANSPARENCY_ML_DSA_PUBLIC_KEY_BYTES,
  KEY_TRANSPARENCY_ML_DSA_SECRET_KEY_BYTES,
  KEY_TRANSPARENCY_PROTOCOL,
  encodeKeyTransparencySignaturePayload,
  isKeyTransparencyHash,
  isKeyTransparencyLabel,
  keyTransparencyEpoch,
  keyTransparencyHeadPayload,
} from '../../shared/key-transparency-protocol.js';
import {
  appendKeyTransparencyRecord,
  initializeKeyTransparencyDatabase,
  readKeyTransparencyLogState,
  readKeyTransparencySnapshot,
} from '../database/key-transparency-db.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { SHA3_512_ALGORITHM } from '../utils/crypto-consts.js';

const SIGNER_KEY_ID_DOMAIN = Buffer.from(PROTOCOL_KEYS.KEY_TRANSPARENCY_SIGNER_KEY, 'utf8');

let signerSecretKey = null;
let signerPublicKey = null;
let signerKeyId = null;
let signedHeadCache = null;

function hashWithDomain(domain, bytes) {
  const hash = crypto.createHash(SHA3_512_ALGORITHM);
  hash.update(domain);
  hash.update(bytes);
  return hash.digest('hex');
}

// Sign current log head
function signHead(state, epoch) {
  if (!signerSecretKey || !signerPublicKey || !signerKeyId) {
    throw new Error('Key-transparency signer is unavailable');
  }
  const genesisEpoch = Number.isSafeInteger(state.genesisEpoch) ? state.genesisEpoch : epoch;
  if (
    signedHeadCache &&
    signedHeadCache.epoch === epoch &&
    signedHeadCache.genesisEpoch === genesisEpoch &&
    signedHeadCache.entryCount === state.entryCount &&
    signedHeadCache.rootHash === state.rootHash &&
    signedHeadCache.signerKeyId === signerKeyId
  ) {
    return { ...signedHeadCache };
  }
  const unsigned = {
    entryCount: state.entryCount,
    epoch,
    genesisEpoch,
    protocol: KEY_TRANSPARENCY_PROTOCOL,
    rootHash: state.rootHash,
    signerKeyId,
  };
  const payload = encodeKeyTransparencySignaturePayload(
    'log-head',
    keyTransparencyHeadPayload(unsigned)
  );
  let signature = null;
  try {
    signature = ml_dsa87.sign(payload, signerSecretKey);
    const head = Object.freeze({
      ...unsigned,
      signature: Buffer.from(signature).toString('base64'),
    });
    signedHeadCache = head;
    return { ...head };
  } finally {
    payload.fill(0);
    signature?.fill(0);
  }
}

export async function initializeKeyTransparencyService(dilithiumKeyPair) {
  if (
    !(dilithiumKeyPair?.publicKey instanceof Uint8Array) ||
    dilithiumKeyPair.publicKey.length !== KEY_TRANSPARENCY_ML_DSA_PUBLIC_KEY_BYTES ||
    !(dilithiumKeyPair?.secretKey instanceof Uint8Array) ||
    dilithiumKeyPair.secretKey.length !== KEY_TRANSPARENCY_ML_DSA_SECRET_KEY_BYTES
  ) throw new Error('Key-transparency ML-DSA signer is invalid');
  await initializeKeyTransparencyDatabase();
  signerPublicKey = dilithiumKeyPair.publicKey;
  signerSecretKey = dilithiumKeyPair.secretKey;
  signerKeyId = hashWithDomain(SIGNER_KEY_ID_DOMAIN, signerPublicKey);
  signedHeadCache = null;
}

export function destroyKeyTransparencyService() {
  signerPublicKey = null;
  signerSecretKey = null;
  signerKeyId = null;
  signedHeadCache = null;
}

export function keyTransparencySignerKeyId() {
  return signerKeyId;
}

// Append one record
export async function appendKeyTransparency(request) {
  if (
    !request ||
    typeof request !== 'object' ||
    !isKeyTransparencyLabel(request.epochLabel) ||
    !isKeyTransparencyHash(request.recordHash) ||
    !Number.isSafeInteger(request.version) ||
    request.version < 1
  ) throw new Error('Invalid key-transparency append');

  // Records land in epoch server is currently in
  const epoch = keyTransparencyEpoch();
  const result = await appendKeyTransparencyRecord({
    epoch,
    epochLabel: request.epochLabel,
    version: request.version,
    recordHash: request.recordHash,
  });
  if (!result.appended) {
    return { appended: false, reason: result.reason, head: signHead(result.state, epoch) };
  }
  signedHeadCache = null;
  return { appended: true, head: signHead(result.state, epoch) };
}

//Serve every record appended in contiguous run of epochs plus current signed head
export async function syncKeyTransparency(fromEpoch, toEpoch) {
  if (
    !Number.isSafeInteger(fromEpoch) ||
    fromEpoch < 0 ||
    !Number.isSafeInteger(toEpoch) ||
    toEpoch < fromEpoch ||
    toEpoch - fromEpoch >= KEY_TRANSPARENCY_DELTA_MAX_EPOCHS
  ) throw new Error('Invalid key-transparency sync range');

  const currentEpoch = keyTransparencyEpoch();
  const boundedTo = Math.min(toEpoch, currentEpoch);
  const { delta, state } = await readKeyTransparencySnapshot(fromEpoch, boundedTo);

  return {
    protocol: KEY_TRANSPARENCY_PROTOCOL,
    currentEpoch,
    fromEpoch: delta.fromEpoch,
    toEpoch: delta.toEpoch,
    firstLogIndex: delta.firstLogIndex,
    records: delta.records,
    head: signHead(state, currentEpoch),
  };
}

export async function readKeyTransparencyHead() {
  const state = await readKeyTransparencyLogState();
  return signHead(state, keyTransparencyEpoch());
}
