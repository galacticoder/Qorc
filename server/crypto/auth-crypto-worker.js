import { parentPort } from 'node:worker_threads';
import { blake3 } from '@noble/hashes/blake3.js';
import { ml_kem1024 as mlKem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa87 as mlDsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ristretto255_oprf as oprf } from '@noble/curves/ed25519.js';
import {
  ML_DSA_87_PUBLIC_KEY_BYTES,
  ML_DSA_87_SIGNATURE_BYTES,
  ML_KEM_1024_CIPHERTEXT_BYTES,
  ML_KEM_1024_PUBLIC_KEY_BYTES,
  ML_KEM_1024_SHARED_SECRET_BYTES,
} from '../../shared/crypto-sizes.js';
import {
  PRIVATE_AUTH_ANONYMITY_SET_SIZE,
  PRIVATE_AUTH_OT_RECORD_BYTES,
  PRIVATE_AUTH_TRANSCRIPT_BYTES,
} from '../../shared/private-auth-protocol.js';
import { UUID_V4_RE } from '../../shared/patterns.js';
import {
  AUTH_CRYPTO_CANCEL_STATE_INDEX,
  AUTH_CRYPTO_OPERATION,
} from './auth-crypto-worker-protocol.js';
import {
  AUTH_OPERATION_CANCELLED_MESSAGE,
  AUTH_OPERATION_FAILED_MESSAGE,
} from '../config/error-codes.js';
import { wipeBytes as wipe } from '../utils/wipe.js';

function exactBytes(value, expectedLength) {
  return value instanceof Uint8Array && value.length === expectedLength;
}

function throwIfCancelled(cancelState) {
  if (Atomics.load(cancelState, AUTH_CRYPTO_CANCEL_STATE_INDEX) === 0) return;
  const error = new Error(AUTH_OPERATION_CANCELLED_MESSAGE);
  error.code = 'AUTH_CRYPTO_CANCELLED';
  throw error;
}

function validateEnvelope(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid auth worker request');
  const keys = Object.keys(data).sort();
  if (keys.join(',') !== 'cancelState,id,payload,type') throw new Error('Invalid auth worker request');
  if (typeof data.id !== 'string' || !UUID_V4_RE.test(data.id)) throw new Error('Invalid auth worker request');
  if (
    !(data.cancelState instanceof Int32Array) ||
    data.cancelState.length !== 1 ||
    data.cancelState.byteOffset !== 0 ||
    !(data.cancelState.buffer instanceof SharedArrayBuffer)
  ) {
    throw new Error('Invalid auth worker cancellation state');
  }
  if (
    data.type !== AUTH_CRYPTO_OPERATION.VERIFY_ANONYMITY_SET &&
    data.type !== AUTH_CRYPTO_OPERATION.ENCRYPT_OT_RECORDS &&
    data.type !== AUTH_CRYPTO_OPERATION.ISSUE_PRIVACY_PASS
  ) {
    throw new Error('Invalid auth worker operation');
  }
  if (!data.payload || typeof data.payload !== 'object' || Array.isArray(data.payload)) {
    throw new Error('Invalid auth worker payload');
  }
}

function issuePrivacyPass(payload, cancelState) {
  const keys = Object.keys(payload).sort().join(',');
  if (
    keys !== 'blindedTokens,count,publicKey,secretKey' ||
    !Number.isInteger(payload.count) || payload.count < 1 || payload.count > 1000 ||
    !exactBytes(payload.blindedTokens, payload.count * 32) ||
    !exactBytes(payload.secretKey, 32) ||
    !exactBytes(payload.publicKey, 32)
  ) {
    throw new Error('Invalid Privacy Pass issuance payload');
  }

  throwIfCancelled(cancelState);
  const blindedTokens = new Array(payload.count);
  for (let index = 0; index < payload.count; index += 1) {
    blindedTokens[index] = payload.blindedTokens.subarray(index * 32, (index + 1) * 32);
  }
  const evaluated = oprf.voprf.blindEvaluateBatch(
    payload.secretKey,
    payload.publicKey,
    blindedTokens
  );
  const evaluatedTokens = new Uint8Array(payload.count * 32);
  const proof = new Uint8Array(evaluated.proof);
  try {
    throwIfCancelled(cancelState);
    if (!Array.isArray(evaluated.evaluated) || evaluated.evaluated.length !== payload.count || proof.length !== 64) {
      throw new Error('Invalid Privacy Pass issuance result');
    }
    for (let index = 0; index < evaluated.evaluated.length; index += 1) {
      if (!exactBytes(evaluated.evaluated[index], 32)) {
        throw new Error('Invalid Privacy Pass evaluated token');
      }
      evaluatedTokens.set(evaluated.evaluated[index], index * 32);
    }
    return { evaluatedTokens, proof };
  } catch (error) {
    wipe(evaluatedTokens);
    wipe(proof);
    throw error;
  } finally {
    for (const token of evaluated.evaluated || []) wipe(token);
    wipe(evaluated.proof);
  }
}

function verifyAnonymitySet(payload, cancelState) {
  const expectedPublicKeysBytes = PRIVATE_AUTH_ANONYMITY_SET_SIZE * ML_DSA_87_PUBLIC_KEY_BYTES;
  const keys = Object.keys(payload).sort().join(',');
  if (
    keys !== 'authPublicKeys,signature,transcript' ||
    !exactBytes(payload.authPublicKeys, expectedPublicKeysBytes) ||
    !exactBytes(payload.signature, ML_DSA_87_SIGNATURE_BYTES) ||
    !exactBytes(payload.transcript, PRIVATE_AUTH_TRANSCRIPT_BYTES)
  ) {
    throw new Error('Invalid anonymity-set verification payload');
  }

  let matched = 0;
  for (let slot = 0; slot < PRIVATE_AUTH_ANONYMITY_SET_SIZE; slot += 1) {
    throwIfCancelled(cancelState);
    const offset = slot * ML_DSA_87_PUBLIC_KEY_BYTES;
    const publicKey = payload.authPublicKeys.subarray(offset, offset + ML_DSA_87_PUBLIC_KEY_BYTES);
    let verified = false;
    try {
      verified = mlDsa87.verify(payload.signature, payload.transcript, publicKey);
    } catch {
      verified = false;
    }
    matched |= verified ? 1 : 0;
  }
  return matched === 1;
}

function encryptOtRecords(payload, cancelState) {
  const publicKeySlabBytes = PRIVATE_AUTH_ANONYMITY_SET_SIZE * ML_KEM_1024_PUBLIC_KEY_BYTES;
  const paddedRecordSlabBytes = PRIVATE_AUTH_ANONYMITY_SET_SIZE * PRIVATE_AUTH_OT_RECORD_BYTES;
  const keys = Object.keys(payload).sort().join(',');
  if (
    keys !== 'clientPublicKeys,paddedRecords' ||
    !exactBytes(payload.clientPublicKeys, publicKeySlabBytes) ||
    !exactBytes(payload.paddedRecords, paddedRecordSlabBytes)
  ) {
    throw new Error('Invalid private-auth OT payload');
  }

  const ciphertexts = new Uint8Array(PRIVATE_AUTH_ANONYMITY_SET_SIZE * ML_KEM_1024_CIPHERTEXT_BYTES);
  const maskedRecords = new Uint8Array(paddedRecordSlabBytes);
  let completed = false;
  try {
    for (let slot = 0; slot < PRIVATE_AUTH_ANONYMITY_SET_SIZE; slot += 1) {
      throwIfCancelled(cancelState);
      const publicKeyOffset = slot * ML_KEM_1024_PUBLIC_KEY_BYTES;
      const recordOffset = slot * PRIVATE_AUTH_OT_RECORD_BYTES;
      const publicKey = payload.clientPublicKeys.subarray(
        publicKeyOffset,
        publicKeyOffset + ML_KEM_1024_PUBLIC_KEY_BYTES
      );
      const paddedRecord = payload.paddedRecords.subarray(recordOffset, recordOffset + PRIVATE_AUTH_OT_RECORD_BYTES);
      let ciphertext = null;
      let sharedSecret = null;
      let mask = null;
      try {
        const encapsulated = mlKem1024.encapsulate(publicKey);
        ciphertext = encapsulated.cipherText;
        sharedSecret = encapsulated.sharedSecret;
        if (!exactBytes(ciphertext, ML_KEM_1024_CIPHERTEXT_BYTES) || !exactBytes(sharedSecret, ML_KEM_1024_SHARED_SECRET_BYTES)) {
          throw new Error('ML-KEM returned an invalid private-auth result');
        }
        mask = blake3(sharedSecret, { dkLen: PRIVATE_AUTH_OT_RECORD_BYTES });
        ciphertexts.set(ciphertext, slot * ML_KEM_1024_CIPHERTEXT_BYTES);
        for (let index = 0; index < PRIVATE_AUTH_OT_RECORD_BYTES; index += 1) {
          maskedRecords[recordOffset + index] = paddedRecord[index] ^ mask[index];
        }
      } finally {
        wipe(ciphertext);
        wipe(sharedSecret);
        wipe(mask);
      }
    }
    completed = true;
    return { ciphertexts, maskedRecords };
  } finally {
    if (!completed) {
      wipe(ciphertexts);
      wipe(maskedRecords);
    }
  }
}

if (!parentPort) throw new Error('Auth crypto worker requires a parent port');

parentPort.on('message', (data) => {
  let responseId = 'unknown';
  let result = null;
  try {
    validateEnvelope(data);
    responseId = data.id;
    if (data.type === AUTH_CRYPTO_OPERATION.VERIFY_ANONYMITY_SET) {
      const matched = verifyAnonymitySet(data.payload, data.cancelState);
      parentPort.postMessage({ id: responseId, success: true, matched });
      return;
    }

    if (data.type === AUTH_CRYPTO_OPERATION.ISSUE_PRIVACY_PASS) {
      result = issuePrivacyPass(data.payload, data.cancelState);
      parentPort.postMessage(
        {
          id: responseId,
          success: true,
          evaluatedTokens: result.evaluatedTokens,
          proof: result.proof,
        },
        [result.evaluatedTokens.buffer, result.proof.buffer]
      );
      result = null;
      return;
    }

    result = encryptOtRecords(data.payload, data.cancelState);
    parentPort.postMessage(
      {
        id: responseId,
        success: true,
        ciphertexts: result.ciphertexts,
        maskedRecords: result.maskedRecords,
      },
      [result.ciphertexts.buffer, result.maskedRecords.buffer]
    );
    result = null;
  } catch (error) {
    parentPort.postMessage({
      id: responseId,
      success: false,
      error: error?.code === 'AUTH_CRYPTO_CANCELLED'
        ? AUTH_OPERATION_CANCELLED_MESSAGE
        : AUTH_OPERATION_FAILED_MESSAGE
    });
  } finally {
    wipe(data?.payload?.authPublicKeys);
    wipe(data?.payload?.signature);
    wipe(data?.payload?.transcript);
    wipe(data?.payload?.clientPublicKeys);
    wipe(data?.payload?.paddedRecords);
    wipe(data?.payload?.blindedTokens);
    wipe(data?.payload?.secretKey);
    wipe(data?.payload?.publicKey);
    wipe(result?.ciphertexts);
    wipe(result?.maskedRecords);
    wipe(result?.evaluatedTokens);
    wipe(result?.proof);
  }
});
