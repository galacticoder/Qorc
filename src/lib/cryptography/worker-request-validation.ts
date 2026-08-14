import {
  PQ_AEAD_CIPHERTEXT_OVERHEAD,
  PQ_AEAD_MAC_SIZE,
  PQ_AEAD_NONCE_SIZE,
  PQ_KEM_CIPHERTEXT_SIZE,
  PQ_KEM_PUBLIC_KEY_SIZE,
  PQ_KEM_SECRET_KEY_SIZE,
  PQ_SIG_PUBLIC_KEY_SIZE,
  PQ_SIG_SECRET_KEY_SIZE,
  PQ_SIG_SIGNATURE_SIZE,
} from '../constants';
import type { WorkerRequestMessage } from '../types/crypto-types';
import { AUTH_CHANNEL_BINDING_BYTES } from '../../../shared/auth-channel-binding.js';
import { PRIVATE_AUTH_ANONYMITY_SET_SIZE } from '../../../shared/private-auth-protocol.js';
import { PRIVACY_PASS_CONFIG } from '../../../shared/privacy-pass-protocol.js';
import { hasExactKeys, hasPrototypePollutionKeys, isPlainObject } from '../sanitizers';
import { ACCOUNT_AUTH_PURPOSE, SERVER_ENTRY_PURPOSE } from '../config/audiences';

export const ARGON2_MAX_INPUT_BYTES = 8192;
export const ARGON2_MAX_MEMORY_KIB = 512 * 1024;
export const ARGON2_MAX_TIME_COST = 10;
export const ARGON2_MAX_PARALLELISM = 4;
export const WORKER_AEAD_MAX_INPUT_BYTES = 20 * 1024 * 1024;
export const WORKER_AEAD_MAX_AAD_BYTES = 1024 * 1024;
export const WORKER_SIGNATURE_MAX_MESSAGE_BYTES = 4 * 1024 * 1024;
export { PRIVATE_AUTH_ANONYMITY_SET_SIZE } from '../../../shared/private-auth-protocol.js';
export const PRIVACY_PASS_MAX_BATCH_SIZE = PRIVACY_PASS_CONFIG.MAX_BATCH_SIZE;
export const OPAQUE_PASSWORD_MAX_BYTES = 4096;

const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const WORKER_AUTH_REGEX = /^[0-9a-f]{64}$/;
const textEncoder = new TextEncoder();

function assertPlainObject(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (!isPlainObject(value) || hasPrototypePollutionKeys(value)) {
    throw new Error(`Invalid ${label}`);
  }
}

function assertExactBytes(value: unknown, length: number, label: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new Error(`Invalid ${label}`);
  }
}

function assertBoundedBytes(value: unknown, maxLength: number, label: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.length > maxLength) {
    throw new Error(`Invalid ${label}`);
  }
}

function validArgon2Pass(pass: unknown): boolean {
  if (pass instanceof Uint8Array) {
    return pass.length > 0 && pass.length <= ARGON2_MAX_INPUT_BYTES;
  }
  if (typeof pass !== 'string' || pass.length === 0 || pass.length > ARGON2_MAX_INPUT_BYTES) {
    return false;
  }
  return textEncoder.encode(pass).length <= ARGON2_MAX_INPUT_BYTES;
}

export function validateArgon2HashParams(params: unknown): void {
  assertPlainObject(params, 'Argon2id parameters');
  if (!hasExactKeys(params, ['pass', 'salt', 'time', 'mem', 'parallelism', 'type', 'version', 'hashLen'])) {
    throw new Error('Invalid Argon2id parameters');
  }
  const { time, mem, parallelism, type, version, hashLen } = params;
  if (
    !validArgon2Pass(params.pass) ||
    !(params.salt instanceof Uint8Array) || params.salt.length < 16 || params.salt.length > 64 ||
    typeof time !== 'number' || !Number.isInteger(time) || time < 1 || time > ARGON2_MAX_TIME_COST ||
    typeof parallelism !== 'number' || !Number.isInteger(parallelism) || parallelism < 1 || parallelism > ARGON2_MAX_PARALLELISM ||
    typeof mem !== 'number' || !Number.isInteger(mem) || mem < 8 * parallelism || mem > ARGON2_MAX_MEMORY_KIB ||
    type !== 2 || version !== 0x13 ||
    typeof hashLen !== 'number' || !Number.isInteger(hashLen) || hashLen < 16 || hashLen > 128
  ) {
    throw new Error('Invalid Argon2id parameters');
  }
}

export function validateArgon2VerifyParams(params: unknown): void {
  assertPlainObject(params, 'Argon2id verification parameters');
  if (
    !hasExactKeys(params, ['pass', 'encoded']) ||
    !validArgon2Pass(params.pass) ||
    typeof params.encoded !== 'string' ||
    params.encoded.length > 512
  ) {
    throw new Error('Invalid Argon2id verification parameters');
  }
  const match = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$[A-Za-z0-9+/]{16,128}\$[A-Za-z0-9+/]{22,172}$/.exec(params.encoded);
  if (!match) throw new Error('Invalid Argon2id encoded hash');
  const memory = Number(match[1]);
  const time = Number(match[2]);
  const parallelism = Number(match[3]);
  if (
    !Number.isSafeInteger(memory) || memory < 8 * parallelism || memory > ARGON2_MAX_MEMORY_KIB ||
    !Number.isSafeInteger(time) || time < 1 || time > ARGON2_MAX_TIME_COST ||
    !Number.isSafeInteger(parallelism) || parallelism < 1 || parallelism > ARGON2_MAX_PARALLELISM
  ) {
    throw new Error('Unsafe Argon2id encoded parameters');
  }
}

export function validateOpaquePassword(password: unknown): asserts password is Uint8Array {
  if (!(password instanceof Uint8Array) || password.length === 0 || password.length > OPAQUE_PASSWORD_MAX_BYTES) {
    throw new Error('Invalid private authentication secret');
  }
}

export function validateOpaqueRegistrationResponse(response: unknown): asserts response is {
  evaluatedElement: Uint8Array;
  serverNonce: Uint8Array;
} {
  assertPlainObject(response, 'registration response');
  assertExactBytes(response.evaluatedElement, 32, 'registration evaluated element');
  assertExactBytes(response.serverNonce, 32, 'registration server nonce');
}

export function validateOpaqueLoginResponse(response: unknown): asserts response is {
  evaluatedElement: Uint8Array;
  envelope: Uint8Array;
  serverNonce: Uint8Array;
  salt: Uint8Array;
} {
  assertPlainObject(response, 'login response');
  assertExactBytes(response.evaluatedElement, 32, 'login evaluated element');
  assertExactBytes(response.envelope, 72, 'login envelope');
  assertExactBytes(response.serverNonce, 32, 'login server nonce');
  assertExactBytes(response.salt, 32, 'login salt');
}

function validatePendingPrivacyPassToken(value: unknown): void {
  assertPlainObject(value, 'Privacy Pass token state');
  const keys = Object.keys(value).sort().join(',');
  const baseKeys = 'blindedElement,blindingFactor,id,issuedAt,pending,purpose,tokenSecret,used';
  const persistedKeys = 'blindedElement,blindingFactor,id,issuedAt,pending,purpose,tokenSecret,unblindedToken,used';
  if (keys !== baseKeys && keys !== persistedKeys) throw new Error('Invalid Privacy Pass token state');
  if (
    typeof value.id !== 'string' || !UUID_V4_REGEX.test(value.id) ||
    !(value.tokenSecret instanceof Uint8Array) || value.tokenSecret.length !== 36 ||
    !(value.blindingFactor instanceof Uint8Array) || value.blindingFactor.length !== 32 ||
    !(value.blindedElement instanceof Uint8Array) || value.blindedElement.length !== 32 ||
    (value.purpose !== ACCOUNT_AUTH_PURPOSE && value.purpose !== SERVER_ENTRY_PURPOSE) ||
    !Number.isSafeInteger(value.issuedAt) || (value.issuedAt as number) <= 0 ||
    value.used !== false || value.pending !== false ||
    (Object.prototype.hasOwnProperty.call(value, 'unblindedToken') && value.unblindedToken !== undefined)
  ) {
    throw new Error('Invalid Privacy Pass token state');
  }
}

function validatePrivacyPassUnblindInput(data: Record<string, unknown>): void {
  const { tokenSecrets, signedBlindedTokens, proof, serverPublicKey } = data;
  if (
    !Array.isArray(tokenSecrets) ||
    !Array.isArray(signedBlindedTokens) ||
    tokenSecrets.length < 1 ||
    tokenSecrets.length > PRIVACY_PASS_MAX_BATCH_SIZE ||
    tokenSecrets.length !== signedBlindedTokens.length
  ) {
    throw new Error('Invalid Privacy Pass issuance batch');
  }
  for (const token of tokenSecrets) validatePendingPrivacyPassToken(token);
  if (!signedBlindedTokens.every((token) => token instanceof Uint8Array && token.length === 32)) {
    throw new Error('Invalid Privacy Pass signed token batch');
  }
  assertExactBytes(proof, 64, 'Privacy Pass proof');
  assertExactBytes(serverPublicKey, 32, 'Privacy Pass public key');
}

export function validateWorkerRequest(value: unknown): asserts value is WorkerRequestMessage {
  assertPlainObject(value, 'worker request');
  if (
    typeof value.id !== 'string' || !UUID_V4_REGEX.test(value.id) ||
    typeof value.type !== 'string' || value.type.length > 64 ||
    typeof value.auth !== 'string' || !WORKER_AUTH_REGEX.test(value.auth)
  ) {
    throw new Error('Malformed worker request');
  }

  const exact = (keys: readonly string[]): void => {
    if (!hasExactKeys(value, ['id', 'type', 'auth', ...keys])) {
      throw new Error('Unexpected worker request fields');
    }
  };

  switch (value.type) {
    case 'kem.generateKeyPair':
    case 'sig.generateKeyPair':
      exact([]);
      break;
    case 'kem.encapsulate':
      exact(['publicKey']);
      assertExactBytes(value.publicKey, PQ_KEM_PUBLIC_KEY_SIZE, 'ML-KEM public key');
      break;
    case 'kem.decapsulate':
      exact(['ciphertext', 'secretKey']);
      assertExactBytes(value.ciphertext, PQ_KEM_CIPHERTEXT_SIZE, 'ML-KEM ciphertext');
      assertExactBytes(value.secretKey, PQ_KEM_SECRET_KEY_SIZE, 'ML-KEM secret key');
      break;
    case 'sig.sign':
      exact(['message', 'secretKey']);
      assertBoundedBytes(value.message, WORKER_SIGNATURE_MAX_MESSAGE_BYTES, 'ML-DSA message');
      assertExactBytes(value.secretKey, PQ_SIG_SECRET_KEY_SIZE, 'ML-DSA secret key');
      break;
    case 'sig.verify':
      exact(['message', 'publicKey', 'signature']);
      assertBoundedBytes(value.message, WORKER_SIGNATURE_MAX_MESSAGE_BYTES, 'ML-DSA message');
      assertExactBytes(value.publicKey, PQ_SIG_PUBLIC_KEY_SIZE, 'ML-DSA public key');
      assertExactBytes(value.signature, PQ_SIG_SIGNATURE_SIZE, 'ML-DSA signature');
      break;
    case 'pp.generateTokenBatch':
      exact(['count', 'purpose']);
      if (!Number.isInteger(value.count) || (value.count as number) < 1 || (value.count as number) > PRIVACY_PASS_MAX_BATCH_SIZE) {
        throw new Error('Invalid Privacy Pass batch size');
      }
      if (value.purpose !== ACCOUNT_AUTH_PURPOSE && value.purpose !== SERVER_ENTRY_PURPOSE) {
        throw new Error('Invalid Privacy Pass purpose');
      }
      break;
    case 'pp.unblindTokens':
      exact(['tokenSecrets', 'signedBlindedTokens', 'proof', 'serverPublicKey']);
      validatePrivacyPassUnblindInput(value);
      break;
    case 'opaque.startRegistration':
    case 'opaque.startLogin':
      exact(['passwordBytes']);
      validateOpaquePassword(value.passwordBytes);
      break;
    case 'opaque.finishRegistration':
      exact(['passwordBytes', 'blindingFactor', 'serverResponse']);
      validateOpaquePassword(value.passwordBytes);
      assertExactBytes(value.blindingFactor, 32, 'OPAQUE blinding factor');
      validateOpaqueRegistrationResponse(value.serverResponse);
      if (!hasExactKeys(value.serverResponse, ['evaluatedElement', 'serverNonce'])) {
        throw new Error('Unexpected registration response fields');
      }
      break;
    case 'opaque.finishLogin':
      exact(['authChannelBinding', 'passwordBytes', 'blindingFactor', 'serverResponse']);
      validateOpaquePassword(value.passwordBytes);
      assertExactBytes(value.blindingFactor, 32, 'OPAQUE blinding factor');
      assertExactBytes(value.authChannelBinding, AUTH_CHANNEL_BINDING_BYTES, 'authentication channel binding');
      validateOpaqueLoginResponse(value.serverResponse);
      if (!hasExactKeys(value.serverResponse, ['evaluatedElement', 'envelope', 'serverNonce', 'salt'])) {
        throw new Error('Unexpected login response fields');
      }
      break;
    case 'opaque.startOTLogin':
      exact(['passwordBytes', 'anonymitySetSize', 'myIndex']);
      validateOpaquePassword(value.passwordBytes);
      if (
        value.anonymitySetSize !== PRIVATE_AUTH_ANONYMITY_SET_SIZE ||
        !Number.isInteger(value.myIndex) ||
        (value.myIndex as number) < 0 ||
        (value.myIndex as number) >= PRIVATE_AUTH_ANONYMITY_SET_SIZE
      ) {
        throw new Error('Invalid private-auth slot');
      }
      break;
    case 'opaque.finishOTLogin':
      exact(['authChannelBinding', 'passwordBytes', 'blindingFactor', 'myPrivKey', 'otRecord', 'evaluatedElement', 'serverNonce']);
      validateOpaquePassword(value.passwordBytes);
      assertExactBytes(value.blindingFactor, 32, 'OPAQUE blinding factor');
      assertExactBytes(value.myPrivKey, PQ_KEM_SECRET_KEY_SIZE, 'private-auth secret key');
      assertExactBytes(value.evaluatedElement, 32, 'private-auth evaluated element');
      assertExactBytes(value.serverNonce, 32, 'private-auth server nonce');
      assertExactBytes(value.authChannelBinding, AUTH_CHANNEL_BINDING_BYTES, 'authentication channel binding');
      assertPlainObject(value.otRecord, 'private-auth record');
      if (!hasExactKeys(value.otRecord, ['ct', 'masked'])) throw new Error('Unexpected private-auth record fields');
      assertExactBytes(value.otRecord.ct, PQ_KEM_CIPHERTEXT_SIZE, 'private-auth ciphertext');
      assertExactBytes(value.otRecord.masked, 1024, 'private-auth masked record');
      break;
    case 'argon2.hash':
      exact(['params']);
      validateArgon2HashParams(value.params);
      break;
    case 'argon2.verify':
      exact(['params']);
      validateArgon2VerifyParams(value.params);
      break;
    case 'aead.encrypt':
      exact(['plaintext', 'key', 'additionalData', 'explicitNonce']);
      assertBoundedBytes(value.plaintext, WORKER_AEAD_MAX_INPUT_BYTES, 'AEAD plaintext');
      assertExactBytes(value.key, 32, 'AEAD key');
      if (value.additionalData !== undefined) assertBoundedBytes(value.additionalData, WORKER_AEAD_MAX_AAD_BYTES, 'AEAD additional data');
      if (value.explicitNonce !== undefined) assertExactBytes(value.explicitNonce, PQ_AEAD_NONCE_SIZE, 'AEAD nonce');
      break;
    case 'aead.decrypt':
      exact(['ciphertext', 'nonce', 'tag', 'key', 'additionalData']);
      if (
        !(value.ciphertext instanceof Uint8Array) ||
        value.ciphertext.length < PQ_AEAD_CIPHERTEXT_OVERHEAD ||
        value.ciphertext.length > WORKER_AEAD_MAX_INPUT_BYTES + PQ_AEAD_CIPHERTEXT_OVERHEAD
      ) {
        throw new Error('Invalid AEAD ciphertext');
      }
      assertExactBytes(value.nonce, PQ_AEAD_NONCE_SIZE, 'AEAD nonce');
      assertExactBytes(value.tag, PQ_AEAD_MAC_SIZE, 'AEAD tag');
      assertExactBytes(value.key, 32, 'AEAD key');
      if (value.additionalData !== undefined) assertBoundedBytes(value.additionalData, WORKER_AEAD_MAX_AAD_BYTES, 'AEAD additional data');
      break;
    default:
      throw new Error('Unsupported worker operation');
  }
}
