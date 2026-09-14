import crypto from 'node:crypto';
import { blake3 } from '@noble/hashes/blake3.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

import { canonicalBase64Shape } from '../../shared/canonical-base64.js';
import {
  ML_DSA_87_PUBLIC_KEY_BYTES,
  ML_DSA_87_SECRET_KEY_BYTES,
  ML_DSA_87_SIGNATURE_BYTES,
  HASH_OUTPUT_BYTES,
} from '../../shared/crypto-sizes.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { validateSealedEnvelope } from './sealed-sender.js';
import { BASE64URL_32_RE } from '../../shared/patterns.js';

const GLOBAL_MIX_PUBLICATION_VERSION = 1;
const GLOBAL_MIX_PUBLICATION_MAX_AGE_MS = 2 * 60_000;
let globalMixAuthentication = null;

export function initializeGlobalMixAuthentication(keyPair) {
  if (
    !(keyPair?.publicKey instanceof Uint8Array) ||
    keyPair.publicKey.length !== ML_DSA_87_PUBLIC_KEY_BYTES ||
    !(keyPair?.secretKey instanceof Uint8Array) ||
    keyPair.secretKey.length !== ML_DSA_87_SECRET_KEY_BYTES
  ) {
    throw new Error('Global mix authentication requires an ML-DSA-87 keypair');
  }
  globalMixAuthentication = {
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey,
  };
}

export function destroyGlobalMixAuthentication() {
  globalMixAuthentication = null;
}

function globalMixPublicationDigest(publication) {
  const payload = Buffer.from(JSON.stringify({
    envelope: publication.envelope,
    issuedAt: publication.issuedAt,
    publicationId: publication.publicationId,
    version: publication.version,
  }), 'utf8');
  const domain = Buffer.from(PROTOCOL_KEYS.GLOBAL_MIX_PUBLICATION_SIGNATURE, 'utf8');
  try {
    const hasher = blake3.create({ dkLen: HASH_OUTPUT_BYTES });
    hasher.update(domain);
    hasher.update(payload);
    return Buffer.from(hasher.digest());
  } finally {
    domain.fill(0);
    payload.fill(0);
  }
}

export function createSignedGlobalMixPublication(sealedEnvelope, now = Date.now()) {
  if (!globalMixAuthentication?.secretKey) {
    throw new Error('Global mix authentication is not initialized');
  }
  if (!validateSealedEnvelope(sealedEnvelope).valid || !Number.isSafeInteger(now)) {
    throw new Error('Invalid global mix publication');
  }
  const publication = {
    envelope: sealedEnvelope,
    issuedAt: now,
    publicationId: crypto.randomBytes(32).toString('base64url'),
    version: GLOBAL_MIX_PUBLICATION_VERSION,
  };
  const digest = globalMixPublicationDigest(publication);
  let signature = null;
  try {
    signature = ml_dsa87.sign(digest, globalMixAuthentication.secretKey);
    return {
      ...publication,
      signature: Buffer.from(signature).toString('base64'),
    };
  } finally {
    digest.fill(0);
    signature?.fill?.(0);
  }
}

export function validateGlobalMixPublication(message, now = Date.now()) {
  if (
    !globalMixAuthentication?.publicKey ||
    !message ||
    typeof message !== 'object' ||
    Array.isArray(message) ||
    (Object.getPrototypeOf(message) !== Object.prototype && Object.getPrototypeOf(message) !== null) ||
    Object.keys(message).sort().join(',') !== 'envelope,issuedAt,publicationId,signature,version' ||
    message.version !== GLOBAL_MIX_PUBLICATION_VERSION ||
    !Number.isSafeInteger(message.issuedAt) ||
    Math.abs(now - message.issuedAt) > GLOBAL_MIX_PUBLICATION_MAX_AGE_MS ||
    typeof message.publicationId !== 'string' ||
    !BASE64URL_32_RE.test(message.publicationId) ||
    !canonicalBase64Shape(message.signature, { exactBytes: ML_DSA_87_SIGNATURE_BYTES }) ||
    !validateSealedEnvelope(message.envelope).valid
  ) {
    return null;
  }
  const digest = globalMixPublicationDigest(message);
  const signature = Buffer.from(message.signature, 'base64');
  let verified = false;
  try {
    verified = ml_dsa87.verify(signature, digest, globalMixAuthentication.publicKey);
  } catch {
    verified = false;
  } finally {
    digest.fill(0);
    signature.fill(0);
  }
  if (!verified) return null;
  return {
    envelope: message.envelope,
    issuedAt: message.issuedAt,
    publicationId: message.publicationId,
  };
}
