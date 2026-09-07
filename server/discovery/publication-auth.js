import { blake3 } from '@noble/hashes/blake3.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

import { canonicalBase64Shape } from '../../shared/canonical-base64.js';
import {
  ML_DSA_87_PUBLIC_KEY_BYTES,
  ML_DSA_87_SECRET_KEY_BYTES,
  ML_DSA_87_SIGNATURE_BYTES,
} from '../../shared/crypto-sizes.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { HASH_OUTPUT_BYTES } from '../utils/crypto-consts.js';

let publicationAuthentication = null;

export function initializeDiscoveryPublicationAuthentication(keyPair) {
  if (
    !(keyPair?.publicKey instanceof Uint8Array) ||
    keyPair.publicKey.length !== ML_DSA_87_PUBLIC_KEY_BYTES ||
    !(keyPair?.secretKey instanceof Uint8Array) ||
    keyPair.secretKey.length !== ML_DSA_87_SECRET_KEY_BYTES
  ) {
    throw new Error('Discovery publication authentication requires an ML-DSA-87 keypair');
  }
  publicationAuthentication = {
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey,
  };
}

export function destroyDiscoveryPublicationAuthentication() {
  publicationAuthentication = null;
}

function publicationDigest(entry) {
  const domain = Buffer.from(PROTOCOL_KEYS.DISCOVERY_PUBLICATION_QUEUE_SIGNATURE, 'utf8');
  const payload = Buffer.from(JSON.stringify(entry), 'utf8');
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

export function signDiscoveryPublicationEntry(entry) {
  if (!publicationAuthentication?.secretKey) {
    throw new Error('Discovery publication authentication is not initialized');
  }
  const digest = publicationDigest(entry);
  let signature = null;
  try {
    signature = ml_dsa87.sign(digest, publicationAuthentication.secretKey);
    return Buffer.from(signature).toString('base64');
  } finally {
    digest.fill(0);
    signature?.fill?.(0);
  }
}

export function verifyDiscoveryPublicationEntry(entry, signatureValue) {
  if (
    !publicationAuthentication?.publicKey ||
    !canonicalBase64Shape(signatureValue, { exactBytes: ML_DSA_87_SIGNATURE_BYTES })
  ) {
    return false;
  }
  const digest = publicationDigest(entry);
  const signature = Buffer.from(signatureValue, 'base64');
  try {
    return ml_dsa87.verify(signature, digest, publicationAuthentication.publicKey);
  } catch {
    return false;
  } finally {
    digest.fill(0);
    signature.fill(0);
  }
}
