import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { canonicalBase64Shape } from '../../shared/canonical-base64.js';
import {
  ML_DSA_87_PUBLIC_KEY_BYTES,
  ML_DSA_87_SECRET_KEY_BYTES,
  ML_DSA_87_SIGNATURE_BYTES,
} from '../../shared/crypto-sizes.js';
import { hasExactPlainObjectKeys } from '../utils/validation.js';
import { UUID_V4_RE } from '../../shared/patterns.js';

export const CLUSTER_MESSAGE_MAX_WIRE_CHARS = 32 * 1024;
export const CLUSTER_MESSAGE_MAX_PAYLOAD_BYTES = 16 * 1024;
export const CLUSTER_MESSAGE_MAX_CLOCK_SKEW_MS = 30_000;
export const CLUSTER_MESSAGE_REPLAY_TTL_MS = 120_000;
export const CLUSTER_SERVER_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$/;

const CLUSTER_MESSAGE_VERSION = 1;
const TARGET_ONLY_TYPES = new Set(['server-approved', 'server-dead', 'primary-elected']);
const TARGET_REASON_TYPES = new Set(['server-force-removed', 'server-rejected']);

function parseJsonObject(raw) {
  try {
    const parsed = JSON.parse(raw);
    return parsed && Object.getPrototypeOf(parsed) === Object.prototype ? parsed : null;
  } catch {
    return null;
  }
}

function validReason(value) {
  return typeof value === 'string' && value.length >= 1 && value.length <= 256 && !/[\u0000-\u001f\u007f]/.test(value);
}

function validatePayload(payload, now) {
  const common = ['issuedAt', 'messageId', 'senderId', 'type', 'version'];
  let expectedKeys = common;
  if (TARGET_ONLY_TYPES.has(payload?.type)) expectedKeys = [...common, 'targetServerId'];
  else if (TARGET_REASON_TYPES.has(payload?.type)) expectedKeys = [...common, 'reason', 'targetServerId'];
  else if (payload?.type !== 'join-request') return false;

  if (
    !hasExactPlainObjectKeys(payload, expectedKeys) ||
    payload.version !== CLUSTER_MESSAGE_VERSION ||
    !UUID_V4_RE.test(payload.messageId) ||
    !CLUSTER_SERVER_ID_RE.test(payload.senderId) ||
    !Number.isSafeInteger(payload.issuedAt) ||
    Math.abs(now - payload.issuedAt) > CLUSTER_MESSAGE_MAX_CLOCK_SKEW_MS
  ) return false;

  if ('targetServerId' in payload && !CLUSTER_SERVER_ID_RE.test(payload.targetServerId)) return false;
  if ('reason' in payload && !validReason(payload.reason)) return false;
  return true;
}

export function createSignedClusterMessage(signingKey, payload) {
  if (!(signingKey instanceof Uint8Array) || signingKey.length !== ML_DSA_87_SECRET_KEY_BYTES) {
    throw new Error('Invalid cluster signing key');
  }
  if (!validatePayload(payload, Date.now())) throw new Error('Invalid cluster message payload');

  const payloadBytes = Buffer.from(JSON.stringify(payload), 'utf8');
  if (payloadBytes.length > CLUSTER_MESSAGE_MAX_PAYLOAD_BYTES) {
    payloadBytes.fill(0);
    throw new Error('Cluster message payload is too large');
  }
  try {
    const signature = ml_dsa87.sign(payloadBytes, signingKey);
    return JSON.stringify({
      payload: payloadBytes.toString('base64'),
      signature: Buffer.from(signature).toString('base64'),
      version: CLUSTER_MESSAGE_VERSION,
    });
  } finally {
    payloadBytes.fill(0);
  }
}

export function inspectSignedClusterMessage(raw, now = Date.now()) {
  if (typeof raw !== 'string' || raw.length < 1 || raw.length > CLUSTER_MESSAGE_MAX_WIRE_CHARS) return null;
  const envelope = parseJsonObject(raw);
  if (
    !hasExactPlainObjectKeys(envelope, ['payload', 'signature', 'version']) ||
    envelope.version !== CLUSTER_MESSAGE_VERSION ||
    !canonicalBase64Shape(envelope.payload, { maxBytes: CLUSTER_MESSAGE_MAX_PAYLOAD_BYTES }) ||
    !canonicalBase64Shape(envelope.signature, { exactBytes: ML_DSA_87_SIGNATURE_BYTES })
  ) return null;

  const payloadBytes = Buffer.from(envelope.payload, 'base64');
  const payload = parseJsonObject(payloadBytes.toString('utf8'));
  if (!validatePayload(payload, now)) {
    payloadBytes.fill(0);
    return null;
  }
  return {
    payload,
    payloadBytes,
    signature: Buffer.from(envelope.signature, 'base64'),
  };
}

export function verifyInspectedClusterMessage(inspected, publicKey) {
  if (
    !inspected ||
    !(publicKey instanceof Uint8Array) ||
    publicKey.length !== ML_DSA_87_PUBLIC_KEY_BYTES
  ) return false;
  return ml_dsa87.verify(inspected.signature, inspected.payloadBytes, publicKey);
}

export function wipeInspectedClusterMessage(inspected) {
  inspected?.payloadBytes?.fill?.(0);
  inspected?.signature?.fill?.(0);
}
