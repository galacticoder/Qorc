import { canonicalBase64Shape } from '../../shared/canonical-base64.js';
import {
  ML_DSA_87_PUBLIC_KEY_BYTES,
  ML_KEM_1024_PUBLIC_KEY_BYTES,
} from '../../shared/crypto-sizes.js';
import { X25519_KEY_BYTES } from '../utils/crypto-consts.js';
import { hasExactPlainObjectKeys } from '../utils/validation.js';
import { CLUSTER_SERVER_ID_RE } from './signed-message.js';

const CLUSTER_SERVER_RECORD_KEYS = new Set([
  'approvedBy',
  'host',
  'isPrimary',
  'joinedAt',
  'lastHeartbeat',
  'port',
  'publicKeys',
  'serverId',
  'status',
]);

export function isValidAdvertisedHost(value) {
  return typeof value === 'string' &&
    /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(value);
}

export function isValidAdvertisedPort(value) {
  return Number.isSafeInteger(value) && value >= 1 && value <= 65535;
}

export function isValidClusterPublicKeys(value) {
  return Boolean(
    hasExactPlainObjectKeys(value, ['dilithium', 'kyber', 'x25519']) &&
    canonicalBase64Shape(value.kyber, { exactBytes: ML_KEM_1024_PUBLIC_KEY_BYTES }) &&
    canonicalBase64Shape(value.dilithium, { exactBytes: ML_DSA_87_PUBLIC_KEY_BYTES }) &&
    canonicalBase64Shape(value.x25519, { exactBytes: X25519_KEY_BYTES })
  );
}

export function isValidClusterServerRecord(value, serverId, now = Date.now()) {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    typeof serverId !== 'string' ||
    !CLUSTER_SERVER_ID_RE.test(serverId) ||
    !Number.isSafeInteger(now)
  ) return false;
  if (Object.keys(value).some((key) => !CLUSTER_SERVER_RECORD_KEYS.has(key))) return false;
  if (
    value.serverId !== serverId ||
    typeof value.isPrimary !== 'boolean' ||
    !Number.isSafeInteger(value.joinedAt) ||
    value.joinedAt <= 0 ||
    value.joinedAt > now + 30_000 ||
    !Number.isSafeInteger(value.lastHeartbeat) ||
    value.lastHeartbeat < value.joinedAt ||
    value.lastHeartbeat > now + 30_000 ||
    value.status !== 'active' ||
    !isValidClusterPublicKeys(value.publicKeys) ||
    !isValidAdvertisedHost(value.host) ||
    !isValidAdvertisedPort(value.port)
  ) return false;
  if ('approvedBy' in value) {
    if (value.approvedBy !== 'auto-approve' && !CLUSTER_SERVER_ID_RE.test(value.approvedBy)) return false;
  } else if (!value.isPrimary) {
    return false;
  }
  return true;
}

export function parseClusterServerRecord(raw, serverId, now = Date.now()) {
  if (typeof raw !== 'string') return null;
  try {
    const parsed = JSON.parse(raw);
    return isValidClusterServerRecord(parsed, serverId, now) ? parsed : null;
  } catch {
    return null;
  }
}
