import { UUID_V4_RE } from '../../shared/patterns.js';

const RESERVED_JSON_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const WIRE_MESSAGE_TYPE_RE = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;

export function hasExactPlainObjectKeys(value, expectedKeys) {
  return Boolean(
    value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).sort().join(',') === [...expectedKeys].sort().join(',')
  );
}

export function hasReservedJsonKey(key) {
  return RESERVED_JSON_KEYS.has(key);
}

export function isSafeWireMessageType(value) {
  return typeof value === 'string' && WIRE_MESSAGE_TYPE_RE.test(value);
}

export function requireUuidV4(value, label) {
  if (typeof value !== 'string' || !UUID_V4_RE.test(value)) {
    throw new Error(`Invalid ${label}`);
  }
  return value;
}

export function isSafeJsonTree(root, {
  maxDepth = 32,
  maxNodes = 20_000,
  maxKeyLength = Number.POSITIVE_INFINITY
} = {}) {
  let nodes = 0;
  const stack = [{ value: root, depth: 0 }];
  while (stack.length > 0) {
    const { value, depth } = stack.pop();
    nodes += 1;
    if (nodes > maxNodes || depth > maxDepth) return false;
    if (value === null || typeof value === 'string' || typeof value === 'boolean') continue;
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) return false;
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) stack.push({ value: item, depth: depth + 1 });
      continue;
    }
    if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) {
      return false;
    }
    for (const [key, child] of Object.entries(value)) {
      if (key.length > maxKeyLength || hasReservedJsonKey(key)) return false;
      stack.push({ value: child, depth: depth + 1 });
    }
  }
  return true;
}
