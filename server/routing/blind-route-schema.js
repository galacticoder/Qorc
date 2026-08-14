import { SignalType } from '../signals.js';
import { validateSealedEnvelope } from './sealed-sender.js';
import { LIVE_ONLY_DELIVERY_POLICY } from '../config/audiences.js';
import { UUID_V4_RE } from '../utils/patterns.js';

export const BLIND_ROUTE_REQUEST_ID_RE = UUID_V4_RE;

export function validateBlindRouteRequest(message) {
  if (
    !message ||
    typeof message !== 'object' ||
    Array.isArray(message) ||
    (Object.getPrototypeOf(message) !== Object.prototype && Object.getPrototypeOf(message) !== null)
  ) {
    return { valid: false, error: 'invalid_blind_route' };
  }
  const keys = Object.keys(message).sort().join(',');
  if (
    keys !== 'requestId,sealedEnvelope,type' &&
    keys !== 'deliveryPolicy,requestId,sealedEnvelope,type'
  ) {
    return { valid: false, error: 'invalid_blind_route' };
  }
  if (
    message.type !== SignalType.BLIND_ROUTE ||
    typeof message.requestId !== 'string' ||
    !BLIND_ROUTE_REQUEST_ID_RE.test(message.requestId) ||
    !message.sealedEnvelope ||
    typeof message.sealedEnvelope !== 'object' ||
    Array.isArray(message.sealedEnvelope) ||
    (message.deliveryPolicy !== undefined && message.deliveryPolicy !== LIVE_ONLY_DELIVERY_POLICY)
  ) {
    return { valid: false, error: 'invalid_blind_route' };
  }
  const sealedValidation = validateSealedEnvelope(message.sealedEnvelope);
  if (!sealedValidation.valid) {
    return { valid: false, error: `invalid_sealed_envelope:${sealedValidation.error}` };
  }
  return {
    valid: true,
    envelopeBytes: sealedValidation.decodedBytes,
    deliveryPolicy: message.deliveryPolicy === LIVE_ONLY_DELIVERY_POLICY
      ? LIVE_ONLY_DELIVERY_POLICY
      : 'durable'
  };
}
