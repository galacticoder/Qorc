/**
 * Anonymous delivery handlers.
 */

import { SignalType } from '../signals.js';
import { sendSecureMessage } from '../messaging/pq-envelope-handler.js';

import * as ServerConfig from '../config/config.js';
import { LIVE_ONLY_DELIVERY_POLICY } from '../config/audiences.js';
import { BLIND_ROUTE_REQUEST_ID_RE, validateBlindRouteRequest } from '../routing/blind-route-schema.js';
import { envInt } from '../utils/env.js';
import { createWindowBudget } from '../utils/window-budget.js';

export function hasAccountAuthentication(ws) {
  return ws?._authenticated === true;
}

export function hasServerEntryAuthorization(ws) {
  if (!ServerConfig.isServerPasswordGateReady()) return true;
  return ws?._hasServerAuth === true;
}

export function isLiveDeliverySocket(ws) {
  return Boolean(
    ws &&
    ws._connectionAbortSignal?.aborted !== true &&
    ws._ingressQueueRejected !== true &&
    (ws.readyState === undefined || ws.readyState === 1)
  );
}

export function hasAnonymousDeliveryAuthorization(ws) {
  return hasAnonymousSocketAuthorization(ws) &&
    ws?._unlinkedSession === true;
}

export function hasAnonymousSocketAuthorization(ws) {
  return isLiveDeliverySocket(ws) &&
    ws?._accountAuthViaAnonymousToken === true &&
    hasServerEntryAuthorization(ws) &&
    hasAccountAuthentication(ws);
}

export function activateAnonymousDeliveryAuthorization(ws) {
  if (!hasAnonymousSocketAuthorization(ws)) return false;
  ws._unlinkedSession = true;
  if (hasAnonymousDeliveryAuthorization(ws)) return true;
  delete ws._unlinkedSession;
  return false;
}

const BLIND_ROUTE_WINDOW_MS = envInt('BLIND_ROUTE_WINDOW_MS', 60_000, 1_000, 10 * 60_000);
const BLIND_ROUTE_MAX_PER_WINDOW = envInt('BLIND_ROUTE_MAX_PER_WINDOW', 30, 1, 10_000);
const BLIND_ROUTE_MAX_BYTES_PER_WINDOW = envInt(
  'BLIND_ROUTE_MAX_BYTES_PER_WINDOW',
  8 * 1024 * 1024,
  64 * 1024,
  512 * 1024 * 1024
);
const BLIND_ROUTE_MAX_ENVELOPE_BYTES = envInt(
  'BLIND_ROUTE_MAX_ENVELOPE_BYTES',
  384 * 1024,
  16 * 1024,
  8 * 1024 * 1024
);

const consumeBlindRouteBudget = createWindowBudget({
  windowMs: BLIND_ROUTE_WINDOW_MS,
  maxCount: BLIND_ROUTE_MAX_PER_WINDOW,
  maxBytes: BLIND_ROUTE_MAX_BYTES_PER_WINDOW
});

/**
 * Handle blind route message
 */
export async function handleBlindRoute({ ws, parsed }) {
  const requestId = typeof parsed?.requestId === 'string' && BLIND_ROUTE_REQUEST_ID_RE.test(parsed.requestId)
    ? parsed.requestId
    : undefined;
  const ack = (fields) => sendSecureMessage(ws, { type: SignalType.BLIND_ROUTE_ACK, requestId, ...fields });

  const requestValidation = validateBlindRouteRequest(parsed);
  if (!requestValidation.valid) {
    return await ack({ success: false, error: requestValidation.error });
  }

  if (!hasAnonymousDeliveryAuthorization(ws)) {
    console.warn('[BLIND-ROUTE] Rejected unauthenticated');
    return await ack({ success: false, error: 'authentication_required' });
  }

  const { sealedEnvelope } = parsed;

  const envelopeBytes = requestValidation.envelopeBytes;
  if (envelopeBytes > BLIND_ROUTE_MAX_ENVELOPE_BYTES) {
    console.warn('[BLIND-ROUTE] Rejected oversized envelope', {
      envelopeSizeClass: envelopeBytes <= 1024 * 1024 ? 'lte-1m' : 'gt-1m'
    });
    return await ack({ success: false, error: 'blind_route_too_large' });
  }

  if (!consumeBlindRouteBudget(ws, envelopeBytes)) {
    console.warn('[BLIND-ROUTE] Rejected due to route budget', {
      count: Number(ws._blindRouteWindowCount || 0),
      windowMs: BLIND_ROUTE_WINDOW_MS
    });
    return await ack({ success: false, error: 'blind_route_rate_limited' });
  }

  const { routeToGlobalMix } = await import('../routing/blind-router.js');
  if (!hasAnonymousDeliveryAuthorization(ws)) return false;
  const routeResult = await routeToGlobalMix(sealedEnvelope, {
    liveOnly: requestValidation.deliveryPolicy === LIVE_ONLY_DELIVERY_POLICY
  });
  if (!routeResult.queued) {
    return await ack({ success: false, error: routeResult.error || 'delivery_unavailable' });
  }

  await ack({ success: true });
}

// Activate authorized socket for global mix broadcast
export async function handleActivateDelivery({ ws, parsed }) {
  const requestId = typeof parsed?.requestId === 'string' &&
    BLIND_ROUTE_REQUEST_ID_RE.test(parsed.requestId)
    ? parsed.requestId
    : undefined;
  const response = (fields) => sendSecureMessage(ws, {
    type: SignalType.ACTIVATE_DELIVERY_RESPONSE,
    requestId,
    ...fields
  });

  if (!requestId || Object.keys(parsed || {}).sort().join(',') !== 'requestId,type') {
    return await response({ success: false, error: 'invalid_activation_request' });
  }

  const isAuthorized = hasAnonymousSocketAuthorization(ws);
  if (!isAuthorized) {
    return await response({ success: false, error: 'authentication_required' });
  }

  const { registerLocalSocket, unregisterLocalSocket } = await import('../routing/blind-router.js');
  if (!hasAnonymousSocketAuthorization(ws)) return false;
  const previousSocketId = ws._blindSocketId;
  let newlyRegistered = false;
  try {
    const socketId = registerLocalSocket(ws);
    newlyRegistered = socketId !== previousSocketId;
  } catch {
    return await response({ success: false, error: 'delivery_registration_failed' });
  }
  if (!activateAnonymousDeliveryAuthorization(ws)) {
    if (newlyRegistered) unregisterLocalSocket(ws);
    return false;
  }

  try {
    const delivered = await response({ success: true });
    if (delivered === false) throw new Error('Activation response was not delivered');
  } catch {
    if (newlyRegistered) {
      unregisterLocalSocket(ws);
      delete ws._unlinkedSession;
    }
    return false;
  }
  return true;
}
