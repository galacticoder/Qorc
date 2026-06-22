/**
 * Inbox Handlers
 * 
 * Handles inbox claiming, rotation, and blind routing.
 */

import {
  SignalType,
  sendSecureMessage,
  cryptoLogger,
  hasAccountAuthentication,
  hasServerOrAccountAuthentication,
} from './core.js';
import { isRouteLookupId, validateCapabilityToken } from '../routing/capability-tokens.js';
import { validateBlindRouteSelectorPolicy } from '../routing/destination-selector-policy.js';

function isLookupId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{64,128}$/.test(value);
}

function envInt(name, fallback, min, max) {
  const parsed = Number.parseInt(process.env[name] || String(fallback), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
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

function estimateBase64DecodedBytes(value) {
  if (typeof value !== 'string' || value.length === 0) return 0;
  const normalizedLength = value.replace(/=+$/g, '').length;
  return Math.floor((normalizedLength * 3) / 4);
}

function estimateSealedEnvelopeBytes(envelope) {
  return estimateBase64DecodedBytes(envelope?.ciphertext) +
    estimateBase64DecodedBytes(envelope?.ephemeralKey) +
    estimateBase64DecodedBytes(envelope?.nonce);
}

function consumeBlindRouteBudget(ws, envelopeBytes) {
  const now = Date.now();
  if (!ws._blindRouteWindowStart || now - ws._blindRouteWindowStart > BLIND_ROUTE_WINDOW_MS) {
    ws._blindRouteWindowStart = now;
    ws._blindRouteWindowCount = 0;
    ws._blindRouteWindowBytes = 0;
  }

  ws._blindRouteWindowCount = Number(ws._blindRouteWindowCount || 0) + 1;
  ws._blindRouteWindowBytes = Number(ws._blindRouteWindowBytes || 0) + Math.max(0, envelopeBytes);

  return ws._blindRouteWindowCount <= BLIND_ROUTE_MAX_PER_WINDOW &&
    ws._blindRouteWindowBytes <= BLIND_ROUTE_MAX_BYTES_PER_WINDOW;
}

/**
 * Handle blind route message
 */
export async function handleBlindRoute({ ws, parsed, state }) {
  if (!hasServerOrAccountAuthentication(ws, state) && !ws._unlinkedSession) {
    cryptoLogger.warn('[BLIND-ROUTE] Rejected - not authenticated');
    return await sendSecureMessage(ws, {
      type: SignalType.BLIND_ROUTE_ACK,
      requestId: typeof parsed?.requestId === 'string' ? parsed.requestId.slice(0, 128) : undefined,
      success: false,
      error: 'authentication_required'
    });
  }

  const { sealedEnvelope } = parsed;

  const selectorPolicy = validateBlindRouteSelectorPolicy(parsed);
  if (!selectorPolicy.valid) {
    cryptoLogger.warn('[BLIND-ROUTE] Rejected destination selector fields', {
      fields: selectorPolicy.fields
    });
    return await sendSecureMessage(ws, {
      type: SignalType.BLIND_ROUTE_ACK,
      success: false,
      error: selectorPolicy.error
    });
  }

  if (!sealedEnvelope) {
    return await sendSecureMessage(ws, {
      type: SignalType.BLIND_ROUTE_ACK,
      success: false,
      error: 'missing_envelope'
    });
  }

  const envelopeBytes = estimateSealedEnvelopeBytes(sealedEnvelope);
  if (envelopeBytes > BLIND_ROUTE_MAX_ENVELOPE_BYTES) {
    cryptoLogger.warn('[BLIND-ROUTE] Rejected oversized envelope', {
      envelopeSizeClass: envelopeBytes <= 1024 * 1024 ? 'lte-1m' : 'gt-1m'
    });
    return await sendSecureMessage(ws, {
      type: SignalType.BLIND_ROUTE_ACK,
      success: false,
      error: 'blind_route_too_large'
    });
  }

  if (!consumeBlindRouteBudget(ws, envelopeBytes)) {
    cryptoLogger.warn('[BLIND-ROUTE] Rejected due to route budget', {
      count: Number(ws._blindRouteWindowCount || 0),
      windowMs: BLIND_ROUTE_WINDOW_MS
    });
    return await sendSecureMessage(ws, {
      type: SignalType.BLIND_ROUTE_ACK,
      success: false,
      error: 'blind_route_rate_limited'
    });
  }

  const { routeToGlobalMix } = await import('../routing/blind-router.js');
  const routeResult = await routeToGlobalMix(sealedEnvelope, {
    originSocketId: ws._blindSocketId
  });
  if (!routeResult.queued) {
    return await sendSecureMessage(ws, {
      type: SignalType.BLIND_ROUTE_ACK,
      success: false,
      error: routeResult.error || 'delivery_unavailable'
    });
  }

  await sendSecureMessage(ws, {
    type: SignalType.BLIND_ROUTE_ACK,
    success: true
  });
}

/**
 * Handle inbox claim request
 */
export async function handleClaimInbox({ ws, parsed, state }) {
  if (Object.prototype.hasOwnProperty.call(parsed || {}, 'mailboxLookupId')) {
    return await sendSecureMessage(ws, {
      type: SignalType.CLAIM_INBOX_RESPONSE,
      success: false,
      error: 'mailbox_lookup_forbidden'
    });
  }

  const {
    capabilityToken,
    routeId,
    bundleLookupId,
    blockListLookupId,
    blindSignature,
    blindSignatureKid
  } = parsed;

  if (!capabilityToken || typeof capabilityToken !== 'string' || !isRouteLookupId(routeId)) {
    return await sendSecureMessage(ws, {
      type: SignalType.CLAIM_INBOX_RESPONSE,
      success: false,
      error: 'missing_params'
    });
  }

  const capabilityValidation = await validateCapabilityToken(capabilityToken);
  if (!capabilityValidation.valid) {
    return await sendSecureMessage(ws, {
      type: SignalType.CLAIM_INBOX_RESPONSE,
      success: false,
      error: capabilityValidation.error || 'invalid_capability_token'
    });
  }

  // blind route signature is accepted only when paired with the high entropy capability token for this authenticated flow
  let hasValidBlindSignature = false;
  if (blindSignature) {
    try {
      if (!blindSignatureKid || typeof blindSignatureKid !== 'string') {
        throw new Error('Missing blind signature key id');
      }
      const { BlindSignatureIssuer } = await import('../security/blind-signatures.js');
      const isValid = await BlindSignatureIssuer.verifySignature(routeId, blindSignature, blindSignatureKid);
      if (isValid) {
        hasValidBlindSignature = true;
        ws._unlinkedSession = true;
        cryptoLogger.info('[ROUTING] Authorized unlinked inbox claim via blind signature');
      }
    } catch (e) {
      cryptoLogger.warn('[ROUTING] Blind signature verification failed', { error: e?.message });
    }
  }

  const isAuthorized = hasAccountAuthentication(ws, state) || (capabilityValidation.valid && hasValidBlindSignature);
  if (!isAuthorized) {
    return await sendSecureMessage(ws, {
      type: SignalType.CLAIM_INBOX_RESPONSE,
      success: false,
      error: 'authentication_required'
    });
  }

  const { claimInboxRoute, registerLocalSocket } = await import('../routing/blind-router.js');
  if (!ws._blindSocketId) {
    try { registerLocalSocket(ws); } catch { }
  }
  const result = await claimInboxRoute(ws, capabilityToken, routeId, isAuthorized);

  if (result.success) {
    const committedBundleLookupId = isLookupId(bundleLookupId) ? bundleLookupId : routeId;
    const committedBlockListLookupId = isLookupId(blockListLookupId) ? blockListLookupId : routeId;

    if (!ws._primaryInboxRouteId) {
      ws._primaryInboxRouteId = routeId;
      ws._primaryBundleLookupId = committedBundleLookupId;
      ws._primaryBlockListLookupId = committedBlockListLookupId;
    }

    if (!ws._claimedInboxRoutes) ws._claimedInboxRoutes = new Set();
    ws._claimedInboxRoutes.add(routeId);
    if (!ws._claimedBundleLookupIds) ws._claimedBundleLookupIds = new Set();
    ws._claimedBundleLookupIds.add(committedBundleLookupId);
  }

  await sendSecureMessage(ws, {
    type: SignalType.CLAIM_INBOX_RESPONSE,
    success: result.success,
    error: result.error
  });
}

/**
 * Handle inbox rotation
 */
export async function handleRotateInbox({ ws, parsed, state }) {
  if (!hasAccountAuthentication(ws, state)) {
    return await sendSecureMessage(ws, {
      type: SignalType.ROTATE_INBOX_RESPONSE,
      requestId: typeof parsed?.requestId === 'string' ? parsed.requestId.slice(0, 128) : undefined,
      success: false,
      error: 'authentication_required'
    });
  }

  if (
    Object.prototype.hasOwnProperty.call(parsed || {}, 'oldMailboxLookupIds') ||
    Object.prototype.hasOwnProperty.call(parsed || {}, 'newMailboxLookupIds')
  ) {
    return await sendSecureMessage(ws, {
      type: SignalType.ROTATE_INBOX_RESPONSE,
      success: false,
      error: 'mailbox_lookup_forbidden'
    });
  }

  const {
    capabilityToken,
    oldRouteIds,
    newRouteIds,
    newBlockListLookupIds,
    newBundleLookupIds
  } = parsed;

  if (!capabilityToken || !oldRouteIds || !newRouteIds) {
    return await sendSecureMessage(ws, {
      type: SignalType.ROTATE_INBOX_RESPONSE,
      success: false,
      error: 'missing_params'
    });
  }

  try {
    const { rotateInboxRoutes } = await import('../routing/blind-router.js');
    const result = await rotateInboxRoutes(ws, capabilityToken, oldRouteIds, newRouteIds, hasAccountAuthentication(ws, state));

    if (result.success) {
      // Update claimed inboxes
      if (ws._claimedInboxRoutes) {
        for (const oldRouteId of oldRouteIds.filter(isRouteLookupId)) {
          ws._claimedInboxRoutes.delete(oldRouteId);
        }
      }
      if (ws._claimedBundleLookupIds && Array.isArray(parsed.oldBundleLookupIds)) {
        for (const oldBundleId of parsed.oldBundleLookupIds.filter(isLookupId)) {
          ws._claimedBundleLookupIds.delete(oldBundleId);
        }
      }
      if (!ws._claimedInboxRoutes) ws._claimedInboxRoutes = new Set();
      if (!ws._claimedBundleLookupIds) ws._claimedBundleLookupIds = new Set();
      for (const routeId of newRouteIds.filter(isRouteLookupId)) {
        ws._claimedInboxRoutes.add(routeId);
      }
      for (const bundleId of (Array.isArray(newBundleLookupIds) ? newBundleLookupIds : newRouteIds).filter(isLookupId)) {
        ws._claimedBundleLookupIds.add(bundleId);
      }
      if (newRouteIds[0]) {
        ws._primaryInboxRouteId = newRouteIds[0];
        ws._primaryBlockListLookupId = (Array.isArray(newBlockListLookupIds) ? newBlockListLookupIds.find(isLookupId) : null) || newRouteIds[0];
        ws._primaryBundleLookupId = (Array.isArray(newBundleLookupIds) ? newBundleLookupIds.find(isLookupId) : null) || newRouteIds[0];
      }

      cryptoLogger.info('[ROUTING] Inbox rotation completed', {
        oldCount: oldRouteIds.length,
        newCount: newRouteIds.length
      });
    }

    await sendSecureMessage(ws, {
      type: SignalType.ROTATE_INBOX_RESPONSE,
      success: result.success,
      error: result.error
    });
  } catch (error) {
    cryptoLogger.error('[ROUTING] Inbox rotation failed', { error: error.message });
    await sendSecureMessage(ws, {
      type: SignalType.ROTATE_INBOX_RESPONSE,
      success: false,
      error: 'rotation_failed'
    });
  }
}
