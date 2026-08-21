/**
 * Call-signal parsing and dispatch for the encrypted receive path
 */

import { EventType } from './event-types';
import { safeJsonParseForCallSignals } from '../utils/message-handler-utils';
import { MAX_CALL_SIGNAL_CLOCK_SKEW_MS } from '../constants';
import { isExactCallSignal, isValidCallingUsername } from '../utils/calling-utils';
import type { CallSignal } from './calling-types';

export interface CallSignalContext {
  localUsername: string;
  payload: {
    content: string;
    from: string;
  };
}

// Authenticate and normalize a call signal without publishing it
export function parseAuthenticatedCallSignal(ctx: CallSignalContext): CallSignal | null {
  const callSignalData = safeJsonParseForCallSignals(ctx.payload.content);
  const now = Date.now();
  if (
    !isExactCallSignal(callSignalData) ||
    !isValidCallingUsername(ctx.localUsername) ||
    ctx.localUsername !== ctx.localUsername.toLowerCase() ||
    !isValidCallingUsername(ctx.payload.from) ||
    ctx.payload.from !== ctx.payload.from.toLowerCase() ||
    ctx.payload.from === ctx.localUsername ||
    callSignalData.from !== ctx.payload.from ||
    callSignalData.to !== ctx.localUsername ||
    Math.abs(now - callSignalData.timestamp) > MAX_CALL_SIGNAL_CLOCK_SKEW_MS
  ) {
    return null;
  }

  const base = {
    type: callSignalData.type,
    callId: callSignalData.callId,
    from: ctx.payload.from,
    to: callSignalData.to,
    timestamp: callSignalData.timestamp
  };
  let authenticatedCallSignal: CallSignal;
  if (callSignalData.type === 'offer') {
    authenticatedCallSignal = Object.freeze({
      ...base,
      type: 'offer',
      data: Object.freeze({
        callType: callSignalData.data.callType
      })
    });
  } else if (callSignalData.type === 'answer') {
    authenticatedCallSignal = Object.freeze({
      ...base,
      type: 'answer'
    });
  } else if (
    callSignalData.type === 'screen-share-start' ||
    callSignalData.type === 'screen-share-ready' ||
    callSignalData.type === 'screen-share-stop'
  ) {
    authenticatedCallSignal = Object.freeze({
      ...base,
      type: callSignalData.type,
      data: Object.freeze({ streamId: callSignalData.data.streamId })
    });
  } else {
    authenticatedCallSignal = Object.freeze({ ...base, type: callSignalData.type });
  }

  return authenticatedCallSignal;
}

export function dispatchAuthenticatedCallSignal(callSignal: CallSignal): void {
  window.dispatchEvent(new CustomEvent(EventType.CALL_SIGNAL, {
    detail: callSignal
  }));
}
