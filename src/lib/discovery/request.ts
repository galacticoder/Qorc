import { EventType } from '../types/event-types';
import { SignalType } from '../types/signal-types';
import { WS_CONTROL_RESPONSE_TIMEOUT_MS, WS_CONTROL_SEND_TIMEOUT_MS } from '../constants';

export class DiscoveryRequestError extends Error {
  constructor(readonly code: string, readonly detail?: string) {
    super(code);
    this.name = 'DiscoveryRequestError';
  }
}

export function parsePublicationAck(detail: unknown, requestId: string): true | undefined {
  if (!detail || typeof detail !== 'object' || Array.isArray(detail)) return undefined;
  const ack = detail as Record<string, unknown>;
  if (ack.requestId !== requestId) return undefined;
  if (Object.getPrototypeOf(ack) !== Object.prototype ||
    ack.type !== SignalType.OK || ack.op !== SignalType.PUBLISH_DISCOVERY) {
    throw new DiscoveryRequestError('publish-invalid-ack');
  }
  const keys = Object.keys(ack).sort().join(',');
  if (ack.success === true && keys === 'op,requestId,success,type') return true;
  if (ack.success === false && keys === 'error,op,requestId,success,type' &&
    typeof ack.error === 'string' && /^[a-z0-9_]{1,64}$/.test(ack.error)) {
    throw new DiscoveryRequestError(ack.error);
  }
  throw new DiscoveryRequestError('publish-invalid-ack');
}

export function requestDiscoveryResponse<T>(options: {
  operation: string;
  events: EventTarget;
  signal: AbortSignal;
  isCurrent: () => boolean;
  send: (signal: AbortSignal) => Promise<void>;
  parse: (detail: unknown) => T | undefined;
  sendTimeoutMs?: number;
  responseTimeoutMs?: number;
  onSent?: (durationMs: number) => void;
  registerConnectionCancel?: (cancel: () => void) => () => void;
}): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const controller = new AbortController();
    const startedAt = performance.now();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let settled = false;
    let unregisterConnectionCancel = () => {};
    const finish = (error?: DiscoveryRequestError, value?: T) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.events.removeEventListener(EventType.SECURE_SERVER_MESSAGE, onMessage);
      options.events.removeEventListener(EventType.EDGE_SERVER_MESSAGE, onTransport);
      options.signal.removeEventListener('abort', onAbort);
      unregisterConnectionCancel();
      controller.abort();
      if (error) reject(error);
      else resolve(value as T);
    };
    const onAbort = () => finish(new DiscoveryRequestError('discovery-request-aborted'));
    const onTransport = () => {
      if (!options.isCurrent()) finish(new DiscoveryRequestError('discovery-transport-changed'));
    };
    const onMessage = (event: Event) => {
      if (settled) return;
      if (!options.isCurrent()) {
        onTransport();
        return;
      }
      try {
        const value = options.parse((event as CustomEvent).detail);
        if (value !== undefined) finish(undefined, value);
      } catch (error) {
        finish(error instanceof DiscoveryRequestError
          ? error
          : new DiscoveryRequestError(`${options.operation}-invalid-response`));
      }
    };
    if (options.signal.aborted) {
      onAbort();
      return;
    }
    if (!options.isCurrent()) {
      onTransport();
      return;
    }
    options.events.addEventListener(EventType.SECURE_SERVER_MESSAGE, onMessage);
    options.events.addEventListener(EventType.EDGE_SERVER_MESSAGE, onTransport);
    options.signal.addEventListener('abort', onAbort, { once: true });
    if (options.registerConnectionCancel) {
      unregisterConnectionCancel = options.registerConnectionCancel(() => {
        finish(new DiscoveryRequestError('discovery-transport-changed'));
      });
    }
    timer = setTimeout(() => {
      finish(new DiscoveryRequestError(`${options.operation}-send-timeout`));
    }, options.sendTimeoutMs ?? WS_CONTROL_SEND_TIMEOUT_MS);
    void Promise.resolve().then(() => {
      if (settled) return;
      return options.send(controller.signal);
    }).then(() => {
      if (settled) return;
      if (!options.isCurrent()) {
        onTransport();
        return;
      }
      clearTimeout(timer);
      timer = setTimeout(() => {
        finish(new DiscoveryRequestError(`${options.operation}-response-timeout`));
      }, options.responseTimeoutMs ?? WS_CONTROL_RESPONSE_TIMEOUT_MS);
      options.onSent?.(Math.round(performance.now() - startedAt));
    }).catch((error) => {
      finish(new DiscoveryRequestError(
        `${options.operation}-send-failed`,
        error instanceof Error ? error.message : String(error),
      ));
    });
  });
}
