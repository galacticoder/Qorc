class WsMessageHandlerDeadlineError extends Error {
  constructor(code) {
    super(code === 'WS_MESSAGE_HANDLER_TIMEOUT'
      ? 'WebSocket message handler timed out'
      : 'WebSocket connection closed');
    this.code = code;
  }
}

export async function awaitMessageHandlerWithDeadline(handlerPromise, { signal, timeoutMs }) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError('timeoutMs must be a positive finite number');
  }
  if (signal?.aborted) {
    throw new WsMessageHandlerDeadlineError('WS_MESSAGE_HANDLER_ABORTED');
  }

  let timeoutId = null;
  let abortHandler = null;
  const deadline = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      reject(new WsMessageHandlerDeadlineError('WS_MESSAGE_HANDLER_TIMEOUT'));
    }, timeoutMs);

    if (signal) {
      abortHandler = () => {
        reject(new WsMessageHandlerDeadlineError('WS_MESSAGE_HANDLER_ABORTED'));
      };
      signal.addEventListener('abort', abortHandler, { once: true });
    }
  });

  try {
    return await Promise.race([Promise.resolve(handlerPromise), deadline]);
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
    if (signal && abortHandler) signal.removeEventListener('abort', abortHandler);
  }
}
