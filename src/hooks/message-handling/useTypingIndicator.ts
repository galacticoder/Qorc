import { useCallback, useEffect, useRef } from 'react';
import { SignalType } from '../../lib/signal-types';
import { TYPING_DOMAIN, TYPING_STOP_DELAY, MIN_TYPING_INTERVAL, CONVERSATION_CHANGE_DEBOUNCE } from '../../lib/constants';

const createRandomHex = (byteLength: number) => {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
};

const createTypingMessageId = (kind: 'start' | 'stop', sequence: number) => {
  const timestampSegment = Date.now().toString(36);
  const entropy = createRandomHex(16);
  return `${TYPING_DOMAIN}:${kind}:v2:${timestampSegment}:${sequence.toString(36)}:${entropy}`;
};

const createTypingNonce = () => createRandomHex(16);

export function useTypingIndicator(
  currentUsername: string,
  selectedConversation?: string,
  sendEncryptedMessage?: (messageId: string, content: string, messageSignalType: string, replyTo?: any) => Promise<void>,
) {
  if (!currentUsername || typeof currentUsername !== 'string' || currentUsername.trim().length === 0 || currentUsername.length > 128) {
    throw new Error('[TypingIndicator] Invalid currentUsername');
  }

  const isTypingRef = useRef(false);
  const pendingTypingRef = useRef(false);
  const lastTypingStartSentRef = useRef(0);
  const isProcessingRef = useRef(false);
  const typingQueueRef = useRef<Promise<void>>(Promise.resolve());
  const timeoutsRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  const queueDepthRef = useRef(0);
  const messageSequenceRef = useRef(0);

  const clearManagedTimeout = useCallback((name: string) => {
    const handle = timeoutsRef.current.get(name);
    if (handle) {
      clearTimeout(handle);
      timeoutsRef.current.delete(name);
    }
  }, []);

  const setManagedTimeout = useCallback(
    (name: string, handler: () => void, delay: number) => {
      clearManagedTimeout(name);
      const handle = setTimeout(() => {
        timeoutsRef.current.delete(name);
        handler();
      }, delay);
      timeoutsRef.current.set(name, handle);
      return handle;
    },
    [clearManagedTimeout],
  );

  const clearAllTimeouts = useCallback(() => {
    timeoutsRef.current.forEach((handle) => clearTimeout(handle));
    timeoutsRef.current.clear();
  }, []);

  const enqueueTypingTask = useCallback((task: () => Promise<void>) => {
    const wrappedTask = async () => {
      queueDepthRef.current = Math.min(queueDepthRef.current + 1, 32);
      try {
        await task();
      } finally {
        queueDepthRef.current = Math.max(queueDepthRef.current - 1, 0);
      }
    };

    typingQueueRef.current = typingQueueRef.current
      .then(() => wrappedTask())
      .catch(() => wrappedTask())
      .catch(() => {});

    return typingQueueRef.current;
  }, []);

  const sendTypingSignal = useCallback(
    async (kind: 'start' | 'stop') => {
      if (!sendEncryptedMessage) return;
      const sequence = ++messageSequenceRef.current;
      const id = createTypingMessageId(kind, sequence);
      const payload = {
        domain: TYPING_DOMAIN,
        type: kind === 'start' ? SignalType.TYPING_START : SignalType.TYPING_STOP,
        timestamp: Date.now(),
        nonce: createTypingNonce(),
        username: currentUsername,
        conversation: selectedConversation ?? null,
      };
      await sendEncryptedMessage(id, JSON.stringify(payload), kind === 'start' ? SignalType.TYPING_START : SignalType.TYPING_STOP);
      isTypingRef.current = kind === 'start';
      if (kind === 'stop') {
        pendingTypingRef.current = false;
      }
    },
    [currentUsername, selectedConversation, sendEncryptedMessage],
  );

  const sendTypingStart = useCallback(
    () =>
      enqueueTypingTask(async () => {
        const now = Date.now();
        const elapsed = now - lastTypingStartSentRef.current;

        if (isProcessingRef.current) {
          pendingTypingRef.current = true;
          return;
        }

        if (isTypingRef.current && elapsed < MIN_TYPING_INTERVAL) {
          pendingTypingRef.current = true;
          return;
        }

        isProcessingRef.current = true;
        try {
          await sendTypingSignal('start');
          lastTypingStartSentRef.current = now;
          isTypingRef.current = true;
          pendingTypingRef.current = false;
        } catch (error) {
          console.error('[TypingIndicator] Failed to send typing start:', error);
          isTypingRef.current = false;
          pendingTypingRef.current = true;
        } finally {
          isProcessingRef.current = false;
        }
      }),
    [enqueueTypingTask, sendTypingSignal],
  );

  const sendTypingStop = useCallback(
    () =>
      enqueueTypingTask(async () => {
        if (!isTypingRef.current) return;

        isProcessingRef.current = true;
        try {
          await sendTypingSignal('stop');
          isTypingRef.current = false;
          pendingTypingRef.current = false;
        } catch (error) {
          console.error('[TypingIndicator] Failed to send typing stop:', error);
          isTypingRef.current = false;
          pendingTypingRef.current = false;
        } finally {
          isProcessingRef.current = false;
        }
      }),
    [enqueueTypingTask, sendTypingSignal],
  );

  const handleLocalTyping = useCallback(() => {
    clearManagedTimeout('debounce');

    const now = Date.now();
    const elapsed = now - lastTypingStartSentRef.current;

    if (!isProcessingRef.current && elapsed > MIN_TYPING_INTERVAL) {
      sendTypingStart();
    }

    setManagedTimeout('debounce', sendTypingStop, TYPING_STOP_DELAY);
  }, [clearManagedTimeout, sendTypingStart, sendTypingStop, setManagedTimeout]);

  const handleConversationChange = useCallback(() => {
    clearManagedTimeout('conversation');
    setManagedTimeout(
      'conversation',
      () => {
        clearManagedTimeout('debounce');
        clearManagedTimeout('retry');
        if (isTypingRef.current) {
          sendTypingStop();
        }
      },
      CONVERSATION_CHANGE_DEBOUNCE,
    );
  }, [clearManagedTimeout, sendTypingStop, setManagedTimeout]);

  const resetTypingAfterSend = useCallback(() => {
    clearManagedTimeout('debounce');
    clearManagedTimeout('retry');
    lastTypingStartSentRef.current = 0;
    pendingTypingRef.current = false;
    isProcessingRef.current = false;
    if (isTypingRef.current) {
      sendTypingStop();
    }
    isTypingRef.current = false;
  }, [clearManagedTimeout, sendTypingStop]);

  useEffect(() => () => {
    clearAllTimeouts();
    if (isTypingRef.current) {
      sendTypingStop();
    }
    isTypingRef.current = false;
    pendingTypingRef.current = false;
  }, [clearAllTimeouts, sendTypingStop]);

  useEffect(() => {
    if (!pendingTypingRef.current || isTypingRef.current) {
      return;
    }

    const now = Date.now();
    const timeUntil = Math.max(MIN_TYPING_INTERVAL - (now - lastTypingStartSentRef.current), 0);
    if (timeUntil <= 0) {
      sendTypingStart();
      return;
    }

    setManagedTimeout(
      'retry',
      () => {
        if (pendingTypingRef.current && !isTypingRef.current) {
          sendTypingStart();
        }
      },
      timeUntil,
    );

    return () => clearManagedTimeout('retry');
  }, [clearManagedTimeout, sendTypingStart, setManagedTimeout]);

  return {
    handleLocalTyping,
    handleConversationChange,
    resetTypingAfterSend,
    isTyping: isTypingRef.current,
  };
}