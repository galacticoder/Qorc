import { useCallback, useEffect, useRef } from 'react';
import { SignalType } from '../../lib/types/signal-types';
import { TYPING_STOP_DELAY, MIN_TYPING_INTERVAL } from '../../lib/constants';
import { unifiedSignalTransport } from '../../lib/transport/unified-signal-transport';
import { getSessionApi } from '../../lib/utils/message-sending-utils';

type ActiveTypingPeer = { account: string; peer: string };

export function useTypingIndicator(
  currentUsername: string,
  selectedConversation?: string,
) {
  if (!currentUsername || typeof currentUsername !== 'string' || currentUsername.trim().length === 0 || currentUsername.length > 128) {
    throw new Error('[TypingIndicator] Invalid currentUsername');
  }

  const accountRef = useRef(currentUsername);
  const selectedPeerRef = useRef(selectedConversation);
  accountRef.current = currentUsername;
  selectedPeerRef.current = selectedConversation;

  const activeTypingRef = useRef<ActiveTypingPeer | null>(null);
  const wantsTypingRef = useRef(false);
  const lastTypingStartSentRef = useRef(0);
  const typingQueueRef = useRef<Promise<void>>(Promise.resolve());
  const startQueuedRef = useRef(false);
  const stopQueuedRef = useRef(new Set<string>());
  const timeoutsRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

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
    },
    [clearManagedTimeout],
  );

  const clearAllTimeouts = useCallback(() => {
    timeoutsRef.current.forEach((handle) => clearTimeout(handle));
    timeoutsRef.current.clear();
  }, []);

  const enqueueTypingTask = useCallback((task: () => Promise<void>): Promise<void> => {
    const run = typingQueueRef.current.then(task, task);
    typingQueueRef.current = run.catch(() => {});
    return run;
  }, []);

  const sendTypingSignal = useCallback(async (
    kind: 'start' | 'stop',
    target: ActiveTypingPeer,
  ): Promise<boolean> => {
    if (accountRef.current !== target.account) return false;
    if (kind === 'start' && selectedPeerRef.current !== target.peer) return false;

    const sessionCheck = await getSessionApi().hasSession({
      selfUsername: target.account,
      peerUsername: target.peer,
    }).catch(() => null);
    if (!sessionCheck?.hasSession || accountRef.current !== target.account) return false;
    if (kind === 'start' && selectedPeerRef.current !== target.peer) return false;

    const type = kind === 'start' ? SignalType.TYPING_START : SignalType.TYPING_STOP;
    const result = await unifiedSignalTransport.send(target.peer, {}, type);
    return result.success &&
      accountRef.current === target.account &&
      (kind === 'stop' || selectedPeerRef.current === target.peer);
  }, []);

  const stopTypingFor = useCallback(async (target: ActiveTypingPeer): Promise<void> => {
    try {
      await sendTypingSignal('stop', target);
    } catch {
    } finally {
      const active = activeTypingRef.current;
      if (active?.account === target.account && active.peer === target.peer) {
        activeTypingRef.current = null;
        lastTypingStartSentRef.current = 0;
      }
    }
  }, [sendTypingSignal]);

  const sendTypingStop = useCallback((target = activeTypingRef.current): Promise<void> => {
    wantsTypingRef.current = false;
    if (!target) return Promise.resolve();
    const key = `${target.account}\0${target.peer}`;
    if (stopQueuedRef.current.has(key)) return typingQueueRef.current;
    stopQueuedRef.current.add(key);
    return enqueueTypingTask(async () => {
      try {
        await stopTypingFor(target);
      } finally {
        stopQueuedRef.current.delete(key);
      }
    });
  }, [enqueueTypingTask, stopTypingFor]);

  const sendTypingStart = useCallback((): Promise<void> => {
    if (startQueuedRef.current) return typingQueueRef.current;
    startQueuedRef.current = true;
    return enqueueTypingTask(async () => {
      try {
        const target = {
          account: accountRef.current,
          peer: selectedPeerRef.current || '',
        };
        if (!target.peer || !wantsTypingRef.current) return;

        const active = activeTypingRef.current;
        if (active && (active.account !== target.account || active.peer !== target.peer)) {
          await stopTypingFor(active);
        }

        const elapsed = Date.now() - lastTypingStartSentRef.current;
        const currentActive = activeTypingRef.current;
        if (
          currentActive?.account === target.account &&
          currentActive.peer === target.peer &&
          elapsed < MIN_TYPING_INTERVAL
        ) return;

        try {
          const sent = await sendTypingSignal('start', target);
          if (sent) {
            activeTypingRef.current = target;
            if (
              wantsTypingRef.current &&
              accountRef.current === target.account &&
              selectedPeerRef.current === target.peer
            ) {
              lastTypingStartSentRef.current = Date.now();
            } else {
              await stopTypingFor(target);
            }
          }
        } catch {
        }
      } finally {
        startQueuedRef.current = false;
      }
    });
  }, [enqueueTypingTask, sendTypingSignal, stopTypingFor]);

  const handleLocalTyping = useCallback(() => {
    if (!selectedPeerRef.current) return;
    wantsTypingRef.current = true;
    void sendTypingStart();
    setManagedTimeout('stop', () => { void sendTypingStop(); }, TYPING_STOP_DELAY);
  }, [sendTypingStart, sendTypingStop, setManagedTimeout]);

  const handleConversationChange = useCallback(() => {
    clearManagedTimeout('stop');
    const active = activeTypingRef.current;
    if (active && active.peer !== selectedPeerRef.current) {
      void sendTypingStop(active);
    }
  }, [clearManagedTimeout, sendTypingStop]);

  const resetTypingAfterSend = useCallback(() => {
    clearManagedTimeout('stop');
    void sendTypingStop();
  }, [clearManagedTimeout, sendTypingStop]);

  useEffect(() => {
    clearAllTimeouts();
    wantsTypingRef.current = false;
    activeTypingRef.current = null;
    lastTypingStartSentRef.current = 0;
    startQueuedRef.current = false;
    stopQueuedRef.current.clear();
  }, [currentUsername, clearAllTimeouts]);

  useEffect(() => () => {
    clearAllTimeouts();
    void sendTypingStop();
  }, [clearAllTimeouts, sendTypingStop]);

  return {
    handleLocalTyping,
    handleConversationChange,
    resetTypingAfterSend,
  };
}
