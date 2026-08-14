import crypto from 'crypto';
import { envInt } from '../utils/env.js';
import { randomDelay } from '../utils/random.js';

const COVER_TRAFFIC_INTERVAL_MS = envInt('SERVER_COVER_TRAFFIC_INTERVAL_MS', 30000, 5000, 10 * 60 * 1000);
const COVER_TRAFFIC_VARIANCE_MS = envInt('SERVER_COVER_TRAFFIC_VARIANCE_MS', 15000, 0, 10 * 60 * 1000);
const COVER_TRAFFIC_WRITES_MIN = envInt('SERVER_COVER_TRAFFIC_WRITES_MIN', 1, 1, 32);
const COVER_TRAFFIC_WRITES_MAX = envInt('SERVER_COVER_TRAFFIC_WRITES_MAX', 3, COVER_TRAFFIC_WRITES_MIN, 64);

let coverTrafficTimer = null;
let coverTrafficActive = false;
let coverTrafficGeneration = 0;
let coverTrafficIterationPromise = null;

export function startCoverTraffic(sendDummyFn) {
  if (coverTrafficActive) return;
  if (typeof sendDummyFn !== 'function') {
    throw new Error('Cover traffic sender is required');
  }

  coverTrafficActive = true;
  const generation = ++coverTrafficGeneration;

  const scheduleNext = () => {
    if (!coverTrafficActive || generation !== coverTrafficGeneration) return;
    const variance = COVER_TRAFFIC_VARIANCE_MS > 0
      ? crypto.randomInt(0, COVER_TRAFFIC_VARIANCE_MS * 2 + 1) - COVER_TRAFFIC_VARIANCE_MS
      : 0;
    const waitMs = Math.max(1000, COVER_TRAFFIC_INTERVAL_MS + variance);

    coverTrafficTimer = setTimeout(async () => {
      coverTrafficTimer = null;
      if (!coverTrafficActive || generation !== coverTrafficGeneration) return;
      const iteration = (async () => {
        try {
          const count = crypto.randomInt(COVER_TRAFFIC_WRITES_MIN, COVER_TRAFFIC_WRITES_MAX + 1);
          for (let i = 0; i < count; i += 1) {
            if (!coverTrafficActive || generation !== coverTrafficGeneration) return;
            await new Promise((resolve) => setTimeout(resolve, randomDelay(10, 50)));
            if (!coverTrafficActive || generation !== coverTrafficGeneration) return;
            try {
              await sendDummyFn();
            } catch {
            }
          }
        } catch {
          console.warn('[TIMING] Cover traffic iteration failed');
        }
      })();
      coverTrafficIterationPromise = iteration;
      try {
        await iteration;
      } finally {
        if (coverTrafficIterationPromise === iteration) {
          coverTrafficIterationPromise = null;
        }
      }
      scheduleNext();
    }, waitMs);
  };

  scheduleNext();
  console.log('[TIMING] Cover traffic started');
}

export async function stopCoverTraffic() {
  const iteration = coverTrafficIterationPromise;
  if (!coverTrafficActive && !coverTrafficTimer && !iteration) return;
  coverTrafficActive = false;
  coverTrafficGeneration += 1;
  if (coverTrafficTimer) {
    clearTimeout(coverTrafficTimer);
    coverTrafficTimer = null;
  }
  await iteration?.catch(() => { });
  console.log('[TIMING] Cover traffic stopped');
}

export const TimingProtection = {
  startCoverTraffic,
  stopCoverTraffic
};
