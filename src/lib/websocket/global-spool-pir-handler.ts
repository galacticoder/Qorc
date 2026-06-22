/**
 * Global Spool Snapshot Handler
 *
 * Offline message catch up
 */

import { SignalType } from '../types/signal-types';
import type { IncomingGlobalSpoolCandidateCallback } from '../types/websocket-types';
import { storage, spool } from '../tauri-bindings';
import {
  GLOBAL_SPOOL_PIR_RESPONSE_TIMEOUT_MS,
  GLOBAL_SPOOL_PIR_LOOP_INTERVAL_MS,
  GLOBAL_SPOOL_PIR_CATCHUP_DELAY_MS,
  GLOBAL_SPOOL_PIR_NOT_READY_RETRY_MS
} from '../constants';

const GLOBAL_SPOOL_EPOCH_STORAGE_KEY = 'opaque-spool-epoch-v1';
const SPOOL_SNAPSHOT_WIRE_VERSION = 'qor-spool-snapshot-gzip-v1';
const SPOOL_SNAPSHOT_VERSION = 'qor-spool-snapshot-v1';

function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  const raw = atob(normalized + padding);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out;
}

async function sha256Base64Url(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  let raw = '';
  for (let offset = 0; offset < digest.length; offset += 0x8000) {
    raw += String.fromCharCode(...digest.subarray(offset, offset + 0x8000));
  }
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function gunzip(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function decodeSpoolSnapshot(snapshot: any): Promise<{ epochId: string; entries: any[] } | null> {
  if (
    !snapshot ||
    snapshot.version !== SPOOL_SNAPSHOT_WIRE_VERSION ||
    snapshot.encoding !== 'base64url+gzip' ||
    typeof snapshot.compressed !== 'string'
  ) {
    return null;
  }
  const plaintext = await gunzip(base64UrlToBytes(snapshot.compressed));
  if (typeof snapshot.digest === 'string' && (await sha256Base64Url(plaintext)) !== snapshot.digest) {
    return null;
  }
  let body: any;
  try {
    body = JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    return null;
  }
  if (body?.version !== SPOOL_SNAPSHOT_VERSION || !Array.isArray(body.entries) || typeof body.epochId !== 'string') {
    return null;
  }
  return { epochId: body.epochId, entries: body.entries };
}

class GlobalSpoolSnapshotHandler {
  private incomingCallback: IncomingGlobalSpoolCandidateCallback | null = null;
  private polling = false;
  private pollTimer: ReturnType<typeof setTimeout> | null = null;
  private lastEpochId: string | null = null;
  private epochLoaded = false;
  private enabled = false;

  setIncomingCandidateCallback(callback: IncomingGlobalSpoolCandidateCallback): void {
    this.incomingCallback = callback;
  }

  startDeliveryLoop(): void {
    this.enabled = true;
    if (this.pollTimer || this.polling) return;
    console.log('[SPOOL] delivery loop armed (offline catch-up)', { firstPollMs: GLOBAL_SPOOL_PIR_CATCHUP_DELAY_MS });
    this.pollTimer = setTimeout(() => {
      this.pollTimer = null;
      void this.poll(true);
    }, GLOBAL_SPOOL_PIR_CATCHUP_DELAY_MS);
  }

  stopDeliveryLoop(): void {
    this.enabled = false;
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }
  }

  requestGlobalSpoolPirPoll(force = false): void {
    void this.poll(force);
  }

  private async loadLastEpoch(): Promise<void> {
    if (this.epochLoaded) return;
    this.epochLoaded = true;
    try {
      await storage.init();
      const raw = await storage.get(GLOBAL_SPOOL_EPOCH_STORAGE_KEY);
      const parsed = raw ? JSON.parse(raw) : null;
      if (parsed && typeof parsed.epochId === 'string') {
        this.lastEpochId = parsed.epochId;
      }
    } catch {
    }
  }

  private async saveLastEpoch(epochId: string): Promise<void> {
    try {
      await storage.init();
      await storage.set(GLOBAL_SPOOL_EPOCH_STORAGE_KEY, JSON.stringify({ epochId }));
    } catch {
    }
  }

  private async poll(force = false): Promise<void> {
    if (!this.enabled) return;
    if (this.polling) return;

    // Yield Tor circuit to user blocking discovery lookup
    if (!force) {
      try {
        const { isPirInteractive } = await import('../pir/pir-client');
        if (isPirInteractive()) {
          if (this.pollTimer) clearTimeout(this.pollTimer);
          this.pollTimer = setTimeout(() => { this.pollTimer = null; void this.poll(false); }, 8_000);
          return;
        }
      } catch { }
    }

    this.polling = true;
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }

    let nextPollDelayMs = Math.max(1_000, GLOBAL_SPOOL_PIR_LOOP_INTERVAL_MS);
    let nextPollForce = false;

    try {
      const { default: websocketClient } = await import('./websocket');
      const connected = !!websocketClient?.isConnectedToServer?.();
      const pq = !!websocketClient?.isPQSessionEstablished?.();
      if (!connected || !pq) {
        console.log('[SPOOL] poll deferred: session not ready', { connected, pq, force });
        nextPollDelayMs = GLOBAL_SPOOL_PIR_NOT_READY_RETRY_MS;
        nextPollForce = force;
        return;
      }

      await this.loadLastEpoch();

      console.log('[SPOOL] fetching snapshot', { force, lastEpochId: this.lastEpochId });
      const raw = (await Promise.race([
        spool.fetchSnapshot(),
        new Promise((resolve) => setTimeout(() => resolve(null), GLOBAL_SPOOL_PIR_RESPONSE_TIMEOUT_MS))
      ])) as any;

      const decoded = await decodeSpoolSnapshot(raw?.snapshot);
      if (!decoded) {
        console.warn('[SPOOL] snapshot fetch/decode failed', { gotRaw: !!raw, gotSnapshot: !!raw?.snapshot });
        return;
      }

      if (!force && decoded.epochId === this.lastEpochId) {
        console.log('[SPOOL] epoch already processed; skipping', { epochId: decoded.epochId });
        return;
      }
      console.log('[SPOOL] processing snapshot', { epochId: decoded.epochId, entries: decoded.entries.length, force });

      let dispatched = 0;
      for (const envelope of decoded.entries) {
        if (!this.incomingCallback || !envelope || typeof envelope !== 'object') continue;
        try {
          await this.incomingCallback({ type: SignalType.SEALED_ENVELOPE, envelope });
          dispatched += 1;
        } catch {
        }
      }
      console.log('[SPOOL] snapshot processed', { epochId: decoded.epochId, dispatched, hadCallback: !!this.incomingCallback });

      this.lastEpochId = decoded.epochId;
      await this.saveLastEpoch(decoded.epochId);
    } catch {
    } finally {
      this.polling = false;
      this.scheduleNextPoll(nextPollDelayMs, nextPollForce);
    }
  }

  private scheduleNextPoll(delayMs = Math.max(1_000, GLOBAL_SPOOL_PIR_LOOP_INTERVAL_MS), force = false): void {
    if (!this.enabled) return;
    if (this.pollTimer) return;
    this.pollTimer = setTimeout(() => {
      this.pollTimer = null;
      void this.poll(force);
    }, Math.max(1_000, delayMs));
  }
}

export const globalSpoolPirHandler = new GlobalSpoolSnapshotHandler();
export const globalSpoolPirQueue = {
  setIncomingCandidateCallback: (cb: IncomingGlobalSpoolCandidateCallback) =>
    globalSpoolPirHandler.setIncomingCandidateCallback(cb),
  startDeliveryLoop: () => globalSpoolPirHandler.startDeliveryLoop(),
  stopDeliveryLoop: () => globalSpoolPirHandler.stopDeliveryLoop(),
  requestGlobalSpoolPirPoll: (force?: boolean) => globalSpoolPirHandler.requestGlobalSpoolPirPoll(force)
};

export function startDeliveryLoop(): void {
  globalSpoolPirHandler.startDeliveryLoop();
}

export function requestGlobalSpoolPirPoll(force = true): void {
  globalSpoolPirHandler.requestGlobalSpoolPirPoll(force);
}
