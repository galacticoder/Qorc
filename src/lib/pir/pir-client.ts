/**
 * Discovery PIR client
 */

import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import { pir } from '../tauri-bindings';

export type PirDatabaseKind = 'discovery';
export const DISCOVERY_PIR_DATABASE_KIND: PirDatabaseKind = 'discovery';

export interface PirManifest {
  version: string;
  kind: PirDatabaseKind;
  epochId: string;
  recordSize: number;
  recordCount: number;
  createdAt: number;
  expiresAt: number;
  slotDerivation?: 'qor-pir-slot-v1';
  slotFingerprintDerivation?: 'qor-pir-slot-fingerprint-v1';
  slotProbeCount?: number;
  slotEpoch?: number;
  bucketCount?: number;
  bucketTargetSize?: number;
  workerConfigured?: boolean;
  workerReady?: boolean;
  workerScheme?: string;
  workerParameterId?: string;
  parameterId?: string;
  workerPublicParams?: string;
  workerDbRows?: number;
  workerDbCols?: number;
  queryPrivacy?: 'computational-pir-worker' | 'computational-pir-required-unavailable';
}

type ManifestResponse = { success: boolean; manifest?: PirManifest; error?: string } | null;

const SLOT_DERIVATION = 'qor-pir-slot-v1';
const SLOT_FINGERPRINT_DERIVATION = 'qor-pir-slot-fingerprint-v1';
const DISCOVERY_PIR_SLOT_KEY_DOMAIN = 'qor-discovery-pir-slot-key-v1';
const FINGERPRINT_BYTES = 2;
const HANDLE_BYTES = 6;
const HANDLE_RECORD_BYTES = FINGERPRINT_BYTES + HANDLE_BYTES;

const manifestCache = new Map<string, { manifest: PirManifest; expiresAt: number }>();
const PIR_MANIFEST_CACHE_MAX_AGE_MS = 30_000;
let pirInteractiveUntil = 0;

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

// parts joined as utf8(part) + 0x00 each
function encodeHashParts(parts: Array<string | number>): Uint8Array {
  const encoded = parts.map((p) => utf8(String(p)));
  const length = encoded.reduce((sum, p) => sum + p.length + 1, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const p of encoded) {
    out.set(p, offset);
    offset += p.length;
    out[offset] = 0;
    offset += 1;
  }
  return out;
}

async function sha256Bytes(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let raw = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    raw += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  const raw = atob(normalized + padding);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out;
}

export async function sha256Base64Url(bytes: Uint8Array): Promise<string> {
  return bytesToBase64Url(await sha256Bytes(bytes));
}

function digestToMod(digest: Uint8Array, modulus: number): number {
  if (!Number.isSafeInteger(modulus) || modulus <= 0) {
    throw new Error('invalid_pir_slot_modulus');
  }
  let value = 0n;
  for (const byte of digest.slice(0, 16)) {
    value = (value << 8n) | BigInt(byte);
  }
  return Number(value % BigInt(modulus));
}

export async function deriveDiscoveryPirSlotKey(token: string): Promise<string> {
  const normalized = typeof token === 'string' ? token.trim().toLowerCase() : '';
  if (!/^[a-f0-9]{64}$/i.test(normalized)) {
    throw new Error('invalid_discovery_token_for_pir_slot');
  }
  return sha256Base64Url(encodeHashParts([DISCOVERY_PIR_SLOT_KEY_DOMAIN, normalized]));
}

export function manifestEpoch(manifest: PirManifest): number {
  return Number.isSafeInteger(manifest.slotEpoch) ? Number(manifest.slotEpoch) : manifest.createdAt;
}

async function derivePirRecordSlot(manifest: PirManifest, slotKey: string, probe = 0): Promise<number> {
  const digest = await sha256Bytes(encodeHashParts([
    SLOT_DERIVATION, manifest.kind, slotKey, manifestEpoch(manifest), manifest.recordCount, probe
  ]));
  return digestToMod(digest, manifest.recordCount);
}

async function derivePirRecordCandidates(manifest: PirManifest, slotKey: string, probeCount: number): Promise<number[]> {
  const count = Math.max(1, Math.min(Number(probeCount) || manifest.slotProbeCount || 64, manifest.recordCount));
  const seen = new Set<number>();
  const candidates: number[] = [];
  for (let probe = 0; probe < count; probe += 1) {
    const slot = await derivePirRecordSlot(manifest, slotKey, probe);
    if (!seen.has(slot)) {
      seen.add(slot);
      candidates.push(slot);
    }
  }
  return candidates;
}

const DISCOVERY_BUCKET_DERIVATION = 'qor-discovery-bucket-v1';
const DISCOVERY_BUCKET_COVER_COUNT = Math.max(0, Number.parseInt(
  (typeof process !== 'undefined' && process.env?.DISCOVERY_BUCKET_COVER_COUNT) || '0', 10
) || 0);

export async function deriveDiscoveryBucketId(slotKey: string, epochStart: number, bucketCount: number): Promise<number> {
  const count = Math.max(1, Math.trunc(bucketCount) || 1);
  const digest = await sha256Bytes(encodeHashParts([DISCOVERY_BUCKET_DERIVATION, epochStart, slotKey]));
  let n = 0;
  for (let i = 0; i < 6; i += 1) n = n * 256 + digest[i];
  return n % count;
}

async function deriveSlotFingerprint(manifest: PirManifest, slotKey: string): Promise<string> {
  const digest = await sha256Bytes(encodeHashParts([
    SLOT_FINGERPRINT_DERIVATION, manifest.kind, slotKey, manifestEpoch(manifest)
  ]));
  return bytesToBase64Url(digest.slice(0, FINGERPRINT_BYTES));
}

function randomRequestId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function signalTypeForPirEvent(eventName: string): SignalType | null {
  if (eventName === EventType.PIR_MANIFEST) return SignalType.PIR_MANIFEST;
  if (eventName === EventType.PIR_RESPONSE) return SignalType.PIR_RESPONSE;
  return null;
}

function waitForEvent<T>(eventName: string, requestId: string, timeoutMs: number): Promise<T | null> {
  if (typeof window === 'undefined') return Promise.resolve(null);
  return new Promise((resolve) => {
    const expectedSignalType = signalTypeForPirEvent(eventName);
    const timeout = setTimeout(() => { cleanup(); resolve(null); }, timeoutMs);
    const handler = (event: Event) => {
      const detail = (event as CustomEvent).detail;
      if (event.type !== eventName && (!expectedSignalType || detail?.type !== expectedSignalType)) return;
      if (detail?.requestId !== requestId) return;
      cleanup();
      resolve(detail as T);
    };
    const cleanup = () => {
      clearTimeout(timeout);
      window.removeEventListener(eventName, handler as EventListener);
      if (expectedSignalType) {
        window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
        window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
      }
    };
    window.addEventListener(eventName, handler as EventListener);
    if (expectedSignalType) {
      window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
      window.addEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
    }
  });
}

export function markPirInteractiveActivity(durationMs = 45_000): void {
  pirInteractiveUntil = Math.max(pirInteractiveUntil, Date.now() + Math.max(0, durationMs));
}

let activePirQueryCount = 0;
let pirQueryQuietUntil = 0;
const HTTP_PIR_COOLDOWN_MS = 60_000;
let httpPirUnavailableUntil = 0;
export function isPirInteractive(): boolean {
  return activePirQueryCount > 0 || Date.now() < pirQueryQuietUntil;
}

export function isComputationalPirAvailable(manifest: PirManifest | null | undefined): boolean {
  return !!manifest?.workerConfigured &&
    manifest.workerReady === true &&
    manifest.queryPrivacy === 'computational-pir-worker' &&
    typeof manifest.workerPublicParams === 'string' &&
    manifest.workerPublicParams.length > 0;
}

export async function requestPirManifest(
  options: { prepareWorker?: boolean; timeoutMs?: number; background?: boolean; kind?: PirDatabaseKind; forceFresh?: boolean } = {}
): Promise<ManifestResponse> {
  const kind = options.kind || DISCOVERY_PIR_DATABASE_KIND;
  if (!options.forceFresh) {
    const cached = manifestCache.get(kind);
    if (cached && cached.expiresAt > Date.now() + 1000) {
      if (!options.prepareWorker || isComputationalPirAvailable(cached.manifest)) {
        return { success: true, manifest: cached.manifest };
      }
    }
  }

  // Prefer the dedicated isolated Tor circuit
  if (Date.now() >= httpPirUnavailableUntil) {
    try {
      const http = await pir.discoveryApiFetch('pir/manifest', JSON.stringify({
        kind,
        prepareWorker: options.prepareWorker === true
      }));
      if (http?.ok === true && http.manifest) {
        const manifest = http.manifest as PirManifest;
        manifestCache.set(kind, {
          manifest,
          expiresAt: Math.min(
            Number.isFinite(manifest.expiresAt) ? manifest.expiresAt : Date.now() + PIR_MANIFEST_CACHE_MAX_AGE_MS,
            Date.now() + PIR_MANIFEST_CACHE_MAX_AGE_MS
          )
        });
        return { success: true, manifest };
      }
      httpPirUnavailableUntil = Date.now() + HTTP_PIR_COOLDOWN_MS;
    } catch {
      httpPirUnavailableUntil = Date.now() + HTTP_PIR_COOLDOWN_MS;
    }
  }

  const requestId = randomRequestId();
  const responsePromise = waitForEvent<any>(
    EventType.PIR_MANIFEST,
    requestId,
    options.timeoutMs || (options.prepareWorker ? 60_000 : 15_000)
  );
  const { default: websocketClient } = await import('../websocket/websocket');
  await websocketClient.sendSecureControlMessage({
    type: SignalType.PIR_MANIFEST_REQUEST,
    requestId,
    prepareWorker: options.prepareWorker === true,
    kind
  });
  const response = await responsePromise;
  if (!response?.success || !response.manifest) {
    return response;
  }

  const manifest = response.manifest as PirManifest;
  manifestCache.set(kind, {
    manifest,
    expiresAt: Math.min(
      Number.isFinite(manifest.expiresAt) ? manifest.expiresAt : Date.now() + PIR_MANIFEST_CACHE_MAX_AGE_MS,
      Date.now() + PIR_MANIFEST_CACHE_MAX_AGE_MS
    )
  });
  return { success: true, manifest };
}

function clearManifestCache(kind: PirDatabaseKind): void {
  manifestCache.delete(kind);
}

async function sendPirQuery(
  manifest: PirManifest,
  query: string,
  options: { timeoutMs?: number; dedicatedOnly?: boolean } = {}
): Promise<{ success: boolean; response?: string; error?: string } | null> {
  activePirQueryCount += 1;
  try {
    if (Date.now() >= httpPirUnavailableUntil) {
      try {
        const http = await pir.queryFetch(manifest.epochId, query);
        if (http?.ok === true && typeof http.response === 'string' && http.response.length > 0) {
          // eslint-disable-next-line no-console
          console.log('[OPRF-DISCOVERY][pir-transport]', { via: 'dedicated', ok: true });
          return { success: true, response: http.response };
        }
        // eslint-disable-next-line no-console
        console.warn('[OPRF-DISCOVERY][pir-transport]', { via: 'dedicated', ok: false, httpOk: http?.ok, err: (http as any)?.error });
        httpPirUnavailableUntil = Date.now() + HTTP_PIR_COOLDOWN_MS;
      } catch (e) {
        // eslint-disable-next-line no-console
        console.warn('[OPRF-DISCOVERY][pir-transport]', { via: 'ws-fallback', err: e instanceof Error ? e.message : String(e) });
        httpPirUnavailableUntil = Date.now() + HTTP_PIR_COOLDOWN_MS;
      }
    } else {
      // eslint-disable-next-line no-console
      console.log('[OPRF-DISCOVERY][pir-transport]', { via: 'ws-cooldown' });
    }

    if (options.dedicatedOnly) {
      return { success: false, error: 'pir_dedicated_unavailable' };
    }

    const requestId = randomRequestId();
    const { default: websocketClient } = await import('../websocket/websocket');
    if (!websocketClient.isConnectedToServer?.() || !websocketClient.isPQSessionEstablished?.()) {
      return { success: false, error: 'pir_transport_not_ready' };
    }
    const responsePromise = waitForEvent<any>(EventType.PIR_RESPONSE, requestId, options.timeoutMs || 120_000);
    try {
      await websocketClient.sendSecureControlMessage({
        type: SignalType.PIR_QUERY,
        requestId,
        epochId: manifest.epochId,
        kind: manifest.kind,
        query
      }, { failIfQueued: true });
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'pir_query_send_failed' };
    }
    const response = await responsePromise;
    if (!response) return { success: false, error: 'pir_query_timeout' };
    if (response.success !== true || typeof response.response !== 'string') {
      return { success: false, error: typeof response.error === 'string' ? response.error : 'pir_query_failed' };
    }
    return { success: true, response: response.response };
  } finally {
    activePirQueryCount = Math.max(0, activePirQueryCount - 1);
    pirQueryQuietUntil = Date.now() + 4_000;
  }
}

function manifestParameterId(manifest: PirManifest): string {
  return manifest.workerParameterId || manifest.parameterId || '';
}

// Retrieve the tiny 24-byte pointer record at one slot. Returns { fingerprint, handle }
async function recoverDiscoveryRecordAt(
  manifest: PirManifest,
  index: number,
  timeoutMs?: number,
  dedicatedOnly = false
): Promise<{ fingerprint: string; handle: string } | null> {
  const q = await pir.queryRecord({
    parameterId: manifestParameterId(manifest),
    recordCount: manifest.recordCount,
    recordSize: manifest.recordSize,
    publicParams: manifest.workerPublicParams as string,
    index
  });
  if (!q?.success || !q.request || !q.handle) return null;

  const answer = await sendPirQuery(manifest, q.request, { timeoutMs, dedicatedOnly });
  if (!answer?.success || !answer.response) return null;

  const recovered = await pir.recoverRecord(q.handle, answer.response);
  if (!recovered?.success || typeof recovered.record !== 'string') return null;

  const bytes = base64UrlToBytes(recovered.record);
  if (bytes.length < HANDLE_RECORD_BYTES) return null;
  return {
    fingerprint: bytesToBase64Url(bytes.slice(0, FINGERPRINT_BYTES)),
    handle: bytesToBase64Url(bytes.slice(FINGERPRINT_BYTES, HANDLE_RECORD_BYTES))
  };
}

function isTransientPirError(error: unknown): boolean {
  const message = (error instanceof Error ? error.message : String(error || '')).toLowerCase();
  return message.includes('pir_epoch_expired')
    || message.includes('pir_epoch_mismatch')
    || message.includes('pir_epoch_not_loaded');
}

export async function fetchPirEncryptedBlobsForTokens(
  tokens: string[],
  options: { timeoutMs?: number; maxCandidatesPerToken?: number; concurrency?: number } = {}
): Promise<string[]> {
  try {
    return await fetchPirEncryptedBlobsForTokensOnce(tokens, options);
  } catch (error) {
    if (!isTransientPirError(error)) throw error;
    clearManifestCache(DISCOVERY_PIR_DATABASE_KIND);
    await new Promise((resolve) => setTimeout(resolve, 250));
    return fetchPirEncryptedBlobsForTokensOnce(tokens, options);
  }
}

async function fetchPirEncryptedBlobsForTokensOnce(
  tokens: string[],
  options: { timeoutMs?: number; maxCandidatesPerToken?: number } = {}
): Promise<string[]> {
  const manifestResponse = await requestPirManifest({
    prepareWorker: false,
    timeoutMs: options.timeoutMs || 120_000,
    kind: DISCOVERY_PIR_DATABASE_KIND,
    forceFresh: true
  });
  const manifest = manifestResponse?.success ? manifestResponse.manifest : null;
  const bucketCount = manifest?.bucketCount;
  if (!manifest || !Number.isInteger(bucketCount) || (bucketCount as number) < 1) {
    throw new Error(manifestResponse?.error || 'discovery_manifest_not_ready');
  }
  const epochStart = manifestEpoch(manifest);

  // k-anonymous BUCKET retrieval
  const bucketIds = new Set<number>();
  for (const token of tokens) {
    const slotKey = await deriveDiscoveryPirSlotKey(token);
    bucketIds.add(await deriveDiscoveryBucketId(slotKey, epochStart, bucketCount as number));
  }
  for (let i = 0; i < DISCOVERY_BUCKET_COVER_COUNT; i += 1) {
    bucketIds.add(Math.floor(Math.random() * (bucketCount as number)));
  }
  const ids = Array.from(bucketIds);

  let resp: any;
  try {
    resp = await pir.discoveryApiFetch('discovery/bucket', JSON.stringify({ epochId: manifest.epochId, bucketIds: ids }));
  } catch (error) {
    throw new Error(`discovery_bucket_fetch_failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  const bucketsObj = resp && typeof resp.buckets === 'object' && resp.buckets ? resp.buckets : {};

  const blobs: string[] = [];
  const seen = new Set<string>();
  for (const id of ids) {
    const arr = bucketsObj[id] ?? bucketsObj[String(id)];
    if (!Array.isArray(arr)) continue;
    for (const b of arr) {
      if (typeof b === 'string' && b.length > 0 && !seen.has(b)) {
        seen.add(b);
        blobs.push(b);
      }
    }
  }
  return blobs;
}

export async function runPirCoverQueries(
  options: { records?: number; timeoutMs?: number; background?: boolean; kind?: PirDatabaseKind } = {}
): Promise<{ success: boolean; queriedRecords: number; error?: string }> {
  try {
    const manifestResponse = await requestPirManifest({
      prepareWorker: true,
      timeoutMs: options.timeoutMs || 120_000,
      background: options.background === true,
      kind: options.kind || DISCOVERY_PIR_DATABASE_KIND,
      forceFresh: true
    });
    const manifest = manifestResponse?.success ? manifestResponse.manifest : null;
    if (!manifest || !isComputationalPirAvailable(manifest)) {
      return { success: false, queriedRecords: 0, error: manifestResponse?.error || 'computational_pir_not_ready' };
    }
    const records = Math.max(1, Math.min(options.records || 1, 4));
    let queried = 0;
    for (let i = 0; i < records; i += 1) {
      const random = new Uint32Array(1);
      crypto.getRandomValues(random);
      const index = manifest.recordCount > 0 ? random[0] % manifest.recordCount : 0;
      const record = await recoverDiscoveryRecordAt(manifest, index, options.timeoutMs, true);
      if (record) queried += 1;
    }
    return { success: queried === records, queriedRecords: queried };
  } catch (error) {
    return { success: false, queriedRecords: 0, error: error instanceof Error ? error.message : String(error) };
  }
}
