/**
 * Spool Tag Index Fetch
 */

import { applySpoolIndexUpdate, spoolIndexDigest, SPOOL_INDEX_MAX_ENTRIES, validateSpoolIndex, validateSpoolIndexUpdate } from '../../../shared/spool-index-updates.js';
import { anonymousHttpFetch } from '../transport/pq-anonymous-http';
import { SPOOL_DETECTION_PROBE_HEX_CHARS, SPOOL_TAG_HEX_CHARS } from '../../../shared/spool-tag-protocol.js';
import { SPOOL_TAG_PROTOCOL, SPOOL_PIR_LAYOUT } from '../../../shared/protocol-keys.js';

export interface SpoolTagIndex {
  epoch: number;
  tags: string[];
  probes: string[];
}

export interface SpoolTagIndexCache {
  readonly serverUrl: string;
  readonly checkpoint: number;
  readonly base: SpoolTagIndex | null;
  readonly index: SpoolTagIndex;
}

async function fetchFullIndex(
  operation: 'spool/tag-index' | 'spool/tag-index-base',
  serverUrl: string, signal: AbortSignal,
): Promise<SpoolTagIndex> {
  const raw = await anonymousHttpFetch(operation, {}, serverUrl, { signal }) as Record<string, unknown> | null;
  signal.throwIfAborted();
  return parseIndex(raw);
}

function parseIndex(raw: Record<string, unknown> | null): SpoolTagIndex {
  if (
    !raw ||
    raw.ok !== true ||
    raw.protocol !== SPOOL_TAG_PROTOCOL ||
    raw.pirLayout !== SPOOL_PIR_LAYOUT ||
    typeof raw.tags !== 'string' ||
    typeof raw.probes !== 'string' ||
    !Number.isSafeInteger(raw.count) ||
    !Number.isSafeInteger(raw.epoch) ||
    (raw.epoch as number) < 0
  ) throw new Error('Invalid spool tag index response');

  const packed = raw.tags as string;
  const count = raw.count as number;
  const packedProbes = raw.probes as string;
  if (
    count < 0 || count > SPOOL_INDEX_MAX_ENTRIES ||
    packed.length !== count * SPOOL_TAG_HEX_CHARS ||
    packedProbes.length !== count * SPOOL_DETECTION_PROBE_HEX_CHARS
  ) throw new Error('Invalid spool tag index response');

  const tags: string[] = new Array(count);
  const probes: string[] = new Array(count);
  for (let i = 0; i < count; i += 1) {
    tags[i] = packed.slice(i * SPOOL_TAG_HEX_CHARS, (i + 1) * SPOOL_TAG_HEX_CHARS);
    probes[i] = packedProbes.slice(
      i * SPOOL_DETECTION_PROBE_HEX_CHARS,
      (i + 1) * SPOOL_DETECTION_PROBE_HEX_CHARS
    );
  }
  const index = validateSpoolIndex({ epoch: raw.epoch as number, tags, probes });
  Object.freeze(index.tags);
  Object.freeze(index.probes);
  return Object.freeze(index);
}

export async function fetchSpoolTagIndex(
  serverUrl: string,
  signal: AbortSignal,
  previous: SpoolTagIndexCache | null,
): Promise<SpoolTagIndexCache> {
  const update = validateSpoolIndexUpdate(await anonymousHttpFetch('spool/tag-index-update', {}, serverUrl, { signal }));
  signal.throwIfAborted();
  // The full path is chosen by the server's shared update capacity, never by detected messages.
  if (update.mode === 'full') {
    const index = await fetchFullIndex('spool/tag-index', serverUrl, signal);
    const base = previous?.serverUrl === serverUrl && previous.checkpoint === update.checkpoint ? previous.base : null;
    return { serverUrl, checkpoint: update.checkpoint, base, index };
  }
  const cachedBase = previous?.serverUrl === serverUrl && previous.checkpoint === update.checkpoint && previous.base;
  let base = cachedBase
    ? previous.base
    : await fetchFullIndex('spool/tag-index-base', serverUrl, signal);
  if (cachedBase && spoolIndexDigest(base) !== update.baseDigest) {
    base = await fetchFullIndex('spool/tag-index-base', serverUrl, signal);
  }
  // A checkpoint can roll over during the two requests. Reject that pair and retry on the next pass.
  if (spoolIndexDigest(base) !== update.baseDigest) throw new Error('Spool checkpoint changed during download');
  const index = applySpoolIndexUpdate(base, update) as SpoolTagIndex;
  signal.throwIfAborted();
  return { serverUrl, checkpoint: update.checkpoint, base, index };
}
