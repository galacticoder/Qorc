/**
 * Spool Tag Index Fetch
 */

import { anonymousHttpFetch } from '../transport/pq-anonymous-http';
import { SPOOL_DETECTION_PROBE_HEX_CHARS, SPOOL_TAG_HEX_CHARS } from '../../../shared/spool-tag-protocol.js';
import { SPOOL_TAG_INDEX_AUDIENCE } from '../config/audiences';
import { SPOOL_TAG_PROTOCOL, SPOOL_PIR_LAYOUT } from '../../../shared/protocol-keys.js';

export interface SpoolTagIndex {
  epoch: number;
  tags: string[];
  probes: string[];
}

export async function fetchSpoolTagIndex(serverUrl: string): Promise<SpoolTagIndex> {
  const raw = await anonymousHttpFetch(SPOOL_TAG_INDEX_AUDIENCE, {}, serverUrl) as Record<string, unknown> | null;
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
    count < 0 ||
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
  return { epoch: raw.epoch as number, tags, probes };
}
