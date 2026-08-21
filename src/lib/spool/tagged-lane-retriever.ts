/**
 * Tagged-lane retrieval loop.
 */

import { SignalType } from '../types/signal-types';
import { SPOOL_TAG_INDEX_POLL_INTERVAL_MS } from '../../../shared/spool-tag-protocol.js';
import { captureCurrentServerContext } from '../security/local-account-scope';
import { fetchSpoolTagIndex } from './tag-index-client';
import { fetchSpoolEntries, sealedEnvelopeFromRecord } from './pir-fetch';
import { detectionTagForProbe, ownDetectionPublicKeyHex } from './detection-key';
import { loadConsumedSpoolProbeCache } from './consumed-probe-cache';

const testedProbes = new Set<string>();
const MAX_TESTED_PROBES = 32_768;
let activeProbeScope: string | null = null;

export type TaggedLaneCandidateCallback = (
  message: { type: SignalType; envelope: unknown }
) => Promise<boolean | void> | boolean | void;

export interface TaggedLaneRetrieverOptions {
  owner: string;
  serverUrl: string;
  deliver: TaggedLaneCandidateCallback;
}

export async function retrieveTaggedLaneOnce(
  options: TaggedLaneRetrieverOptions
): Promise<{ fetched: number; delivered: number } | null> {
  const consumedProbeCache = await loadConsumedSpoolProbeCache(options.owner);
  if (activeProbeScope !== consumedProbeCache.scope) {
    testedProbes.clear();
    activeProbeScope = consumedProbeCache.scope;
  }
  for (const probe of consumedProbeCache.probes) testedProbes.add(probe);

  const index = await fetchSpoolTagIndex(options.serverUrl);
  if (!index || index.tags.length === 0) {
    console.log(
      index ? '[SPOOL-PIR] tag index is empty' : '[SPOOL-PIR] tag index unavailable',
      { entries: index?.tags.length ?? 0 }
    );
    return null;
  }

  const matchedPositions: number[] = [];
  for (let position = 0; position < index.tags.length; position += 1) {
    const probe = index.probes[position];
    if (!probe || testedProbes.has(probe)) continue;
    const expected = await detectionTagForProbe(options.owner, probe);
    if (!expected) continue;
    if (expected === index.tags[position]) {
      matchedPositions.push(position);
    } else {
      testedProbes.add(probe);
    }
  }
  if (testedProbes.size > MAX_TESTED_PROBES) {
    while (testedProbes.size > MAX_TESTED_PROBES) {
      const probe = testedProbes.values().next().value;
      if (typeof probe !== 'string') break;
      testedProbes.delete(probe);
    }
  }

  if (matchedPositions.length === 0) {
    return { fetched: 0, delivered: 0 };
  }

  const positions = Array.from(new Set(matchedPositions));
  const records = await fetchSpoolEntries(
    options.serverUrl,
    index.epoch,
    index.tags.length,
    positions
  );

  let delivered = 0;
  const consumedProbes: string[] = [];
  for (const [position, record] of records) {
    const envelope = sealedEnvelopeFromRecord(
      record,
      index.tags[position],
      index.probes[position]
    );
    if (!envelope) continue;
    try {
      const accepted = await options.deliver({
        type: SignalType.SEALED_ENVELOPE,
        envelope
      });
      if (accepted !== false) {
        testedProbes.add(index.probes[position]);
        consumedProbes.push(index.probes[position]);
        delivered += 1;
      }
    } catch (error) {
      console.warn('[SPOOL-PIR] delivery failed for a retrieved entry', {
        position,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  if (consumedProbes.length > 0) {
    await consumedProbeCache.remember(consumedProbes);
  }

  return { fetched: records.size, delivered };
}

// Polling driver
class TaggedLaneRetriever {
  private timer: ReturnType<typeof setTimeout> | null = null;
  private running = false;
  private generation = 0;
  private owner: string | null = null;
  private deliver: TaggedLaneCandidateCallback | null = null;

  configure(owner: string, deliver: TaggedLaneCandidateCallback) {
    if (this.owner !== null && this.owner !== owner) {
      testedProbes.clear();
      activeProbeScope = null;
    }
    this.owner = owner;
    this.deliver = deliver;
  }

  start(intervalMs: number = SPOOL_TAG_INDEX_POLL_INTERVAL_MS) {
    if (this.timer || this.running) return;
    const generation = ++this.generation;
    const tick = async () => {
      if (generation !== this.generation) return;
      this.running = true;
      try {
        await this.pass();
      } catch (error) {
        console.warn('[SPOOL-PIR] retrieval pass failed', {
          error: error instanceof Error ? error.message : String(error),
        });
      } finally {
        this.running = false;
        if (generation === this.generation) {
          this.timer = setTimeout(tick, intervalMs);
          (this.timer as any)?.unref?.();
        }
      }
    };
    this.timer = setTimeout(tick, 0);
  }

  stop() {
    this.generation += 1;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  private async pass() {
    if (!this.owner || !this.deliver) return;
    const context = await captureCurrentServerContext();
    await retrieveTaggedLaneOnce({
      owner: this.owner,
      serverUrl: context.serverUrl,
      deliver: this.deliver
    });
  }
}

export const taggedLaneRetriever = new TaggedLaneRetriever();
