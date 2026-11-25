/**
 * Tagged-lane retrieval loop.
 */

import { MAX_TESTED_PROBES } from '../constants';
import { SignalType } from '../types/signal-types';
import { SPOOL_TAG_INDEX_POLL_INTERVAL_MS } from '../../../shared/spool-tag-protocol.js';
import { captureCurrentServerContext, deriveLocalAccountScope } from '../security/local-account-scope';
import { fetchSpoolTagIndex, type SpoolTagIndex, type SpoolTagIndexCache } from './tag-index-client';
import { fetchSpoolEntries, sealedEnvelopeFromRecord } from './pir-fetch';
import { createDetectionTagMatcher } from './detection-key';
import { loadConsumedSpoolProbeCacheForScope } from './consumed-probe-cache';

const testedProbes = new Set<string>();
let activeProbeScope: string | null = null;

export type TaggedLaneCandidateCallback = (
  message: { type: SignalType; envelope: unknown }
) => Promise<boolean | void> | boolean | void;

interface TaggedLaneRetrieverOptions {
  accountScope: string;
  serverUrl: string;
  deliver: TaggedLaneCandidateCallback;
  signal: AbortSignal;
  fetchIndex(): Promise<SpoolTagIndex>;
}

async function retrieveTaggedLaneOnce(
  options: TaggedLaneRetrieverOptions
): Promise<void> {
  const { accountScope, serverUrl, deliver, signal } = options;
  const consumedProbeCache = await loadConsumedSpoolProbeCacheForScope(accountScope);
  signal.throwIfAborted();
  if (activeProbeScope !== consumedProbeCache.scope) {
    testedProbes.clear();
    activeProbeScope = consumedProbeCache.scope;
  }
  for (const probe of consumedProbeCache.probes) testedProbes.add(probe);

  const index = await options.fetchIndex();
  signal.throwIfAborted();
  if (index.tags.length === 0) return;

  const matchProbe = await createDetectionTagMatcher(accountScope, signal);
  signal.throwIfAborted();
  const matchedPositions: number[] = [];
  for (let position = 0; position < index.tags.length; position += 1) {
    const probe = index.probes[position];
    if (!probe || testedProbes.has(probe)) continue;
    const expected = matchProbe(probe);
    if (!expected) continue;
    if (expected === index.tags[position]) {
      matchedPositions.push(position);
    } else {
      testedProbes.add(probe);
    }
  }
  while (testedProbes.size > MAX_TESTED_PROBES) {
    const probe = testedProbes.values().next().value;
    if (probe === undefined) break;
    testedProbes.delete(probe);
  }

  if (matchedPositions.length === 0) return;

  const records = await fetchSpoolEntries(
    serverUrl,
    index.epoch,
    index.tags.length,
    matchedPositions,
    signal,
  );
  signal.throwIfAborted();

  const consumedProbes: string[] = [];
  for (const [position, record] of records) {
    const envelope = sealedEnvelopeFromRecord(
      record,
      index.tags[position],
      index.probes[position]
    );
    if (!envelope) continue;
    try {
      const accepted = await deliver({
        type: SignalType.SEALED_ENVELOPE,
        envelope
      });
      signal.throwIfAborted();
      if (accepted !== false) {
        testedProbes.add(index.probes[position]);
        consumedProbes.push(index.probes[position]);
      }
    } catch {
      signal.throwIfAborted();
    }
  }
  if (consumedProbes.length > 0) {
    await consumedProbeCache.remember(consumedProbes, signal);
  }
}

// Polling driver
class TaggedLaneRetriever {
  private timer: ReturnType<typeof setTimeout> | null = null;
  private controller: AbortController | null = null;
  private inFlight: Promise<void> | null = null;
  private owner: string | null = null;
  private deliver: TaggedLaneCandidateCallback | null = null;
  private indexCache: SpoolTagIndexCache | null = null;

  configure(owner: string, deliver: TaggedLaneCandidateCallback): void {
    if (this.owner !== null && this.owner !== owner) this.stop();
    this.owner = owner;
    this.deliver = deliver;
  }

  start(intervalMs = SPOOL_TAG_INDEX_POLL_INTERVAL_MS): void {
    if (this.controller || !this.owner || !this.deliver) return;
    const owner = this.owner;
    const controller = new AbortController();
    this.controller = controller;

    const tick = (): void => {
      if (controller.signal.aborted) return;
      this.timer = null;
      const pass = (async () => {
        const previous = this.inFlight;
        if (previous) await previous;
        controller.signal.throwIfAborted();
        const context = await captureCurrentServerContext();
        controller.signal.throwIfAborted();
        const deliver = this.deliver;
        if (!deliver) return;
        await retrieveTaggedLaneOnce({
          accountScope: deriveLocalAccountScope(context, owner),
          serverUrl: context.serverUrl,
          deliver,
          signal: controller.signal,
          fetchIndex: async () => {
            const result = await fetchSpoolTagIndex(context.serverUrl, controller.signal, this.indexCache);
            controller.signal.throwIfAborted();
            this.indexCache = result;
            return result.index;
          },
        });
      })().catch(() => { });

      this.inFlight = pass;
      void pass.then(() => {
        if (this.inFlight === pass) this.inFlight = null;
        if (this.controller === controller) this.timer = setTimeout(tick, intervalMs);
      });
    };

    this.timer = setTimeout(tick, 0);
  }

  stop(): void {
    this.controller?.abort();
    this.controller = null;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    this.indexCache = null;
    testedProbes.clear();
    activeProbeScope = null;
  }
}

export const taggedLaneRetriever = new TaggedLaneRetriever();
