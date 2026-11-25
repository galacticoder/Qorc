import { KEY_TRANSPARENCY_MAX_PREFIX_CACHE_CONTACTS, MAX_CACHED_TRANSITIONS } from '../constants';
import { computeKeyTransparencyRecordHash, deriveKeyTransparencyEpochLabel } from './crypto';
import { verifyKeyTransparencyTransitions, type KeyTransparencyPublishedTransition } from './verifier';
import type { VerifiedKeyTransparencyContactState } from './types';

interface VerificationContext {
  account: string;
  server: string;
  generation: number;
  signer: string;
  policy: string;
}
interface VerifiedPrefix {
  fingerprints: string[];
  state: Readonly<VerifiedKeyTransparencyContactState> | null;
}

export class VerifiedPrefixCache {
  private context: string | null = null;
  private readonly entries = new Map<string, VerifiedPrefix>();

  clear(): void {
    this.entries.clear();
    this.context = null;
  }

  verify(
    context: VerificationContext,
    published: KeyTransparencyPublishedTransition[],
    discoveryKey: Uint8Array,
  ): VerifiedKeyTransparencyContactState | null {
    const scope = JSON.stringify([context.account, context.server, context.generation, context.signer, context.policy]);
    if (this.context !== scope) {
      this.clear();
      this.context = scope;
    }
    const label = deriveKeyTransparencyEpochLabel(discoveryKey, 0);
    try {
      if (published.length > MAX_CACHED_TRANSITIONS) {
        this.entries.delete(label);
        return verifyKeyTransparencyTransitions(null, published, discoveryKey);
      }
      const fingerprints = published.map(entry => JSON.stringify([
        entry.epoch,
        entry.record,
        computeKeyTransparencyRecordHash(entry.transition.signedUpdate, entry.transition.authorization),
      ]));
      const cached = this.entries.get(label);
      const validPrefix = cached && fingerprints.length >= cached.fingerprints.length &&
        cached.fingerprints.every((fingerprint, i) => fingerprint === fingerprints[i]);
      const state = verifyKeyTransparencyTransitions(
        validPrefix ? cached.state : null,
        validPrefix ? published.slice(cached.fingerprints.length) : published,
        discoveryKey,
      );
      if (!this.entries.has(label) && this.entries.size >= KEY_TRANSPARENCY_MAX_PREFIX_CACHE_CONTACTS) {
        const oldest = this.entries.keys().next().value;
        if (oldest !== undefined) this.entries.delete(oldest);
      }
      this.entries.set(label, { fingerprints, state: state ? Object.freeze({ ...state }) : null });
      return state ? { ...state } : null;
    } catch (error) {
      this.entries.delete(label);
      throw error;
    }
  }
}
