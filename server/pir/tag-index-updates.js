import { SPOOL_INDEX_CHECKPOINT_MS, buildSpoolIndexUpdate } from '../../shared/spool-index-updates.js';

export class SpoolIndexUpdates {
  #base = null;
  #checkpoint = null;
  #update = null;
  #current = null;

  read(current, now = Date.now()) {
    const checkpoint = Math.floor(now / SPOOL_INDEX_CHECKPOINT_MS);
    if (checkpoint !== this.#checkpoint) {
      this.#checkpoint = checkpoint;
      this.#base = current;
      this.#current = null;
    }
    if (!this.#current || this.#current.epoch !== current.epoch ||
        this.#current.tags.length !== current.tags.length ||
        this.#current.tags.some((tag, index) => tag !== current.tags[index] || this.#current.probes[index] !== current.probes[index])) {
      this.#update = buildSpoolIndexUpdate(this.#base, current, checkpoint);
      if (this.#update.mode === 'full') {
        this.#base = current;
        this.#update = buildSpoolIndexUpdate(this.#base, current, checkpoint);
      }
      this.#current = current;
    }
    return { base: this.#base, update: this.#update };
  }
}
