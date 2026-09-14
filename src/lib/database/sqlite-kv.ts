/**
 * SQLite KV wrapper
 */

import { database } from '../tauri-bindings';
import { blake3 } from '@noble/hashes/blake3.js';
import { STORAGE_KEY_DOMAINS } from './storage-keys';
import { bytesToHex } from '../../../shared/bytes.js';

export class SQLiteKV {
  private static readonly MAX_MUTATION_DELETIONS = 2_048;
  private readonly namespace: string;
  private readonly assertCurrent: () => void;

  private constructor(accountScope: string, assertCurrent: () => void) {
    this.namespace = SQLiteKV.accountNamespace(accountScope);
    this.assertCurrent = assertCurrent;
  }

  static accountNamespace(value: string): string {
    if (
      typeof value !== 'string' ||
      value !== value.trim().toLowerCase() ||
      !value ||
      value.length > 120 ||
      /[^a-z0-9._-]/.test(value)
    ) {
      throw new Error('Invalid database owner');
    }
    const input = new TextEncoder().encode(`${STORAGE_KEY_DOMAINS.DATABASE_OWNER}\0${value}`);
    const digest = blake3(input, { dkLen: 32 });
    try {
      return bytesToHex(digest);
    } finally {
      input.fill(0);
      digest.fill(0);
    }
  }

  static async forUser(accountScope: string, assertCurrent: () => void): Promise<SQLiteKV> {
    assertCurrent();
    const view = new SQLiteKV(accountScope, assertCurrent);
    assertCurrent();
    return view;
  }

  // Set a binary value
  async setBinary(store: string, key: string, value: Uint8Array): Promise<void> {
    this.assertCurrent();
    const fullStore = `${this.namespace}_${store}`;
    await database.setSecure(fullStore, key, value);
    this.assertCurrent();
  }

  // Get a binary value
  async getBinary(store: string, key: string): Promise<Uint8Array | null> {
    this.assertCurrent();
    const fullStore = `${this.namespace}_${store}`;
    const value = await database.getSecure(fullStore, key);
    this.assertCurrent();
    return value;
  }

  async has(store: string, key: string): Promise<boolean> {
    this.assertCurrent();
    const fullStore = `${this.namespace}_${store}`;
    const result = await database.hasSecure(fullStore, key);
    this.assertCurrent();
    return result;
  }

  // Delete a key
  async delete(store: string, key: string): Promise<void> {
    this.assertCurrent();
    const fullStore = `${this.namespace}_${store}`;
    await database.delete(fullStore, key);
    this.assertCurrent();
  }

  async deleteMany(store: string, keys: string[]): Promise<number> {
    this.assertCurrent();
    const fullStore = `${this.namespace}_${store}`;
    if (keys.length === 0) return 0;
    for (let offset = 0; offset < keys.length; offset += SQLiteKV.MAX_MUTATION_DELETIONS) {
      this.assertCurrent();
      const batch = keys.slice(offset, offset + SQLiteKV.MAX_MUTATION_DELETIONS);
      await database.mutateSecure([], batch.map((key) => ({ store: fullStore, key })));
      this.assertCurrent();
    }
    return keys.length;
  }

  async mutate(
    writes: Array<{ store: string; key: string; value: Uint8Array }>,
    deletions: Array<{ store: string; key: string }>,
  ): Promise<void> {
    this.assertCurrent();
    const committed = await database.mutateSecure(
      writes.map(({ store, key, value }) => ({
        store: `${this.namespace}_${store}`,
        key,
        value,
      })),
      deletions.map(({ store, key }) => ({
        store: `${this.namespace}_${store}`,
        key,
      })),
    );
    this.assertCurrent();
    if (!committed) throw new Error('Database quota exceeded');
  }

  async selectorsByStorePrefix(prefix: string): Promise<Array<{ store: string; key: string }>> {
    this.assertCurrent();
    const selectors = await database.scanSecureKeys(`${this.namespace}_${prefix}`);
    this.assertCurrent();
    const namespacePrefix = `${this.namespace}_`;
    const results: Array<{ store: string; key: string }> = [];
    for (const [fullStore, key] of selectors) {
      if (!fullStore.startsWith(namespacePrefix)) {
        throw new Error('Database selector escaped its account namespace');
      }
      results.push({ store: fullStore.substring(namespacePrefix.length), key });
    }
    return results;
  }

  async keysForStore(store: string): Promise<string[]> {
    this.assertCurrent();
    const fullStore = `${this.namespace}_${store}`;
    const keys = await database.listSecureKeys(fullStore);
    this.assertCurrent();
    return keys;
  }

  // Clear all entries for a store
  async clearStore(store: string): Promise<number> {
    this.assertCurrent();
    const keys = await this.keysForStore(store);
    this.assertCurrent();
    return this.deleteMany(store, keys);
  }
}
