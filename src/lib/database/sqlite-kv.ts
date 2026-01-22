/**
 * SQLite KV wrapper
 */

import { database } from '../tauri-bindings';

export class SQLiteKV {
  private static instances: Map<string, SQLiteKV> = new Map();
  private readonly username: string;

  private constructor(username: string) {
    this.username = SQLiteKV.sanitizeIdentifier(username);
  }

  static sanitizeIdentifier(value: string): string {
    return (value || 'unknown').replace(/[^a-zA-Z0-9_-]/g, '_');
  }

  // Get or create a SQLiteKV instance for a user
  static async forUser(username: string): Promise<SQLiteKV> {
    const key = SQLiteKV.sanitizeIdentifier(username);
    let inst = SQLiteKV.instances.get(key);
    if (!inst) {
      inst = new SQLiteKV(username);
      SQLiteKV.instances.set(key, inst);
    }
    return inst;
  }

  // Purge a user database
  static async purgeUserDb(username: string): Promise<void> {
    const key = SQLiteKV.sanitizeIdentifier(username);
    const inst = SQLiteKV.instances.get(key);
    if (inst) {
      SQLiteKV.instances.delete(key);
    }
    
    try { await database.clearStore(`kv_data_${key}`); } catch { }
  }

  // KV operations --

  // Set a binary value
  async setBinary(store: string, key: string, value: Uint8Array): Promise<void> {
    const fullStore = `${this.username}_${store}`;
    await database.setSecure(fullStore, key, value);
  }

  // Get a binary value
  async getBinary(store: string, key: string): Promise<Uint8Array | null> {
    const fullStore = `${this.username}_${store}`;
    return await database.getSecure(fullStore, key);
  }

  // Delete a key
  async delete(store: string, key: string): Promise<void> {
    const fullStore = `${this.username}_${store}`;
    await database.delete(fullStore, key);
  }

  async deleteMany(store: string, keys: string[]): Promise<number> {
    const fullStore = `${this.username}_${store}`;
    let count = 0;
    for (const key of keys) {
      await database.delete(fullStore, key);
      count++;
    }
    return count;
  }

  // Scan by store prefix
  async scanByStorePrefix(prefix: string): Promise<Array<{ store: string; key: string; value: Uint8Array }>> {
    const results = await database.scanSecure(`${this.username}_${prefix}`);
    return results.map(([fullStore, key, value]) => {
      const store = fullStore.startsWith(`${this.username}_`)
        ? fullStore.substring(this.username.length + 1)
        : fullStore;
      return { store, key, value };
    });
  }

  // Get all entries for a store
  async entriesForStore(store: string): Promise<Array<{ key: string; value: Uint8Array }>> {
    const fullStore = `${this.username}_${store}`;
    const results = await database.listSecure(fullStore);
    return results.map(([key, value]) => ({ key, value }));
  }

  // Clear all entries for a store
  async clearStore(store: string): Promise<number> {
    const fullStore = `${this.username}_${store}`;
    await database.clearStore(fullStore);
    return 1;
  }

  async setJsonKey(key: string, value: any): Promise<void> {
    const json = JSON.stringify(value);
    const encoder = new TextEncoder();
    await this.setBinary('secure_json', key, encoder.encode(json));
  }

  // Get a JSON value
  async getJsonKey<T = any>(key: string): Promise<T | null> {
    const bytes = await this.getBinary('secure_json', key);
    if (!bytes) return null;
    const decoder = new TextDecoder();
    try {
      return JSON.parse(decoder.decode(bytes)) as T;
    } catch {
      return null;
    }
  }

  async deleteJsonKey(key: string): Promise<void> {
    await this.delete('secure_json', key);
  }

  async clearSecureKeys(): Promise<void> {
    await this.clearStore('secure_json');
  }

  async clearAll(): Promise<void> {
    await this.clearStore('kv_data');
    await this.clearStore('secure_json');
  }
}
