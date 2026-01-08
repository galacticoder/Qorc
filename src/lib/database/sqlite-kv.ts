/**
 * SQLite KV wrapper
 */

import initSqlJs, { Database, SqlJsStatic } from 'sql.js';
import wasmUrl from 'sql.js/dist/sql-wasm.wasm?url';

export class SQLiteKV {
  private static SQL: SqlJsStatic | null = null;
  private static instances: Map<string, SQLiteKV> = new Map();

  private db: Database | null = null;
  private readonly username: string;
  private readonly filename: string;

  private constructor(username: string) {
    this.username = SQLiteKV.sanitizeIdentifier(username);
    this.filename = `qorchat_${this.username}_db.sqlite`;
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
    await inst.ensureReady();
    return inst;
  }

  // Purge a user database
  static async purgeUserDb(username: string): Promise<void> {
    const key = SQLiteKV.sanitizeIdentifier(username);
    const inst = SQLiteKV.instances.get(key);
    if (inst) {
      await inst.destroy();
      SQLiteKV.instances.delete(key);
    }
    try {
      const root = await (navigator as any).storage.getDirectory();
      const dir = await root.getDirectoryHandle('sqlite-kv', { create: true });
      await dir.removeEntry(`qorchat_${key}_db.sqlite`, { recursive: false }).catch(() => {});
    } catch {}
  }

  // Ensure the database is ready
  private async ensureReady(): Promise<void> {
    if (!SQLiteKV.SQL) {
      SQLiteKV.SQL = await initSqlJs({ locateFile: () => wasmUrl });
    }
    if (this.db) return;
    this.db = await this.openFromOPFS();
    this.ensureSchema();
  }

  // Ensure the database schema exists
  private ensureSchema(): void {
    if (!this.db) return;
    this.db.run(`PRAGMA journal_mode = WAL;`);
    this.db.run(`PRAGMA synchronous = FULL;`);
    this.db.run(`PRAGMA foreign_keys = ON;`);
    this.db.run(`PRAGMA temp_store = MEMORY;`);
    this.db.run(`PRAGMA secure_delete = ON;`);
    this.db.run(`CREATE TABLE IF NOT EXISTS kv_data (
      store TEXT NOT NULL,
      key TEXT NOT NULL,
      value BLOB NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      PRIMARY KEY(store, key)
    );`);
    this.db.run(`CREATE TABLE IF NOT EXISTS secure_keys (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );`);
  }

  // Open the database from OPFS
  private async openFromOPFS(): Promise<Database> {
    const SQL = SQLiteKV.SQL!;
    const root = await (navigator as any).storage.getDirectory();
    const dir = await root.getDirectoryHandle('sqlite-kv', { create: true });
    let fileHandle: FileSystemFileHandle | null = null;
    try {
      fileHandle = await dir.getFileHandle(this.filename, { create: false });
    } catch {
      fileHandle = await dir.getFileHandle(this.filename, { create: true });
    }
    try {
      const file = await fileHandle.getFile();
      const ab = await file.arrayBuffer();
      const bytes = new Uint8Array(ab);
      if (bytes && bytes.length > 0) {
        return new SQL.Database(bytes);
      }
      return new SQL.Database();
    } catch {
      return new SQL.Database();
    }
  }

  // Persist database to OPFS
  private async persist(): Promise<void> {
    if (!this.db) return;
    const data = this.db.export();
    try {
      const root = await (navigator as any).storage.getDirectory();
      const dir = await root.getDirectoryHandle('sqlite-kv', { create: true });
      const fileHandle = await dir.getFileHandle(this.filename, { create: true });
      const writable = await (fileHandle as any).createWritable();
      await writable.write(data);
      await writable.close();
    } catch {}
  }

  // Destroy database and clean up resources
  async destroy(): Promise<void> {
    try { await this.persist(); } catch {}
    try { this.db?.close(); } catch {}
    this.db = null;
  }

  // KV operations --

  // Set a binary value
  async setBinary(store: string, key: string, value: Uint8Array): Promise<void> {
    if (!this.db) await this.ensureReady();
    const now = Date.now();
    const stmt = this.db!.prepare(`INSERT INTO kv_data(store,key,value,created_at,updated_at)
      VALUES(?,?,?,?,?) ON CONFLICT(store,key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`);
    try {
      stmt.run([store, key, value, now, now]);
    } finally { try { stmt.free(); } catch {} }
    await this.persist();
  }

  // Get a binary value
  async getBinary(store: string, key: string): Promise<Uint8Array | null> {
    if (!this.db) await this.ensureReady();
    const stmt = this.db!.prepare(`SELECT value FROM kv_data WHERE store=? AND key=?`);
    try {
      stmt.bind([store, key]);
      if (stmt.step()) {
        const row = stmt.getAsObject();
        const v = (row as any).value as Uint8Array | null;
        return v || null;
      }
      return null;
    } finally { try { stmt.free(); } catch {} }
  }

  // Delete a key
  async delete(store: string, key: string): Promise<void> {
    if (!this.db) await this.ensureReady();
    const stmt = this.db!.prepare(`DELETE FROM kv_data WHERE store=? AND key=?`);
    try { stmt.run([store, key]); } finally { try { stmt.free(); } catch {} }
    await this.persist();
  }

  // Delete multiple keys
  async deleteMany(store: string, keys: string[]): Promise<number> {
    if (!this.db) await this.ensureReady();
    if (keys.length === 0) return 0;
    this.db!.run('BEGIN;');
    try {
      const stmt = this.db!.prepare(`DELETE FROM kv_data WHERE store=? AND key=?`);
      try {
        for (const k of keys) stmt.run([store, k]);
      } finally { try { stmt.free(); } catch {} }
      this.db!.run('COMMIT;');
    } catch {
      try { this.db!.run('ROLLBACK;'); } catch {}
    }
    await this.persist();
    return keys.length;
  }

  // Scan by store prefix
  async scanByStorePrefix(prefix: string): Promise<Array<{ store: string; key: string; value: Uint8Array }>> {
    if (!this.db) await this.ensureReady();
    const results: Array<{ store: string; key: string; value: Uint8Array }> = [];
    const stmt = this.db!.prepare(`SELECT store, key, value FROM kv_data WHERE store LIKE ?`);
    try {
      stmt.bind([`${prefix}%`]);
      while (stmt.step()) {
        const row = stmt.getAsObject();
        results.push({ store: (row as any).store as string, key: (row as any).key as string, value: (row as any).value as Uint8Array });
      }
    } finally { try { stmt.free(); } catch {} }
    return results;
  }

  // Get all entries for a store
  async entriesForStore(store: string): Promise<Array<{ key: string; value: Uint8Array }>> {
    if (!this.db) await this.ensureReady();
    const results: Array<{ key: string; value: Uint8Array }> = [];
    const stmt = this.db!.prepare(`SELECT key, value FROM kv_data WHERE store=?`);
    try {
      stmt.bind([store]);
      while (stmt.step()) {
        const row = stmt.getAsObject();
        results.push({ key: (row as any).key as string, value: (row as any).value as Uint8Array });
      }
    } finally { try { stmt.free(); } catch {} }
    return results;
  }

  // Clear all entries for a store
  async clearStore(store: string): Promise<number> {
    if (!this.db) await this.ensureReady();
    const stmt = this.db!.prepare(`DELETE FROM kv_data WHERE store=?`);
    try { stmt.run([store]); } finally { try { stmt.free(); } catch {} }
    await this.persist();
    return this.db!.getRowsModified?.() ?? 0;
  }

  // Clear all entries except the ones in keepStores
  async clearAllExcept(keepStores: Set<string>): Promise<number> {
    if (!this.db) await this.ensureReady();
    const stmt = this.db!.prepare(`DELETE FROM kv_data WHERE store NOT IN (${Array.from(keepStores).map(() => '?').join(',') || "''"})`);
    try { stmt.run(Array.from(keepStores)); } finally { try { stmt.free(); } catch {} }
    await this.persist();
    return this.db!.getRowsModified?.() ?? 0;
  }

  // secure_keys helpers
  async setJsonKey(key: string, value: any): Promise<void> {
    if (!this.db) await this.ensureReady();
    const json = JSON.stringify(value);
    const stmt = this.db!.prepare(`INSERT INTO secure_keys(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`);
    try { stmt.run([key, json]); } finally { try { stmt.free(); } catch {} }
    await this.persist();
  }

  // Get a JSON value
  async getJsonKey<T = any>(key: string): Promise<T | null> {
    if (!this.db) await this.ensureReady();
    const stmt = this.db!.prepare(`SELECT value FROM secure_keys WHERE key=?`);
    try {
      stmt.bind([key]);
      if (stmt.step()) {
        const row = stmt.getAsObject();
        const v = (row as any).value as string;
        try { return JSON.parse(v) as T; } catch { return null; }
      }
      return null;
    } finally { try { stmt.free(); } catch {} }
  }

  // Delete a JSON key
  async deleteJsonKey(key: string): Promise<void> {
    if (!this.db) await this.ensureReady();
    const stmt = this.db!.prepare(`DELETE FROM secure_keys WHERE key=?`);
    try { stmt.run([key]); } finally { try { stmt.free(); } catch {} }
    await this.persist();
  }

  // Clear all secure keys
  async clearSecureKeys(): Promise<void> {
    if (!this.db) await this.ensureReady();
    this.db!.run('DELETE FROM secure_keys;');
    await this.persist();
  }

  // Clear all data
  async clearAll(): Promise<void> {
    if (!this.db) await this.ensureReady();
    this.db!.run('DELETE FROM kv_data;');
    this.db!.run('DELETE FROM secure_keys;');
    await this.persist();
  }
}
