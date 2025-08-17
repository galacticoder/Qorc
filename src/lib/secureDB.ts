import { CryptoUtils } from "./unified-crypto";

export class SecureDB {
  private dbName: string;
  private username: string;
  private encryptionKey: CryptoKey | null = null;

  constructor(username: string) {
    this.username = username;
    this.dbName = `securechat_${username}_db`;
  }

  async initializeWithKey(key: CryptoKey): Promise<void> {
    this.encryptionKey = key;
    console.log("[SecureDB] SecureDB initialized");
  }

  private async encryptData(data: any): Promise<Uint8Array> { //change this later
    if (!this.encryptionKey) throw new Error("Encryption key not initialized");

    const iv = crypto.getRandomValues(new Uint8Array(CryptoUtils.Config.IV_LENGTH));
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(JSON.stringify(data));

    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: CryptoUtils.Config.AUTH_TAG_LENGTH * 8 },
      this.encryptionKey,
      dataBuffer
    );

    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    return combined;
  }

  private async decryptData(encryptedData: Uint8Array): Promise<any> {
    if (!this.encryptionKey) throw new Error("Encryption key not initialized");

    const iv = encryptedData.slice(0, CryptoUtils.Config.IV_LENGTH);
    const data = encryptedData.slice(CryptoUtils.Config.IV_LENGTH);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, tagLength: CryptoUtils.Config.AUTH_TAG_LENGTH * 8 },
      this.encryptionKey,
      data
    );

    return JSON.parse(new TextDecoder().decode(decrypted));
  }

  private openDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, 1);

      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains("data")) {
          db.createObjectStore("data");
        }
      };

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async saveMessages(messages: any[]): Promise<void> {
    if (!this.encryptionKey) throw new Error("Encryption key not initialized");
    const encrypted = await this.encryptData(messages);

    const db = await this.openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("data", "readwrite");
      const store = tx.objectStore("data");
      store.put(encrypted, "messages");
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async loadMessages(): Promise<any[]> {
    const db = await this.openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("data", "readonly");
      const store = tx.objectStore("data");
      const request = store.get("messages");

      request.onsuccess = async () => {
        if (!request.result) return resolve([]);
        try {
          const data = await this.decryptData(request.result);
          resolve(data);
        } catch (err) {
          reject(err);
        }
      };

      request.onerror = () => reject(request.error);
    });
  }

  async saveUsers(users: any[]): Promise<void> {
    if (!this.encryptionKey) throw new Error("Encryption key not initialized");
    const encrypted = await this.encryptData(users);

    const db = await this.openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("data", "readwrite");
      const store = tx.objectStore("data");
      store.put(encrypted, "users");
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async loadUsers(): Promise<any[]> {
    const db = await this.openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("data", "readonly");
      const store = tx.objectStore("data");
      const request = store.get("users");

      request.onsuccess = async () => {
        if (!request.result) return resolve([]);
        try {
          const data = await this.decryptData(request.result);
          resolve(data);
        } catch (err) {
          reject(err);
        }
      };

      request.onerror = () => reject(request.error);
    });
  }

  async clearDatabase(): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.deleteDatabase(this.dbName);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }
}
