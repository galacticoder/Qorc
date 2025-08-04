import { argon2id } from "@noble/hashes/argon2";
import { CryptoUtils } from "./unified-crypto";

export class SecureDB {
  private dbName: string;
  private username: string;
  private encryptionKey: CryptoKey | null = null;

  constructor(username: string) {
    this.username = username;
    this.dbName = `securechat_${username}_db`;
  }

  async initialize(password: string): Promise<void> {
    this.encryptionKey = await this.deriveKey(password);
  }

  private async deriveKey(password: string): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    const salt = encoder.encode(`SecureChatSalt-${this.username}`);
    
    const derivedKey = argon2id(passwordBuffer, salt, {
      t: 3,
      m: 65536,
      p: 1,
      dkLen: 32
    });
    
    return crypto.subtle.importKey(
      "raw",
      derivedKey,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  }

  private async encryptData(data: any): Promise<Uint8Array> {
    if (!this.encryptionKey) throw new Error("Encryption key not initialized");
    
    const iv = crypto.getRandomValues(new Uint8Array(CryptoUtils.Config.IV_LENGTH));
    const encoder = new TextEncoder();
    const dataString = JSON.stringify(data);
    const dataBuffer = encoder.encode(dataString);
    
    const encrypted = await crypto.subtle.encrypt(
      { 
        name: "AES-GCM", 
        iv,
        tagLength: CryptoUtils.Config.AUTH_TAG_LENGTH * 8
      },
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
      { 
        name: "AES-GCM", 
        iv,
        tagLength: CryptoUtils.Config.AUTH_TAG_LENGTH * 8
      },
      this.encryptionKey,
      data
    );
    
    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decrypted));
  }

  async saveMessages(messages: any[]): Promise<void> {
    const encrypted = await this.encryptData(messages);
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, 1);
      
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const db = request.result;
        const tx = db.transaction("data", "readwrite");
        const store = tx.objectStore("data");
        store.put(encrypted, "messages");
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      };
      
      request.onupgradeneeded = (event) => {
        const db = request.result;
        if (!db.objectStoreNames.contains("data")) {
          db.createObjectStore("data");
        }
      };
    });
  }

  async loadMessages(): Promise<any[]> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, 1);
      
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const db = request.result;
        const tx = db.transaction("data", "readonly");
        const store = tx.objectStore("data");
        const getRequest = store.get("messages");
        
        getRequest.onerror = () => reject(getRequest.error);
        getRequest.onsuccess = () => {
          if (!getRequest.result) {
            resolve([]);
            return;
          }
          
          this.decryptData(getRequest.result)
            .then(resolve)
            .catch(reject);
        };
      };
      
      request.onupgradeneeded = (event) => {
        const db = request.result;
        if (!db.objectStoreNames.contains("data")) {
          db.createObjectStore("data");
        }
      };
    });
  }

  async saveUsers(users: any[]): Promise<void> {
    const encrypted = await this.encryptData(users);
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, 1);
      
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const db = request.result;
        const tx = db.transaction("data", "readwrite");
        const store = tx.objectStore("data");
        store.put(encrypted, "users");
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      };
    });
  }

  async loadUsers(): Promise<any[]> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, 1);
      
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const db = request.result;
        const tx = db.transaction("data", "readonly");
        const store = tx.objectStore("data");
        const getRequest = store.get("users");
        
        getRequest.onerror = () => reject(getRequest.error);
        getRequest.onsuccess = () => {
          if (!getRequest.result) {
            resolve([]);
            return;
          }
          
          this.decryptData(getRequest.result)
            .then(resolve)
            .catch(reject);
        };
      };
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