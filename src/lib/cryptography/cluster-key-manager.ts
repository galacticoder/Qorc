/**
 * Cluster Key Manager
 * Handles fetching and caching public keys from all servers in the cluster.
 */

import { PostQuantumHash } from './hash';
import { PostQuantumUtils } from '../utils/pq-utils';
import { STORAGE_KEYS } from '../database/storage-keys';
import { CRYPTO_CACHE_TTL_MS } from '../constants';
import { system } from '../tauri-bindings';

interface ServerPublicKeys {
  kyberPublicBase64: string;
  dilithiumPublicBase64: string;
  x25519PublicBase64: string;
}

interface ServerKeyEntry {
  serverId: string;
  publicKeys: ServerPublicKeys;
  fingerprint: string;
  fetchedAt: number;
}

interface ClusterKeysResponse {
  success: boolean;
  serverKeys: Array<{
    serverId: string;
    publicKeys: ServerPublicKeys;
  }>;
  timestamp: number;
}

export class ClusterKeyManager {
  private static instance: ClusterKeyManager;
  private serverKeys: Map<string, ServerKeyEntry> = new Map();
  private fetchPromise: Promise<void> | null = null;
  private lastFetchTime = 0;

  private constructor() {
    this.loadFromStorage();
  }

  static getInstance(): ClusterKeyManager {
    if (!ClusterKeyManager.instance) {
      ClusterKeyManager.instance = new ClusterKeyManager();
    }
    return ClusterKeyManager.instance;
  }

  // Fetch all server keys from the cluster endpoint
  async fetchServerKeys(serverUrl?: string): Promise<void> {
    if (this.fetchPromise) {
      return this.fetchPromise;
    }

    if (Date.now() - this.lastFetchTime < CRYPTO_CACHE_TTL_MS && this.serverKeys.size > 0) {
      return;
    }

    this.fetchPromise = this._doFetch(serverUrl);
    try {
      await this.fetchPromise;
    } finally {
      this.fetchPromise = null;
    }
  }

  private async _doFetch(serverUrl?: string): Promise<void> {
    try {
      let storedUrl = null;
      try {
        const result = await system.getServerUrl();
        storedUrl = result || null;
      } catch { }

      const url = serverUrl || storedUrl || import.meta.env.VITE_WS_URL;

      if (!url) {
        return;
      }

      const httpUrl = url.replace('ws://', 'http://').replace('wss://', 'https://');
      const endpoint = `${httpUrl}/api/cluster/server-keys`;

      const response = await fetch(endpoint, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'omit',
      });

      if (!response.ok) {
        if (response.status === 404) {
          return;
        }
        throw new Error(`Failed to fetch server keys: ${response.status}`);
      }

      const data: ClusterKeysResponse = await response.json();

      if (!data.success || !Array.isArray(data.serverKeys)) {
        throw new Error('Invalid response format from cluster keys endpoint');
      }

      this.serverKeys.clear();

      for (const server of data.serverKeys) {
        const fingerprint = this.computeFingerprint(server.publicKeys);

        this.serverKeys.set(server.serverId, {
          serverId: server.serverId,
          publicKeys: server.publicKeys,
          fingerprint,
          fetchedAt: Date.now(),
        });
      }

      this.lastFetchTime = Date.now();
      this.saveToStorage();
    } catch (error) {
      console.error('[ClusterKeyManager] Failed to fetch server keys:', error);
    }
  }

  // Get keys for a specific server ID
  getServerKeys(serverId: string): ServerKeyEntry | null {
    return this.serverKeys.get(serverId) || null;
  }

  // Get all server keys
  getAllServerKeys(): ServerKeyEntry[] {
    return Array.from(this.serverKeys.values());
  }

  // Find server keys by fingerprint
  findKeysByFingerprint(fingerprint: string): ServerKeyEntry | null {
    for (const entry of this.serverKeys.values()) {
      if (entry.fingerprint === fingerprint) {
        return entry;
      }
    }
    return null;
  }

  // Try to match server keys against known servers
  matchServerKeys(publicKeys: ServerPublicKeys): string | null {
    const fingerprint = this.computeFingerprint(publicKeys);

    for (const entry of this.serverKeys.values()) {
      if (entry.fingerprint === fingerprint) {
        return entry.serverId;
      }
    }

    return null;
  }

  // Update keys for a specific server
  updateServerKeys(serverId: string, publicKeys: ServerPublicKeys): void {
    const fingerprint = this.computeFingerprint(publicKeys);

    this.serverKeys.set(serverId, {
      serverId,
      publicKeys,
      fingerprint,
      fetchedAt: Date.now(),
    });

    this.saveToStorage();
  }

  // Compute fingerprint from public keys
  private computeFingerprint(publicKeys: ServerPublicKeys): string {
    const encoded = JSON.stringify({
      kyberPublicBase64: publicKeys.kyberPublicBase64,
      dilithiumPublicBase64: publicKeys.dilithiumPublicBase64,
      x25519PublicBase64: publicKeys.x25519PublicBase64,
    });
    const digest = PostQuantumHash.blake3(new TextEncoder().encode(encoded));
    return PostQuantumUtils.bytesToHex(digest);
  }

  // Save keys to encrypted storage
  private saveToStorage(): void {
    try {
      const entries = Array.from(this.serverKeys.values());
      (async () => {
        try {
          const { encryptedStorage } = await import('../database/encrypted-storage');
          await encryptedStorage.setItem(STORAGE_KEYS.CLUSTER_KEY_STORAGE, JSON.stringify({
            keys: entries,
            lastFetch: this.lastFetchTime,
          }));
        } catch { }
      })();
    } catch (error) {
      console.error('[ClusterKeyManager] Failed to save keys:', error);
    }
  }

  // Load keys from encrypted storage
  private loadFromStorage(): void {
    try {
      (async () => {
        try {
          const { encryptedStorage } = await import('../database/encrypted-storage');
          const stored = await encryptedStorage.getItem(STORAGE_KEYS.CLUSTER_KEY_STORAGE);
          const raw = typeof stored === 'string' ? stored : stored ? JSON.stringify(stored) : null;
          if (!raw) return;
          const data = JSON.parse(raw);
          if (!data.keys || !Array.isArray(data.keys)) return;
          if (Date.now() - data.lastFetch < CRYPTO_CACHE_TTL_MS) {
            for (const entry of data.keys) {
              this.serverKeys.set(entry.serverId, entry);
            }
            this.lastFetchTime = data.lastFetch;
          }
        } catch { }
      })();
    } catch (error) {
      console.error('[ClusterKeyManager] Failed to load keys:', error);
    }
  }

  // Clear all cached keys
  clearCache(): void {
    this.serverKeys.clear();
    this.lastFetchTime = 0;
    try {
      (async () => { try { const { encryptedStorage } = await import('../database/encrypted-storage'); await encryptedStorage.setItem(STORAGE_KEYS.CLUSTER_KEY_STORAGE, ''); } catch { } })();
    } catch { }
  }

  // Check if we have any server keys
  hasKeys(): boolean {
    return this.serverKeys.size > 0;
  }
}

export const clusterKeyManager = ClusterKeyManager.getInstance();