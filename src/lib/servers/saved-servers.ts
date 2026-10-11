import { storage } from '../tauri-bindings';
import { STORAGE_KEYS } from '../database/storage-keys';
import { normalizeToWss } from './server-address';
import { validateServerProfile } from '../../../shared/server-profile.js';

export interface ServerProfile {
  readonly name: string;
  readonly icon: string | null;
}

export interface SavedServer extends ServerProfile {
  readonly url: string;
}

interface SavedServersState {
  readonly servers: readonly SavedServer[];
  readonly loaded: boolean;
  readonly error: string;
}

export const SAVED_SERVER_LIMIT = 32;
let state: SavedServersState = { servers: [], loaded: false, error: '' };
let loadPromise: Promise<void> | null = null;
let mutationTail: Promise<unknown> = Promise.resolve();
const listeners = new Set<() => void>();

function publish(next: SavedServersState): void {
  state = next;
  listeners.forEach((listener) => listener());
}

function parseServers(raw: string | null): readonly SavedServer[] {
  if (raw === null) return [];
  if (raw.length > 1_500_000) throw new Error('Saved server list is oversized');
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed) || parsed.length > SAVED_SERVER_LIMIT) throw new Error('Invalid saved server list');
  const addresses = new Set<string>();
  return Object.freeze(parsed.map((entry: unknown) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
      Object.keys(entry).sort().join(',') !== 'icon,name,url') throw new Error('Invalid saved server entry');
    const server = entry as SavedServer;
    if (typeof server.url !== 'string' || !server.url || normalizeToWss(server.url) !== server.url ||
      addresses.has(server.url) || !validateServerProfile({ name: server.name, icon: server.icon })) {
      throw new Error('Invalid saved server entry');
    }
    addresses.add(server.url);
    return Object.freeze({ name: server.name, url: server.url, icon: server.icon });
  }));
}

async function mutate(operation: (servers: readonly SavedServer[]) => readonly SavedServer[]): Promise<void> {
  await savedServers.load();
  const next = mutationTail.then(async () => {
    const servers = parseServers(JSON.stringify(operation(state.servers)));
    const serialized = JSON.stringify(servers);
    if (!await storage.set(STORAGE_KEYS.SAVED_SERVERS, serialized) ||
      await storage.get(STORAGE_KEYS.SAVED_SERVERS) !== serialized) {
      throw new Error('Saved servers could not be stored');
    }
    publish({ servers, loaded: true, error: '' });
  });
  mutationTail = next.catch(() => undefined);
  await next;
}

export const savedServers = {
  subscribe(listener: () => void): () => void {
    listeners.add(listener);
    return () => { listeners.delete(listener); };
  },
  getSnapshot(): SavedServersState { return state; },
  async load(): Promise<void> {
    if (state.loaded) return;
    if (loadPromise) return loadPromise;
    loadPromise = (async () => {
      try {
        const servers = parseServers(await storage.get(STORAGE_KEYS.SAVED_SERVERS));
        publish({ servers, loaded: true, error: '' });
      } catch (error) {
        publish({ ...state, error: error instanceof Error ? error.message : 'Saved servers could not be loaded' });
        throw error;
      } finally {
        loadPromise = null;
      }
    })();
    await loadPromise;
  },
  async save(entry: SavedServer, previousUrl?: string): Promise<void> {
    const url = normalizeToWss(entry.url);
    if (!url) throw new Error('Enter a valid server address');
    const server = { name: entry.name.trim(), url, icon: entry.icon };
    if (!validateServerProfile({ name: server.name, icon: server.icon })) throw new Error('Enter a server name of 1–80 characters');
    await mutate((servers) => {
      if (servers.some((saved) => saved.url === url && saved.url !== previousUrl)) throw new Error('This server is already saved');
      if (previousUrl && !servers.some((saved) => saved.url === previousUrl)) throw new Error('This saved server no longer exists');
      if (previousUrl) return servers.map((saved) => saved.url === previousUrl ? server : saved);
      if (servers.length >= SAVED_SERVER_LIMIT) throw new Error(`You can save up to ${SAVED_SERVER_LIMIT} servers`);
      return [...servers, server];
    });
  },
  async remove(url: string): Promise<void> {
    await mutate((servers) => servers.filter((server) => server.url !== url));
  },
  async updateIcon(url: string, icon: string | null): Promise<void> {
    await savedServers.load();
    if (!state.servers.some((server) => server.url === url && server.icon !== icon)) return;
    await mutate((servers) => servers.map((server) => server.url === url ? { ...server, icon } : server));
  },
};
