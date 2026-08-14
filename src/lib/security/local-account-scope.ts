import { blake3 } from '@noble/hashes/blake3.js';
import { storage, websocket } from '../tauri-bindings';
import { PinnedServer } from '../utils/auth-utils';
import { canonicalAuthUsername, isCanonicalAuthUsername } from '../sanitizers';
import { bytesToHex } from '../utils/byte-utils';
import { STORAGE_KEY_DOMAINS, STORAGE_PREFIXES } from '../database/storage-keys';

function digestScope(domain: string, parts: string[]): string {
  const encoded = new TextEncoder().encode([domain, ...parts].join('\0'));
  const digest = blake3(encoded, { dkLen: 32 });
  try {
    return bytesToHex(digest);
  } finally {
    encoded.fill(0);
    digest.fill(0);
  }
}

export interface CurrentServerContext {
  readonly serverUrl: string;
  readonly serverScope: string;
}

function canonicalAccountUsername(username: string): string {
  return canonicalAuthUsername(username, 'local account owner');
}

function validateServerUrl(value: unknown): string {
  const serverUrl = typeof value === 'string' ? value.trim() : '';
  if (!serverUrl || serverUrl.length > 2048) {
    throw new Error('Authenticated server identity is unavailable');
  }
  return serverUrl;
}

export async function captureCurrentServerContext(): Promise<CurrentServerContext> {
  const serverUrl = validateServerUrl(await websocket.getServerUrl());
  const serverKeys = await PinnedServer.load();
  if (!serverKeys) throw new Error('Pinned server identity is unavailable');
  if (validateServerUrl(await websocket.getServerUrl()) !== serverUrl) {
    throw new Error('Authenticated server changed during operation');
  }
  const serverScope = digestScope(STORAGE_KEY_DOMAINS.LOCAL_SERVER_SCOPE, [
    serverUrl,
    serverKeys.kyberPublicBase64,
    serverKeys.dilithiumPublicBase64,
    serverKeys.x25519PublicBase64,
  ]);
  return { serverUrl, serverScope };
}

export async function getCurrentServerScope(): Promise<string> {
  return (await captureCurrentServerContext()).serverScope;
}

export async function assertCurrentServerContext(context: CurrentServerContext): Promise<void> {
  const current = await captureCurrentServerContext();
  if (current.serverUrl !== context.serverUrl || current.serverScope !== context.serverScope) {
    throw new Error('Authenticated server changed during operation');
  }
}

export function deriveLocalAccountScope(
  context: CurrentServerContext,
  username: string
): string {
  const normalized = canonicalAccountUsername(username);
  if (!/^[a-f0-9]{64}$/.test(context.serverScope)) {
    throw new Error('Invalid authenticated server scope');
  }
  return digestScope(STORAGE_KEY_DOMAINS.LOCAL_ACCOUNT_SCOPE, [context.serverScope, normalized]);
}

export async function getCurrentLocalAccountScope(username: string): Promise<string> {
  return deriveLocalAccountScope(await captureCurrentServerContext(), username);
}

function lastAccountStorageKeys(serverScope: string): { username: string; displayName: string } {
  return {
    username: `${STORAGE_PREFIXES.LAST_AUTH_USER}${serverScope}`,
    displayName: `${STORAGE_PREFIXES.LAST_AUTH_DISPLAY}${serverScope}`,
  };
}

export async function loadLastAuthenticatedAccount(): Promise<{
  username: string | null;
  displayName: string | null;
}> {
  const context = await captureCurrentServerContext();
  const keys = lastAccountStorageKeys(context.serverScope);
  const [username, displayName] = await Promise.all([
    storage.get(keys.username),
    storage.get(keys.displayName),
  ]);
  await assertCurrentServerContext(context);
  if (username === null && displayName === null) {
    return { username: null, displayName: null };
  }
  if (
    typeof username !== 'string' ||
    !isCanonicalAuthUsername(username) ||
    typeof displayName !== 'string' ||
    displayName.length === 0 ||
    displayName.length > 256 ||
    /[\x00-\x1f\x7f]/.test(displayName)
  ) {
    throw new Error('Local account marker is incomplete or invalid');
  }
  return { username, displayName };
}

export async function storeLastAuthenticatedAccount(
  username: string,
  displayName: string
): Promise<void> {
  if (
    (displayName.length === 0 || displayName.length > 256 || /[\x00-\x1f\x7f]/.test(displayName))
  ) {
    throw new Error('Invalid local account display name');
  }
  canonicalAuthUsername(username, 'local account owner');
  const context = await captureCurrentServerContext();
  const keys = lastAccountStorageKeys(context.serverScope);
  try {
    if (!await storage.set(keys.username, username)) {
      throw new Error('Failed to store local account marker');
    }
    if (!await storage.set(keys.displayName, displayName)) {
      throw new Error('Failed to store local account display marker');
    }
    const [storedUsername, storedDisplayName] = await Promise.all([
      storage.get(keys.username),
      storage.get(keys.displayName),
    ]);
    if (
      storedUsername !== username ||
      storedDisplayName !== displayName
    ) {
      throw new Error('Local account marker could not be verified');
    }
    await assertCurrentServerContext(context);
  } catch (error) {
    await Promise.allSettled([storage.remove(keys.username), storage.remove(keys.displayName)]);
    throw error;
  }
}

export async function clearLastAuthenticatedAccount(): Promise<void> {
  const context = await captureCurrentServerContext();
  const keys = lastAccountStorageKeys(context.serverScope);
  const removed = await Promise.all([
    storage.remove(keys.username),
    storage.remove(keys.displayName),
  ]);
  const remains = await Promise.all([
    storage.has(keys.username),
    storage.has(keys.displayName),
  ]);
  if (removed.some(result => result !== true) || remains.some(Boolean)) {
    throw new Error('Local account marker deletion could not be verified');
  }
  await assertCurrentServerContext(context);
}
