import { LOCAL_ACCOUNT_SCOPE_SERVER_URL_LENGTH_LIMIT } from '../constants';
import { blake3 } from '@noble/hashes/blake3.js';
import { storage, websocket } from '../tauri-bindings';
import { PinnedServer } from '../utils/auth-utils';
import { canonicalAuthUsername, hasExactObjectKeys, isCanonicalAuthUsername, isValidDisplayName } from '../sanitizers';
import { STORAGE_KEY_DOMAINS, STORAGE_PREFIXES } from '../database/storage-keys';
import { Base64 } from '../cryptography/base64';
import type { ServerKeyMaterial } from '../types/websocket-types';
import { bytesToHex } from '../../../shared/bytes.js';

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
  if (!serverUrl || serverUrl.length > LOCAL_ACCOUNT_SCOPE_SERVER_URL_LENGTH_LIMIT) {
    throw new Error('Authenticated server identity is unavailable');
  }
  return serverUrl;
}

export async function captureCurrentServerContext(expectedMaterial?: ServerKeyMaterial): Promise<CurrentServerContext> {
  const serverUrl = validateServerUrl(await websocket.getServerUrl());
  const serverKeys = await PinnedServer.load();
  if (!serverKeys) throw new Error('Pinned server identity is unavailable');
  if (expectedMaterial && (
    !expectedMaterial.dilithiumPublicKey || !expectedMaterial.x25519PublicKey ||
    serverKeys.kyberPublicBase64 !== Base64.arrayBufferToBase64(expectedMaterial.kyberPublicKey) ||
    serverKeys.dilithiumPublicBase64 !== Base64.arrayBufferToBase64(expectedMaterial.dilithiumPublicKey) ||
    serverKeys.x25519PublicBase64 !== Base64.arrayBufferToBase64(expectedMaterial.x25519PublicKey)
  )) throw new Error('Authenticated anonymous server identity no longer matches its pin');
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

type LastAuthenticatedAccount = { username: string; displayName: string };

let accountMarkerWrites = Promise.resolve();

function updateAccountMarker(operation: () => Promise<void>): Promise<void> {
  const write = accountMarkerWrites.then(operation);
  accountMarkerWrites = write.catch(() => { });
  return write;
}

function accountMarkerKey(serverScope: string): string {
  return `${STORAGE_PREFIXES.LAST_AUTH_ACCOUNT}${serverScope}`;
}

function parseAccountMarker(raw: string): LastAuthenticatedAccount {
  let record: unknown;
  try {
    record = JSON.parse(raw);
  } catch {
    throw new Error('Local account marker is invalid');
  }
  if (!hasExactObjectKeys(record, ['username', 'displayName']) ||
      !isCanonicalAuthUsername(record.username) || !isValidDisplayName(record.displayName)) {
    throw new Error('Local account marker is invalid');
  }
  return { username: record.username, displayName: record.displayName };
}

export async function loadLastAuthenticatedAccount(): Promise<{
  username: string | null;
  displayName: string | null;
}> {
  await accountMarkerWrites;
  const context = await captureCurrentServerContext();
  const raw = await storage.get(accountMarkerKey(context.serverScope));
  await assertCurrentServerContext(context);
  return raw === null ? { username: null, displayName: null } : parseAccountMarker(raw);
}

export function storeLastAuthenticatedAccount(
  username: string,
  displayName: string,
  assertCurrent: () => void,
): Promise<void> {
  return updateAccountMarker(async () => {
    canonicalAuthUsername(username, 'local account owner');
    if (!isValidDisplayName(displayName)) throw new Error('Invalid local account display name');
    assertCurrent();
    const context = await captureCurrentServerContext();
    assertCurrent();
    const key = accountMarkerKey(context.serverScope);
    const record = JSON.stringify({ username, displayName } satisfies LastAuthenticatedAccount);
    if (!await storage.set(key, record) || await storage.get(key) !== record) {
      throw new Error('Local account marker could not be verified');
    }
    await assertCurrentServerContext(context);
    assertCurrent();
  });
}

export function clearLastAuthenticatedAccount(assertCurrent: () => void): Promise<void> {
  return updateAccountMarker(async () => {
    assertCurrent();
    const context = await captureCurrentServerContext();
    assertCurrent();
    const key = accountMarkerKey(context.serverScope);
    if (!await storage.remove(key) || await storage.has(key)) {
      throw new Error('Local account marker deletion could not be verified');
    }
    await assertCurrentServerContext(context);
    assertCurrent();
  });
}
