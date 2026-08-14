/**
 * Unlinkable autologin using Privacy Pass resume tokens
 */

import { account } from '../tauri-bindings';
import {
  PrivacyPassClient,
  PrivacyPassHelpers,
  TokenSerializer,
  isPrivacyPassTokenUsable,
  type AnonymousToken
} from '../cryptography/privacy-pass-client';
import { getCurrentLocalAccountScope, getCurrentServerScope } from '../security/local-account-scope';
import { tokenVault } from '../database/token-vault';
import { wipeAnonymousToken as wipeToken, wipeAnonymousTokens as wipeTokens } from '../cryptography/wipe';
import { ACCOUNT_AUTH_PURPOSE } from '../config/audiences';

const RESUME_POOL_TARGET = 32;
let poolMutationTail: Promise<void> = Promise.resolve();
let poolLifecycleToken: object = {};

export function invalidateResumePoolOperations(): void {
  poolLifecycleToken = {};
}

function assertCurrentPoolLifecycle(token: object): void {
  if (token !== poolLifecycleToken) {
    throw new Error('Resume-token operation is no longer current');
  }
}

async function withPoolMutation<T>(token: object, operation: () => Promise<T>): Promise<T> {
  const previous = poolMutationTail;
  let release!: () => void;
  poolMutationTail = new Promise<void>((resolve) => { release = resolve; });
  await previous;
  try {
    assertCurrentPoolLifecycle(token);
    return await operation();
  } finally {
    release();
  }
}

async function resumePoolServerScope(username: string): Promise<string | null> {
  const accountScope = await getCurrentLocalAccountScope(username);
  if (!await account.isUnlocked(accountScope)) return null;
  return getCurrentServerScope();
}

async function loadPool(serverScope: string, lifecycleToken: object): Promise<AnonymousToken[]> {
  assertCurrentPoolLifecycle(lifecycleToken);
  const raw = await account.tokenVaultLoad(serverScope, 'resume');
  assertCurrentPoolLifecycle(lifecycleToken);
  if (raw === null) return [];
  if (typeof raw !== 'string') throw new Error('Invalid resume-token pool');
  const tokens = await TokenSerializer.deserializeBatch(raw);
  try {
    assertCurrentPoolLifecycle(lifecycleToken);
  } catch (error) {
    wipeTokens(tokens);
    throw error;
  }
  if (tokens.length > RESUME_POOL_TARGET) {
    for (const token of tokens) wipeToken(token);
    throw new Error('Resume-token pool exceeds its fixed capacity');
  }
  const usable = tokens.filter((token) =>
    !token.pending && isPrivacyPassTokenUsable(token, ACCOUNT_AUTH_PURPOSE)
  );
  for (const token of tokens) {
    if (!usable.includes(token)) wipeToken(token);
  }
  return usable;
}

async function savePool(tokens: AnonymousToken[], serverScope: string, lifecycleToken: object): Promise<void> {
  assertCurrentPoolLifecycle(lifecycleToken);
  const usable = tokens.filter((token) =>
    !token.pending && isPrivacyPassTokenUsable(token, ACCOUNT_AUTH_PURPOSE)
  );
  if (usable.length > RESUME_POOL_TARGET) {
    throw new Error('Resume-token pool exceeds its fixed capacity');
  }
  if (usable.length === 0) {
    const removed = await account.tokenVaultRemove(serverScope, 'resume');
    assertCurrentPoolLifecycle(lifecycleToken);
    if (!removed) {
      throw new Error('Resume-token pool deletion could not be verified');
    }
    return;
  }
  const serialized = await TokenSerializer.serializeBatch(usable);
  assertCurrentPoolLifecycle(lifecycleToken);
  const stored = await account.tokenVaultStore(serverScope, 'resume', serialized);
  assertCurrentPoolLifecycle(lifecycleToken);
  if (!stored) {
    throw new Error('Resume-token pool could not be persisted');
  }
  const verified = await account.tokenVaultLoad(serverScope, 'resume');
  assertCurrentPoolLifecycle(lifecycleToken);
  if (verified !== serialized) {
    throw new Error('Resume-token pool update could not be verified');
  }
}

/**
 * Refill the machine bound resume pool from the unlocked vault
 */
export async function replenishResumePool(username: string, replaceExisting = false): Promise<void> {
  const lifecycleToken = poolLifecycleToken;
  const serverScope = await resumePoolServerScope(username);
  if (!serverScope) throw new Error('Native account must be unlocked before replenishing resume credentials');
  assertCurrentPoolLifecycle(lifecycleToken);
  return withPoolMutation(lifecycleToken, async () => {
    let existing: AnonymousToken[] = [];
    if (replaceExisting) {
      const removed = await account.tokenVaultRemove(serverScope, 'resume');
      assertCurrentPoolLifecycle(lifecycleToken);
      if (!removed) {
        throw new Error('Resume-token pool replacement could not remove the old pool');
      }
    } else {
      existing = await loadPool(serverScope, lifecycleToken);
    }
    const retained = existing;
    const need = RESUME_POOL_TARGET - retained.length;
    let reserved: AnonymousToken[] = [];
    try {
      if (need <= 0) return;
      assertCurrentPoolLifecycle(lifecycleToken);
      reserved = await tokenVault.reserveResumeTokens(need);
      assertCurrentPoolLifecycle(lifecycleToken);
      if (reserved.length === 0) {
        if (replaceExisting) await savePool([], serverScope, lifecycleToken);
        return;
      }

      await savePool([...retained, ...reserved], serverScope, lifecycleToken);
    } catch (error) {
      throw error;
    } finally {
      wipeTokens(existing);
      wipeTokens(reserved);
    }
  });
}

export async function hasResumeToken(username: string): Promise<boolean> {
  const lifecycleToken = poolLifecycleToken;
  const serverScope = await resumePoolServerScope(username);
  if (!serverScope) return false;
  assertCurrentPoolLifecycle(lifecycleToken);
  return withPoolMutation(lifecycleToken, async () => {
    const tokens = await loadPool(serverScope, lifecycleToken);
    try {
      return tokens.length > 0;
    } finally {
      wipeTokens(tokens);
    }
  });
}

export async function takeResumeRedemption(username: string): Promise<Record<string, unknown> | null> {
  const lifecycleToken = poolLifecycleToken;
  const serverScope = await resumePoolServerScope(username);
  if (!serverScope) return null;
  assertCurrentPoolLifecycle(lifecycleToken);
  return withPoolMutation(lifecycleToken, async () => {
    const tokens = await loadPool(serverScope, lifecycleToken);
    if (tokens.length === 0) return null;
    const [token, ...rest] = tokens;
    let redemption: Awaited<ReturnType<PrivacyPassClient['prepareRedemption']>> | null = null;
    try {
      const client = new PrivacyPassClient();
      redemption = await client.prepareRedemption(token);
      await savePool(rest, serverScope, lifecycleToken);
      return PrivacyPassHelpers.formatResponse(redemption);
    } catch (error) {
      throw new Error(`Resume token could not be reserved: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      redemption?.nullifier.fill(0);
      redemption?.mac.fill(0);
      wipeTokens(tokens);
    }
  });
}

export async function clearResumePool(username: string): Promise<void> {
  const lifecycleToken = poolLifecycleToken;
  const serverScope = await resumePoolServerScope(username);
  if (!serverScope) return;
  assertCurrentPoolLifecycle(lifecycleToken);
  return withPoolMutation(lifecycleToken, async () => {
    const removed = await account.tokenVaultRemove(serverScope, 'resume');
    assertCurrentPoolLifecycle(lifecycleToken);
    if (!removed) {
      throw new Error('Resume-token pool deletion could not be verified');
    }
  });
}
