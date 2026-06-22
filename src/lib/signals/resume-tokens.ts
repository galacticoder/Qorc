/**
 * Unlinkable autologin using Privacy Pass resume tokens. long-lived but one time use tokens that can be redeemed
 */

import { storage } from '../tauri-bindings';
import {
  PrivacyPassClient,
  PrivacyPassHelpers,
  TokenSerializer,
  type AnonymousToken
} from '../cryptography/privacy-pass-client';

const RESUME_POOL_STORAGE_KEY = 'qor_resume_pool_v1';
const RESUME_POOL_TARGET = 32;

async function loadPool(): Promise<AnonymousToken[]> {
  try {
    await storage.init();
    const raw = await storage.get(RESUME_POOL_STORAGE_KEY);
    if (!raw || typeof raw !== 'string') return [];
    const tokens = await TokenSerializer.deserializeBatch(raw);
    return tokens.filter((t) => !!t.unblindedToken && !t.used);
  } catch {
    return [];
  }
}

async function savePool(tokens: AnonymousToken[]): Promise<void> {
  try {
    await storage.init();
    const usable = tokens.filter((t) => !!t.unblindedToken && !t.used);
    if (usable.length === 0) {
      await storage.remove(RESUME_POOL_STORAGE_KEY);
      return;
    }
    await storage.set(RESUME_POOL_STORAGE_KEY, await TokenSerializer.serializeBatch(usable));
  } catch {
  }
}

/**
 * Refill the machine bound resume pool from the unlocked vault
 */
export async function replenishResumePool(): Promise<void> {
  try {
    const existing = await loadPool();
    const need = RESUME_POOL_TARGET - existing.length;
    if (need <= 0) {
      console.log('[AUTOLOGIN] resume-pool replenish: already full', { existing: existing.length });
      return;
    }
    const { tokenVault } = await import('../database/token-vault');
    const vaultUnlocked = (tokenVault as any).isUnlocked === true;
    const reserved = await tokenVault.reserveResumeTokens(need);
    console.log('[AUTOLOGIN] resume-pool replenish', {
      existing: existing.length, need, reserved: reserved?.length || 0, vaultUnlocked
    });
    if (!reserved || reserved.length === 0) return;
    await savePool([...existing, ...reserved]);
    const after = await loadPool();
    console.log('[AUTOLOGIN] resume-pool after save', { size: after.length });
  } catch (e) {
    console.log('[AUTOLOGIN] resume-pool replenish FAILED', { error: e instanceof Error ? e.message : String(e) });
  }
}

export async function hasResumeToken(): Promise<boolean> {
  const n = (await loadPool()).length;
  console.log('[AUTOLOGIN] hasResumeToken check', { poolSize: n });
  return n > 0;
}

/**
 * Take one token from the pool and return a formatted redemption payload for it
 */
export async function takeResumeRedemption(): Promise<Record<string, unknown> | null> {
  const tokens = await loadPool();
  if (tokens.length === 0) return null;
  const [token, ...rest] = tokens;
  await savePool(rest);
  try {
    const client = new PrivacyPassClient();
    const redemption = await client.prepareRedemption(token);
    return PrivacyPassHelpers.formatResponse(redemption);
  } catch {
    return null;
  }
}

export async function clearResumePool(): Promise<void> {
  try {
    await storage.init();
    await storage.remove(RESUME_POOL_STORAGE_KEY);
  } catch {
    // ignore
  }
}
