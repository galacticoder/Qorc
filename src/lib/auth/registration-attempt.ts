import { storage } from '../tauri-bindings';
import { PostQuantumUtils } from '../utils/pq-utils';
import { computePrivateAuthStorageId } from '../utils/auth-utils';
import {
  assertCurrentServerContext,
  captureCurrentServerContext,
} from '../security/local-account-scope';
import { canonicalAuthUsername } from '../sanitizers';
import { STORAGE_PREFIXES } from '../database/storage-keys';
import { Base64 } from '../cryptography/base64';
import { PostQuantumRandom } from '../cryptography/random';

const attemptLocks = new Map<string, Promise<void>>();

async function withAttemptLock<T>(key: string, operation: () => Promise<T>): Promise<T> {
  const previous = attemptLocks.get(key) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  const tail = previous.then(() => current, () => current);
  attemptLocks.set(key, tail);

  await previous.catch(() => undefined);
  try {
    return await operation();
  } finally {
    release();
    if (attemptLocks.get(key) === tail) attemptLocks.delete(key);
  }
}

function validateUsername(username: string): string {
  return canonicalAuthUsername(username, 'registration owner');
}

function validateAttemptId(value: unknown): string {
  if (typeof value !== 'string' || value.length !== 44) {
    throw new Error('Stored registration attempt is invalid');
  }
  const decoded = PostQuantumUtils.base64ToUint8Array(value);
  try {
    if (
      decoded.length !== 32 ||
      Base64.arrayBufferToBase64(decoded) !== value
    ) {
      throw new Error('Stored registration attempt is invalid');
    }
    return value;
  } finally {
    decoded.fill(0);
  }
}

function storageKey(username: string, serverScope: string): string {
  return `${STORAGE_PREFIXES.REGISTRATION_ATTEMPT}${computePrivateAuthStorageId(username, serverScope)}`;
}

export async function getOrCreateRegistrationAttempt(username: string): Promise<string> {
  const owner = validateUsername(username);
  const context = await captureCurrentServerContext();
  const key = storageKey(owner, context.serverScope);
  return withAttemptLock(key, async () => {
    await assertCurrentServerContext(context);
    const existing = await storage.get(key);
    await assertCurrentServerContext(context);
    if (existing !== null) return validateAttemptId(existing);

    const random = PostQuantumRandom.randomBytes(32);
    let attemptId: string | null = null;
    try {
      attemptId = Base64.arrayBufferToBase64(random);
      if (!await storage.set(key, attemptId)) {
        throw new Error('Registration retry state could not be persisted');
      }
      if (await storage.get(key) !== attemptId) {
        throw new Error('Registration retry state could not be verified');
      }
      await assertCurrentServerContext(context);
      return attemptId;
    } catch (error) {
      if (attemptId !== null && await storage.get(key).catch(() => null) === attemptId) {
        await storage.remove(key).catch(() => false);
      }
      throw error;
    } finally {
      random.fill(0);
    }
  });
}

export async function clearRegistrationAttempt(username: string): Promise<void> {
  const owner = validateUsername(username);
  const context = await captureCurrentServerContext();
  const key = storageKey(owner, context.serverScope);
  await withAttemptLock(key, async () => {
    await assertCurrentServerContext(context);
    if (!await storage.remove(key)) {
      throw new Error('Registration retry state could not be removed');
    }
    if (await storage.has(key)) {
      throw new Error('Registration retry state deletion could not be verified');
    }
    await assertCurrentServerContext(context);
  });
}
