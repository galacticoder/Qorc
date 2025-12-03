import * as authUtils from './auth-utils.js';
import crypto from 'node:crypto';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { SignalType, SignalMessages } from '../signals.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { UserDatabase } from '../database/database.js';
import { rateLimitMiddleware } from '../rate-limiting/rate-limit-middleware.js';
import { isOnline as presenceIsOnline, withRedisClient } from '../presence/presence.js';
import { TokenService } from './token-service.js';
import { TokenDatabase } from './token-database.js';
import { TokenMiddleware } from './token-middleware.js';
import { TokenSecurityManager } from './token-security.js';

import { sendSecureMessage } from '../messaging/pq-envelope-handler.js';

async function rejectConnection(ws, type, reason, code = 1008) {
  console.log(`[AUTH] Rejecting connection: ${type} - ${reason}`);
  await sendSecureMessage(ws, { type, message: reason });
  ws.close(code, reason);
  return;
}

async function sendAuthError(ws, { message, code = 'AUTH_FAILED', category = 'general', attemptsRemaining = undefined, locked = false, cooldownSeconds = undefined, logout = false }) {
  const payload = {
    type: SignalType.AUTH_ERROR,
    message,
    code,
    category,
    locked,
  };
  if (attemptsRemaining !== undefined) payload.attemptsRemaining = attemptsRemaining;
  if (cooldownSeconds !== undefined) payload.cooldownSeconds = cooldownSeconds;
  if (logout) payload.logout = true;
  try { await sendSecureMessage(ws, payload); } catch (e) {
    console.error('[AUTH] Failed to send soft auth error:', e?.message || e);
  }
  return { handled: true };
}

function ensureAttemptState(ws) {
  if (!ws.clientState) ws.clientState = {};
  if (!ws.clientState.attempts) {
    // Randomize attempts between 5-10
    const randomAttempts = () => crypto.randomInt(5, 11);
    ws.clientState = SecureStateManager.setState(ws, {
      attempts: {
        username: randomAttempts(),
        account_password: randomAttempts(),
        passphrase: randomAttempts(),
        server_password: randomAttempts()
      }
    });
  }
}

class DistributedLockManager {
  /**
   * Acquire a distributed lock using Redis SET NX with TTL
   * @param {string} key - Lock key
   * @param {number} ttlMs - Lock TTL in milliseconds
   * @returns {Promise<{key: string, token: string} | null>} Lock object or null if failed
   */
  static async acquire(key, ttlMs = 5000) {
    const lockKey = `lock:${key}`;
    const token = crypto.randomBytes(16).toString('hex');
    const ttlSeconds = Math.ceil(ttlMs / 1000);

    try {
      const acquired = await withRedisClient(async (client) => {
        const result = await client.set(lockKey, token, 'NX', 'EX', ttlSeconds);
        return result === 'OK';
      });

      if (acquired) {
        return { key: lockKey, token };
      }
      return null;
    } catch (error) {
      console.error('[LOCK] Failed to acquire distributed lock:', error);
      return null;
    }
  }

  /**
   * Release a distributed lock with token verification
   * @param {string} key - Lock key
   * @param {string} token - Lock token for verification
   */
  static async release(key, token = null) {
    try {
      await withRedisClient(async (client) => {
        if (token) {
          const luaScript = `
            if redis.call("get", KEYS[1]) == ARGV[1] then
              return redis.call("del", KEYS[1])
            else
              return 0
            end
          `;
          await client.eval(luaScript, 1, key, token);
        }
      });
    } catch (error) {
      console.error('[LOCK] Failed to release distributed lock:', error);
    }
  }
}

// Immutable state manager to prevent accidental mutation
export class SecureStateManager {
  static states = new WeakMap();
  static setState(ws, updates) {
    const current = this.states.get(ws) || {};
    const newState = Object.freeze({
      ...current,
      ...updates,
      lastModified: Date.now(),
      stateVersion: (current.stateVersion || 0) + 1
    });
    this.states.set(ws, newState);
    return newState;
  }
  static getState(ws) {
    return this.states.get(ws) || {};
  }
}

// Secure wrapper to clear sensitive strings from memory
class SecureString {
  constructor(value) {
    this.buffer = Buffer.from(String(value || ''), 'utf8');
  }
  toString() {
    return this.buffer?.toString('utf8') || '';
  }
  clear() {
    try { if (this.buffer) crypto.randomFillSync(this.buffer); } catch { }
    this.buffer = null;
  }
}

export class AccountAuthHandler {
  constructor(serverHybridKeyPair) {
    this.serverHybridKeyPair = serverHybridKeyPair;
    console.log('[AUTH] AccountAuthHandler initialized');
  }

  async processDeviceChallengeRequest(ws) {
    console.log('[AUTH] Processing device challenge request');
    try {
      const deviceService = ws._deviceAttestationService;
      if (!deviceService) {
        throw new Error('Device attestation service not initialized');
      }
      const challenge = deviceService.generateChallenge();
      await sendSecureMessage(ws, {
        type: SignalType.DEVICE_CHALLENGE,
        challenge: challenge.nonce
      });
    } catch (e) {
      console.error('[AUTH] Failed to generate device challenge:', e);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Challenge generation failed");
    }
  }

  async processDeviceAttestation(ws, str) {
    console.log('[AUTH] Processing device attestation');
    try {
      const parsed = JSON.parse(str);
      const { attestation } = parsed;

      if (!attestation) {
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Missing attestation data");
      }

      const deviceService = ws._deviceAttestationService;
      if (!deviceService) {
        throw new Error('Device attestation service not initialized');
      }

      // Verify signature but do not consume challenge yet
      deviceService.verifySignature(attestation);

      // Store for later use in handleSignUp
      ws.clientState = SecureStateManager.setState(ws, {
        deviceAttestation: attestation
      });

      await sendSecureMessage(ws, {
        type: SignalType.DEVICE_ATTESTATION_ACK
      });
      console.log('[AUTH] Device attestation verified and stored');
    } catch (e) {
      console.error('[AUTH] Device attestation verification failed:', e.message);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Attestation verification failed");
    }
  }

  async processAuthRequest(ws, str) {
    console.log('[AUTH] Processing authentication request');

    if (!str || typeof str !== 'string') {
      console.error('[AUTH] Invalid authentication request format');
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid request format");
    }

    if (str.length > 1048576) { // 1MB limit
      console.error('[AUTH] Authentication request too large');
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Request too large");
    }

    try {
      const parsed = JSON.parse(str);
      const { type, passwordData, userData } = parsed;

      if (!parsed || typeof parsed !== 'object') {
        console.error('[AUTH] Invalid authentication data structure');
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid request structure");
      }

      console.log(`[AUTH] Auth type: ${type}`);

      // Verify request signature only if a client public key is already known for this connection
      if (ws.clientPublicKey) {
        const signatureHeader = ws.headers?.['x-request-signature'];
        if (!signatureHeader) {
          return rejectConnection(ws, SignalType.AUTH_ERROR, "Missing request signature");
        }
        if (!(await this.verifyRequestSignature(str, signatureHeader, ws))) {
          return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid request signature");
        }
      }

      // Decrypt both payloads sequentially for no race conditions
      const passwordEnvelope = await CryptoUtils.Hybrid.decryptIncoming(
        passwordData,
        {
          kyberSecretKey: this.serverHybridKeyPair.kyber.secretKey,
          kyberPublicKey: this.serverHybridKeyPair.kyber.publicKey,
          x25519SecretKey: this.serverHybridKeyPair.x25519.secretKey,
          dilithiumPublicKey: passwordData?.metadata?.sender?.dilithiumPublicKey
        },
        { expectJsonPayload: true }
      );
      const userEnvelope = await CryptoUtils.Hybrid.decryptIncoming(
        userData,
        {
          kyberSecretKey: this.serverHybridKeyPair.kyber.secretKey,
          kyberPublicKey: this.serverHybridKeyPair.kyber.publicKey,
          x25519SecretKey: this.serverHybridKeyPair.x25519.secretKey,
          dilithiumPublicKey: userData?.metadata?.sender?.dilithiumPublicKey
        },
        { expectJsonPayload: true }
      );

      const passwordPayload = passwordEnvelope.payloadJson;
      const userPayload = userEnvelope.payloadJson;

      if (!userPayload || !passwordPayload) {
        console.error('[AUTH] Failed to decrypt authentication data');
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
      }

      if (typeof userPayload !== 'object' || typeof passwordPayload !== 'object') {
        console.error('[AUTH] Invalid decrypted payload structure');
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
      }

      const username = userPayload.usernameSent;
      const passwordSecure = new SecureString(passwordPayload.content);
      const password = passwordSecure.toString();

      // Reset per-connection attempt state when username changes mid-connection
      try {
        ensureAttemptState(ws);
        if (ws.clientState?.username && ws.clientState.username !== username) {
          const randomAttempts = () => crypto.randomInt(5, 11);
          const currentAttestation = ws.clientState.deviceAttestation;
          ws.clientState = SecureStateManager.setState(ws, {
            attempts: { username: randomAttempts(), account_password: randomAttempts(), passphrase: randomAttempts(), server_password: randomAttempts() },
            accountPasswordLockedUntil: undefined,
            serverPasswordLockedUntil: undefined,
            pendingPasswordHash: false,
            pendingPassphrase: false,
            deviceAttestation: currentAttestation
          });
        }
      } catch { }

      if (!username || typeof username !== 'string' || username.length > 32) {
        console.error(`[AUTH] Invalid username in authentication data (type: ${typeof username}, length: ${username?.length || 0})`);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
      }

      if (!password || typeof password !== 'string' || password.length > 512) {
        console.error('[AUTH] Invalid password in authentication data');
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
      }

      // Prevent multiple concurrent logins via distributed lock + TOCTOU presence check
      if (type === SignalType.ACCOUNT_SIGN_IN) {
        const lockKey = `auth:${username}`;
        const lock = await DistributedLockManager.acquire(lockKey, 5000);
        if (!lock) {
          return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication in progress");
        }
        try {
          const alreadyOnline = await presenceIsOnline(username);
          if (alreadyOnline) {
            return rejectConnection(ws, SignalType.AUTH_ERROR, "Account already logged in");
          }
        } finally {
          await DistributedLockManager.release(lock.key, lock.token);
        }
      }

      // Per-user auth limiter before processing
      try {
        const userAuthCheck = await rateLimitMiddleware.checkUserAuthStatus(username);
        if (!userAuthCheck.allowed) {
          console.warn(`[AUTH] User auth blocked by rate limit for ${username}: ${userAuthCheck.reason}`);
          return sendAuthError(ws, { message: userAuthCheck.reason, code: 'USER_AUTH_RATE_LIMIT', category: 'rate_limit' });
        }
      } catch { }

      if (!authUtils.validateUsernameFormat(username)) {
        console.error(`[AUTH] Invalid username format: "${username}" (length: ${username.length}, regex test: ${/^[a-zA-Z0-9_-]+$/.test(username)})`);
        const info = await rateLimitMiddleware.recordCredentialFailure(username, 'account_password', ws);
        return sendAuthError(ws, {
          message: SignalMessages.INVALIDNAME,
          code: 'INVALID_USERNAME_FORMAT',
          category: 'username',
          attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
          locked: !!info?.locked,
          cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
        });
      }
      if (!authUtils.validateUsernameLength(username)) {
        console.error(`[AUTH] Invalid username length: "${username}" (length: ${username.length}, expected: 3-32)`);
        const info = await rateLimitMiddleware.recordCredentialFailure(username, 'account_password', ws);
        return sendAuthError(ws, {
          message: SignalMessages.INVALIDNAMELENGTH,
          code: 'INVALID_USERNAME_LENGTH',
          category: 'username',
          attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
          locked: !!info?.locked,
          cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
        });
      }

      if (type === SignalType.ACCOUNT_SIGN_UP) {
        console.log(`[AUTH] Handling sign up for user: ${username}`);
        return this.handleSignUp(ws, username, password);
      }
      if (type === SignalType.ACCOUNT_SIGN_IN) {
        console.log(`[AUTH] Handling sign in for user: ${username}`);
        return this.handleSignIn(ws, username, password);
      }

      console.error(`[AUTH] Invalid auth type: ${type}`);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid auth type");
    } catch (error) {
      try { if (typeof passwordSecure !== 'undefined') passwordSecure.clear(); } catch { }
      console.error('[AUTH] Auth processing error:', error);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
    }
  }

  async handleSignUp(ws, username, password) {
    console.log(`[AUTH] Starting sign up for user: ${username}`);
    const existingUser = await UserDatabase.loadUser(username);
    if (existingUser) {
      console.error(`[AUTH] Username already exists: ${username}`);
      const info = await rateLimitMiddleware.recordCredentialFailure(username, 'account_password', ws);
      return sendAuthError(ws, {
        message: SignalMessages.NAMEEXISTSERROR,
        code: 'USERNAME_TAKEN',
        category: 'username',
        attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
        locked: !!info?.locked,
        cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
      });
    }

    console.log(`[AUTH] Storing password hash for user: ${username}`);

    if (typeof password !== 'string' || !password.startsWith('$argon2')) {
      console.error(`[AUTH] Expected Argon2 encoded hash for new user ${username}`);
      const info = await rateLimitMiddleware.recordCredentialFailure(username, 'account_password', ws);
      return sendAuthError(ws, {
        message: "Invalid password hash format",
        code: 'INVALID_PASSWORD_HASH',
        category: 'account_password',
        attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
        locked: !!info?.locked,
        cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
      });
    }

    // Parse Argon2 parameters from the provided encoded hash and persist them for future login
    let parsed;
    try {
      parsed = await CryptoUtils.Password.parseArgon2Hash(password);
      await AccountAuthHandler.validateArgon2Parameters(parsed);
    } catch (e) {
      console.error(`[AUTH] Failed to parse password hash params for user ${username}:`, e);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid password hash parameters");
    }

    const deviceAttestationData = ws.clientState?.deviceAttestation;
    if (!deviceAttestationData || !deviceAttestationData.devicePublicKey || !deviceAttestationData.signature || !deviceAttestationData.challenge) {
      console.error(`[AUTH] Missing device attestation for signup: ${username}`);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Device attestation required");
    }

    let attestationResult;
    try {
      const deviceService = ws._deviceAttestationService;
      if (!deviceService) {
        throw new Error('Device attestation service not initialized');
      }
      attestationResult = await deviceService.verifyAttestation(deviceAttestationData);

      if (!attestationResult.allowed) {
        console.warn(`[AUTH] Device attestation denied for ${username}: ${attestationResult.reason}`);
        return sendAuthError(ws, {
          message: attestationResult.reason || 'Device account limit reached',
          code: 'DEVICE_LIMIT_REACHED',
          category: 'device',
          limit: attestationResult.limit,
          current: attestationResult.current
        });
      }

      console.log(`[AUTH] Device attestation verified for ${username}, count: ${attestationResult.newCount}`);
    } catch (e) {
      console.error(`[AUTH] Device attestation verification failed for ${username}:`, e.message);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Device attestation verification failed");
    }

    const passwordHashStored = UserDatabase.encodeStoredPasswordHash(password);

    const userRecord = {
      username,
      passwordHash: password,
      passwordHashStored,
      passphraseHash: null,
      version: null,
      algorithm: null,
      salt: null,
      memoryCost: null,
      timeCost: null,
      parallelism: null,
      passwordVersion: parsed.version,
      passwordAlgorithm: parsed.algorithm,
      passwordSalt: typeof parsed.salt === 'string' ? parsed.salt : parsed.salt.toString('base64'),
      passwordMemoryCost: parsed.memoryCost,
      passwordTimeCost: parsed.timeCost,
      passwordParallelism: parsed.parallelism
    };

    await UserDatabase.saveUserRecord(userRecord);
    console.log(`[AUTH] User record saved for: ${username}`);

    // Send account authentication success first
    await sendSecureMessage(ws, {
      type: SignalType.IN_ACCOUNT,
      message: "Account created successfully",
      username: username
    });

    // Then request passphrase setup with fresh Argon2 parameters
    const passphraseSalt = crypto.randomBytes(16).toString('base64');
    await sendSecureMessage(ws, {
      type: SignalType.PASSPHRASE_HASH,
      version: 19,
      algorithm: 'argon2id',
      salt: passphraseSalt,
      memoryCost: CryptoUtils.Config.ARGON2_MEMORY,
      timeCost: CryptoUtils.Config.ARGON2_TIME,
      parallelism: CryptoUtils.Config.ARGON2_PARALLELISM,
      message: "Please hash your passphrase with this info and send back"
    });

    ws.clientState = SecureStateManager.setState(ws, { username, pendingPassphrase: true, hasPassedAccountLogin: true });
    try { ws._username = username; } catch { }
    if (ws._sessionId) {
      try {
        const { ConnectionStateManager: StateManager } = await import('../presence/connection-state.js');
        await StateManager.updateState(ws._sessionId, {
          username,
          pendingPassphrase: true,
          hasPassedAccountLogin: true
        });
        console.log(`[AUTH] User ${username} state persisted to Redis for session: ${ws._sessionId}`);
      } catch (error) {
        console.error(`[AUTH] Failed to persist state to Redis for user ${username}:`, error.message);
      }
    }

    console.log(`[AUTH] User ${username} pending passphrase set on connection`);
    return { username, pending: true };
  }

  async handleSignIn(ws, username, password) {
    console.log(`[AUTH] Starting sign in for user: ${username}`);

    {
      const status = await rateLimitMiddleware.getUserCredentialStatus(username, 'account_password', ws);
      if (!status.allowed) {
        return sendAuthError(ws, {
          message: "Too many attempts. Please wait before trying again.",
          code: 'ACCOUNT_PASSWORD_COOLDOWN',
          category: 'account_password',
          attemptsRemaining: 0,
          locked: true,
          cooldownSeconds: status.remainingBlockTime
        });
      }
    }

    const startTime = Date.now();

    const userData = await UserDatabase.loadUser(username);
    if (!userData) {
      // Consistent timing to prevent user enumeration
      const elapsedTime = Date.now() - startTime;
      const minTime = 300;
      if (elapsedTime < minTime) await new Promise(r => setTimeout(r, minTime - elapsedTime));
      const info = await rateLimitMiddleware.recordCredentialFailure(username, 'credentials', ws);
      return sendAuthError(ws, {
        message: "Invalid username or password",
        code: info?.locked ? 'ACCOUNT_PASSWORD_LOCKED' : 'AUTH_FAILED',
        category: 'credentials',
        attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
        locked: !!info?.locked,
        cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
      });
    }

    // Password hash parameter negotiation for Argon2
    const isStoredArgon2 = typeof userData.passwordHash === 'string' && userData.passwordHash.startsWith('$argon2');

    if (isStoredArgon2 && !(typeof password === 'string' && password.startsWith('$argon2'))) {
      console.log(`[AUTH] Sending password hash parameters challenge to user: ${username}`);

      // Use stored parameters if present; otherwise parse from encoded hash
      let hashParams;
      if (userData.passwordSalt && userData.passwordMemoryCost && userData.passwordTimeCost && userData.passwordParallelism) {
        hashParams = {
          version: userData.passwordVersion || 19,
          algorithm: userData.passwordAlgorithm || 'argon2id',
          salt: userData.passwordSalt,
          memoryCost: userData.passwordMemoryCost,
          timeCost: userData.passwordTimeCost,
          parallelism: userData.passwordParallelism
        };
      } else {
        try {
          const parsedHash = await CryptoUtils.Password.parseArgon2Hash(userData.passwordHash);
          hashParams = {
            version: parsedHash.version,
            algorithm: parsedHash.algorithm,
            salt: typeof parsedHash.salt === 'string' ? parsedHash.salt : parsedHash.salt.toString('base64'),
            memoryCost: parsedHash.memoryCost,
            timeCost: parsedHash.timeCost,
            parallelism: parsedHash.parallelism
          };
        } catch (e) {
          console.error(`[AUTH] Failed to parse stored password hash for ${username}:`, e);
          return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
        }
      }

      await sendSecureMessage(ws, {
        type: SignalType.PASSWORD_HASH_PARAMS,
        version: hashParams.version,
        algorithm: hashParams.algorithm,
        salt: hashParams.salt,
        memoryCost: hashParams.memoryCost,
        timeCost: hashParams.timeCost,
        parallelism: hashParams.parallelism,
        message: "Please hash your password with these parameters and send back"
      });

      // Store username only in memory. do not persist to Redis until credentials are verified
      ws.clientState = SecureStateManager.setState(ws, { username, pendingPasswordHash: true });
      try {
        if (ws._sessionId) {
          const { ConnectionStateManager: StateManager } = await import('../presence/connection-state.js');
          await StateManager.updateState(ws._sessionId, { pendingPasswordHash: true });
        }
      } catch (e) {
        console.warn('[AUTH] Failed to persist pendingPasswordHash to session state:', e?.message || e);
      }
      console.log(`[AUTH] User ${username} pending password hash challenge`);
      return { username, pending: true };
    }

    let isPasswordValid = false;

    try {
      if (isStoredArgon2) {
        const crypto = await import('crypto');
        const maxLength = Math.max(userData.passwordHash.length, password.length);
        const normalizedStored = Buffer.from(userData.passwordHash.padEnd(maxLength, '\0'), 'utf8');
        const normalizedProvided = Buffer.from(password.padEnd(maxLength, '\0'), 'utf8');
        isPasswordValid = crypto.timingSafeEqual(normalizedStored, normalizedProvided) &&
          userData.passwordHash.length === password.length;
      } else {
        console.error(`[AUTH] Account ${username} uses unsupported password format`);
        isPasswordValid = false;
      }
    } catch (error) {
      console.error(`[AUTH] Error during password verification: ${error.message}`);
      isPasswordValid = false;
    }

    if (!isPasswordValid) {
      const elapsedTime = Date.now() - startTime;
      const minTime = 300; // Minimum 300ms for failed attempts
      if (elapsedTime < minTime) {
        await new Promise(resolve => setTimeout(resolve, minTime - elapsedTime));
      }

      const info = await rateLimitMiddleware.recordCredentialFailure(username, 'credentials', ws);
      return sendAuthError(ws, {
        message: "Invalid username or password",
        code: info?.locked ? 'ACCOUNT_PASSWORD_LOCKED' : 'AUTH_FAILED',
        category: 'credentials',
        attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
        locked: !!info?.locked,
        cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
      });
    }

    console.log(`[AUTH] Password verified for user: ${username}`);

    // Determine passphrase parameters either from stored columns or by parsing stored hash
    let passParams = null;
    try {
      const latest = (await UserDatabase.loadUser(username)) || userData;

      let parsed = null;
      if (typeof latest?.passphrasehash === 'string' && latest.passphrasehash.startsWith('$argon2')) {
        try {
          parsed = await CryptoUtils.Password.parseArgon2Hash(latest.passphrasehash);
        } catch (parseError) {
          console.warn(`[AUTH] Failed to parse stored passphrase hash for user ${username}:`, parseError?.message || parseError);
        }
      } else {
        console.warn(`[AUTH] No valid passphraseHash to parse for user ${username}`);
      }

      if (latest && latest.version && latest.salt) {
        const memoryCost = typeof latest.memorycost === 'number' && Number.isFinite(latest.memorycost)
          ? latest.memorycost
          : parsed?.memoryCost;
        const timeCost = typeof latest.timecost === 'number' && Number.isFinite(latest.timecost)
          ? latest.timecost
          : parsed?.timeCost;
        const parallelism = typeof latest.parallelism === 'number' && Number.isFinite(latest.parallelism)
          ? latest.parallelism
          : parsed?.parallelism;

        if (memoryCost && timeCost && parallelism) {
          passParams = {
            version: latest.version,
            algorithm: latest.algorithm || parsed?.algorithm,
            salt: typeof latest.salt === 'string' ? latest.salt : latest.salt?.toString('base64'),
            memoryCost,
            timeCost,
            parallelism
          };
        }
      } else if (parsed) {
        passParams = {
          version: parsed.version,
          algorithm: parsed.algorithm,
          salt: typeof parsed.salt === 'string' ? parsed.salt : parsed.salt.toString('base64'),
          memoryCost: parsed.memoryCost,
          timeCost: parsed.timeCost,
          parallelism: parsed.parallelism
        };
      }
    } catch (e) {
      console.warn(`[AUTH] Failed to derive passphrase parameters for user ${username}:`, e?.message || e);
    }

    if (passParams) {
      const requiredFields = ['version', 'algorithm', 'salt', 'memoryCost', 'timeCost', 'parallelism'];
      const missingFields = requiredFields.filter(field =>
        passParams[field] === undefined ||
        passParams[field] === null ||
        (typeof passParams[field] === 'number' && !Number.isFinite(passParams[field]))
      );

      if (missingFields.length > 0) {
        console.error(`[AUTH] Incomplete passphrase parameters for user ${username}, missing: ${missingFields.join(', ')}`);
        passParams = null;
      }
    }

    if (passParams) {
      console.log(`[AUTH] Requesting passphrase for user: ${username}`);
      await sendSecureMessage(ws, {
        type: SignalType.PASSPHRASE_HASH,
        version: passParams.version,
        algorithm: passParams.algorithm,
        salt: passParams.salt,
        memoryCost: passParams.memoryCost,
        timeCost: passParams.timeCost,
        parallelism: passParams.parallelism,
        message: "Please hash your passphrase with this info and send back"
      });

      // Mark account-login step as passed only after password verification succeeded
      ws.clientState = SecureStateManager.setState(ws, { username, pendingPassphrase: true, hasPassedAccountLogin: true });
      try {
        if (ws._sessionId) {
          const { ConnectionStateManager: StateManager } = await import('../presence/connection-state.js');
          await StateManager.updateState(ws._sessionId, { username, hasPassedAccountLogin: true });
        }
      } catch { }

      console.log(`[AUTH] User ${username} pending passphrase set for sign in`);
      return { username, pending: true };
    }

    console.error(`[AUTH] No passphrase hash info for user: ${username}`);

    const info = await rateLimitMiddleware.recordCredentialFailure(username, 'passphrase', ws);
    return sendAuthError(ws, {
      message: "Authentication failed",
      code: info?.locked ? 'PASSPHRASE_LOCKED' : 'PASSPHRASE_MISSING',
      category: 'passphrase',
      attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
      locked: !!info?.locked,
      cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
    });
  }

  async handlePassphrase(ws, username, passphraseHash, isNewUser = false) {
    console.log(`[AUTH] Handling passphrase for user: ${username}, isNewUser: ${isNewUser}`);

    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[AUTH] Invalid username in passphrase handling: ${username}`);
      const info = await rateLimitMiddleware.recordCredentialFailure(username, 'passphrase', ws);
      return sendAuthError(ws, {
        message: "Invalid username",
        code: 'INVALID_USERNAME',
        category: 'username',
        attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
        locked: !!info?.locked,
        cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
      });
    }

    if (!passphraseHash || typeof passphraseHash !== 'string' || passphraseHash.length < 10 || passphraseHash.length > 5000) {
      console.error(`[AUTH] Invalid passphrase hash format for user: ${username}`);
      const info = await rateLimitMiddleware.recordCredentialFailure(username, 'passphrase', ws);
      return sendAuthError(ws, {
        message: info?.locked ? "Invalid passphrase format" : "Invalid passphrase format",
        code: info?.locked ? 'PASSPHRASE_LOCKED' : 'INVALID_PASSPHRASE_FORMAT',
        category: 'passphrase',
        attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
        locked: !!info?.locked,
        cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
      });
    }

    {
      const status = await rateLimitMiddleware.getUserCredentialStatus(username, 'passphrase', ws);
      if (!status.allowed) {
        return sendAuthError(ws, { message: "Too many attempts. Please wait before trying again.", code: 'PASSPHRASE_COOLDOWN', category: 'passphrase', attemptsRemaining: 0, locked: true, cooldownSeconds: status.remainingBlockTime });
      }
    }

    if (!ws.clientState || ws.clientState.username !== username || !ws.clientState.pendingPassphrase) {
      console.error(`[AUTH] Unexpected passphrase submission for user: ${username}`);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Unexpected passphrase submission");
    }

    const userRecord = await UserDatabase.loadUser(username);
    if (!userRecord) {
      console.error(`[AUTH] User does not exist: ${username}`);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "User does not exist");
    }

    const hasStoredPassphrase = typeof userRecord.passphrasehash === 'string' && userRecord.passphrasehash.length > 0;
    const isInitialPassphrase = isNewUser || !hasStoredPassphrase;

    if (isInitialPassphrase) {
      console.log(`[AUTH] Processing passphrase for: ${username}`);

      if (!passphraseHash.startsWith('$argon2')) {
        console.error(`[AUTH] Invalid passphrase hash format for user: ${username}`);
        const info = await rateLimitMiddleware.recordCredentialFailure(username, 'passphrase', ws);
        return sendAuthError(ws, {
          message: "Invalid passphrase hash format",
          code: info?.locked ? 'PASSPHRASE_LOCKED' : 'INVALID_PASSPHRASE_HASH',
          category: 'passphrase',
          attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
          locked: !!info?.locked,
          cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
        });
      }

      userRecord.passphraseHash = passphraseHash;
      try {
        const parsed = await CryptoUtils.Password.parseArgon2Hash(passphraseHash);

        if (!parsed.salt || parsed.salt.length < 16) {
          throw new Error('Invalid salt length');
        }
        if (parsed.memoryCost < 1024 || parsed.memoryCost > 1048576) {
          throw new Error('Invalid memory cost');
        }
        if (parsed.timeCost < 1 || parsed.timeCost > 100) {
          throw new Error('Invalid time cost');
        }
        if (parsed.parallelism < 1 || parsed.parallelism > 16) {
          throw new Error('Invalid parallelism');
        }

        userRecord.version = parsed.version;
        userRecord.algorithm = parsed.algorithm;
        userRecord.salt = typeof parsed.salt === 'string' ? parsed.salt : parsed.salt.toString('base64');
        userRecord.memoryCost = parsed.memoryCost;
        userRecord.timeCost = parsed.timeCost;
        userRecord.parallelism = parsed.parallelism;
        console.log(`[AUTH] Passphrase hash parsed for new user: ${username}`);
      } catch (e) {
        console.error(`[AUTH] Failed to parse passphrase hash params for user ${username}:`, e);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid passphrase hash parameters");
      }
      await UserDatabase.saveUserRecord(userRecord);
      console.log(`[AUTH] User record updated with passphrase for: ${username}`);
    } else {
      console.log(`[AUTH] Verifying passphrase for user: ${username}`);

      const storedHash = userRecord.passphrasehash;
      const providedHash = passphraseHash;

      if (!storedHash || !providedHash) {
        console.error(`[AUTH] Missing passphrase hash for user: ${username}`);
        const info = await rateLimitMiddleware.recordCredentialFailure(username, 'passphrase', ws);
        return sendAuthError(ws, {
          message: "Authentication failed",
          code: info?.locked ? 'PASSPHRASE_LOCKED' : 'PASSPHRASE_MISSING',
          category: 'passphrase',
          attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
          locked: !!info?.locked,
          cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
        });
      }

      const crypto = await import('crypto');
      let isValid = false;

      try {
        const parsedStored = await CryptoUtils.Password.parseArgon2Hash(storedHash);
        const parsedProvided = await CryptoUtils.Password.parseArgon2Hash(providedHash);

        const algEqual = String(parsedStored.algorithm).toLowerCase() === String(parsedProvided.algorithm).toLowerCase();
        const verEqual = parsedStored.version === parsedProvided.version;
        const paramsEqual = (
          parsedStored.memoryCost === parsedProvided.memoryCost &&
          parsedStored.timeCost === parsedProvided.timeCost &&
          parsedStored.parallelism === parsedProvided.parallelism
        );

        // Constant-time equality for salt and hash bytes
        const saltEqual = (
          parsedStored.salt.length === parsedProvided.salt.length &&
          crypto.timingSafeEqual(parsedStored.salt, parsedProvided.salt)
        );
        const hashEqual = (
          parsedStored.hash.length === parsedProvided.hash.length &&
          crypto.timingSafeEqual(parsedStored.hash, parsedProvided.hash)
        );

        isValid = algEqual && verEqual && paramsEqual && saltEqual && hashEqual;
      } catch (parseError) {
        console.error(`[AUTH] Failed to parse passphrase hash: ${parseError.message}`);
        isValid = false;
      }

      if (!isValid) {
        console.error(`[AUTH] Passphrase verification failed for user: ${username}`);
        const info = await rateLimitMiddleware.recordCredentialFailure(username, 'passphrase', ws);
        return sendAuthError(ws, {
          message: "Authentication failed",
          code: info?.locked ? 'PASSPHRASE_LOCKED' : 'INCORRECT_PASSPHRASE',
          category: 'passphrase',
          attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
          locked: !!info?.locked,
          cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
        });
      }

      console.log(`[AUTH] Passphrase verified for user: ${username}`);
    }

    passphraseHash = null;

    // Mark passphrase verified and dont finalize until Signal bundle is received
    ws.clientState = SecureStateManager.setState(ws, {
      username,
      pendingPassphrase: false,
      pendingSignalBundle: true,
      hasPassedAccountLogin: true,
      hasAuthenticated: false,
      passphraseVerifiedAt: Date.now()
    });
    console.log(`[AUTH] User ${username} cleared pending passphrase, awaiting Signal bundle`);

    await sendSecureMessage(ws, {
      type: SignalType.PASSPHRASE_SUCCESS,
      message: "Passphrase verified. Please send Signal Protocol bundle to complete authentication."
    });

    return { username, pending: true, awaitingBundle: true };
  }

  async handlePasswordHash(ws, username, hashedPassword) {
    console.log(`[AUTH] Handling password hash response for user: ${username}`);

    {
      const status = await rateLimitMiddleware.getUserCredentialStatus(username, 'account_password', ws);
      if (!status.allowed) {
        return sendAuthError(ws, { message: "Too many attempts. Please wait before trying again.", code: 'ACCOUNT_PASSWORD_COOLDOWN', category: 'account_password', attemptsRemaining: 0, locked: true, cooldownSeconds: status.remainingBlockTime });
      }
    }

    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[AUTH] Invalid username in password hash handling: ${username}`);
      const info = await rateLimitMiddleware.recordCredentialFailure(username, 'account_password', ws);
      return sendAuthError(ws, {
        message: "Invalid username",
        code: 'INVALID_USERNAME',
        category: 'username',
        attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
        locked: !!info?.locked,
        cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
      });
    }

    if (!hashedPassword || typeof hashedPassword !== 'string' || !hashedPassword.startsWith('$argon2')) {
      console.error(`[AUTH] Invalid password hash format for user: ${username}`);
      const info = await rateLimitMiddleware.recordCredentialFailure(username, 'account_password', ws);
      return sendAuthError(ws, {
        message: "Invalid password hash format",
        code: 'INVALID_PASSWORD_HASH',
        category: 'account_password',
        attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
        locked: !!info?.locked,
        cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
      });
    }

    if (!ws.clientState || ws.clientState.username !== username || !ws.clientState.pendingPasswordHash) {
      console.error(`[AUTH] Unexpected password hash submission for user: ${username}`);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Unexpected password hash submission");
    }

    const userData = await UserDatabase.loadUser(username);
    if (!userData) {
      console.error(`[AUTH] User does not exist: ${username}`);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "User does not exist");
    }

    // Constant-time comparison of encoded Argon2 hashes
    let isPasswordValid = false;
    try {
      const storedHash = userData.passwordHashStored;
      if (storedHash && storedHash.startsWith('v') && storedHash.includes(':')) {
        isPasswordValid = UserDatabase.verifyStoredPasswordHash(hashedPassword, storedHash);
      } else {
        isPasswordValid = false;
      }
    } catch (error) {
      console.error(`[AUTH] Error during password hash verification: ${error.message}`);
      isPasswordValid = false;
    }

    if (!isPasswordValid) {
      console.error(`[AUTH] Incorrect password hash for user: ${username}`);
      const info = await rateLimitMiddleware.recordCredentialFailure(username, 'account_password', ws);
      return sendAuthError(ws, {
        message: "Incorrect password",
        code: info?.locked ? 'ACCOUNT_PASSWORD_LOCKED' : 'INCORRECT_PASSWORD',
        category: 'account_password',
        attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
        locked: !!info?.locked,
        cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
      });
    }

    console.log(`[AUTH] Password verified for user: ${username}`);

    ws.clientState = SecureStateManager.setState(ws, { pendingPasswordHash: false });

    // Derive passphrase parameters either from stored columns or by parsing stored passphrase hash
    let passParams = null;
    try {
      if (userData.version && userData.salt) {
        passParams = {
          version: userData.version,
          algorithm: userData.algorithm,
          salt: typeof userData.salt === 'string' ? userData.salt : userData.salt.toString('base64'),
          memoryCost: userData.memorycost,
          timeCost: userData.timecost,
          parallelism: userData.parallelism,
        };
      } else if (typeof userData.passphrasehash === 'string' && userData.passphrasehash.startsWith('$argon2')) {
        const parsed = await CryptoUtils.Password.parseArgon2Hash(userData.passphrasehash);
        passParams = {
          version: parsed.version,
          algorithm: parsed.algorithm,
          salt: typeof parsed.salt === 'string' ? parsed.salt : parsed.salt.toString('base64'),
          memoryCost: parsed.memoryCost,
          timeCost: parsed.timeCost,
          parallelism: parsed.parallelism,
        };
      } else {
        console.warn(`[AUTH] No valid passphraseHash to parse (password hash) for user ${username}`);
      }
    } catch (e) {
      console.warn(`[AUTH] Failed to derive passphrase parameters for user ${username}:`, e?.message || e);
      passParams = null;
    }

    if (passParams) {
      // Validate all required fields are present before sending
      const requiredFields = ['version', 'algorithm', 'salt', 'memoryCost', 'timeCost', 'parallelism'];
      const missingFields = requiredFields.filter(field =>
        passParams[field] === undefined ||
        passParams[field] === null ||
        (typeof passParams[field] === 'number' && !Number.isFinite(passParams[field]))
      );

      if (missingFields.length > 0) {
        console.error(`[AUTH] Incomplete passphrase parameters for user ${username}, missing: ${missingFields.join(', ')}`);
        passParams = null;
      }
    }

    if (passParams) {
      console.log(`[AUTH] Requesting passphrase for user: ${username}`);
      await sendSecureMessage(ws, {
        type: SignalType.PASSPHRASE_HASH,
        version: passParams.version,
        algorithm: passParams.algorithm,
        salt: passParams.salt,
        memoryCost: passParams.memoryCost,
        timeCost: passParams.timeCost,
        parallelism: passParams.parallelism,
        message: "Please hash your passphrase with this info and send back"
      });

      // Mark account-login step as passed password verified
      ws.clientState = SecureStateManager.setState(ws, { username, pendingPassphrase: true, hasPassedAccountLogin: true });
      try {
        if (ws._sessionId) {
          const { ConnectionStateManager: StateManager } = await import('../presence/connection-state.js');
          await StateManager.updateState(ws._sessionId, { username, hasPassedAccountLogin: true });
        }
      } catch { }

      console.log(`[AUTH] User ${username} pending passphrase set for sign in`);
      return { username, pending: true };
    }

    console.error(`[AUTH] No passphrase hash info for user: ${username}`);

    const info = await rateLimitMiddleware.recordCredentialFailure(username, 'passphrase', ws);
    return sendAuthError(ws, {
      message: "Authentication failed",
      code: info?.locked ? 'PASSPHRASE_LOCKED' : 'PASSPHRASE_MISSING',
      category: 'passphrase',
      attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
      locked: !!info?.locked,
      cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
    });
  }

  async finalizeAuth(ws, username, logMessage) {
    console.log(`[AUTH] Finalizing authentication: ${logMessage} for user: ${username}`);

    if (!ws.clientState || ws.clientState.username !== username) {
      console.error(`[AUTH] Invalid or missing client state during finalization: ${username}`);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid authentication state");
    }
    if (ws.clientState.hasAuthenticated) {
      console.error(`[AUTH] User already authenticated: ${username}`);
      return rejectConnection(ws, SignalType.NAMEEXISTSERROR, SignalMessages.NAMEEXISTSERROR);
    }
    if (!ws.clientState.hasPassedAccountLogin) {
      console.error(`[AUTH] Invalid state transition - account login not completed: ${username}`);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid authentication state");
    }

    // Ensure we have a deviceId for this connection and persist it on ws
    const deviceId = ws.deviceId || await this.generateDeviceId(ws);
    ws.deviceId = deviceId;

    // Enforce TLS and device proof-of-possession before issuing any tokens
    try {
      const req = ws.upgradeReq || ws._socket;
      const isTLS = !!(req && req.socket && req.socket.encrypted);
      if (!isTLS) {
        console.error('[AUTH] TLS required for authentication');
        return rejectConnection(ws, SignalType.AUTH_ERROR, 'TLS required');
      }
      return await this.startDeviceProof(ws, username);
    } catch (e) {
      console.error('[AUTH] Device proof initiation failed:', e?.message || e);
      return rejectConnection(ws, SignalType.AUTH_ERROR, 'Authentication failed');
    }
  }

  // Device proof-of-possession (Ed25519) flow
  async startDeviceProof(ws, username) {
    const nonce = crypto.randomBytes(32).toString('base64');
    ws.clientState = SecureStateManager.setState(ws, {
      pendingDeviceProof: true,
      deviceProofNonce: nonce,
      deviceProofIssuedAt: Date.now(),
    });
    try {
      await sendSecureMessage(ws, {
        type: SignalType.DEVICE_PROOF_CHALLENGE,
        nonce
      });
      console.log(`[AUTH] Sent device proof challenge to ${username}`);
      return { username, pendingDeviceProof: true };
    } catch (e) {
      console.error('[AUTH] Failed to send device proof challenge:', e?.message || e);
      return rejectConnection(ws, SignalType.AUTH_ERROR, 'Authentication failed');
    }
  }

  async processDeviceProofResponse(ws, str) {
    try {
      const parsed = typeof str === 'string' ? JSON.parse(str) : str;
      const { type, deviceId, nonce, publicKeyPem, signatureBase64 } = parsed || {};
      const username = ws.clientState?.username;
      if (type !== SignalType.DEVICE_PROOF_RESPONSE || !username) {
        return rejectConnection(ws, SignalType.AUTH_ERROR, 'Unexpected device proof response');
      }
      if (!ws.clientState?.pendingDeviceProof || !ws.clientState?.deviceProofNonce) {
        return rejectConnection(ws, SignalType.AUTH_ERROR, 'No device proof in progress');
      }
      if (nonce !== ws.clientState.deviceProofNonce) {
        return rejectConnection(ws, SignalType.AUTH_ERROR, 'Invalid device proof nonce');
      }
      if (Date.now() - (ws.clientState.deviceProofIssuedAt || 0) > 60_000) {
        return rejectConnection(ws, SignalType.AUTH_ERROR, 'Device proof expired');
      }
      const did = ws.deviceId || deviceId;
      if (!did || typeof did !== 'string') {
        return rejectConnection(ws, SignalType.AUTH_ERROR, 'Missing device id');
      }
      // Verify signature
      let ok = false;
      try {
        const keyObj = crypto.createPublicKey({ key: publicKeyPem, format: 'pem', type: 'spki' });
        const msg = Buffer.from(`device-proof:v1|${nonce}|${did}`, 'utf8');
        const sig = Buffer.from(signatureBase64 || '', 'base64');
        ok = crypto.verify(null, msg, keyObj, sig);
      } catch (_e) {
        ok = false;
      }
      if (!ok) {
        console.error('[AUTH] Device proof verification failed');
        return rejectConnection(ws, SignalType.AUTH_ERROR, 'Device proof failed');
      }

      // Persist/update device session with public key (in securityFlags)
      try {
        await TokenDatabase.createOrUpdateDeviceSession({
          deviceId: did,
          userId: username,
          deviceName: this.extractDeviceName(ws),
          deviceType: 'desktop',
          fingerprint: null,
          riskScore: 'low',
          location: null,
          userAgent: null,
          clientVersion: ws.headers?.['x-client-version'] || 'unknown',
          securityFlags: {
            deviceEd25519PublicKey: publicKeyPem
          }
        });
      } catch (e) {
        console.warn('[AUTH] Failed to persist device public key:', e?.message || e);
      }

      // Clear pending proof state and issue tokens
      ws.clientState = SecureStateManager.setState(ws, {
        pendingDeviceProof: false,
        deviceProofNonce: undefined,
        deviceProofIssuedAt: undefined
      });

      return await this.issueTokensAfterDeviceProof(ws, username);
    } catch (e) {
      console.error('[AUTH] processDeviceProofResponse error:', e?.message || e);
      return rejectConnection(ws, SignalType.AUTH_ERROR, 'Authentication failed');
    }
  }

  async issueTokensAfterDeviceProof(ws, username) {
    const deviceId = ws.deviceId || await this.generateDeviceId(ws);
    const req = ws.upgradeReq || ws._socket;
    const authContext = await TokenMiddleware.createAuthContext(username, deviceId, req);
    let tlsBinding = null;
    try {
      tlsBinding = TokenMiddleware.getTLSFingerprint(req);
    } catch (e) {
      console.error('[AUTH] TLS fingerprint unavailable for token issuance:', e?.message || e);
      return rejectConnection(ws, SignalType.AUTH_ERROR, 'TLS fingerprint required');
    }

    if (!tlsBinding) {
      console.error('[AUTH] TLS binding missing, rejecting connection');
      return rejectConnection(ws, SignalType.AUTH_ERROR, 'TLS binding required');
    }

    const tokenPair = await TokenService.createTokenPair(
      username,
      deviceId,
      tlsBinding
    );

    // Store refresh token in database
    try {
      await TokenDatabase.storeRefreshToken({
        tokenId: TokenService.parseTokenUnsafe(tokenPair.refreshToken).jti,
        userId: username,
        deviceId: deviceId,
        family: tokenPair.family,
        rawToken: tokenPair.refreshToken,
        expiresAt: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60),
        deviceFingerprint: authContext.deviceFingerprint,
        securityContext: authContext.securityContext,
        createdFrom: authContext.createdFrom,
        userAgent: authContext.userAgent
      });
    } catch (e) {
      if ((e?.message || '').includes('Maximum active refresh tokens')) {
        await sendSecureMessage(ws, {
          type: SignalType.AUTH_ERROR,
          code: 'MAX_SESSIONS',
          message: 'Maximum active sessions reached. Please logout from another device and try again.'
        });
        return { username, authenticated: false, error: 'MAX_SESSIONS' };
      }
      throw e;
    }

    ws.clientState = SecureStateManager.setState(ws, {
      authenticationTime: Date.now(),
      finalizedBy: 'AccountAuthHandler',
      tokenFamily: tokenPair.family,
      accessToken: tokenPair.accessToken,
      hasTokens: true
    });

    // Store account auth state for reconnection recovery
    const { ConnectionStateManager } = await import('../presence/connection-state.js');
    await ConnectionStateManager.storeUserAuthState(username, {
      hasPassedAccountLogin: true,
      hasAuthenticated: false,
      accountAuthTime: Date.now(),
      finalizedBy: 'AccountAuthHandler',
      tokenFamily: tokenPair.family
    });

    ws.clientState = SecureStateManager.setState(ws, {
      ...ws.clientState,
      tokenPair: tokenPair,
      accountAuthComplete: true
    });

    if (!ws.clientState?.recoveredAt) {
      await sendSecureMessage(ws, {
        type: SignalType.IN_ACCOUNT,
        username: username,
        message: "Account authentication successful. Please enter server password."
      });
    }

    console.log(`[AUTH] Device proof verified and tokens issued for user: ${username}`);
    return { username, authenticated: false, tokens: tokenPair };
  }

  /**
   * Generate unique device ID for the connection
   */
  async generateDeviceId(ws) {
    const request = ws.upgradeReq || ws._socket;
    const deviceContext = TokenMiddleware.extractDeviceContext(request);

    const tlsInfo = request?.socket?.encrypted ? {
      cipher: request.socket.getCipher?.(),
      protocol: request.socket.getProtocol?.(),
      sessionId: request.socket.getSession ? request.socket.getSession().slice(0, 16) : undefined
    } : {};

    const deviceSecret = crypto.randomBytes(32);
    const deviceData = {
      secret: deviceSecret.toString('base64'),
      userAgent: deviceContext.userAgent,
      ip: deviceContext.ip,
      tls: tlsInfo,
      timestamp: Date.now()
    };

    const hmacKey = CryptoUtils.Hash.blake3(Buffer.from(process.env.DEVICE_ID_KEY || 'derive-device-id-key'));
    const mac = await CryptoUtils.Hash.generateBlake3Mac(new TextEncoder().encode(JSON.stringify(deviceData)), hmacKey);
    return Buffer.from(mac).toString('hex').slice(0, 32);
  }

  /**
   * Extract device name from request headers
   */
  extractDeviceName(ws) {
    try {
      const request = ws.upgradeReq || ws._socket;

      const headers = request?.headers || {};
      const userAgent = headers['user-agent'] || '';
      const clientName = headers['x-client-name'] || 'End2End Chat';
      const clientVersion = headers['x-client-version'] || 'unknown';

      if (userAgent.includes('Electron')) {
        return `${clientName} (${clientVersion})`;
      }

      // Parse basic device info from user agent
      if (userAgent.includes('Windows')) return `${clientName} on Windows`;
      if (userAgent.includes('Mac')) return `${clientName} on macOS`;
      if (userAgent.includes('Linux')) return `${clientName} on Linux`;

      return `${clientName} Desktop`;
    } catch (error) {
      console.warn('[AUTH] Failed to extract device name:', error.message);
      return 'End2End Chat (unknown)';
    }
  }

  /**
   * Generate password hash parameters for client-side hashing
   */
  async generatePasswordHashParams() {
    const salt = new Uint8Array(crypto.randomBytes(16));
    const saltBase64 = Buffer.from(salt).toString('base64');

    return {
      version: 19,
      algorithm: 'argon2id',
      salt: saltBase64,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
      message: "Please hash your password with these parameters and send back"
    };
  }

}

import { presenceService } from '../presence/presence-service.js';

export class ServerAuthHandler {
  constructor(serverHybridKeyPair, _unusedClients, serverConfig) {
    this.serverHybridKeyPair = serverHybridKeyPair;
    this.ServerConfig = serverConfig;
    console.log('[AUTH] ServerAuthHandler initialized');
  }

  async handleServerAuthentication(ws, str, clientState) {
    const username = clientState?.username;

    if (!username) {
      console.error('[AUTH] No username found - account authentication required first');
      console.error('[AUTH] clientState:', JSON.stringify(clientState));
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Please complete account authentication first");
    }

    console.log(`[AUTH] Handling server authentication for user: ${username}`);

    const parsed = JSON.parse(str);

    if (parsed.type !== SignalType.SERVER_LOGIN) {
      console.error(`[AUTH] Expected SERVER_LOGIN but got: ${parsed.type}`);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Expected login information");
    }

    try {
      {
        const status = await rateLimitMiddleware.getUserCredentialStatus(username, 'server_password', ws);
        if (!status.allowed) {
          return sendAuthError(ws, { message: "Too many attempts. Please wait before trying again.", code: 'SERVER_PASSWORD_COOLDOWN', category: 'server_password', attemptsRemaining: 0, locked: true, cooldownSeconds: status.remainingBlockTime });
        }
      }

      const passwordEnvelope = await CryptoUtils.Hybrid.decryptIncoming(
        parsed.passwordData,
        {
          kyberSecretKey: this.serverHybridKeyPair.kyber.secretKey,
          x25519SecretKey: this.serverHybridKeyPair.x25519.secretKey,
          kyberPublicKey: this.serverHybridKeyPair.kyber.publicKey,
          dilithiumPublicKey: parsed.passwordData?.metadata?.sender?.dilithiumPublicKey
        },
        { expectJsonPayload: true }
      );
      const passwordPayload = passwordEnvelope.payloadJson;

      if (!passwordPayload || !passwordPayload.content) {
        console.error(`[AUTH] Invalid password format for user: ${username}`);
        const info = await rateLimitMiddleware.recordCredentialFailure(username, 'server_password', ws);
        return sendAuthError(ws, {
          message: "Invalid password format",
          code: 'INVALID_SERVER_PASSWORD_FORMAT',
          category: 'server_password',
          attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
          locked: !!info?.locked,
          cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
        });
      }

      const serverPasswordHash = this.ServerConfig.getServerPasswordHash();
      if (!serverPasswordHash) {
        console.error('[AUTH] Server password not configured');
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Server not properly configured");
      }

      const passwordValid = await CryptoUtils.Password.verifyPassword(serverPasswordHash, passwordPayload.content);

      if (!passwordValid) {
        console.error(`[AUTH] Incorrect server password for user: ${username}`);
        const info = await rateLimitMiddleware.recordCredentialFailure(username, 'server_password', ws);
        return sendAuthError(ws, {
          message: "Incorrect password",
          code: info?.locked ? 'SERVER_PASSWORD_LOCKED' : 'INCORRECT_SERVER_PASSWORD',
          category: 'server_password',
          attemptsRemaining: typeof info?.attemptsRemaining === 'number' ? info.attemptsRemaining : undefined,
          locked: !!info?.locked,
          cooldownSeconds: info?.locked ? info.remainingBlockTime : undefined
        });
      }

      if (!ws.clientState?.hasPassedAccountLogin) {
        console.error(`[AUTH] Invalid state - account login not completed: ${username}`);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Account authentication required first");
      }

      if (ws.clientState?.hasAuthenticated) {
        console.error(`[AUTH] User already authenticated: ${username}`);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "User already authenticated");
      }

      ws.clientState = SecureStateManager.setState(ws, { hasAuthenticated: true, serverAuthTime: Date.now(), finalizedBy: 'ServerAuthHandler' });

      // Map this authenticated connection for local delivery and mark presence online
      try { ws._username = username; } catch { }
      try { global.gateway?.addLocalConnection?.(username, ws); } catch (e) { console.warn('[AUTH] addLocalConnection failed:', e?.message || e); }
      try { await presenceService.setUserOnline(username, ws._sessionId || ''); } catch (e) { console.warn('[AUTH] setUserOnline failed:', e?.message || e); }

      if (!ws._sessionId) {
        console.error('[AUTH] No session ID available for state update');
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Session state error");
      }

      const { ConnectionStateManager: StateManager } = await import('../presence/connection-state.js');
      const stateUpdateSuccess = await StateManager.updateState(ws._sessionId, {
        username: username,
        hasAuthenticated: true,
        serverAuthTime: Date.now()
      });

      if (!stateUpdateSuccess) {
        console.error(`[AUTH] Failed to persist authentication state to Redis for user: ${username}`);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Failed to save authentication state");
      }

      console.log(`[AUTH] Authentication state persisted to Redis for user: ${username}`);

      let finalTokens = ws.clientState.tokenPair || null;

      if (!finalTokens) {
        console.log(`[AUTH] No stored tokens found, generating new tokens for user: ${username}`);

        const authContext = await TokenMiddleware.createAuthContext(
          username,
          ws.deviceId,
          ws.upgradeReq || ws._socket
        );

        // Ensure deviceId is set and stable for this connection
        const deviceId = ws.deviceId || await this.generateDeviceId(ws);
        ws.deviceId = deviceId;

        let tlsBinding = null;
        try {
          tlsBinding = TokenMiddleware.getTLSFingerprint(ws.upgradeReq || ws._socket);
        } catch (e) {
          console.error('[AUTH] TLS fingerprint unavailable during server auth token issuance:', e?.message || e);
          return rejectConnection(ws, SignalType.AUTH_ERROR, 'TLS fingerprint required');
        }
        if (!tlsBinding) {
          console.error('[AUTH] TLS binding missing during server auth token issuance');
          return rejectConnection(ws, SignalType.AUTH_ERROR, 'TLS binding required');
        }

        finalTokens = await TokenService.createTokenPair(
          username,
          deviceId,
          tlsBinding
        );

        // Store refresh token
        await TokenDatabase.storeRefreshToken({
          tokenId: TokenService.parseTokenUnsafe(finalTokens.refreshToken).jti,
          userId: username,
          deviceId: deviceId,
          family: finalTokens.family,
          rawToken: finalTokens.refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60),
          deviceFingerprint: authContext.deviceFingerprint,
          securityContext: authContext.securityContext,
          createdFrom: authContext.createdFrom,
          userAgent: null
        });
      } else {
        console.log(`[AUTH] Using stored tokens from account authentication for user: ${username}`);
      }

      // Detect suspicious activity on server authentication
      try {
        const authContext = await TokenMiddleware.createAuthContext(
          username,
          ws.deviceId,
          ws.upgradeReq || ws._socket
        );

        const suspiciousActivity = await TokenSecurityManager.detectSuspiciousActivity(
          username,
          TokenService.parseTokenUnsafe(finalTokens.refreshToken).jti,
          {
            serverAuth: true,
            ipAddress: authContext.createdFrom,
            userAgent: authContext.userAgent,
            deviceFingerprint: authContext.deviceFingerprint
          }
        );

        if (suspiciousActivity.suspicious) {
          console.warn(`[AUTH] Suspicious activity on server auth: ${username}`, suspiciousActivity.flags);
        }
      } catch (error) {
        console.warn('[AUTH] Failed to check suspicious activity for server auth:', error.message);
      }

      ws.clientState = SecureStateManager.setState(ws, {
        ...ws.clientState,
        accessToken: finalTokens.accessToken,
        tokenFamily: finalTokens.family,
        hasTokens: true,
      });

      // Store full authentication state for reconnection recovery
      const { ConnectionStateManager } = await import('../presence/connection-state.js');
      await ConnectionStateManager.storeUserAuthState(username, {
        hasPassedAccountLogin: true,
        hasAuthenticated: true,
        accountAuthTime: ws.clientState.accountAuthTime || ws.clientState.authenticationTime,
        serverAuthTime: Date.now(),
        finalizedBy: 'ServerAuthHandler',
        fullAuthComplete: true,
        tokenFamily: ws.clientState.tokenFamily
      });

      // Send authentication success with tokens
      const response = {
        type: SignalType.AUTH_SUCCESS,
        message: "Authentication successful",
        username: username,
        quantumSecure: true,
        securityLevel: 256
      };

      // Include final tokens if newly generated
      if (finalTokens) {
        response.tokens = {
          accessToken: finalTokens.accessToken,
          refreshToken: finalTokens.refreshToken,
          expiresIn: finalTokens.expiresIn,
          tokenType: finalTokens.tokenType,
          quantumSecure: true
        };
      }

      // Mark WebSocket as authenticated for PQ session
      ws._authenticated = true;

      await sendSecureMessage(ws, response);

      // Deliver any queued offline messages after complete server authentication
      try {
        const { MessageDatabase } = await import('../database/database.js');
        console.log(`[AUTH] Checking for offline messages for user: ${username}`);
        const queued = await MessageDatabase.takeOfflineMessages(username, 200);
        console.log(`[AUTH] Found ${queued.length} offline messages for user: ${username}`);

        if (queued.length) {
          let deliveredCount = 0;
          for (const msg of queued) {
            try {
              await sendSecureMessage(ws, msg);
              deliveredCount++;
              console.log(`[AUTH] Delivered offline message ${deliveredCount}/${queued.length} to user: ${username}`);
            } catch (e) {
              console.error(`[AUTH] Failed to send offline message to user ${username}:`, e);
              try {
                await MessageDatabase.queueOfflineMessage(username, msg);
                console.log(`[AUTH] Re-queued failed offline message for user ${username}`);
              } catch (requeueError) {
                console.error(`[AUTH] Failed to re-queue offline message for user ${username}:`, requeueError);
              }
              break;
            }
          }
          console.log(`[AUTH] Successfully delivered ${deliveredCount}/${queued.length} offline messages to user: ${username}`);
        } else {
          console.log(`[AUTH] No offline messages found for user: ${username}`);
        }
      } catch (e) {
        console.error('[AUTH] Failed to deliver offline messages:', e);
      }

      console.log(`[AUTH] Server authentication successful for user: ${username}`);
      return true;
    } catch (error) {
      console.error(`[AUTH] Server authentication error for user ${username}:`, error);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
    }
  }

}

AccountAuthHandler.validateArgon2Parameters = async function (parsed) {
  const MIN_MEMORY = 65536;
  const MIN_TIME = 3;
  const MIN_SALT_LENGTH = 16;
  if (String(parsed.algorithm).toLowerCase() !== 'argon2id') throw new Error(`Only argon2id accepted`);
  if (parsed.memoryCost < MIN_MEMORY) throw new Error(`Memory cost too low`);
  if (parsed.timeCost < MIN_TIME) throw new Error(`Time cost too low`);
  const saltLen = typeof parsed.salt === 'string' ? Buffer.from(parsed.salt, 'base64').length : parsed.salt.length;
  if (saltLen < MIN_SALT_LENGTH) throw new Error(`Salt too short`);
  return parsed;
};

AccountAuthHandler.prototype.verifyRequestSignature = async function (data, signature, ws) {
  const clientKeyBase64 = ws.clientPublicKey;
  if (!clientKeyBase64 || typeof clientKeyBase64 !== 'string') {
    return false;
  }
  try {
    const publicKey = new Uint8Array(Buffer.from(clientKeyBase64, 'base64'));
    if (!publicKey.length) return false;
    const msg = Buffer.from(String(data), 'utf8');
    const sig = Buffer.from(signature || '', 'base64');
    if (!sig.length) return false;
    return ml_dsa87.verify(sig, msg, publicKey);
  } catch {
    return false;
  }
};
