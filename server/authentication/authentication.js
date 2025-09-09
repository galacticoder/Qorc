import * as authUtils from './auth-utils.js';
import { SignalType, SignalMessages } from '../signals.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { UserDatabase, PrekeyDatabase } from '../database/database.js';
import { rateLimitMiddleware } from '../rate-limiting/rate-limit-middleware.js';
import { isOnline as presenceIsOnline } from '../presence/presence.js';

function rejectConnection(ws, type, reason, code = 1008) {
  console.log(`[AUTH] Rejecting connection: ${type} - ${reason}`);
  ws.send(JSON.stringify({ type, message: reason }));
  ws.close(code, reason);
  return;
}

// Soft failure helper: send error without closing connection, with optional metadata
function sendAuthError(ws, { message, code = 'AUTH_FAILED', category = 'general', attemptsRemaining = undefined, locked = false, cooldownSeconds = undefined, logout = false }) {
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
  try { ws.send(JSON.stringify(payload)); } catch (e) {
    console.error('[AUTH] Failed to send soft auth error:', e?.message || e);
  }
  return { handled: true };
}

// Initialize per-connection attempt counters lazily
function ensureAttemptState(ws) {
  if (!ws.clientState) ws.clientState = {};
  if (!ws.clientState.attempts) {
    ws.clientState.attempts = {
      username: 5,
      account_password: 5,
      passphrase: 5,
      server_password: 5
    };
  }
}

function decAttempt(ws, category) {
  ensureAttemptState(ws);
  if (typeof ws.clientState.attempts[category] !== 'number') ws.clientState.attempts[category] = 5;
  ws.clientState.attempts[category] = Math.max(0, ws.clientState.attempts[category] - 1);
  return ws.clientState.attempts[category];
}

export class AccountAuthHandler {
  constructor(serverHybridKeyPair) {
    this.serverHybridKeyPair = serverHybridKeyPair;
    console.log('[AUTH] AccountAuthHandler initialized');
  }

  async processAuthRequest(ws, str) {
    console.log('[AUTH] Processing authentication request');
    
    // SECURITY: Validate input size to prevent DoS attacks
    if (!str || typeof str !== 'string') {
      console.error('[AUTH] Invalid authentication request format');
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid request format");
    }
    
    // SECURITY: Prevent extremely large payloads that could cause DoS
    if (str.length > 1048576) { // 1MB limit
      console.error('[AUTH] Authentication request too large');
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Request too large");
    }
    
    try {
      const parsed = JSON.parse(str);
      const { type, passwordData, userData } = parsed;
      
      // SECURITY: Validate parsed object structure
      if (!parsed || typeof parsed !== 'object') {
        console.error('[AUTH] Invalid authentication data structure');
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid request structure");
      }
      
      console.log(`[AUTH] Auth type: ${type}`);

      const [passwordPayload, userPayload] = await Promise.all([
        CryptoUtils.Hybrid.decryptHybridPayload(passwordData, this.serverHybridKeyPair),
        CryptoUtils.Hybrid.decryptHybridPayload(userData, this.serverHybridKeyPair)
      ]);

      if (!userPayload || !passwordPayload) {
        console.error('[AUTH] Failed to decrypt authentication data');
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
      }

      // SECURITY: Validate decrypted payload structure
      if (typeof userPayload !== 'object' || typeof passwordPayload !== 'object') {
        console.error('[AUTH] Invalid decrypted payload structure');
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
      }

      console.log('[AUTH] Decryption succeeded');
      
      const username = userPayload.usernameSent;
      const password = passwordPayload.content;
      const hybridPublicKeys = userPayload.hybridPublicKeys;
      
      // Reset per-connection attempt state when username changes mid-connection
      try {
        ensureAttemptState(ws);
        if (ws.clientState?.username && ws.clientState.username !== username) {
          ws.clientState.attempts = { username: 5, account_password: 5, passphrase: 5, server_password: 5 };
          delete ws.clientState.accountPasswordLockedUntil;
          delete ws.clientState.serverPasswordLockedUntil;
          ws.clientState.pendingPasswordHash = false;
          ws.clientState.pendingPassphrase = false;
        }
      } catch {}
      
      // SECURITY: Validate extracted fields
      if (!username || typeof username !== 'string' || username.length > 32) {
        console.error(`[AUTH] Invalid username in authentication data (type: ${typeof username}, length: ${username?.length || 0})`);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
      }
      
      if (!password || typeof password !== 'string' || password.length > 512) {
        console.error('[AUTH] Invalid password in authentication data');
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
      }

      console.log(`[AUTH] Processing auth for user: ${username}`);

      // Prevent multiple logins for the same account (already authenticated elsewhere) using presence
      if (type === SignalType.ACCOUNT_SIGN_IN) {
        let retries = 2;
        while (retries > 0) {
          try {
            const alreadyOnline = await presenceIsOnline(username);
            if (alreadyOnline) {
              console.warn(`[AUTH] User already online: ${username}`);
              // SECURITY: Add delay to prevent rapid retry attacks
              await new Promise(resolve => setTimeout(resolve, 1000));
              return rejectConnection(ws, SignalType.AUTH_ERROR, "Account already logged in");
            }
            break;
          } catch (error) {
            retries--;
            if (retries === 0) {
              console.error(`[AUTH] Failed to check presence after retries for ${username}:`, error);
            } else {
              await new Promise(resolve => setTimeout(resolve, 100));
            }
          }
        }
      }

      // SECURITY: Additional validation already performed above
      // This check is now redundant but kept for defensive programming

      // Per-user auth limiter before processing (across connections)
      try {
        const userAuthCheck = await rateLimitMiddleware.checkUserAuthStatus(username);
        if (!userAuthCheck.allowed) {
          console.warn(`[AUTH] User auth blocked by rate limit for ${username}: ${userAuthCheck.reason}`);
          // Soft error: do not disconnect; let client show timer
          return sendAuthError(ws, { message: userAuthCheck.reason, code: 'USER_AUTH_RATE_LIMIT', category: 'rate_limit' });
        }
      } catch {}

      if (!authUtils.validateUsernameFormat(username)) {
        console.error(`[AUTH] Invalid username format: "${username}" (length: ${username.length}, regex test: ${/^[a-zA-Z0-9_-]+$/.test(username)})`);
        const remaining = decAttempt(ws, 'username');
        return sendAuthError(ws, { message: SignalMessages.INVALIDNAME, code: 'INVALID_USERNAME_FORMAT', category: 'username', attemptsRemaining: remaining, locked: remaining === 0 });
      }
      if (!authUtils.validateUsernameLength(username)) {
        console.error(`[AUTH] Invalid username length: "${username}" (length: ${username.length}, expected: 3-32)`);
        const remaining = decAttempt(ws, 'username');
        return sendAuthError(ws, { message: SignalMessages.INVALIDNAMELENGTH, code: 'INVALID_USERNAME_LENGTH', category: 'username', attemptsRemaining: remaining, locked: remaining === 0 });
      }

      // Track only active connection state on the WebSocket itself; avoid global maps
      ws.clientState = { username, hasPassedAccountLogin: true, hasAuthenticated: false };

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
      console.error('[AUTH] Auth processing error:', error);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
    }
  }

  async handleSignUp(ws, username, password) {
    console.log(`[AUTH] Starting sign up for user: ${username}`);
    const existingUser = await UserDatabase.loadUser(username);
    if (existingUser) {
      console.error(`[AUTH] Username already exists: ${username}`);
      const remaining = decAttempt(ws, 'username');
      return sendAuthError(ws, { message: SignalMessages.NAMEEXISTSERROR, code: 'USERNAME_TAKEN', category: 'username', attemptsRemaining: remaining, locked: remaining === 0 });
    }

    // Expect client-side Argon2 hash; do not hash on server
    console.log(`[AUTH] Storing client-provided Argon2 password hash for user: ${username}`);

    if (typeof password !== 'string' || !password.startsWith('$argon2')) {
      console.error(`[AUTH] Expected Argon2 encoded hash for new user ${username}`);
      const remaining = decAttempt(ws, 'account_password');
      return sendAuthError(ws, { message: "Invalid password hash format", code: 'INVALID_PASSWORD_HASH', category: 'account_password', attemptsRemaining: remaining, locked: remaining === 0 });
    }

    // Parse Argon2 parameters from the provided encoded hash and persist them for future login
    let parsed;
    try {
      parsed = await CryptoUtils.Password.parseArgon2Hash(password);
      // Validate parsed values
      if (!parsed || !parsed.salt) throw new Error('Invalid Argon2 hash parameters');
    } catch (e) {
      console.error(`[AUTH] Failed to parse password hash params for user ${username}:`, e);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid password hash parameters");
    }

    const userRecord = {
      username,
      passwordHash: password, // Store encoded Argon2 hash from client
      passphraseHash: null,
      version: null,
      algorithm: null,
      salt: null,
      memoryCost: null,
      timeCost: null,
      parallelism: null,
      // Persist password params for deterministic future verification
      passwordVersion: parsed.version,
      passwordAlgorithm: parsed.algorithm,
      passwordSalt: parsed.salt.toString('base64'),
      passwordMemoryCost: parsed.memoryCost,
      passwordTimeCost: parsed.timeCost,
      passwordParallelism: parsed.parallelism
    };

    await UserDatabase.saveUserRecord(userRecord);
    console.log(`[AUTH] User record saved for: ${username}`);

    // SECURITY: Removed server-side prekey generation - client will generate prekeys

    ws.send(JSON.stringify({
      type: SignalType.PASSPHRASE_HASH,
      message: "Please hash your passphrase and send it back"
    }));

    ws.clientState.pendingPassphrase = true;
    console.log(`[AUTH] User ${username} pending passphrase set on connection`);
    return { username, pending: true };
  }

  async handleSignIn(ws, username, password) {
    console.log(`[AUTH] Starting sign in for user: ${username}`);
    
    // Check local cooldown for account password attempts
    ensureAttemptState(ws);
    if (ws.clientState.accountPasswordLockedUntil && Date.now() < ws.clientState.accountPasswordLockedUntil) {
      const secondsLeft = Math.ceil((ws.clientState.accountPasswordLockedUntil - Date.now()) / 1000);
      return sendAuthError(ws, { message: "Too many attempts. Please wait before trying again.", code: 'ACCOUNT_PASSWORD_COOLDOWN', category: 'account_password', attemptsRemaining: 0, locked: true, cooldownSeconds: secondsLeft });
    }
    
    // SECURITY: Additional timing attack protection
    const startTime = Date.now();
    
    const userData = await UserDatabase.loadUser(username);
    if (!userData) {
      console.error(`[AUTH] Account does not exist: ${username}`);
      // SECURITY: Consistent timing to prevent user enumeration
      const elapsedTime = Date.now() - startTime;
      const minTime = 200; // Minimum 200ms response time
      if (elapsedTime < minTime) {
        await new Promise(resolve => setTimeout(resolve, minTime - elapsedTime));
      }
      const remaining = decAttempt(ws, 'username');
      return sendAuthError(ws, { message: "Account does not exist, Register instead.", code: 'ACCOUNT_NOT_FOUND', category: 'username', attemptsRemaining: remaining, locked: remaining === 0 });
    }

    // Password hash parameter negotiation for Argon2
    const isStoredArgon2 = typeof userData.passwordHash === 'string' && userData.passwordHash.startsWith('$argon2');

    // If stored is Argon2 but incoming isn't, send challenge with stored params
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
            salt: parsedHash.salt.toString('base64'),
            memoryCost: parsedHash.memoryCost,
            timeCost: parsedHash.timeCost,
            parallelism: parsedHash.parallelism
          };
        } catch (e) {
          console.error(`[AUTH] Failed to parse stored password hash for ${username}:`, e);
          return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
        }
      }

      ws.send(JSON.stringify({
        type: SignalType.PASSWORD_HASH_PARAMS,
        version: hashParams.version,
        algorithm: hashParams.algorithm,
        salt: hashParams.salt,
        memoryCost: hashParams.memoryCost,
        timeCost: hashParams.timeCost,
        parallelism: hashParams.parallelism,
        message: "Please hash your password with these parameters and send back"
      }));

      ws.clientState.pendingPasswordHash = true;
      console.log(`[AUTH] User ${username} pending password hash challenge`);
      return { username, pending: true };
    }

    // Handle both new client-hashed passwords and legacy plaintext passwords
    let isPasswordValid = false;
    let needsMigration = false;
    
    try {
      if (isStoredArgon2) {
        // Both are hashes - constant-time equality comparison
        const crypto = await import('crypto');
        const maxLength = Math.max(userData.passwordHash.length, password.length);
        const normalizedStored = Buffer.from(userData.passwordHash.padEnd(maxLength, '\0'), 'utf8');
        const normalizedProvided = Buffer.from(password.padEnd(maxLength, '\0'), 'utf8');
        isPasswordValid = crypto.timingSafeEqual(normalizedStored, normalizedProvided) &&
                         userData.passwordHash.length === password.length;
      } else {
        // Legacy plaintext stored password
        console.log(`[AUTH] Legacy plaintext comparison for ${username}`);
        const crypto = await import('crypto');
        const maxLength = Math.max((userData.passwordHash || '').length, password.length);
        const normalizedStored = Buffer.from((userData.passwordHash || '').padEnd(maxLength, '\0'), 'utf8');
        const normalizedProvided = Buffer.from(password.padEnd(maxLength, '\0'), 'utf8');
        isPasswordValid = crypto.timingSafeEqual(normalizedStored, normalizedProvided) &&
                         (userData.passwordHash || '').length === password.length;
        if (isPasswordValid) {
          needsMigration = true;
          console.log(`[AUTH] Legacy user ${username} authenticated - advise client-side reset to migrate`);
        }
      }
    } catch (error) {
      console.error(`[AUTH] Error during password verification: ${error.message}`);
      isPasswordValid = false;
    }
    
    // Migrate legacy passwords to hashed format after successful authentication
    if (isPasswordValid && needsMigration) {
      // Skipping automatic migration (client-side hashing only); suggest a client-side password reset to migrate
      console.log(`[AUTH] Legacy password verified for ${username} - suggest client-side password reset to migrate to Argon2`);
    }
    
    if (!isPasswordValid) {
      console.error(`[AUTH] Incorrect password for user: ${username}`);
      // SECURITY: Do not consume per-user rate limit here; rely on 5-attempt logic and per-connection limit
      
      // SECURITY: Consistent timing to prevent timing attacks
      const elapsedTime = Date.now() - startTime;
      const minTime = 300; // Minimum 300ms for failed attempts
      if (elapsedTime < minTime) {
        await new Promise(resolve => setTimeout(resolve, minTime - elapsedTime));
      }
      
      // Decrement account password attempts and optionally apply cooldown
      const remaining = decAttempt(ws, 'account_password');
      let cooldownSeconds = undefined;
      if (remaining === 0) {
        // Apply short cooldown like typical apps
        const COOLDOWN = 60; // 60 seconds
        ws.clientState.accountPasswordLockedUntil = Date.now() + COOLDOWN * 1000;
        cooldownSeconds = COOLDOWN;
      }
      return sendAuthError(ws, { message: "Incorrect password", code: remaining === 0 ? 'ACCOUNT_PASSWORD_LOCKED' : 'INCORRECT_PASSWORD', category: 'account_password', attemptsRemaining: remaining, locked: remaining === 0, cooldownSeconds });
    }

    console.log(`[AUTH] Password verified for user: ${username}`);

    if (userData.version && userData.salt) {
      console.log(`[AUTH] Requesting passphrase for user: ${username}`);
      ws.send(JSON.stringify({
        type: SignalType.PASSPHRASE_HASH,
        version: userData.version,
        algorithm: userData.algorithm,
        salt: userData.salt.toString('base64'),
        memoryCost: userData.memoryCost,
        timeCost: userData.timeCost,
        parallelism: userData.parallelism,
        message: "Please hash your passphrase with this info and send back"
      }));

      ws.clientState.pendingPassphrase = true;
      console.log(`[AUTH] User ${username} pending passphrase set for sign in`);
      return { username, pending: true };
    }

    console.error(`[AUTH] No passphrase hash info for user: ${username}`);
    return rejectConnection(ws, SignalType.AUTH_ERROR, "No passphrase hash info stored. Sign up instead");
  }

  async handlePassphrase(ws, username, passphraseHash, isNewUser = false) {
    console.log(`[AUTH] Handling passphrase for user: ${username}, isNewUser: ${isNewUser}`);
    
    // SECURITY: Validate inputs
    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[AUTH] Invalid username in passphrase handling: ${username}`);
      const remaining = decAttempt(ws, 'username');
      return sendAuthError(ws, { message: "Invalid username", code: 'INVALID_USERNAME', category: 'username', attemptsRemaining: remaining, locked: remaining === 0 });
    }
    
    if (!passphraseHash || typeof passphraseHash !== 'string' || passphraseHash.length < 10 || passphraseHash.length > 1000) {
      console.error(`[AUTH] Invalid passphrase hash format for user: ${username}`);
      const remaining = decAttempt(ws, 'passphrase');
      // If exhausted on passphrase at this stage, log out but keep connection
      if (remaining === 0) {
        try {
          const { ConnectionStateManager } = await import('../presence/connection-state.js');
          if (ws._sessionId) await ConnectionStateManager.updateState(ws._sessionId, { hasPassedAccountLogin: false, hasAuthenticated: false, username: null, pendingPassphrase: false });
          if (username) await ConnectionStateManager.clearUserAuthState(username);
        } catch (e) { console.warn('[AUTH] Failed to update state during passphrase lockout:', e?.message || e); }
        return sendAuthError(ws, { message: "Invalid passphrase format", code: 'PASSPHRASE_LOCKED', category: 'passphrase', attemptsRemaining: 0, locked: true, logout: true });
      }
      return sendAuthError(ws, { message: "Invalid passphrase format", code: 'INVALID_PASSPHRASE_FORMAT', category: 'passphrase', attemptsRemaining: remaining, locked: false });
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

    if (isNewUser) {
      console.log(`[AUTH] Processing new user passphrase for: ${username}`);
      
      // SECURITY: Validate passphrase hash format for new users
      if (!passphraseHash.startsWith('$argon2')) {
        console.error(`[AUTH] Invalid passphrase hash format for new user: ${username}`);
        const remaining = decAttempt(ws, 'passphrase');
        if (remaining === 0) {
          try {
            const { ConnectionStateManager } = await import('../presence/connection-state.js');
            if (ws._sessionId) await ConnectionStateManager.updateState(ws._sessionId, { hasPassedAccountLogin: false, hasAuthenticated: false, username: null, pendingPassphrase: false });
            if (username) await ConnectionStateManager.clearUserAuthState(username);
          } catch (e) { console.warn('[AUTH] Failed to update state during passphrase lockout (new user):', e?.message || e); }
          return sendAuthError(ws, { message: "Invalid passphrase hash format", code: 'PASSPHRASE_LOCKED', category: 'passphrase', attemptsRemaining: 0, locked: true, logout: true });
        }
        return sendAuthError(ws, { message: "Invalid passphrase hash format", code: 'INVALID_PASSPHRASE_HASH', category: 'passphrase', attemptsRemaining: remaining, locked: false });
      }
      
      userRecord.passphraseHash = passphraseHash;
      try {
        const parsed = await CryptoUtils.Password.parseArgon2Hash(passphraseHash);
        
        // SECURITY: Validate parsed parameters
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
        userRecord.salt = parsed.salt.toString('base64');
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
      console.log(`[AUTH] Verifying passphrase for existing user: ${username}`);
      
      // SECURITY: Enhanced constant-time comparison to prevent timing attacks
      const storedHash = userRecord.passphraseHash;
      const providedHash = passphraseHash;

      if (!storedHash || !providedHash) {
        console.error(`[AUTH] Missing passphrase hash for user: ${username}`);
        const remaining = decAttempt(ws, 'passphrase');
        if (remaining === 0) {
          try {
            const { ConnectionStateManager } = await import('../presence/connection-state.js');
            if (ws._sessionId) await ConnectionStateManager.updateState(ws._sessionId, { hasPassedAccountLogin: false, hasAuthenticated: false, username: null, pendingPassphrase: false });
            if (username) await ConnectionStateManager.clearUserAuthState(username);
          } catch (e) { console.warn('[AUTH] Failed to update state during missing passphrase lockout:', e?.message || e); }
          return sendAuthError(ws, { message: "Authentication failed", code: 'PASSPHRASE_LOCKED', category: 'passphrase', attemptsRemaining: 0, locked: true, logout: true });
        }
        return sendAuthError(ws, { message: "Authentication failed", code: 'PASSPHRASE_MISSING', category: 'passphrase', attemptsRemaining: remaining, locked: false });
      }

      // SECURITY: Use crypto.timingSafeEqual for proper constant-time comparison
      const crypto = await import('crypto');
      let isValid = false;

      try {
        // Ensure both strings are the same length by padding with null bytes
        const maxLength = Math.max(storedHash.length, providedHash.length);
        const normalizedStored = Buffer.from(storedHash.padEnd(maxLength, '\0'), 'utf8');
        const normalizedProvided = Buffer.from(providedHash.padEnd(maxLength, '\0'), 'utf8');

        // Use Node.js built-in constant-time comparison
        isValid = crypto.timingSafeEqual(normalizedStored, normalizedProvided) &&
                  storedHash.length === providedHash.length;
      } catch (error) {
        console.error(`[AUTH] Error during constant-time comparison: ${error.message}`);
        isValid = false;
      }

      if (!isValid) {
        console.error(`[AUTH] Passphrase verification failed for user: ${username}`);
        // SECURITY: Do not consume per-user rate limit here; rely on 5-attempt logic and per-connection limit
        const remaining = decAttempt(ws, 'passphrase');
        if (remaining === 0) {
          try {
            const { ConnectionStateManager } = await import('../presence/connection-state.js');
            if (ws._sessionId) await ConnectionStateManager.updateState(ws._sessionId, { hasPassedAccountLogin: false, hasAuthenticated: false, username: null, pendingPassphrase: false });
            if (username) await ConnectionStateManager.clearUserAuthState(username);
          } catch (e) { console.warn('[AUTH] Failed to update state during passphrase lockout:', e?.message || e); }
          return sendAuthError(ws, { message: "Authentication failed", code: 'PASSPHRASE_LOCKED', category: 'passphrase', attemptsRemaining: 0, locked: true, logout: true });
        }
        return sendAuthError(ws, { message: "Authentication failed", code: 'INCORRECT_PASSPHRASE', category: 'passphrase', attemptsRemaining: remaining, locked: false });
      }
      
      console.log(`[AUTH] Passphrase verified for user: ${username}`);
    }

    // SECURITY: Clear sensitive data from memory
    passphraseHash = null;

    ws.clientState.pendingPassphrase = false;
    console.log(`[AUTH] User ${username} cleared pending passphrase on connection`);

    const auth = await this.finalizeAuth(ws, username, isNewUser ? "User registered with passphrase" : "User logged in with passphrase");

    // Attach verification time to this connection only
    ws.clientState = {
      ...(ws.clientState || {}),
      username,
      hasPassedAccountLogin: true,
      hasAuthenticated: ws.clientState?.hasAuthenticated || false,
      passphraseVerifiedAt: Date.now()
    };

    console.log(`[AUTH] Authentication completed for user: ${username}`);
    return auth;
  }

  async handlePasswordHash(ws, username, hashedPassword) {
    console.log(`[AUTH] Handling password hash response for user: ${username}`);
    
    // Respect cooldown for account password attempts
    ensureAttemptState(ws);
    if (ws.clientState.accountPasswordLockedUntil && Date.now() < ws.clientState.accountPasswordLockedUntil) {
      const secondsLeft = Math.ceil((ws.clientState.accountPasswordLockedUntil - Date.now()) / 1000);
      return sendAuthError(ws, { message: "Too many attempts. Please wait before trying again.", code: 'ACCOUNT_PASSWORD_COOLDOWN', category: 'account_password', attemptsRemaining: 0, locked: true, cooldownSeconds: secondsLeft });
    }
    
    // Validate inputs
    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[AUTH] Invalid username in password hash handling: ${username}`);
      const remaining = decAttempt(ws, 'username');
      return sendAuthError(ws, { message: "Invalid username", code: 'INVALID_USERNAME', category: 'username', attemptsRemaining: remaining, locked: remaining === 0 });
    }
    
    if (!hashedPassword || typeof hashedPassword !== 'string' || !hashedPassword.startsWith('$argon2')) {
      console.error(`[AUTH] Invalid password hash format for user: ${username}`);
      const remaining = decAttempt(ws, 'account_password');
      return sendAuthError(ws, { message: "Invalid password hash format", code: 'INVALID_PASSWORD_HASH', category: 'account_password', attemptsRemaining: remaining, locked: remaining === 0 });
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
      const crypto = await import('crypto');
      const maxLength = Math.max(userData.passwordHash.length, hashedPassword.length);
      const normalizedStored = Buffer.from(userData.passwordHash.padEnd(maxLength, '\0'), 'utf8');
      const normalizedProvided = Buffer.from(hashedPassword.padEnd(maxLength, '\0'), 'utf8');
      isPasswordValid = crypto.timingSafeEqual(normalizedStored, normalizedProvided) &&
                       userData.passwordHash.length === hashedPassword.length;
    } catch (error) {
      console.error(`[AUTH] Error during password hash verification: ${error.message}`);
      isPasswordValid = false;
    }
    
    if (!isPasswordValid) {
      console.error(`[AUTH] Incorrect password hash for user: ${username}`);
      const remaining = decAttempt(ws, 'account_password');
      let cooldownSeconds = undefined;
      if (remaining === 0) {
        const COOLDOWN = 60;
        ws.clientState.accountPasswordLockedUntil = Date.now() + COOLDOWN * 1000;
        cooldownSeconds = COOLDOWN;
      }
      return sendAuthError(ws, { message: "Incorrect password", code: remaining === 0 ? 'ACCOUNT_PASSWORD_LOCKED' : 'INCORRECT_PASSWORD', category: 'account_password', attemptsRemaining: remaining, locked: remaining === 0, cooldownSeconds });
    }

    console.log(`[AUTH] Password verified for user: ${username}`);
    
    // Clear pending flag
    ws.clientState.pendingPasswordHash = false;

    // Continue with passphrase verification like normal sign-in flow
    if (userData.version && userData.salt) {
      console.log(`[AUTH] Requesting passphrase for user: ${username}`);
      ws.send(JSON.stringify({
        type: SignalType.PASSPHRASE_HASH,
        version: userData.version,
        algorithm: userData.algorithm,
        salt: userData.salt.toString('base64'),
        memoryCost: userData.memoryCost,
        timeCost: userData.timeCost,
        parallelism: userData.parallelism,
        message: "Please hash your passphrase with this info and send back"
      }));

      ws.clientState.pendingPassphrase = true;
      console.log(`[AUTH] User ${username} pending passphrase set for sign in`);
      return { username, pending: true };
    }

    console.error(`[AUTH] No passphrase hash info for user: ${username}`);
    return rejectConnection(ws, SignalType.AUTH_ERROR, "No passphrase hash info stored. Sign up instead");
  }

  async finalizeAuth(ws, username, logMessage) {
    console.log(`[AUTH] Finalizing authentication: ${logMessage} for user: ${username}`);

    // SECURITY: Validate authentication state transition using ws state only
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

    // SECURITY: Update state atomically on this connection only
    // Note: hasAuthenticated should only be set by ServerAuthHandler after server login
    ws.clientState = {
      ...ws.clientState,
      authenticationTime: Date.now(),
      finalizedBy: 'AccountAuthHandler'
    };

    // Store account authentication state for reconnection recovery
    const { ConnectionStateManager } = await import('../presence/connection-state.js');
    await ConnectionStateManager.storeUserAuthState(username, {
      hasPassedAccountLogin: true,
      hasAuthenticated: false, // Server auth still required
      accountAuthTime: Date.now(),
      finalizedBy: 'AccountAuthHandler'
    });

    ws.send(JSON.stringify({
      type: SignalType.IN_ACCOUNT,
      message: "Account authentication successful"
    }));

    // SECURITY: Removed server-side prekey replenishment - client manages prekeys

    // SECURITY: Offline message delivery moved to server authentication handler
    // Messages will only be delivered after server password authentication is complete

    console.log(`[AUTH] Authentication successful for user: ${username}`);
    return { username, authenticated: true };
  }

}

export class ServerAuthHandler {
  constructor(serverHybridKeyPair, _unusedClients, serverConfig) {
    this.serverHybridKeyPair = serverHybridKeyPair;
    this.ServerConfig = serverConfig;
    console.log('[AUTH] ServerAuthHandler initialized');
  }

  async handleServerAuthentication(ws, str, clientState) {
    console.log(`[AUTH] Handling server authentication for user: ${clientState.username}`);
    const parsed = JSON.parse(str);

    if (parsed.type !== SignalType.SERVER_LOGIN) {
      console.error(`[AUTH] Expected SERVER_LOGIN but got: ${parsed.type}`);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Expected login information");
    }

    try {
      // Respect cooldown for server password attempts
      ensureAttemptState(ws);
      if (ws.clientState.serverPasswordLockedUntil && Date.now() < ws.clientState.serverPasswordLockedUntil) {
        const secondsLeft = Math.ceil((ws.clientState.serverPasswordLockedUntil - Date.now()) / 1000);
        return sendAuthError(ws, { message: "Too many attempts. Please wait before trying again.", code: 'SERVER_PASSWORD_COOLDOWN', category: 'server_password', attemptsRemaining: 0, locked: true, cooldownSeconds: secondsLeft });
      }

      const passwordPayload = await CryptoUtils.Hybrid.decryptHybridPayload(parsed.passwordData, this.serverHybridKeyPair);

      if (!passwordPayload || !passwordPayload.content) {
        console.error(`[AUTH] Invalid password format for user: ${clientState.username}`);
        const remaining = decAttempt(ws, 'server_password');
        return sendAuthError(ws, { message: "Invalid password format", code: 'INVALID_SERVER_PASSWORD_FORMAT', category: 'server_password', attemptsRemaining: remaining, locked: remaining === 0 });
      }

      const serverPasswordHash = this.ServerConfig.getServerPasswordHash();
      if (!serverPasswordHash) {
        console.error('[AUTH] Server password not configured');
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Server not properly configured");
      }
      
      const passwordValid = await CryptoUtils.Password.verifyPassword(serverPasswordHash, passwordPayload.content);

      if (!passwordValid) {
        console.error(`[AUTH] Incorrect server password for user: ${clientState.username}`);
        const remaining = decAttempt(ws, 'server_password');
        let cooldownSeconds = undefined;
        if (remaining === 0) {
          // Discord-like behavior: apply cooldown without disconnect
          const COOLDOWN = 60; // 60 seconds cooldown
          ws.clientState.serverPasswordLockedUntil = Date.now() + COOLDOWN * 1000;
          cooldownSeconds = COOLDOWN;
        }
        return sendAuthError(ws, { message: "Incorrect password", code: remaining === 0 ? 'SERVER_PASSWORD_LOCKED' : 'INCORRECT_SERVER_PASSWORD', category: 'server_password', attemptsRemaining: remaining, locked: remaining === 0, cooldownSeconds });
      }

      // SECURITY: Validate state transition for server authentication using ws state
      if (!ws.clientState?.hasPassedAccountLogin) {
        console.error(`[AUTH] Invalid state - account login not completed: ${clientState.username}`);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Account authentication required first");
      }

      if (ws.clientState?.hasAuthenticated) {
        console.error(`[AUTH] User already authenticated: ${clientState.username}`);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "User already authenticated");
      }

      // SECURITY: Atomic state update
      ws.clientState = {
        ...(ws.clientState || {}),
        hasAuthenticated: true,
        serverAuthTime: Date.now(),
        finalizedBy: 'ServerAuthHandler'
      };

      // Store full authentication state for reconnection recovery
      const { ConnectionStateManager } = await import('../presence/connection-state.js');
      await ConnectionStateManager.storeUserAuthState(clientState.username, {
        hasPassedAccountLogin: true,
        hasAuthenticated: true,
        accountAuthTime: ws.clientState.accountAuthTime || ws.clientState.authenticationTime,
        serverAuthTime: Date.now(),
        finalizedBy: 'ServerAuthHandler',
        fullAuthComplete: true
      });

      ws.send(JSON.stringify({
        type: SignalType.AUTH_SUCCESS,
        message: "Authentication successful"
      }));

      // Deliver any queued offline messages after complete server authentication
      try {
        const { MessageDatabase } = await import('../database/database.js');
        console.log(`[AUTH] Checking for offline messages for user: ${clientState.username}`);
        const queued = await MessageDatabase.takeOfflineMessages(clientState.username, 200);
        console.log(`[AUTH] Found ${queued.length} offline messages for user: ${clientState.username}`);
        
        if (queued.length) {
          let deliveredCount = 0;
          for (const msg of queued) {
            try {
              ws.send(JSON.stringify(msg));
              deliveredCount++;
              console.log(`[AUTH] Delivered offline message ${deliveredCount}/${queued.length} to user: ${clientState.username}`);
            } catch (e) {
              console.error(`[AUTH] Failed to send offline message to user ${clientState.username}:`, e);
              // If sending fails, re-queue
              try {
                await MessageDatabase.queueOfflineMessage(clientState.username, msg);
                console.log(`[AUTH] Re-queued failed offline message for user ${clientState.username}`);
              } catch (requeueError) {
                console.error(`[AUTH] Failed to re-queue offline message for user ${clientState.username}:`, requeueError);
              }
              break;
            }
          }
          console.log(`[AUTH] Successfully delivered ${deliveredCount}/${queued.length} offline messages to user: ${clientState.username}`);
        } else {
          console.log(`[AUTH] No offline messages found for user: ${clientState.username}`);
        }
      } catch (e) {
        console.error('[AUTH] Failed to deliver offline messages:', e);
      }

      console.log(`[AUTH] Server authentication successful for user: ${clientState.username}`);
      return true;
    } catch (error) {
      console.error(`[AUTH] Server authentication error for user ${clientState.username}:`, error);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
    }
  }
}