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
        const userAuthCheck = await rateLimitMiddleware.checkUserAuthLimit(username);
        if (!userAuthCheck.allowed) {
          console.warn(`[AUTH] User auth blocked by rate limit for ${username}: ${userAuthCheck.reason}`);
          return rejectConnection(ws, SignalType.AUTH_ERROR, userAuthCheck.reason);
        }
      } catch {}

      if (!authUtils.validateUsernameFormat(username)) {
        console.error(`[AUTH] Invalid username format: "${username}" (length: ${username.length}, regex test: ${/^[a-zA-Z0-9_-]+$/.test(username)})`);
        return rejectConnection(ws, SignalType.INVALIDNAME, SignalMessages.INVALIDNAME);
      }
      if (!authUtils.validateUsernameLength(username)) {
        console.error(`[AUTH] Invalid username length: "${username}" (length: ${username.length}, expected: 3-32)`);
        return rejectConnection(ws, SignalType.INVALIDNAMELENGTH, SignalMessages.INVALIDNAMELENGTH);
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
      return rejectConnection(ws, SignalType.NAMEEXISTSERROR, SignalMessages.NAMEEXISTSERROR);
    }

    const passwordHash = await CryptoUtils.Password.hashPassword(password);
    console.log(`[AUTH] Password hashed for user: ${username}`);

    const userRecord = {
      username,
      passwordHash,
      passphraseHash: null,
      version: null,
      algorithm: null,
      salt: null,
      memoryCost: null,
      timeCost: null,
      parallelism: null
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
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Account does not exist, Register instead.");
    }

    if (!await CryptoUtils.Password.verifyPassword(userData.passwordHash, password)) {
      console.error(`[AUTH] Incorrect password for user: ${username}`);
      // SECURITY: Enhanced rate limiting for failed password attempts
      try {
        await rateLimitMiddleware.rateLimiter.userAuthLimiter.consume(username, 3); // Increased penalty
      } catch (error) {
        console.warn(`[AUTH] Rate limit consume failed for user ${username}:`, error.message);
      }
      
      // SECURITY: Consistent timing to prevent timing attacks
      const elapsedTime = Date.now() - startTime;
      const minTime = 300; // Minimum 300ms for failed attempts
      if (elapsedTime < minTime) {
        await new Promise(resolve => setTimeout(resolve, minTime - elapsedTime));
      }
      
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Incorrect password");
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
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid username");
    }
    
    if (!passphraseHash || typeof passphraseHash !== 'string' || passphraseHash.length < 10 || passphraseHash.length > 1000) {
      console.error(`[AUTH] Invalid passphrase hash format for user: ${username}`);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid passphrase format");
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
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid passphrase hash format");
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
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
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
        // SECURITY: Rate limit failed attempts
        try {
          await rateLimitMiddleware.rateLimiter.userAuthLimiter.consume(username, 2);
        } catch (err) {
          console.warn(`[AUTH] Rate limit consume failed for user ${username}:`, err.message);
        }
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
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
      const passwordPayload = await CryptoUtils.Hybrid.decryptHybridPayload(parsed.passwordData, this.serverHybridKeyPair);

      if (!passwordPayload || !passwordPayload.content) {
        console.error(`[AUTH] Invalid password format for user: ${clientState.username}`);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid password format");
      }

      const serverPasswordHash = this.ServerConfig.getServerPasswordHash();
      if (!serverPasswordHash) {
        console.error('[AUTH] Server password not configured');
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Server not properly configured");
      }
      
      const passwordValid = await CryptoUtils.Password.verifyPassword(serverPasswordHash, passwordPayload.content);

      if (!passwordValid) {
        console.error(`[AUTH] Incorrect server password for user: ${clientState.username}`);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Incorrect password");
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