import * as authUtils from './auth-utils.js';
import { SignalType, SignalMessages } from '../signals.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { UserDatabase } from '../database/database.js';
import { rateLimitMiddleware } from '../rate-limiting/rate-limit-middleware.js';

function rejectConnection(ws, type, reason, code = 1008) {
  console.log(`[AUTH] Rejecting connection: ${type} - ${reason}`);
  ws.send(JSON.stringify({ type, message: reason }));
  ws.close(code, reason);
  return;
}

export class AccountAuthHandler {
  constructor(serverHybridKeyPair, clients) {
    this.serverHybridKeyPair = serverHybridKeyPair;
    this.clients = clients;
    this.pendingPassphrases = new Map();
    console.log('[AUTH] AccountAuthHandler initialized');
  }

  async processAuthRequest(ws, str) {
    console.log('[AUTH] Processing authentication request');
    try {
      const { type, passwordData, userData } = JSON.parse(str);
      console.log(`[AUTH] Auth type: ${type}`);

      const [passwordPayload, userPayload] = await Promise.all([
        CryptoUtils.Hybrid.decryptHybridPayload(passwordData, this.serverHybridKeyPair),
        CryptoUtils.Hybrid.decryptHybridPayload(userData, this.serverHybridKeyPair)
      ]);

      if (!userPayload || !passwordPayload) {
        console.error('[AUTH] Failed to decrypt authentication data');
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Failed to decrypt authentication data");
      }

      const username = userPayload.usernameSent;
      const password = passwordPayload.content;
      const hybridPublicKeys = userPayload.hybridPublicKeys;

      console.log(`[AUTH] Processing auth for user: ${username}`);

      // Prevent multiple logins for the same account (already authenticated elsewhere)
      if (type === SignalType.ACCOUNT_SIGN_IN) {
        const existing = this.clients.get(username);
        const isAlreadyLoggedIn = !!(existing && existing.clientState && existing.clientState.hasAuthenticated);
        if (isAlreadyLoggedIn) {
          console.warn(`[AUTH] User already logged in: ${username}`);
          return rejectConnection(ws, SignalType.AUTH_ERROR, "Account already logged in");
        }
      }

      if (!username || !password) {
        console.error('[AUTH] Invalid authentication data format');
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid authentication data format");
      }

      // Per-user auth limiter before processing (across connections)
      try {
        const userAuthCheck = await rateLimitMiddleware.checkUserAuthLimit(username);
        if (!userAuthCheck.allowed) {
          console.warn(`[AUTH] User auth blocked by rate limit for ${username}: ${userAuthCheck.reason}`);
          return rejectConnection(ws, SignalType.AUTH_ERROR, userAuthCheck.reason);
        }
      } catch {}

      if (!authUtils.validateUsernameFormat(username)) {
        console.error(`[AUTH] Invalid username format: ${username}`);
        return rejectConnection(ws, SignalType.INVALIDNAME, SignalMessages.INVALIDNAME);
      }
      if (!authUtils.validateUsernameLength(username)) {
        console.error(`[AUTH] Invalid username length: ${username}`);
        return rejectConnection(ws, SignalType.INVALIDNAMELENGTH, SignalMessages.INVALIDNAMELENGTH);
      }

      // Track only active connection state; do not store user keys or profiles in memory
      this.clients.set(username, {
        ws,
        clientState: { username, hasPassedAccountLogin: true, hasAuthenticated: false }
      });

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
    const existingUser = UserDatabase.loadUser(username);
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

    UserDatabase.saveUserRecord(userRecord);
    console.log(`[AUTH] User record saved for: ${username}`);

    ws.send(JSON.stringify({
      type: SignalType.PASSPHRASE_HASH,
      message: "Please hash your passphrase and send it back"
    }));

    this.pendingPassphrases.set(username, ws);
    console.log(`[AUTH] User ${username} added to pending passphrases`);
    return { username, pending: true };
  }

  async handleSignIn(ws, username, password) {
    console.log(`[AUTH] Starting sign in for user: ${username}`);
    const userData = UserDatabase.loadUser(username);
    if (!userData) {
      console.error(`[AUTH] Account does not exist: ${username}`);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Account does not exist, Register instead.");
    }

    if (!await CryptoUtils.Password.verifyPassword(userData.passwordHash, password)) {
      console.error(`[AUTH] Incorrect password for user: ${username}`);
      try { await rateLimitMiddleware.rateLimiter.userAuthLimiter.consume(username, 1); } catch {}
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

      this.pendingPassphrases.set(username, ws);
      console.log(`[AUTH] User ${username} added to pending passphrases for sign in`);
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
    
    if (!this.pendingPassphrases.has(username)) {
      console.error(`[AUTH] Unexpected passphrase submission for user: ${username}`);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Unexpected passphrase submission");
    }

    const userRecord = UserDatabase.loadUser(username);
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
      UserDatabase.saveUserRecord(userRecord);
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
      
      // SECURITY: Normalize lengths and use constant-time comparison
      const maxLength = Math.max(storedHash.length, providedHash.length);
      const normalizedStored = storedHash.padEnd(maxLength, '\0');
      const normalizedProvided = providedHash.padEnd(maxLength, '\0');
      
      let result = 0;
      for (let i = 0; i < maxLength; i++) {
        result |= normalizedStored.charCodeAt(i) ^ normalizedProvided.charCodeAt(i);
      }
      
      // SECURITY: Add additional length check to prevent bypass
      result |= storedHash.length ^ providedHash.length;
      
      if (result !== 0) {
        console.error(`[AUTH] Passphrase verification failed for user: ${username}`);
        // SECURITY: Rate limit failed attempts
        try { 
          await rateLimitMiddleware.rateLimiter.userAuthLimiter.consume(username, 2); 
        } catch {}
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
      }
      
      console.log(`[AUTH] Passphrase verified for user: ${username}`);
    }

    // SECURITY: Clear sensitive data from memory
    passphraseHash = null;

    this.pendingPassphrases.delete(username);
    console.log(`[AUTH] User ${username} removed from pending passphrases`);

    const auth = await this.finalizeAuth(ws, username, isNewUser ? "User registered with passphrase" : "User logged in with passphrase");

    // SECURITY: Validate existing client state before updating
    const existingClient = this.clients.get(username);
    if (existingClient && existingClient.ws !== ws) {
      console.error(`[AUTH] WebSocket mismatch during passphrase handling: ${username}`);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Connection state inconsistency");
    }

    this.clients.set(username, {
      ws,
      clientState: {
        username,
        hasPassedAccountLogin: true,
        hasAuthenticated: false, // Both registration and login need server password
        passphraseVerifiedAt: Date.now()
      },
      hybridPublicKeys: existingClient?.hybridPublicKeys || null
    });

    console.log(`[AUTH] Authentication completed for user: ${username}`);
    return auth;
  }

  finalizeAuth(ws, username, logMessage) {
    console.log(`[AUTH] Finalizing authentication: ${logMessage} for user: ${username}`);

    // SECURITY: Comprehensive state validation to prevent bypass attacks
    const existingClient = this.clients.get(username);

    // SECURITY: Validate authentication state transition
    if (existingClient) {
      if (existingClient.clientState?.hasAuthenticated) {
        console.error(`[AUTH] User already authenticated: ${username}`);
        return rejectConnection(ws, SignalType.NAMEEXISTSERROR, SignalMessages.NAMEEXISTSERROR);
      }

      // SECURITY: Ensure proper state progression
      if (!existingClient.clientState?.hasPassedAccountLogin) {
        console.error(`[AUTH] Invalid state transition - account login not completed: ${username}`);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid authentication state");
      }

      // SECURITY: Validate WebSocket connection consistency
      if (existingClient.ws !== ws) {
        console.error(`[AUTH] WebSocket mismatch during finalization: ${username}`);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Connection state inconsistency");
      }
    } else {
      console.error(`[AUTH] No existing client state found during finalization: ${username}`);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid authentication state");
    }

    if (authUtils.isServerFull(this.clients)) {
      console.error(`[AUTH] Server is full, rejecting user: ${username}`);
      return rejectConnection(ws, SignalType.SERVERLIMIT, SignalMessages.SERVERLIMIT, 101);
    }

    // SECURITY: Update state atomically to prevent race conditions
    this.clients.set(username, {
      ...existingClient,
      clientState: {
        ...existingClient.clientState,
        hasAuthenticated: true,
        authenticationTime: Date.now(),
        finalizedBy: 'AccountAuthHandler'
      }
    });

    ws.send(JSON.stringify({
      type: SignalType.IN_ACCOUNT,
      message: "Account authentication successful"
    }));

    console.log(`[AUTH] Authentication successful for user: ${username}`);
    return { username, authenticated: true };
  }
}

export class ServerAuthHandler {
  constructor(serverHybridKeyPair, clients, serverConfig) {
    this.serverHybridKeyPair = serverHybridKeyPair;
    this.clients = clients;
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

      const passwordValid = await CryptoUtils.Password.verifyPassword(this.ServerConfig.SERVER_PASSWORD, passwordPayload.content);

      if (!passwordValid) {
        console.error(`[AUTH] Incorrect server password for user: ${clientState.username}`);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Incorrect password");
      }

      const existingClient = this.clients.get(clientState.username);
      if (!existingClient) {
        console.error(`[AUTH] User not found in client list: ${clientState.username}`);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "User not found in client list");
      }

      // SECURITY: Validate state transition for server authentication
      if (!existingClient.clientState?.hasPassedAccountLogin) {
        console.error(`[AUTH] Invalid state - account login not completed: ${clientState.username}`);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Account authentication required first");
      }

      if (existingClient.clientState?.hasAuthenticated) {
        console.error(`[AUTH] User already authenticated: ${clientState.username}`);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "User already authenticated");
      }

      // SECURITY: Validate WebSocket consistency
      if (existingClient.ws !== ws) {
        console.error(`[AUTH] WebSocket mismatch in server auth: ${clientState.username}`);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Connection state inconsistency");
      }

      // SECURITY: Atomic state update
      this.clients.set(clientState.username, {
        ws,
        hybridPublicKeys: existingClient.hybridPublicKeys,
        clientState: {
          ...existingClient.clientState,
          hasAuthenticated: true,
          serverAuthTime: Date.now(),
          finalizedBy: 'ServerAuthHandler'
        }
      });

      ws.send(JSON.stringify({
        type: SignalType.AUTH_SUCCESS,
        message: "Authentication successful"
      }));

      console.log(`[AUTH] Server authentication successful for user: ${clientState.username}`);
      return true;
    } catch (error) {
      console.error(`[AUTH] Server authentication error for user ${clientState.username}:`, error);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
    }
  }
}