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

      this.clients.set(username, {
        ws,
        hybridPublicKeys,
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
      userRecord.passphraseHash = passphraseHash;
      try {
        const parsed = await CryptoUtils.Password.parseArgon2Hash(passphraseHash);
        userRecord.version = parsed.version;
        userRecord.algorithm = parsed.algorithm;
        userRecord.salt = parsed.salt.toString('base64');
        userRecord.memoryCost = parsed.memoryCost;
        userRecord.timeCost = parsed.timeCost;
        userRecord.parallelism = parsed.parallelism;
        console.log(`[AUTH] Passphrase hash parsed for new user: ${username}`);
      } catch (e) {
        console.warn(`[AUTH] Failed to parse passphrase hash params for user ${username}:`, e);
      }
      UserDatabase.saveUserRecord(userRecord);
      console.log(`[AUTH] User record updated with passphrase for: ${username}`);
    } else {
      console.log(`[AUTH] Verifying passphrase for existing user: ${username}`);
      if (userRecord.passphraseHash !== passphraseHash) {
        console.error(`[AUTH] Passphrase hash mismatch for user: ${username}`);
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Passphrase hash mismatch");
      }
      console.log(`[AUTH] Passphrase verified for user: ${username}`);
    }

    this.pendingPassphrases.delete(username);
    console.log(`[AUTH] User ${username} removed from pending passphrases`);

    const auth = await this.finalizeAuth(ws, username, isNewUser ? "User registered with passphrase" : "User logged in with passphrase");

    const existingClient = this.clients.get(username);
    this.clients.set(username, {
      ws,
      clientState: { username, hasPassedAccountLogin: true, hasAuthenticated: true },
      hybridPublicKeys: existingClient?.hybridPublicKeys || null
    });

    console.log(`[AUTH] Authentication completed for user: ${username}`);
    return auth;
  }

  finalizeAuth(ws, username, logMessage) {
    console.log(`[AUTH] Finalizing authentication: ${logMessage} for user: ${username}`);
    const existingClient = this.clients.get(username);
    if (existingClient && existingClient.clientState?.hasAuthenticated) {
      console.error(`[AUTH] User already authenticated: ${username}`);
      return rejectConnection(ws, SignalType.NAMEEXISTSERROR, SignalMessages.NAMEEXISTSERROR);
    }

    if (authUtils.isServerFull(this.clients)) {
      console.error(`[AUTH] Server is full, rejecting user: ${username}`);
      return rejectConnection(ws, SignalType.SERVERLIMIT, SignalMessages.SERVERLIMIT, 101);
    }

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

      this.clients.set(clientState.username, {
        ws,
        hybridPublicKeys: existingClient.hybridPublicKeys,
        clientState: { ...existingClient.clientState, hasAuthenticated: true }
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