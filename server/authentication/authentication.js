import * as authUtils from './auth-utils.js';
import { SignalType, SignalMessages } from '../signals.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { UserDatabase } from '../database/database.js';

function rejectConnection(ws, type, reason, code = 1008) {
  ws.send(JSON.stringify({ type, message: reason }));
  ws.close(code, reason);
  console.log(`Rejected user connection for reason: ${reason}`);
  return;
}

export class AccountAuthHandler {
  constructor(serverKeyPair, clients) {
    this.serverKeyPair = serverKeyPair;
    this.clients = clients;
    this.pendingPassphrases = new Map();
  }

  async processAuthRequest(ws, str) {
    try {
      const { type, passwordData, userData } = JSON.parse(str);

      const [passwordPayload, userPayload] = await Promise.all([
        CryptoUtils.Decrypt.decryptAndFormatPayload(passwordData, this.serverKeyPair.privateKey),
        CryptoUtils.Decrypt.decryptAndFormatPayload(userData, this.serverKeyPair.privateKey)
      ]);

      const username = userPayload.usernameSent;
      const password = passwordPayload.content;

      if (!authUtils.validateUsernameFormat(username))
        return rejectConnection(ws, SignalType.INVALIDNAME, SignalMessages.INVALIDNAME);
      if (!authUtils.validateUsernameLength(username))
        return rejectConnection(ws, SignalType.INVALIDNAMELENGTH, SignalMessages.INVALIDNAMELENGTH);

      if (type === SignalType.ACCOUNT_SIGN_UP)
        return this.handleSignUp(ws, username, password);
      if (type === SignalType.ACCOUNT_SIGN_IN)
        return this.handleSignIn(ws, username, password);

      return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid auth type");
    } catch (error) {
      console.error('Auth processing error:', error);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
    }
  }

  async handleSignUp(ws, username, password) {
    const existingUser = UserDatabase.loadUser(username);
    if (existingUser)
      return rejectConnection(ws, SignalType.NAMEEXISTSERROR, SignalMessages.NAMEEXISTSERROR);

    const passwordHash = await CryptoUtils.Password.hashPassword(password);

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

    ws.send(JSON.stringify({
      type: SignalType.PASSPHRASE_HASH,
      message: "Please hash your passphrase and send it back"
    }));

    this.pendingPassphrases.set(username, ws);
    return { username, pending: true };
  }


  async handleSignIn(ws, username, password) {
    const userData = UserDatabase.loadUser(username);
    if (!userData)
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Account does not exist, Register instead.");

    if (!await CryptoUtils.Password.verifyPassword(userData.passwordHash, password))
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Incorrect password");

    if (userData.version && userData.salt) {
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
      return { username, pending: true };
    }

    return rejectConnection(ws, SignalType.AUTH_ERROR, "No passphrase hash info stored. Sign up instead");
  }


  async handlePassphrase(ws, username, passphraseHash, isNewUser = false) {
    if (!this.pendingPassphrases.has(username))
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Unexpected passphrase submission");

    const userRecord = UserDatabase.loadUser(username);
    if (!userRecord)
      return rejectConnection(ws, SignalType.AUTH_ERROR, "User does not exist");

    if (isNewUser) {
      userRecord.passphraseHash = passphraseHash;
      try {
        const parsed = await CryptoUtils.Password.parseArgon2Hash(passphraseHash);
        userRecord.version = parsed.version;
        userRecord.algorithm = parsed.algorithm;
        userRecord.salt = parsed.salt.toString('base64');
        userRecord.memoryCost = parsed.memoryCost;
        userRecord.timeCost = parsed.timeCost;
        userRecord.parallelism = parsed.parallelism;
      } catch (e) {
        console.warn("Failed to parse passphrase hash params:", e);
      }
      UserDatabase.saveUserRecord(userRecord);
    } else {
      if (userRecord.passphraseHash !== passphraseHash) {
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Passphrase hash mismatch");
      }
    }

    this.pendingPassphrases.delete(username);
    const auth = await this.finalizeAuth(ws, username, isNewUser ? "User registered with passphrase" : "User logged in with passphrase");

    this.clients.set(username, {
      ws,
      clientState: { username, hasPassedAccountLogin: true, hasAuthenticated: true }
    });

    return auth;
  }



  finalizeAuth(ws, username, logMessage) {
    if (this.clients.has(username))
      return rejectConnection(ws, SignalType.NAMEEXISTSERROR, SignalMessages.NAMEEXISTSERROR);

    if (authUtils.isServerFull(this.clients))
      return rejectConnection(ws, SignalType.SERVERLIMIT, SignalMessages.SERVERLIMIT, 101);

    ws.send(JSON.stringify({
      type: SignalType.IN_ACCOUNT,
      message: "Account authentication successful"
    }));

    console.log(`${logMessage}: ${username}`);
    return { username, authenticated: true };
  }
}

export class ServerAuthHandler {
  constructor(serverKeyPair, clients, serverConfig) {
    this.serverKeyPair = serverKeyPair;
    this.clients = clients;
    this.ServerConfig = serverConfig;
  }

  async handleServerAuthentication(ws, str, clientState) {
    console.log(`Waiting for '${clientState.username}' to send server password...`);
    const parsed = JSON.parse(str);

    if (parsed.type !== SignalType.SERVER_LOGIN)
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Expected login information");

    console.log("Login info received. Processing: ", parsed);

    try {
      const [passwordPayload, userPayload] = await Promise.all([
        CryptoUtils.Decrypt.decryptAndFormatPayload(parsed.passwordData, this.serverKeyPair.privateKey),
        CryptoUtils.Decrypt.decryptAndFormatPayload(parsed.userData, this.serverKeyPair.privateKey)
      ]);

      if (!await CryptoUtils.Password.verifyPassword(this.ServerConfig.SERVER_PASSWORD, passwordPayload.content)) {
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Incorrect password");
      }

      this.clients.set(clientState.username, { ws, publicKey: userPayload.publicKey });

      console.log(`User '${clientState.username}' authenticated and connected.`);
      console.log(`Received public key from ${clientState.username}`);

      ws.send(JSON.stringify({
        type: SignalType.AUTH_SUCCESS,
        message: "Authentication successful"
      }));

      return true;
    } catch (error) {
      console.error('Server authentication error:', error);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
    }
  }
}
