import * as authUtils from './auth-utils.js';
import { SignalType, SignalMessages } from '../signals.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import * as db from '../database/database.js';

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

      if (!authUtils.validateUsernameFormat(username)) return rejectConnection(ws, SignalType.INVALIDNAME, SignalMessages.INVALIDNAME);
      if (!authUtils.validateUsernameLength(username)) return rejectConnection(ws, SignalType.INVALIDNAMELENGTH, SignalMessages.INVALIDNAMELENGTH);

      if (type === SignalType.ACCOUNT_SIGN_UP) return this.handleSignUp(ws, username, password);
      if (type === SignalType.ACCOUNT_SIGN_IN) return this.handleSignIn(ws, username, password);

      return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid auth type");
    } catch (error) {
      console.error('Auth processing error:', error);
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
    }
  }

  async handleSignUp(ws, username, password) {
    if (!authUtils.isUsernameAvailable(username)) return rejectConnection(ws, SignalType.NAMEEXISTSERROR, SignalMessages.NAMEEXISTSERROR);

    const hash = await CryptoUtils.Password.hashPassword(password);
    db.userDatabase.set(username, { passwordHash: hash });
    await db.saveUserDatabase();

    return this.finalizeAuth(ws, username, "User registered");
  }

  async handleSignIn(ws, username, password) {
    const userData = db.userDatabase.get(username);
    if (!userData) return rejectConnection(ws, SignalType.AUTH_ERROR, "Account does not exist, Register instead.");
    
    if (!await CryptoUtils.Password.verifyPassword(userData.passwordHash, password)) return rejectConnection(ws, SignalType.AUTH_ERROR, "Incorrect password");

    return this.finalizeAuth(ws, username, "User logged in");
  }

  finalizeAuth(ws, username, logMessage) {
    if (this.clients.has(username)) return rejectConnection(ws, SignalType.NAMEEXISTSERROR, SignalMessages.NAMEEXISTSERROR);

    if (authUtils.isServerFull(this.clients)) return rejectConnection(ws, SignalType.SERVERLIMIT, SignalMessages.SERVERLIMIT, 101);

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

    if (parsed.type !== SignalType.LOGIN_INFO) return rejectConnection(ws, SignalType.AUTH_ERROR, "Expected login information");
  
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