import { WebSocketServer } from 'ws';
import { SignalType, SignalMessages } from './signals.js';
import * as crypto from './unified-crypto.js';

const PORT = 8080;
const MAX_CLIENTS = 100;
const SERVER_ID = 'SecureChat-Server';
const SERVER_PASSWORD = 'secret123';

const clients = new Map();
const userDatabase = new Map(); // username => password (plaintext)

async function startServer() {
  const serverKeyPair = await crypto.generateRSAKeyPair();
  console.log("Server RSA key pair generated");

  const publicKeyPEM = await crypto.exportPublicKeyToPEM(serverKeyPair.publicKey);
  const privateKeyPEM = await crypto.exportPrivateKeyToPEM(serverKeyPair.privateKey);

  const wss = new WebSocketServer({ port: PORT });
  console.log(`SecureChat relay server running on ws://localhost:${PORT}`);

  function rejectConnection(ws, type, reason, code = 1008) {
    ws.send(JSON.stringify({ type, message: reason }));
    ws.close(code, reason);
    console.log(`Rejected user connection for reason: ${reason}`);
    return;
  }

  wss.on('connection', async (ws) => {
    let username = null;
    let hasPassedAccountLogin = false;
    let hasAuthenticated = false;


    ws.send(JSON.stringify({
      type: SignalType.SERVER_PUBLIC_KEY,
      publicKey: publicKeyPEM,
    }));

    ws.on('message', async (message) => {
      try {
        const str = message.toString().trim();

        if (!hasPassedAccountLogin) {
          let parsed = JSON.parse(str);

          if (parsed.type === SignalType.ACCOUNT_SIGN_UP || parsed.type === SignalType.ACCOUNT_SIGN_IN) {
            const passwordPayload = await crypto.decryptAndFormatPayload(
              parsed.passwordData,
              serverKeyPair.privateKey
            );
            
            const userPayload = await crypto.decryptAndFormatPayload(
              parsed.userData,
              serverKeyPair.privateKey
            );

            username = userPayload.usernameSent;
            const password = passwordPayload.content;

            // Validate username format, length etc.
            const validUsername = /^[a-zA-Z0-9_-]+$/;
            if (!validUsername.test(username)) return rejectConnection(ws, SignalType.INVALIDNAME, SignalMessages.INVALIDNAME);
            if (username.length < 3 || username.length > 16) return rejectConnection(ws, SignalType.INVALIDNAMELENGTH, SignalMessages.INVALIDNAMELENGTH);

            if (parsed.type === SignalType.ACCOUNT_SIGN_UP) {
              if (userDatabase.has(username)) {
                return rejectConnection(ws, SignalType.NAMEEXISTSERROR, SignalMessages.NAMEEXISTSERROR);
              }
              // Save password hash (use a secure hash, e.g. bcrypt or SHA-512 for demo)
              const passwordHash = password;
              userDatabase.set(username, passwordHash);
              console.log(`User registered: ${username}`);
              console.log("Current user database:");
              for (const [user, passHash] of userDatabase.entries()) {
                console.log(` - ${user}: ${passHash}`);
              }
            }

            if (parsed.type === SignalType.ACCOUNT_SIGN_IN) {
              if (!userDatabase.has(username)) {
                return rejectConnection(ws, SignalType.AUTH_ERROR, "User does not exist");
              }
              const storedHash = userDatabase.get(username);
              const passwordHash = password;
              if (storedHash !== passwordHash) {
                return rejectConnection(ws, SignalType.AUTH_ERROR, "Incorrect password");
              }
              console.log(`User logged in: ${username}`);
              console.log("Current user database:");
              for (const [user, passHash] of userDatabase.entries()) {
                console.log(` - ${user}: ${passHash}`);
              }
            }

            if (clients.has(username)) {
              return rejectConnection(ws, SignalType.NAMEEXISTSERROR, SignalMessages.NAMEEXISTSERROR);
            }

            if (clients.size >= MAX_CLIENTS) return rejectConnection(ws, SignalType.SERVERLIMIT, SignalMessages.SERVERLIMIT, 101);

            ws.send(JSON.stringify({
              type: SignalType.IN_ACCOUNT,
              message: "Account signing-in/signing-up successful"
            }));

            hasPassedAccountLogin = true;
            console.log(`User '${username}' has logged into their account`)
            return;
          }

          return rejectConnection(ws, SignalType.AUTH_ERROR, "Expected login or register information");
        }

        if (!hasAuthenticated){ //authenticate client if not already
          console.log(`Waiting for '${username}' to send server password...`)
          let parsed = JSON.parse(str);

          if (parsed.type === SignalType.LOGIN_INFO) {
            console.log("Login info received. Processing: ", parsed);
            
            const passwordPayload = await crypto.decryptAndFormatPayload(
              parsed.passwordData, 
              serverKeyPair.privateKey
            );
            
            if (passwordPayload.content !== SERVER_PASSWORD) return rejectConnection(ws, SignalType.AUTH_ERROR, "Incorrect password");

            const userPayload = await crypto.decryptAndFormatPayload(
              parsed.userData, 
              serverKeyPair.privateKey
            );
                          
            clients.set(username, { ws, publicKey: null });
            console.log(`User '${username}' authenticated and connected.`);
            
            clients.get(username).publicKey = userPayload.publicKey;
            console.log(`Received public key from ${username}`);
            
            const keyMap = {};
            for (const [uname, data] of clients.entries()) {
              if (data.publicKey) keyMap[uname] = data.publicKey;
            }
            
            const keyUpdate = JSON.stringify({
              type: SignalType.PUBLICKEYS,
              message: JSON.stringify(keyMap),
            });
            
            console.log("Broadcasting public keys: ", keyUpdate);
            
            for (const [, client] of clients.entries()) {
              if (client.publicKey) client.ws.send(keyUpdate);
            }
            
            await broadcastEncryptedSystemMessage(`${username} has joined the chat.`, { excludeUsername: username });
            
            ws.send(JSON.stringify({
              type: SignalType.AUTH_SUCCESS,
              message: "Authentication successful"
            }));
            
            hasAuthenticated = true;
            return;
          }
          return rejectConnection(ws, SignalType.AUTH_ERROR, "Expected login information");
        }
        
        try {
          const parsed = JSON.parse(str);
          console.log(`Received message from ${username}:`, parsed);
          
          if (parsed.type === SignalType.ENCRYPTED_MESSAGE && parsed.to && clients.has(parsed.to)) {
            const target = clients.get(parsed.to);
            target.ws.send(JSON.stringify(parsed));
            console.log(`Relayed message from ${parsed.from} to ${parsed.to}`);
          }

          if (parsed.type === SignalType.FILE_MESSAGE_CHUNK && parsed.to && clients.has(parsed.to)) {
            const target = clients.get(parsed.to);
            target.ws.send(JSON.stringify(parsed));
            console.log(`Relayed file chunk ${parsed.chunkIndex + 1}/${parsed.totalChunks} from ${parsed.from} to ${parsed.to}`);
          }
        } catch (e) {
          console.warn("Non-JSON message:", str);
        }
      } catch (err) {
        console.error("Message error: ", err);
      }
    });

    ws.on('close', async () => {
      if (username && hasAuthenticated) {
        clients.delete(username);
        console.log(`User '${username}' has disconnected.`);

        await broadcastEncryptedSystemMessage(`${username} has left the chat.`, { signalType: SignalType.USER_DISCONNECT });
      }
    });
  });

  async function broadcastEncryptedSystemMessage(content, options = {}) {
    const {
      signalType = SignalType.ENCRYPTED_MESSAGE,
      excludeUsername = null,
    } = options;

    console.log(`Broadcasting system message: ${content}`);

    const promises = [];

    for (const [clientUsername, client] of clients.entries()) {
      if (clientUsername !== excludeUsername && client.publicKey) {
        try {
          const finalPayload = await crypto.encryptAndFormatPayload({
            recipientPEM: client.publicKey,
            from: SERVER_ID,
            to: clientUsername,
            type: signalType,
            typeInside: "system",
            content: content,
            timestamp: Date.now()
          });

          console.log(`finalPayload for ${clientUsername}: `, JSON.stringify(finalPayload));
          promises.push(client.ws.send(JSON.stringify(finalPayload)));
          console.log(`finalPayload for ${clientUsername} sent`);
        } catch (e) {
          console.error(`Failed to encrypt system message for ${clientUsername}:`, e);
        }
      }
    }

    await Promise.allSettled(promises);
  }
}

startServer();
