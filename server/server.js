import https from 'https';
import { WebSocketServer } from 'ws';
import selfsigned from 'selfsigned';
import { SignalType } from './signals.js';
import  { CryptoUtils } from './crypto/unified-crypto.js';
import { MessageDatabase } from './database/database.js'
import * as ServerConfig from './config/config.js'
import { MessagingUtils } from './messaging/messaging-utils.js'
import * as authentication from './authentication/authentication.js'
import { setServerPasswordOnInput } from './authentication/auth-utils.js'

const clients = new Map();

const attrs = [{ name: 'commonName', value: 'localhost' }];
const pems = selfsigned.generate(attrs, { days: 365, keySize: 4096});

const server = https.createServer({
  key: pems.private,
  cert: pems.cert,
});

async function startServer() {
  await setServerPasswordOnInput();
  const serverKeyPair = await CryptoUtils.Keys.generateRSAKeyPair();

  const authHandler = new authentication.AccountAuthHandler(serverKeyPair, clients);
  const serverAuthHandler = new authentication.ServerAuthHandler(serverKeyPair, clients, ServerConfig);

  console.log("Server RSA key pair generated");
  console.log(`For self signed certificates allow here first https://localhost:${ServerConfig.PORT}`);

  server.listen(ServerConfig.PORT, '0.0.0.0', () => {
    console.log(`SecureChat relay server running on wss://0.0.0.0:${ServerConfig.PORT}`);
  });

  const wss = new WebSocketServer({ server });

  wss.on('connection', async (ws) => {
    let clientState = {
      username: null,
      hasPassedAccountLogin: false,
      hasAuthenticated: false
    };

    ws.send(JSON.stringify({ //send server key on connect
      type: SignalType.SERVER_PUBLIC_KEY,
      publicKey: await CryptoUtils.Keys.exportPublicKeyToPEM(serverKeyPair.publicKey),
    }));

    ws.on('message', async (message) => {
      try {
        const str = message.toString().trim();
        console.log("Exact receive log: ", str)
        let parsed;

        try {
          parsed = JSON.parse(str);
        } catch {
          console.log("Invalid JSON format");
          return;
        }

        switch (parsed.type) {
          case SignalType.ACCOUNT_SIGN_IN:
          case SignalType.ACCOUNT_SIGN_UP:
            const authResult = await authHandler.processAuthRequest(ws, str);

            if (authResult && (authResult.authenticated || authResult.pending)) {
              clientState.hasPassedAccountLogin = true;
              clientState.username = authResult.username;

              ws.send(JSON.stringify({ type: SignalType.IN_ACCOUNT, message: "Logged in successfully" }));
              
              if (authResult.pending) console.log(`User '${authResult.username}' pending passphrase`);
              else clients.set(clientState.username, { ws, clientState });
            }
            else {
              ws.send(JSON.stringify({ type: SignalType.ERROR, message: "Login failed" }));
            }

            break;
          

          case SignalType.PASSPHRASE_HASH:
          case SignalType.PASSPHRASE_HASH_NEW: {
            console.log(`Passphrase hash signal received: ${parsed.type}`);

            if (!clientState.username) {
              ws.send(JSON.stringify({ type: SignalType.ERROR, message: "Username not set" }));
              break;
            }

            if (!parsed.passphraseHash) {
              ws.send(JSON.stringify({ type: SignalType.ERROR, message: "Passphrase hash missing" }));
              break;
            }

            await authHandler.handlePassphrase(ws, clientState.username, parsed.passphraseHash, parsed.type === SignalType.PASSPHRASE_HASH_NEW)
                        
            ws.send(JSON.stringify({
              type: SignalType.PASSPHRASE_SUCCESS,
              message: parsed.type === SignalType.PASSPHRASE_HASH_NEW
                ? "Passphrase saved successfully"
                : "Passphrase verified successfully"
            }));

            break;
          }

          case SignalType.SERVER_LOGIN:
            if (!clientState.hasPassedAccountLogin) {
              ws.send(JSON.stringify({ type: SignalType.ERROR, message: "Account login required first" }));
              break;
            }
            if (clientState.hasAuthenticated) {
              ws.send(JSON.stringify({ type: SignalType.ERROR, message: "Already authenticated" }));
              break;
            }
            const serverAuthSuccess = await serverAuthHandler.handleServerAuthentication(ws, str, clientState);
            if (serverAuthSuccess) {
              clientState.hasAuthenticated = true;
              ws.send(JSON.stringify({ type: SignalType.AUTH_SUCCESS, message: "Server authentication successful" }));
              MessagingUtils.broadcastPublicKeys(clients);
              await MessagingUtils.broadcastUserJoin(clients, clientState.username);
            } else {
              ws.send(JSON.stringify({ type: SignalType.AUTH_ERROR, message: "Server authentication failed" }));
            }
            break;

          case SignalType.UPDATE_DB:
            console.log(`Update db message sent from '${clientState.username}': ${parsed}`)
            await MessageDatabase.saveMessageInDB(parsed, serverKeyPair.privateKey)
            break;

          case SignalType.ENCRYPTED_MESSAGE:
          case SignalType.FILE_MESSAGE_CHUNK:
            if (!clientState.hasAuthenticated) {
              ws.send(JSON.stringify({ type: SignalType.ERROR, message: "Not authenticated yet" }));
              break;
            }
            if (!parsed.to || !clients.has(parsed.to)) {
              ws.send(JSON.stringify({ type: SignalType.ERROR, message: "Target user not found" }));
              break;
            }

            const target = clients.get(parsed.to);
            target.ws.send(JSON.stringify(parsed));

            const isFileChunk = parsed.type === SignalType.FILE_MESSAGE_CHUNK;
            console.log(
              isFileChunk
                ? `Relayed file chunk ${parsed.chunkIndex + 1}/${parsed.totalChunks} from ${parsed.from} to ${parsed.to}`
                : `Relayed message from ${parsed.from} to ${parsed.to}`
            );
            break;

          default:
            ws.send(JSON.stringify({ type: SignalType.ERROR, message: `Unknown message type: ${parsed}` }));
        }

      } catch (err) {
        console.error("Message handler error:", err);
      }
    });

    ws.on('close', async () => {
      if (clientState.username) {
        if (clients.has(clientState.username)) {
          clients.delete(clientState.username);
          console.log(`User '${clientState.username}' has disconnected.`);
          await MessagingUtils.broadcastUserLeave(clients, clientState.username);
        } else {
          console.log(`User '${clientState.username}' disconnected but was not in clients map.`);
        }
      } else {
        console.log(`A connection without username disconnected.`);
      }
    });
  });

}

startServer();