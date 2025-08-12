import https from 'https';
import { WebSocketServer } from 'ws';
import selfsigned from 'selfsigned';
import { SignalType } from './signals.js';
import { CryptoUtils } from './crypto/unified-crypto.js';
import { MessageDatabase } from './database/database.js';
import * as ServerConfig from './config/config.js';
import { MessagingUtils } from './messaging/messaging-utils.js';
import * as authentication from './authentication/authentication.js';
import { setServerPasswordOnInput } from './authentication/auth-utils.js';

const clients = new Map();

const { private: key, cert } = selfsigned.generate([{ name: 'commonName', value: 'localhost' }], {
  days: 365,
  keySize: 4096,
});

const server = https.createServer({ key, cert });

async function startServer() {
  await setServerPasswordOnInput();
  const serverKeyPair = await CryptoUtils.Keys.generateRSAKeyPair();

  const authHandler = new authentication.AccountAuthHandler(serverKeyPair, clients);
  const serverAuthHandler = new authentication.ServerAuthHandler(serverKeyPair, clients, ServerConfig);

  console.log(`Server RSA key pair generated.`);
  console.log(`Allow self-signed cert: https://localhost:${ServerConfig.PORT}`);

  server.listen(ServerConfig.PORT, '0.0.0.0', () =>
    console.log(`SecureChat relay running on wss://0.0.0.0:${ServerConfig.PORT}`)
  );

  const wss = new WebSocketServer({ server });

  wss.on('connection', async (ws) => {
    let clientState = { username: null, hasPassedAccountLogin: false, hasAuthenticated: false };

    ws.send(
      JSON.stringify({
        type: SignalType.SERVER_PUBLIC_KEY,
        publicKey: await CryptoUtils.Keys.exportPublicKeyToPEM(serverKeyPair.publicKey),
      })
    );

    ws.on('message', async (msg) => {
      let parsed;
      try {
        parsed = JSON.parse(msg.toString().trim());
      } catch {
        return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Invalid JSON format' }));
      }

      try {
        switch (parsed.type) {
          case SignalType.ACCOUNT_SIGN_IN:
          case SignalType.ACCOUNT_SIGN_UP: {
            const result = await authHandler.processAuthRequest(ws, msg.toString());
            if (result?.authenticated || result?.pending) {
              clientState.hasPassedAccountLogin = true;
              clientState.username = result.username;

              if (result.pending) 
                console.log(`User '${result.username}' pending passphrase`);

              ws.send(JSON.stringify({ type: SignalType.IN_ACCOUNT, message: 'Logged in successfully' }));

              if (!result.pending) clients.set(clientState.username, { ws, clientState });
            } else {
              ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Login failed' }));
            }
            break;
          }

          case SignalType.PASSPHRASE_HASH:
          case SignalType.PASSPHRASE_HASH_NEW: {
            if (!clientState.username) {
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Username not set' }));
            }
            if (!parsed.passphraseHash) {
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Passphrase hash missing' }));
            }
            await authHandler.handlePassphrase(
              ws,
              clientState.username,
              parsed.passphraseHash,
              parsed.type === SignalType.PASSPHRASE_HASH_NEW
            );
            ws.send(
              JSON.stringify({
                type: SignalType.PASSPHRASE_SUCCESS,
                message:
                  parsed.type === SignalType.PASSPHRASE_HASH_NEW
                    ? 'Passphrase saved successfully'
                    : 'Passphrase verified successfully',
              })
            );
            break;
          }

          case SignalType.SERVER_LOGIN: { //server password handling
            if (!clientState.hasPassedAccountLogin)
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Account login required first' }));

            if (clientState.hasAuthenticated)
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Already authenticated' }));

            const success = await serverAuthHandler.handleServerAuthentication(ws, msg.toString(), clientState);
            if (success) {
              clientState.hasAuthenticated = true;
              ws.send(JSON.stringify({ type: SignalType.AUTH_SUCCESS, message: 'Server authentication successful' }));
              MessagingUtils.broadcastPublicKeys(clients);
              await MessagingUtils.broadcastUserJoin(clients, clientState.username);
            } else {
              ws.send(JSON.stringify({ type: SignalType.AUTH_ERROR, message: 'Server authentication failed' }));
            }
            break;
          }

          case SignalType.UPDATE_DB: {
            console.log(`Update db message sent from '${clientState.username}': ${parsed}`)
            await MessageDatabase.saveMessageInDB(parsed, serverKeyPair.privateKey)

            console.log("Loading user messages...__________________________((((((((")
            const userMessagesHistory = MessageDatabase.getMessagesForUser(clientState.username, 50) //message history to send to client
            // console.log("usermessage hiostory: ", userMessagesHistory)
            console.log("Loaded user messages__________________________)))))))")
            break;
          }

          case SignalType.ENCRYPTED_MESSAGE:
          case SignalType.FILE_MESSAGE_CHUNK: {
            if (!clientState.hasAuthenticated) return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Not authenticated yet' }));
            if (!parsed.to || !clients.has(parsed.to)) return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Target user not found' }));

            clients.get(parsed.to).ws.send(JSON.stringify(parsed));

            console.log(
              parsed.type === SignalType.FILE_MESSAGE_CHUNK
                ? `Relayed file chunk ${parsed.chunkIndex + 1}/${parsed.totalChunks} from ${parsed.from} to ${parsed.to}`
                : `Relayed message from ${parsed.from} to ${parsed.to}`
            );

            break;
          }

          default:
            ws.send(JSON.stringify({ type: SignalType.ERROR, message: `Unknown message type: ${parsed.type}` }));
        }
      } catch (err) {
        console.error('Message handler error:', err);
      }
    });

    ws.on('close', async () => {
      if (clientState.username && clients.has(clientState.username)) {
        clients.delete(clientState.username);
        await MessagingUtils.broadcastUserLeave(clients, clientState.username);
        console.log(`User '${clientState.username}' disconnected.`);
      }
    });
  });
}

startServer();
