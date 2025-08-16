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
  console.log('[SERVER] Starting SecureChat server');
  await setServerPasswordOnInput();
  const serverHybridKeyPair = await CryptoUtils.Hybrid.generateHybridKeyPair();

  console.log('[SERVER] Server hybrid key pair generated (X25519 + Kyber768)');
  console.log(`[SERVER] Allow self-signed cert: https://localhost:${ServerConfig.PORT}`);

  server.listen(ServerConfig.PORT, '0.0.0.0', () =>
    console.log(`[SERVER] SecureChat relay running on wss://0.0.0.0:${ServerConfig.PORT}`)
  );

  const wss = new WebSocketServer({ server });

  const authHandler = new authentication.AccountAuthHandler(serverHybridKeyPair, clients);
  const serverAuthHandler = new authentication.ServerAuthHandler(serverHybridKeyPair, clients, ServerConfig);

  wss.on('connection', async (ws) => {
    let clientState = { username: null, hasPassedAccountLogin: false, hasAuthenticated: false };

    ws.send(
      JSON.stringify({
        type: SignalType.SERVER_PUBLIC_KEY,
        hybridKeys: {
          x25519PublicBase64: await CryptoUtils.Hybrid.exportX25519PublicBase64(serverHybridKeyPair.x25519.publicKey),
          kyberPublicBase64: await CryptoUtils.Hybrid.exportKyberPublicBase64(serverHybridKeyPair.kyber.publicKey)
        }
      })
    );

    ws.on('message', async (msg) => {
      let parsed;
      try {
        parsed = JSON.parse(msg.toString().trim());
        console.log(`[SERVER] Received message type: ${parsed.type} from user: ${clientState.username || 'unknown'}`);
      } catch {
        console.error('[SERVER] Invalid JSON format received');
        return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Invalid JSON format' }));
      }

      try {
        switch (parsed.type) {
          case SignalType.ACCOUNT_SIGN_IN:
          case SignalType.ACCOUNT_SIGN_UP: {
            console.log(`[SERVER] Processing ${parsed.type} request`);
            const result = await authHandler.processAuthRequest(ws, msg.toString());
            if (result?.authenticated || result?.pending) {
              clientState.hasPassedAccountLogin = true;
              clientState.username = result.username;

              if (result.pending) {
                console.log(`[SERVER] User '${result.username}' pending passphrase`);
              }

              ws.send(JSON.stringify({ type: SignalType.IN_ACCOUNT, message: 'Logged in successfully' }));

              if (!result.pending) {
                console.log(`[SERVER] User '${clientState.username}' completed account authentication`);
              }
            } else {
              console.error(`[SERVER] Login failed for user: ${clientState.username || 'unknown'}`);
              ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Login failed' }));
            }
            break;
          }

          case SignalType.PASSPHRASE_HASH:
          case SignalType.PASSPHRASE_HASH_NEW: {
            console.log(`[SERVER] Processing passphrase hash for user: ${clientState.username}`);
            if (!clientState.username) {
              console.error('[SERVER] Username not set for passphrase submission');
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Username not set' }));
            }
            if (!parsed.passphraseHash) {
              console.error('[SERVER] Passphrase hash missing');
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Passphrase hash missing' }));
            }

            await authHandler.handlePassphrase(
              ws,
              clientState.username,
              parsed.passphraseHash,
              parsed.type === SignalType.PASSPHRASE_HASH_NEW
            );

            const successMessage = parsed.type === SignalType.PASSPHRASE_HASH_NEW
              ? 'Passphrase saved successfully'
              : 'Passphrase verified successfully';
            console.log(`[SERVER] Sending passphrase success to user: ${clientState.username}`);
            ws.send(
              JSON.stringify({
                type: SignalType.PASSPHRASE_SUCCESS,
                message: successMessage,
              })
            );
            break;
          }

          case SignalType.SERVER_LOGIN: {
            console.log(`[SERVER] Processing server login for user: ${clientState.username}`);
            if (!clientState.hasPassedAccountLogin) {
              console.error('[SERVER] Account login required first');
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Account login required first' }));
            }

            if (clientState.hasAuthenticated) {
              console.error('[SERVER] User already authenticated');
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Already authenticated' }));
            }

            const success = await serverAuthHandler.handleServerAuthentication(ws, msg.toString(), clientState);
            if (success) {
              clientState.hasAuthenticated = true;
              console.log(`[SERVER] Server authentication successful for user: ${clientState.username}`);
              ws.send(JSON.stringify({ type: SignalType.AUTH_SUCCESS, message: 'Server authentication successful' }));

              console.log(`[SERVER] Broadcasting public keys and user join for: ${clientState.username}`);
              MessagingUtils.broadcastPublicKeys(clients);
              await MessagingUtils.broadcastUserJoin(clients, clientState.username);
            } else {
              console.error(`[SERVER] Server authentication failed for user: ${clientState.username}`);
              ws.send(JSON.stringify({ type: SignalType.AUTH_ERROR, message: 'Server authentication failed' }));
            }
            break;
          }

          case SignalType.UPDATE_DB: {
            console.log(`[SERVER] Saving message to database from user: ${clientState.username}`);
            await MessageDatabase.saveMessageInDB(parsed, serverHybridKeyPair);
            console.log(`[SERVER] Message saved to database successfully`);
            //send to user after
            break;
          }

          case SignalType.HYBRID_KEYS_UPDATE: {
            console.log(`[SERVER] Processing hybrid keys update for user: ${clientState.username}`);
            if (!clientState.username) {
              console.error('[SERVER] Username not set for hybrid keys update');
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Username not set' }));
            }

            try {
              const userPayload = await CryptoUtils.Hybrid.decryptHybridPayload(parsed.userData, serverHybridKeyPair);
              const username = userPayload.usernameSent;
              const hybridPublicKeys = userPayload.hybridPublicKeys;

              if (username === clientState.username && hybridPublicKeys) {
                console.log(`[SERVER] Updating hybrid keys for user: ${username}`);
                const existingClient = clients.get(username);
                if (existingClient) {
                  existingClient.hybridPublicKeys = hybridPublicKeys;
                  console.log(`[SERVER] Hybrid keys updated successfully for user: ${username}`);
                }
              }
            } catch (error) {
              console.error(`[SERVER] Failed to process hybrid keys update for user ${clientState.username}:`, error);
              ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Failed to update hybrid keys' }));
            }
            break;
          }

          case SignalType.ENCRYPTED_MESSAGE:
          case SignalType.FILE_MESSAGE_CHUNK: {
            console.log(`[SERVER] Processing ${parsed.type} from user: ${clientState.username} to user: ${parsed.to}`);
            if (!clientState.hasAuthenticated) {
              console.error('[SERVER] User not authenticated for message sending');
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Not authenticated yet' }));
            }
            if (!parsed.to || !clients.has(parsed.to)) {
              console.error(`[SERVER] Target user not found: ${parsed.to}`);
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Target user not found' }));
            }

            const recipient = clients.get(parsed.to);
            if (recipient && recipient.ws) {
              console.log(`[SERVER] Forwarding message from ${clientState.username} to ${parsed.to}`);
              const messageToSend = {
                type: SignalType.ENCRYPTED_MESSAGE,
                ...parsed.encryptedPayload
              };
              recipient.ws.send(JSON.stringify(messageToSend));
              console.log(`[SERVER] Message relayed`);
            } else {
              console.error(`[SERVER] Recipient WebSocket not available for user: ${parsed.to}`);
            }
            break;
          }

          default:
            console.error(`[SERVER] Unknown message type: ${parsed.type}`);
            ws.send(JSON.stringify({ type: SignalType.ERROR, message: `Unknown message type: ${msg}` }));
        }
      } catch (err) {
        console.error(`[SERVER] Message handler error for user ${clientState.username}:`, err);
      }
    });

    ws.on('close', async () => {
      if (clientState.username && clients.has(clientState.username)) {
        clients.delete(clientState.username);
        await MessagingUtils.broadcastUserLeave(clients, clientState.username);
        console.log(`[SERVER] User '${clientState.username}' disconnected`);
      }
    });
  });
}

startServer();
