import https from 'https';
import fs from 'fs';
import { WebSocketServer } from 'ws';
import selfsigned from 'selfsigned';
import { SignalType } from './signals.js';
import { CryptoUtils } from './crypto/unified-crypto.js';
import { MessageDatabase, PrekeyDatabase } from './database/database.js';
import * as ServerConfig from './config/config.js';
import { MessagingUtils } from './messaging/messaging-utils.js';
import * as authentication from './authentication/authentication.js';
import { setServerPasswordOnInput } from './authentication/auth-utils.js';
import { ed25519 } from '@noble/curves/ed25519';
import { rateLimitMiddleware } from './rate-limiting/rate-limit-middleware.js';

const clients = new Map();

const CERT_PATH = process.env.TLS_CERT_PATH; //use real later for production and in dev use selfsigned
const KEY_PATH = process.env.TLS_KEY_PATH;

let server;
if (CERT_PATH && KEY_PATH && fs.existsSync(CERT_PATH) && fs.existsSync(KEY_PATH)) {
  console.log('[SERVER] Using provided TLS certificate and key');
  const key = fs.readFileSync(KEY_PATH);
  const cert = fs.readFileSync(CERT_PATH);
  server = https.createServer({ key, cert });
} else {
  console.warn('[SERVER] No TLS_CERT_PATH/TLS_KEY_PATH provided; generating self-signed certificate for development');
  const { private: key, cert } = selfsigned.generate([{ name: 'commonName', value: 'localhost' }], {
    days: 365,
    keySize: 4096,
  });
  server = https.createServer({ key, cert });
}

async function startServer() {
  console.log('[SERVER] Starting SecureChat server');
  await setServerPasswordOnInput();
  const serverHybridKeyPair = await CryptoUtils.Hybrid.generateHybridKeyPair();

  console.log('[SERVER] Server hybrid key pair generated (X25519 + Kyber768)');
  console.log(`[SERVER] Allow self-signed cert: https://localhost:${ServerConfig.PORT}`);
  console.log('[SERVER] Rate limiting enabled with privacy-first approach');
  try {
    console.log('[SERVER] Rate limiter backend:', rateLimitMiddleware.getStats().backend);
  } catch (error) {
    console.error('[SERVER] Failed to get rate limiter stats:', error);
  }

  server.listen(ServerConfig.PORT, '0.0.0.0', () =>
    console.log(`[SERVER] SecureChat relay running on wss://0.0.0.0:${ServerConfig.PORT}`)
  );

  const wss = new WebSocketServer({ server });

  const authHandler = new authentication.AccountAuthHandler(serverHybridKeyPair, clients);
  const serverAuthHandler = new authentication.ServerAuthHandler(serverHybridKeyPair, clients, ServerConfig);

  // Periodic rate limiting status logging
  setInterval(async () => {
    try {
      const stats = rateLimitMiddleware.getStats();
      const globalStatus = await rateLimitMiddleware.getGlobalConnectionStatus();

      if (globalStatus.isBlocked || stats.userMessageLimiters > 0 || stats.userBundleLimiters > 0) {
        console.log('[RATE-LIMIT-STATUS]', {
          globalConnectionBlocked: globalStatus.isBlocked,
          globalConnectionAttempts: globalStatus.attempts,
          activeUserLimiters: stats.totalUserLimiters,
          timestamp: new Date().toISOString()
        });
      }
    } catch (error) {
      console.error('[SERVER] Error in rate limiting status logging:', error);
    }
  }, 60000); // Log every minute

  wss.on('connection', async (ws) => {
    // Apply connection rate limiting before processing the connection
    try {
      if (!(await rateLimitMiddleware.checkConnectionLimit(ws))) {
        console.log('[SERVER] Connection rejected due to rate limiting');
        return; // Connection will be closed by the middleware
      }
    } catch (error) {
      console.error('[SERVER] Rate limiting error during connection:', error);
      ws.close();
      return;
    }

    let clientState = { username: null, hasPassedAccountLogin: false, hasAuthenticated: false };

    // Store rate limiting info in client state for monitoring
    clientState.connectionTime = Date.now();

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
          case SignalType.X3DH_PUBLISH_BUNDLE: {
            if (!clientState.hasPassedAccountLogin || !clientState.username) {
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Account login required first' }));
            }

            // Apply bundle operation rate limiting
            try {
              if (!(await rateLimitMiddleware.checkBundleLimit(ws, clientState.username))) {
                console.log(`[SERVER] Bundle operation blocked due to rate limiting for user: ${clientState.username}`);
                break;
              }
            } catch (error) {
              console.error(`[SERVER] Rate limiting error during bundle operation for user ${clientState.username}:`, error);
              break;
            }
            try {
              console.log(`[SERVER] Received ${SignalType.X3DH_PUBLISH_BUNDLE} from user: ${clientState.username}`);
              const b = parsed.bundle || {};
              console.log('[SERVER] Bundle summary:', {
                identityEd25519PublicBase64: (b.identityEd25519PublicBase64 || '').slice(0, 16) + '...',
                identityX25519PublicBase64: (b.identityX25519PublicBase64 || '').slice(0, 16) + '...',
                signedPreKey: b.signedPreKey ? { id: b.signedPreKey.id, publicKeyBase64: (b.signedPreKey.publicKeyBase64 || '').slice(0, 16) + '...' } : null,
                oneTimePreKeysCount: Array.isArray(b.oneTimePreKeys) ? b.oneTimePreKeys.length : 0,
                ratchetPublicBase64: (b.ratchetPublicBase64 || '').slice(0, 16) + '...'
              });
              // ensure signedPreKey was signed by identity Ed25519 key and optionally Dilithium key
              try {
                const idEd = Buffer.from(b.identityEd25519PublicBase64 || '', 'base64');
                const spk = Buffer.from(b.signedPreKey?.publicKeyBase64 || '', 'base64');
                const ed25519Sig = Buffer.from(b.signedPreKey?.ed25519SignatureBase64 || b.signedPreKey?.signatureBase64 || '', 'base64');

                // Verify Ed25519 signature
                const ed25519Valid = idEd.length === 32 && spk.length === 32 && ed25519Sig.length === 64 && ed25519.verify(ed25519Sig, spk, idEd);

                // Verify Dilithium signature if present
                let dilithiumValid = true;
                if (b.signedPreKey?.dilithiumSignatureBase64 && b.identityDilithiumPublicBase64) {
                  try {
                    const { ml_dsa87 } = await import("@noble/post-quantum/ml-dsa");
                    const idDilithium = Buffer.from(b.identityDilithiumPublicBase64, 'base64');
                    const dilithiumSig = Buffer.from(b.signedPreKey.dilithiumSignatureBase64, 'base64');

                    console.log('[SERVER] Dilithium key lengths:', {
                      publicKeyLength: idDilithium.length,
                      signatureLength: dilithiumSig.length,
                      signedPreKeyLength: spk.length
                    });

                    console.log('[SERVER] ml_dsa87 object:', Object.keys(ml_dsa87));

                    try {
                      // Correct order: publicKey, message, signature
                      dilithiumValid = await ml_dsa87.verify(idDilithium, spk, dilithiumSig);
                    } catch (error) {
                      // Try alternative parameter order if the first fails
                      console.warn('[SERVER] Dilithium verification failed with standard order, trying alternative:', error);
                      dilithiumValid = await ml_dsa87.verify(dilithiumSig, spk, idDilithium);
                    }
                  } catch (dilithiumError) {
                    console.error('[SERVER] Dilithium signature verification failed:', dilithiumError?.message || dilithiumError);
                    dilithiumValid = false; // Fail the verification if Dilithium verification fails
                  }
                }

                const valid = ed25519Valid && dilithiumValid;
                if (!valid) {
                  console.warn('[SERVER] Rejected bundle due to invalid signedPreKey signature for user', clientState.username);
                  return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Invalid signedPreKey signature' }));
                }
              } catch (e) {
                console.warn('[SERVER] Bundle verification failed (continuing may be insecure):', e?.message || e);
              }
              PrekeyDatabase.publishBundle(clientState.username, parsed.bundle);
              ws.send(JSON.stringify({ type: 'ok', message: 'bundle-published' }));
            } catch (e) {
              ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Failed to publish bundle' }));
            }
            break;
          }

          case SignalType.X3DH_REQUEST_BUNDLE: {
            if (!clientState.hasPassedAccountLogin) {
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Account login required first' }));
            }

            // Apply bundle operation rate limiting
            try {
              if (!(await rateLimitMiddleware.checkBundleLimit(ws, clientState.username))) {
                console.log(`[SERVER] Bundle operation blocked due to rate limiting for user: ${clientState.username}`);
                break;
              }
            } catch (error) {
              console.error(`[SERVER] Rate limiting error during bundle operation for user ${clientState.username}:`, error);
              break;
            }
            const target = parsed.username;
            console.log(`[SERVER] Bundle request from ${clientState.username} for ${target}`);
            const out = PrekeyDatabase.takeBundleForRecipient(target);
            if (!out) {
              console.log(`[SERVER] No bundle available for ${target}`);
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'No bundle available' }));
            }
            console.log(`[SERVER] Delivering prekey bundle for ${target} to ${clientState.username}`, {
              hasOneTime: !!out.oneTimePreKey,
              signedPreKeyId: out.signedPreKey?.id,
              bundleKeys: Object.keys(out),
              signedPreKeyKeys: Object.keys(out.signedPreKey || {})
            });
            ws.send(JSON.stringify({ type: SignalType.X3DH_DELIVER_BUNDLE, bundle: out, username: target }));
            break;
          }
          case SignalType.ACCOUNT_SIGN_IN:
          case SignalType.ACCOUNT_SIGN_UP: {
            // Apply authentication rate limiting
            try {
              if (!(await rateLimitMiddleware.checkAuthLimit(ws))) {
                console.log(`[SERVER] Authentication blocked due to rate limiting for ${parsed.type}`);
                break;
              }
            } catch (error) {
              console.error('[SERVER] Rate limiting error during authentication:', error);
              break;
            }

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

              // Offline message delivery removed
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

              console.log(`[SERVER] Decrypted hybrid keys update:`, {
                username,
                hasHybridKeys: !!hybridPublicKeys,
                hybridKeysStructure: hybridPublicKeys ? Object.keys(hybridPublicKeys) : null
              });

              if (username === clientState.username && hybridPublicKeys) {
                console.log(`[SERVER] Updating hybrid keys for user: ${username}`);
                const existingClient = clients.get(username);
                console.log(`[SERVER] Existing client for ${username}:`, {
                  exists: !!existingClient,
                  hasHybridKeys: existingClient ? !!existingClient.hybridPublicKeys : false,
                  clientKeys: existingClient ? Object.keys(existingClient) : null
                });

                if (existingClient) {
                  existingClient.hybridPublicKeys = hybridPublicKeys;
                  console.log(`[SERVER] Hybrid keys updated successfully for user: ${username}`);
                  console.log(`[SERVER] Client after update:`, {
                    hasHybridKeys: !!existingClient.hybridPublicKeys,
                    hybridKeysStructure: existingClient.hybridPublicKeys ? Object.keys(existingClient.hybridPublicKeys) : null
                  });
                } else {
                  console.error(`[SERVER] No existing client found for user: ${username}`);
                }
              }
            } catch (error) {
              console.error(`[SERVER] Failed to process hybrid keys update for user ${clientState.username}:`, error);
              ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Failed to update hybrid keys' }));
            }
            break;
          }

          case SignalType.ENCRYPTED_MESSAGE:
          case SignalType.FILE_MESSAGE_CHUNK:
          case SignalType.DR_SEND: {
            console.log(`[SERVER] Processing ${parsed.type} from user: ${clientState.username} to user: ${parsed.to}`);
            if (!clientState.hasAuthenticated) {
              console.error('[SERVER] User not authenticated for message sending');
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Not authenticated yet' }));
            }
            if (!parsed.to || !clients.has(parsed.to)) {
              console.warn(`[SERVER] Target user offline or not found: ${parsed.to}, not delivering`);
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Recipient offline; message not delivered' }));
            }

            // Apply message rate limiting
            try {
              if (!(await rateLimitMiddleware.checkMessageLimit(ws, clientState.username))) {
                console.log(`[SERVER] Message blocked due to rate limiting for user: ${clientState.username}`);
                break;
              }
            } catch (error) {
              console.error(`[SERVER] Rate limiting error during message for user ${clientState.username}:`, error);
              break;
            }

            const recipient = clients.get(parsed.to);
            if (recipient && recipient.ws) {
              console.log(`[SERVER] Forwarding message from ${clientState.username} to ${parsed.to}`);
              const messageToSend = parsed.type === SignalType.DR_SEND
                ? { type: SignalType.DR_SEND, from: clientState.username, to: parsed.to, payload: parsed.payload }
                : { type: SignalType.ENCRYPTED_MESSAGE, ...parsed.encryptedPayload };
              recipient.ws.send(JSON.stringify(messageToSend));
              console.log(`[SERVER] Message relayed`);
            } else {
              console.error(`[SERVER] Recipient WebSocket not available for user: ${parsed.to}`);
            }
            break;
          }

          case SignalType.RATE_LIMIT_STATUS: {
            // Admin function: Get rate limiting statistics
            // This could be restricted to admin users in production
            console.log(`[SERVER] Rate limit status request from user: ${clientState.username || 'unknown'}`);
            const stats = rateLimitMiddleware.getStats();
            const globalStatus = await rateLimitMiddleware.getGlobalConnectionStatus();
            const userStatus = clientState.username ? await rateLimitMiddleware.getUserStatus(clientState.username) : null;

            ws.send(JSON.stringify({
              type: SignalType.RATE_LIMIT_STATUS,
              stats,
              globalConnectionStatus: globalStatus,
              userStatus
            }));
            break;
          }

          case SignalType.RATE_LIMIT_RESET: {
            // Admin function: Reset rate limits
            // This could be restricted to admin users in production
            console.log(`[SERVER] Rate limit reset request from user: ${clientState.username || 'unknown'}`);

            if (parsed.resetType === 'global') {
              await rateLimitMiddleware.resetGlobalConnectionLimits();
              ws.send(JSON.stringify({
                type: SignalType.RATE_LIMIT_STATUS,
                message: 'Global connection rate limits reset successfully'
              }));
            } else if (parsed.resetType === 'user' && parsed.username) {
              await rateLimitMiddleware.resetUserLimits(parsed.username);
              ws.send(JSON.stringify({
                type: SignalType.RATE_LIMIT_STATUS,
                message: `Rate limits reset successfully for user: ${parsed.username}`
              }));
            } else {
              ws.send(JSON.stringify({
                type: SignalType.ERROR,
                message: 'Invalid reset type or missing username'
              }));
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
