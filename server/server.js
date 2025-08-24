import https from 'https';
import fs from 'fs';
import { WebSocketServer } from 'ws';
import selfsigned from 'selfsigned';
import { SignalType } from './signals.js';
import { CryptoUtils } from './crypto/unified-crypto.js';
import { MessageDatabase, PrekeyDatabase, LibsignalBundleDB } from './database/database.js';
import * as ServerConfig from './config/config.js';
import { MessagingUtils } from './messaging/messaging-utils.js';
import * as authentication from './authentication/authentication.js';
import { setServerPasswordOnInput } from './authentication/auth-utils.js';
import { ed25519 } from '@noble/curves/ed25519';
import { rateLimitMiddleware } from './rate-limiting/rate-limit-middleware.js';

const clients = new Map();
const wsToUsername = new WeakMap(); // Map WebSocket -> username for consistent client tracking

const bundleCache = new Map(); // Cache for bundle requests to prevent redundant operations

// Message batching for database operations
const messageBatch = [];
const BATCH_SIZE = 10;
const BATCH_TIMEOUT = 1000; // 1 second
let batchTimer = null;

// Batch processing function for database operations
async function processBatch() {
  if (messageBatch.length === 0) return;

  const batch = messageBatch.splice(0, messageBatch.length);
  console.log(`[SERVER] Processing batch of ${batch.length} database operations`);

  // Process all batched operations
  for (const operation of batch) {
    try {
      await operation.execute();
    } catch (error) {
      console.error('[SERVER] Batch operation failed:', error);
    }
  }

  if (batchTimer) {
    clearTimeout(batchTimer);
    batchTimer = null;
  }
}

// Add operation to batch
function addToBatch(operation) {
  messageBatch.push(operation);

  // Process immediately if batch is full
  if (messageBatch.length >= BATCH_SIZE) {
    processBatch();
  } else if (!batchTimer) {
    // Set timer for partial batch
    batchTimer = setTimeout(processBatch, BATCH_TIMEOUT);
  }
}

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

  // Optimized periodic rate limiting status logging - only when needed
  let statusLogInterval = null;
  const startStatusLogging = () => {
    if (statusLogInterval) return;
    statusLogInterval = setInterval(async () => {
      try {
        const stats = rateLimitMiddleware.getStats();
        const globalStatus = await rateLimitMiddleware.getGlobalConnectionStatus();

        // Only log if there's actually something to report
        if (globalStatus.isBlocked || stats.userMessageLimiters > 0 || stats.userBundleLimiters > 0) {
          console.log('[RATE-LIMIT-STATUS]', {
            globalConnectionBlocked: globalStatus.isBlocked,
            globalConnectionAttempts: globalStatus.attempts,
            activeUserLimiters: stats.totalUserLimiters,
            timestamp: new Date().toISOString()
          });
        } else {
          // Stop logging if nothing to report for efficiency
          clearInterval(statusLogInterval);
          statusLogInterval = null;
        }
      } catch (error) {
        console.error('[SERVER] Error in rate limiting status logging:', error);
      }
    }, 60000); // Log every minute
  };

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

    let clientState = {
      username: null,
      hasPassedAccountLogin: false,
      hasAuthenticated: false,
      connectionTime: Date.now(),
      messageCount: 0,
      lastActivity: Date.now()
    };

    // Start status logging on first active connection (guarded internally)
    startStatusLogging();

    // Note: Do not add WebSocket to `clients` map.
    // `clients` is keyed by username only (set during/after authentication).

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
      // Update activity tracking
      clientState.lastActivity = Date.now();
      clientState.messageCount++;

      let parsed;
      try {
        parsed = JSON.parse(msg.toString().trim());
        console.log(`[SERVER] Received message type: ${parsed.type} from user: ${clientState.username || 'unknown'}`);
        
        // Debug message structure for encrypted messages
        if (parsed.type === SignalType.ENCRYPTED_MESSAGE) {
          console.log(`[SERVER] Message structure:`, {
            hasTo: 'to' in parsed,
            hasEncryptedPayload: 'encryptedPayload' in parsed,
            toValue: parsed.to,
            encryptedPayloadTo: parsed.encryptedPayload?.to,
            allKeys: Object.keys(parsed)
          });
        }
      } catch {
        console.error('[SERVER] Invalid JSON format received');
        return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Invalid JSON format' }));
      }

      try {
        switch (parsed.type) {


          case SignalType.LIBSIGNAL_PUBLISH_BUNDLE: {
            if (!clientState.hasPassedAccountLogin || !clientState.username) {
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Account login required first' }));
            }
            try {
              LibsignalBundleDB.publish(clientState.username, parsed.bundle);
              ws.send(JSON.stringify({ type: 'ok', message: 'libsignal-bundle-published' }));
            } catch (e) {
              ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Failed to publish libsignal bundle' }));
            }
            break;
          }



          case SignalType.LIBSIGNAL_REQUEST_BUNDLE: {
            if (!clientState.hasPassedAccountLogin) {
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Account login required first' }));
            }
            const target = parsed.username;
            const out = LibsignalBundleDB.take(target);
            if (!out) {
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'No libsignal bundle available' }));
            }
            ws.send(JSON.stringify({ type: SignalType.LIBSIGNAL_DELIVER_BUNDLE, bundle: out, username: target }));
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
              // Maintain ws->username mapping for cleanup and quick lookup
              wsToUsername.set(ws, result.username);

              if (result.pending) {
                console.log(`[SERVER] User '${result.username}' pending passphrase`);
              }

              ws.send(JSON.stringify({ type: SignalType.IN_ACCOUNT, message: 'Logged in successfully' }));

              if (!result.pending) {
                console.log(`[SERVER] User '${clientState.username}' completed account authentication`);
                // Ensure username entry exists in clients with ws attached (set by AccountAuthHandler)
                const existing = clients.get(clientState.username);
                if (existing && !existing.ws) existing.ws = ws;
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

              console.log(`[SERVER] Broadcasting public keys for: ${clientState.username}`);
              MessagingUtils.broadcastPublicKeys(clients);

              // Offline message delivery removed
            } else {
              console.error(`[SERVER] Server authentication failed for user: ${clientState.username}`);
              ws.send(JSON.stringify({ type: SignalType.AUTH_ERROR, message: 'Server authentication failed' }));
            }
            break;
          }

          case SignalType.UPDATE_DB: {
            console.log(`[SERVER] Queuing message for batch database save from user: ${clientState.username}`);

            // Add to batch instead of immediate processing
            addToBatch({
              execute: async () => {
                await MessageDatabase.saveMessageInDB(parsed, serverHybridKeyPair);
                console.log(`[SERVER] Message saved to database successfully (batched)`);
              }
            });

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

          // Note: Read receipts, delivery receipts, and typing indicators are now handled as encrypted messages
          // The server treats them as opaque encrypted data and just forwards them

          case SignalType.ENCRYPTED_MESSAGE:
          case SignalType.FILE_MESSAGE_CHUNK:
          case SignalType.DR_SEND: {
            console.log(`[SERVER] Processing ${parsed.type} from user: ${clientState.username} to user: ${parsed.to}`);
            
            // Log encrypted message details to verify it's ciphertext
            if (parsed.type === SignalType.ENCRYPTED_MESSAGE && parsed.encryptedPayload) {
              console.log(`[SERVER] Signal Protocol encrypted message details:`, {
                from: parsed.encryptedPayload.from,
                to: parsed.encryptedPayload.to,
                messageType: parsed.encryptedPayload.type,
                sessionId: parsed.encryptedPayload.sessionId,
                contentLength: parsed.encryptedPayload.content?.length || 0,
                contentPreview: parsed.encryptedPayload.content?.substring(0, 50) + '...',
                isBase64: /^[A-Za-z0-9+/]*={0,2}$/.test(parsed.encryptedPayload.content || ''),
                messageStructure: Object.keys(parsed),
                isSignalProtocol: parsed.encryptedPayload.type === 1 || parsed.encryptedPayload.type === 3 // Signal Protocol message types
              });
            }
            
            {
              const entry = clientState.username ? clients.get(clientState.username) : null;
              const isAuthed = entry?.clientState?.hasAuthenticated ?? clientState.hasAuthenticated;
              if (!isAuthed) {
                console.error('[SERVER] User not authenticated for message sending');
                return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Not authenticated yet' }));
              }
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

            const toUser = parsed.to || parsed.encryptedPayload?.to;
            const recipient = clients.get(toUser);
            if (recipient && recipient.ws) {
              console.log(`[SERVER] Forwarding message from ${clientState.username} to ${parsed.to}`);
              
              let messageToSend;
              if (parsed.type === SignalType.DR_SEND) {
                messageToSend = { type: SignalType.DR_SEND, from: clientState.username, to: toUser, payload: parsed.payload };
              } else if (parsed.type === SignalType.ENCRYPTED_MESSAGE) {
                // Verify Signal Protocol message integrity before relaying
                const encryptedPayload = parsed.encryptedPayload;
                if (!encryptedPayload || !encryptedPayload.content || !encryptedPayload.type) {
                  console.error(`[SERVER] Invalid Signal Protocol message structure:`, {
                    hasEncryptedPayload: !!encryptedPayload,
                    hasContent: !!encryptedPayload?.content,
                    hasType: !!encryptedPayload?.type,
                    structure: encryptedPayload ? Object.keys(encryptedPayload) : []
                  });
                  return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Invalid message structure' }));
                }
                
                // Preserve the full message structure for Signal Protocol decryption
                messageToSend = { 
                  type: SignalType.ENCRYPTED_MESSAGE, 
                  encryptedPayload: encryptedPayload 
                };
                
                console.log(`[SERVER] Signal Protocol message validated and ready for relay`);
              } else {
                messageToSend = parsed;
              }
              
              recipient.ws.send(JSON.stringify(messageToSend));
              console.log(`[SERVER] Message relayed to ${toUser}:`, {
                type: messageToSend.type,
                hasEncryptedPayload: !!messageToSend.encryptedPayload,
                encryptedPayloadKeys: messageToSend.encryptedPayload ? Object.keys(messageToSend.encryptedPayload) : [],
                messageStructure: Object.keys(messageToSend),
                isSignalProtocol: messageToSend.type === SignalType.ENCRYPTED_MESSAGE
              });
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

          case 'request-server-public-key': {
            // Re-send server public key on request
            ws.send(
              JSON.stringify({
                type: SignalType.SERVER_PUBLIC_KEY,
                hybridKeys: {
                  x25519PublicBase64: await CryptoUtils.Hybrid.exportX25519PublicBase64(serverHybridKeyPair.x25519.publicKey),
                  kyberPublicBase64: await CryptoUtils.Hybrid.exportKyberPublicBase64(serverHybridKeyPair.kyber.publicKey)
                }
              })
            );
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
      // Clean up client state
      const mappedUsername = wsToUsername.get(ws) || clientState.username;
      if (mappedUsername && clients.has(mappedUsername)) {
        clients.delete(mappedUsername);
        console.log(`[SERVER] User '${mappedUsername}' disconnected`);
      }
      // Remove mapping
      if (wsToUsername.has(ws)) wsToUsername.delete(ws);

      // Stop status logging if no more active connections
      if (wss.clients.size === 0 && statusLogInterval) {
        clearInterval(statusLogInterval);
        statusLogInterval = null;
        console.log('[SERVER] No active connections, stopped status logging');
      }

      // Log connection stats
      const connectionDuration = Date.now() - clientState.connectionTime;
      console.log(`[SERVER] Connection closed - Duration: ${connectionDuration}ms, Messages: ${clientState.messageCount}`);
    });
  });
}

startServer();
