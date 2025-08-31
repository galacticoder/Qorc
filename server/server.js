import https from 'https';
import fs from 'fs';
import path from 'path';
import { WebSocketServer } from 'ws';
import selfsigned from 'selfsigned';
import { SignalType } from './signals.js';
import { CryptoUtils } from './crypto/unified-crypto.js';
import { MessageDatabase, PrekeyDatabase, LibsignalBundleDB } from './database/database.js';
import * as ServerConfig from './config/config.js';
import { MessagingUtils } from './messaging/messaging-utils.js';
import * as authentication from './authentication/authentication.js';
import { setServerPasswordOnInput } from './authentication/auth-utils.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { rateLimitMiddleware } from './rate-limiting/rate-limit-middleware.js';
import { setOnline, setOffline, refreshOnline, createSubscriber, subscribeUserChannel } from './presence/presence.js';

// COMPLETELY REMOVED: No in-memory client tracking for millions of users
// All user data stored on WebSocket.clientState and Redis presence only

// Message batching for database operations with memory management
const messageBatch = [];
const BATCH_SIZE = 10;
const BATCH_TIMEOUT = 1000; // 1 second
const MAX_BATCH_SIZE = 100; // SECURITY: Prevent memory exhaustion
let batchTimer = null;

// Batch processing function for database operations
async function processBatch() {
  if (messageBatch.length === 0) return;

  // SECURITY: Limit batch size to prevent memory exhaustion
  const batchToProcess = messageBatch.splice(0, Math.min(messageBatch.length, MAX_BATCH_SIZE));
  console.log(`[SERVER] Processing batch of ${batchToProcess.length} database operations`);

  // Process all batched operations with error isolation
  const results = await Promise.allSettled(
    batchToProcess.map(operation => operation.execute())
  );

  // Log failed operations without exposing sensitive data
  const failedCount = results.filter(result => result.status === 'rejected').length;
  if (failedCount > 0) {
    console.error(`[SERVER] ${failedCount}/${batchToProcess.length} batch operations failed`);
  }

  // SECURITY: Clear processed operations from memory
  batchToProcess.length = 0;

  if (batchTimer) {
    clearTimeout(batchTimer);
    batchTimer = null;
  }

  // Continue processing if there are more operations
  if (messageBatch.length > 0) {
    setImmediate(processBatch);
  }
}

// Add operation to batch with overflow protection
function addToBatch(operation) {
  // SECURITY: Prevent memory exhaustion from unbounded batch growth
  if (messageBatch.length >= MAX_BATCH_SIZE * 2) {
    console.warn('[SERVER] Batch queue full, processing immediately');
    processBatch();
    return;
  }

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

// SECURITY: Validate and sanitize certificate paths to prevent path traversal
function validateCertPath(certPath) {
  if (!certPath || typeof certPath !== 'string') return false;
  
  // SECURITY: Limit path length to prevent DoS
  if (certPath.length > 1000) {
    console.error('[SERVER] Certificate path too long:', certPath.length);
    return false;
  }

  // SECURITY: Prevent path traversal attacks - check for dangerous patterns
  const dangerousPatterns = ['../', '..\\', '%2e%2e', '%2f', '%5c', '\0'];
  const lowerPath = certPath.toLowerCase();
  for (const pattern of dangerousPatterns) {
    if (lowerPath.includes(pattern)) {
      console.error('[SERVER] Dangerous pattern detected in certificate path:', pattern);
      return false;
    }
  }

  // SECURITY: Prevent path traversal attacks
  const normalizedPath = path.resolve(certPath);
  const allowedDir = path.resolve('./certs'); // Only allow certs in ./certs directory

  if (!normalizedPath.startsWith(allowedDir + path.sep) && normalizedPath !== allowedDir) {
    console.error('[SERVER] Certificate path outside allowed directory:', certPath);
    return false;
  }

  // SECURITY: Only allow .pem, .crt, .key files
  const allowedExtensions = ['.pem', '.crt', '.key'];
  const ext = path.extname(normalizedPath).toLowerCase();
  if (!allowedExtensions.includes(ext)) {
    console.error('[SERVER] Invalid certificate file extension:', ext);
    return false;
  }

  // SECURITY: Additional check for file existence and readability
  try {
    fs.accessSync(normalizedPath, fs.constants.R_OK);
  } catch (error) {
    console.error('[SERVER] Certificate file not accessible:', error.message);
    return false;
  }

  return normalizedPath;
}

let server;
const validCertPath = CERT_PATH ? validateCertPath(CERT_PATH) : null;
const validKeyPath = KEY_PATH ? validateCertPath(KEY_PATH) : null;

if (validCertPath && validKeyPath && fs.existsSync(validCertPath) && fs.existsSync(validKeyPath)) {
  console.log('[SERVER] Using provided TLS certificate and key');
  try {
    const key = fs.readFileSync(validKeyPath);
    const cert = fs.readFileSync(validCertPath);
    server = https.createServer({ key, cert });
  } catch (error) {
    console.error('[SERVER] Failed to read TLS certificates:', error.message);
    console.log('[SERVER] Falling back to self-signed certificate');
    const { private: key, cert } = selfsigned.generate([{ name: 'commonName', value: 'localhost' }], {
      days: 365,
      keySize: 4096,
    });
    server = https.createServer({ key, cert });
  }
} else {
  console.warn('[SERVER] No TLS_CERT_PATH/TLS_KEY_PATH provided; generating self-signed certificate for development');
  const { private: key, cert } = selfsigned.generate([{ name: 'commonName', value: 'localhost' }], {
    days: 365,
    keySize: 4096,
  });
  server = https.createServer({ key, cert });
}

async function startServer() {
  console.log('[SERVER] Starting end2end server');
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
    console.log(`[SERVER] end2end relay running on wss://0.0.0.0:${ServerConfig.PORT}`)
  );

  const wss = new WebSocketServer({ server });

  const authHandler = new authentication.AccountAuthHandler(serverHybridKeyPair);
  const serverAuthHandler = new authentication.ServerAuthHandler(serverHybridKeyPair, null, ServerConfig);

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

    // No global clients map; use ws.clientState and Redis presence only

    ws.send(
      JSON.stringify({
        type: SignalType.SERVER_PUBLIC_KEY,
        hybridKeys: {
          x25519PublicBase64: await CryptoUtils.Hybrid.exportX25519PublicBase64(serverHybridKeyPair.x25519.publicKey),
          kyberPublicBase64: await CryptoUtils.Hybrid.exportKyberPublicBase64(serverHybridKeyPair.kyber.publicKey)
        }
      })
    );

    // Presence: per-connection subscriber for delivery
    let presenceUnsub = null;
    let presenceSub = null;

    ws.on('message', async (msg) => {
      // SECURITY: Rate limit message processing to prevent DoS
      if (clientState.messageCount > 10000) { // Reset counter periodically
        const timeSinceConnection = Date.now() - clientState.connectionTime;
        if (timeSinceConnection > 60000) { // Reset every minute
          clientState.messageCount = 0;
          clientState.connectionTime = Date.now();
        } else if (clientState.messageCount > 1000) { // Hard limit per minute
          console.warn(`[SERVER] Message rate limit exceeded for user: ${clientState.username}`);
          return ws.close(1008, 'Message rate limit exceeded');
        }
      }

      // Update activity tracking
      clientState.lastActivity = Date.now();
      clientState.messageCount++;

      // SECURITY: Validate message size to prevent DoS
      if (msg.length > 1024 * 1024) { // 1MB limit
        console.error(`[SERVER] Message too large: ${msg.length} bytes from user: ${clientState.username}`);
        return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Message too large' }));
      }

      let parsed;
      try {
        const msgString = msg.toString().trim();
        
        // SECURITY: Additional validation for message content
        if (msgString.length === 0) {
          console.error('[SERVER] Empty message received');
          return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Empty message' }));
        }

        parsed = JSON.parse(msgString);
        
        // SECURITY: Validate message structure
        if (!parsed || typeof parsed !== 'object' || !parsed.type) {
          console.error('[SERVER] Invalid message structure received');
          return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Invalid message structure' }));
        }

        // SECURITY: Validate message type
        if (typeof parsed.type !== 'string' || parsed.type.length > 100) {
          console.error('[SERVER] Invalid message type received');
          return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Invalid message type' }));
        }

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
      } catch (error) {
        console.error('[SERVER] JSON parsing error:', error.message);
        return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Invalid JSON format' }));
      }

      try {
        switch (parsed.type) {
          case SignalType.ADMIN_GENERATE_PREKEYS: {
            // SECURITY: Admin endpoint - requires full authentication and admin privileges
            if (!clientState.hasAuthenticated || !clientState.username) {
              console.error('[SERVER] Unauthorized admin access attempt');
              return ws.send(JSON.stringify({ type: SignalType.AUTH_ERROR, message: 'Full authentication required for admin functions' }));
            }
            
            // SECURITY: In production, this should check admin role/permissions
            // For now, only allow users to generate prekeys for themselves
            const target = clientState.username; // SECURITY: Remove ability to target other users
            
            // SECURITY: Rate limit admin operations per user
            const now = Date.now();
            if (!clientState.lastAdminOp) clientState.lastAdminOp = 0;
            if (now - clientState.lastAdminOp < 60000) { // 1 minute cooldown
              console.error(`[SERVER] Admin operation rate limited for user: ${clientState.username}`);
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Admin operation rate limited - try again in 1 minute' }));
            }
            clientState.lastAdminOp = now;
            
            try {
              // SECURITY: Limit number of prekeys that can be generated
              const currentCount = PrekeyDatabase.countAvailableOneTimePreKeys(target);
              if (currentCount > 500) { // Don't allow more than 500 prekeys
                return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Too many existing prekeys' }));
              }
              
              const list = Array.from({ length: 100 }, (_, i) => ({ id: i + 1, publicKeyBase64: CryptoUtils.Hash.arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(32))) }));
              PrekeyDatabase.storeOneTimePreKeys(target, list);
              ws.send(JSON.stringify({ type: 'ok', message: 'prekeys-generated', username: target, count: list.length }));
              console.log(`[SERVER] Admin generated prekeys for user: ${target}`);
            } catch (e) {
              console.error('[SERVER] Admin prekey generation failed:', e);
              ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Failed to generate prekeys' }));
            }
            break;
          }


          case SignalType.LIBSIGNAL_PUBLISH_BUNDLE: {
            if (!clientState.hasPassedAccountLogin || !clientState.username) {
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Account login required first' }));
            }
            try {
              // Store main bundle data
              LibsignalBundleDB.publish(clientState.username, parsed.bundle);
              // Store one-time prekeys for consumption
              if (Array.isArray(parsed.bundle?.oneTimePreKeys)) {
                try {
                  PrekeyDatabase.storeOneTimePreKeys(clientState.username, parsed.bundle.oneTimePreKeys);
                } catch (e) {
                  console.error('[SERVER] Failed to store one-time prekeys:', e);
                }
              }
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
            
            // SECURITY: Validate username parameter
            const target = parsed.username;
            if (!target || typeof target !== 'string' || target.length < 3 || target.length > 32) {
              console.error(`[SERVER] Invalid username in bundle request: ${target}`);
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Invalid username format' }));
            }
            
            // SECURITY: Validate username format (alphanumeric, underscore, hyphen only)
            if (!/^[a-zA-Z0-9_-]+$/.test(target)) {
              console.error(`[SERVER] Invalid username characters in bundle request: ${target}`);
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Invalid username characters' }));
            }
            
            // Try to consume a one-time prekey; fallback to base bundle if none
            let out = PrekeyDatabase.takeBundleForRecipient(target);
            if (!out) {
              out = LibsignalBundleDB.take(target);
            }
            if (!out) {
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'No libsignal bundle available' }));
            }
            ws.send(JSON.stringify({ type: SignalType.LIBSIGNAL_DELIVER_BUNDLE, bundle: out, username: target }));
            // Auto-replenish if pool is low
            try {
              const remaining = PrekeyDatabase.countAvailableOneTimePreKeys(target);
              if (remaining < 20) {
                const list = Array.from({ length: 100 }, (_, i) => ({ id: i + 1, publicKeyBase64: CryptoUtils.Base64.arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(32))) }));
                PrekeyDatabase.storeOneTimePreKeys(target, list);
                console.log(`[SERVER] Auto-replenished one-time prekeys for ${target}: 100 generated`);
              }
            } catch (e) {
              console.warn('[SERVER] Auto-replenish failed:', e);
            }
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
              // Username stored in clientState only - no global memory structures

              // Mark presence and subscribe to delivery channel
              try {
                await setOnline(result.username, 120);
                presenceSub = presenceSub || await createSubscriber();
                presenceUnsub = await subscribeUserChannel(presenceSub, result.username, (raw) => {
                  try { ws.send(raw); } catch {}
                });
              } catch (e) {
                console.warn('[SERVER] Presence registration failed:', e?.message || e);
              }

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

              // No global public-key broadcast; keys are fetched on-demand per peer

              // Offline message delivery removed
              // Refresh online TTL after full auth
              try { await setOnline(clientState.username, 120); } catch {}
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
            // Legacy hybrid key updates are ignored to avoid server memory usage
            // Clients should use Libsignal bundles and on-demand session setup
            break;
          }

          // Note: Read receipts, delivery receipts, and typing indicators are now handled as encrypted messages
          // The server treats them as opaque encrypted data and just forwards them

          case SignalType.ENCRYPTED_MESSAGE:
          case SignalType.FILE_MESSAGE_CHUNK:
          case SignalType.DR_SEND: {
            console.log(`[SERVER] Processing ${parsed.type} from user: ${clientState.username} to user: ${parsed.to}`);
            
            // SECURITY: Log only non-sensitive metadata for encrypted messages
            if (parsed.type === SignalType.ENCRYPTED_MESSAGE && parsed.encryptedPayload) {
              console.log(`[SERVER] Signal Protocol encrypted message received:`, {
                from: parsed.encryptedPayload.from,
                to: parsed.encryptedPayload.to,
                messageType: parsed.encryptedPayload.type,
                sessionId: parsed.encryptedPayload.sessionId,
                contentLength: parsed.encryptedPayload.content?.length || 0,
                // SECURITY: Remove content preview to prevent data leakage
                isBase64: /^[A-Za-z0-9+/]*={0,2}$/.test(parsed.encryptedPayload.content || ''),
                messageStructure: Object.keys(parsed).filter(key => key !== 'content'), // Exclude content
                isSignalProtocol: parsed.encryptedPayload.type === 1 || parsed.encryptedPayload.type === 3 // Signal Protocol message types
              });
            }
            
            {
              const isAuthed = clientState.hasAuthenticated;
              if (!isAuthed) {
                console.error('[SERVER] User not authenticated for message sending');
                return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Not authenticated yet' }));
              }
            }
            if (!parsed.to) {
              console.warn(`[SERVER] Target user offline or not found: ${parsed.to}, queueing`);
              try {
                // Queue encrypted payload for delivery when user comes online
                MessageDatabase.queueOfflineMessage(parsed.to, {
                  type: parsed.type,
                  to: parsed.to,
                  encryptedPayload: parsed.encryptedPayload
                });
                // Inform sender that message has been queued
                try { ws.send(JSON.stringify({ type: 'ok', message: 'queued' })); } catch {}
              } catch (e) {
                console.error('[SERVER] Failed to queue offline message:', e);
                try { ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Failed to queue message' })); } catch {}
              }
              break;
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
              
            // Try pub-sub delivery first; fallback to offline queue
            try {
              const payload = JSON.stringify(messageToSend);
              const { publishToUser } = await import('./presence/presence.js');
              const published = await publishToUser(toUser, payload);
              if (published) {
                try { ws.send(JSON.stringify({ type: 'ok', message: 'relayed' })); } catch {}
                console.log(`[SERVER] Message published to user channel for ${toUser}`);
              } else {
                throw new Error('publish-failed');
              }
            } catch (e) {
              console.warn('[SERVER] Pub-sub delivery failed, queueing offline:', e?.message || e);
              try {
                MessageDatabase.queueOfflineMessage(parsed.to, {
                  type: parsed.type,
                  to: parsed.to,
                  encryptedPayload: parsed.encryptedPayload
                });
              } catch (qe) {
                console.error('[SERVER] Failed to queue offline message:', qe);
              }
            }
            console.log(`[SERVER] Message handling complete for ${toUser}:`, {
                type: messageToSend.type,
                hasEncryptedPayload: !!messageToSend.encryptedPayload,
                encryptedPayloadKeys: messageToSend.encryptedPayload ? Object.keys(messageToSend.encryptedPayload) : [],
                messageStructure: Object.keys(messageToSend),
                isSignalProtocol: messageToSend.type === SignalType.ENCRYPTED_MESSAGE
              });
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
      // Clean up client state - username stored in clientState only
      const username = clientState.username;
      if (username) {
        try { await setOffline(username); } catch {}
        console.log(`[SERVER] User '${username}' disconnected`);
      }

      // Unsubscribe presence channel
      try { if (presenceUnsub) await presenceUnsub(); } catch {}
      try { if (presenceSub) await presenceSub.quit?.(); } catch {}

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

// SECURITY: Graceful shutdown and cleanup
process.on('SIGINT', async () => {
  console.log('[SERVER] Received SIGINT, shutting down gracefully...');
  await gracefulShutdown();
});

process.on('SIGTERM', async () => {
  console.log('[SERVER] Received SIGTERM, shutting down gracefully...');
  await gracefulShutdown();
});

process.on('uncaughtException', (error) => {
  console.error('[SERVER] Uncaught exception:', error);
  gracefulShutdown().then(() => process.exit(1));
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[SERVER] Unhandled rejection at:', promise, 'reason:', reason);
  gracefulShutdown().then(() => process.exit(1));
});

async function gracefulShutdown() {
  console.log('[SERVER] Starting graceful shutdown...');
  
  try {
    // Clear batch timer
    if (batchTimer) {
      clearTimeout(batchTimer);
      batchTimer = null;
    }
    
    // Process remaining batched operations
    if (messageBatch.length > 0) {
      console.log(`[SERVER] Processing ${messageBatch.length} remaining batch operations...`);
      await processBatch();
    }
    
    // No global data structures to clear - all user data in Redis and per-connection state
    // Designed for millions of users without memory issues
    
    // Close server
    if (server) {
      await new Promise((resolve) => {
        server.close(resolve);
      });
    }
    
    console.log('[SERVER] Graceful shutdown completed');
    
    // Exit the process after cleanup
    process.exit(0);
  } catch (error) {
    console.error('[SERVER] Error during graceful shutdown:', error);
    process.exit(1);
  }
}

startServer().catch(error => {
  console.error('[SERVER] Failed to start server:', error);
  process.exit(1);
});
