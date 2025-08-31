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
import { ConnectionStateManager } from './presence/connection-state.js';

// COMPLETELY REMOVED: No in-memory client tracking for millions of users
// All user data stored in Redis-based connection state for scalability

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

  // Cleanup stale Redis data from previous server runs
  try {
    console.log('[SERVER] Cleaning up stale session data...');
    await ConnectionStateManager.cleanupStaleUsernameMappings();
    await ConnectionStateManager.cleanupExpiredSessions();
  } catch (error) {
    console.error('[SERVER] Warning: Failed to cleanup stale session data:', error);
  }

  // SECURITY: Removed periodic pre-key maintenance - clients manage their own prekeys

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

    // Create Redis-based session for scalable connection state management
    let sessionId = null;
    let messageCount = 0; // Keep message count in memory for rate limiting
    const connectionTime = Date.now();

    // Start status logging on first active connection (guarded internally)
    startStatusLogging();

    // Create Redis-based session for connection state
    try {
      sessionId = await ConnectionStateManager.createSession();
      console.log(`[SERVER] Created session: ${sessionId}`);
    } catch (error) {
      console.error('[SERVER] Failed to create session:', error);
      ws.close(1011, 'Internal server error');
      return;
    }

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
      if (messageCount > 10000) { // Reset counter periodically
        const timeSinceConnection = Date.now() - connectionTime;
        if (timeSinceConnection > 60000) { // Reset every minute
          messageCount = 0;
        } else if (messageCount > 1000) { // Hard limit per minute
          const state = await ConnectionStateManager.getState(sessionId);
          console.warn(`[SERVER] Message rate limit exceeded for user: ${state?.username || 'unknown'}`);
          return ws.close(1008, 'Message rate limit exceeded');
        }
      }

      // Update activity tracking and increment message count
      await ConnectionStateManager.refreshSession(sessionId);
      messageCount++;

      // SECURITY: Validate message size to prevent DoS
      if (msg.length > 1024 * 1024) { // 1MB limit
        const state = await ConnectionStateManager.getState(sessionId);
        console.error(`[SERVER] Message too large: ${msg.length} bytes from user: ${state?.username || 'unknown'}`);
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

        // Get current session state for logging
        const currentState = await ConnectionStateManager.getState(sessionId);
        console.log(`[SERVER] Received message type: ${parsed.type} from user: ${currentState?.username || 'unknown'}`);
        
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
          case SignalType.REQUEST_PREKEY_GENERATION: {
            // SECURITY: Requires authentication
            const state = await ConnectionStateManager.getState(sessionId);
            if (!state?.hasAuthenticated || !state?.username) {
              console.error('[SERVER] Unauthorized prekey generation request');
              return ws.send(JSON.stringify({ type: SignalType.AUTH_ERROR, message: 'Authentication required' }));
            }
            
            try {
              // Check current prekey count
              const currentCount = PrekeyDatabase.countAvailableOneTimePreKeys(state.username);
              const needsGeneration = currentCount < 10;
              
              if (!needsGeneration) {
                return ws.send(JSON.stringify({ 
                  type: SignalType.ERROR, 
                  message: `Sufficient prekeys available (${currentCount}). Generation not needed.` 
                }));
              }
              
              // Request client to generate prekeys (no server-side private key generation)
              console.log(`[SERVER] Requesting client-side prekey generation for user: ${state.username}`);
              ws.send(JSON.stringify({ 
                type: SignalType.CLIENT_GENERATE_PREKEYS,
                message: 'Please generate 100 one-time prekeys client-side',
                requestedCount: 100,
                currentCount: currentCount
              }));
              
            } catch (e) {
              console.error('[SERVER] Prekey generation request failed:', e);
              ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Failed to process prekey request' }));
            }
            break;
          }

          case SignalType.CLIENT_SUBMIT_PREKEYS: {
            // Handle client-generated prekeys (public keys only)
            const state = await ConnectionStateManager.getState(sessionId);
            if (!state?.hasAuthenticated || !state?.username) {
              console.error('[SERVER] Unauthorized prekey submission');
              return ws.send(JSON.stringify({ type: SignalType.AUTH_ERROR, message: 'Authentication required' }));
            }

            try {
              // Validate and store client-generated public keys
              if (!Array.isArray(parsed.prekeys) || parsed.prekeys.length === 0) {
                return ws.send(JSON.stringify({ 
                  type: SignalType.ERROR, 
                  message: 'Invalid prekeys format - must be array of public keys' 
                }));
              }

              // Validate each prekey has required public key fields only
              for (const prekey of parsed.prekeys) {
                if (!prekey.id || !prekey.publicKeyBase64) {
                  throw new Error('Invalid prekey format - missing id or publicKeyBase64');
                }
                if (typeof prekey.id !== 'string' && typeof prekey.id !== 'number') {
                  throw new Error('Invalid prekey id format');
                }
                if (typeof prekey.publicKeyBase64 !== 'string' || prekey.publicKeyBase64.length < 10) {
                  throw new Error('Invalid public key format');
                }
              }

              // Store the public keys
              PrekeyDatabase.storeOneTimePreKeys(state.username, parsed.prekeys);
              
              console.log(`[SERVER] Stored ${parsed.prekeys.length} client-generated prekeys for user: ${state.username}`);
              ws.send(JSON.stringify({ 
                type: 'ok', 
                message: 'prekeys-stored',
                count: parsed.prekeys.length
              }));

            } catch (e) {
              console.error('[SERVER] Failed to store client prekeys:', e);
              ws.send(JSON.stringify({ 
                type: SignalType.ERROR, 
                message: 'Failed to store prekeys: ' + e.message 
              }));
            }
            break;
          }

          case SignalType.PREKEY_STATUS: {
            // Check current prekey status for the authenticated user
            const state = await ConnectionStateManager.getState(sessionId);
            if (!state?.hasAuthenticated || !state?.username) {
              console.error('[SERVER] Unauthorized prekey status request');
              return ws.send(JSON.stringify({ type: SignalType.AUTH_ERROR, message: 'Authentication required' }));
            }

            try {
              const currentCount = PrekeyDatabase.countAvailableOneTimePreKeys(state.username);
              const needsGeneration = currentCount < 10;
              
              ws.send(JSON.stringify({
                type: SignalType.PREKEY_STATUS,
                currentCount: currentCount,
                needsGeneration: needsGeneration,
                threshold: 10
              }));

              // If low, automatically request generation
              if (needsGeneration) {
                console.log(`[SERVER] Auto-requesting prekey generation for user: ${state.username} (${currentCount} remaining)`);
                ws.send(JSON.stringify({ 
                  type: SignalType.CLIENT_GENERATE_PREKEYS,
                  message: 'Low prekey count detected. Please generate 100 one-time prekeys client-side',
                  requestedCount: 100,
                  currentCount: currentCount,
                  reason: 'auto-low-count'
                }));
              }

            } catch (e) {
              console.error('[SERVER] Failed to check prekey status:', e);
              ws.send(JSON.stringify({ 
                type: SignalType.ERROR, 
                message: 'Failed to check prekey status' 
              }));
            }
            break;
          }

          case SignalType.LIBSIGNAL_PUBLISH_BUNDLE: {
            const state = await ConnectionStateManager.getState(sessionId);
            if (!state?.hasPassedAccountLogin || !state?.username) {
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Account login required first' }));
            }
            
            try {
              // Store main bundle data (public keys only - client never sends private keys)
              LibsignalBundleDB.publish(state.username, parsed.bundle);
              
              // Store one-time prekeys for consumption (public keys only)
              if (Array.isArray(parsed.bundle?.oneTimePreKeys)) {
                try {
                  PrekeyDatabase.storeOneTimePreKeys(state.username, parsed.bundle.oneTimePreKeys);
                } catch (e) {
                  console.error('[SERVER] Failed to store one-time prekeys:', e);
                  return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Invalid one-time prekeys' }));
                }
              }
              
              ws.send(JSON.stringify({ type: 'ok', message: 'libsignal-bundle-published' }));
            } catch (e) {
              console.error('[SERVER] Bundle publication failed:', e);
              ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Failed to publish libsignal bundle' }));
            }
            break;
          }



          case SignalType.LIBSIGNAL_REQUEST_BUNDLE: {
            const state = await ConnectionStateManager.getState(sessionId);
            if (!state?.hasPassedAccountLogin) {
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
            let out = await PrekeyDatabase.takeBundleForRecipient(target);
            if (!out) {
              out = LibsignalBundleDB.take(target);
            }
            if (!out) {
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'No libsignal bundle available' }));
            }
            ws.send(JSON.stringify({ type: SignalType.LIBSIGNAL_DELIVER_BUNDLE, bundle: out, username: target }));
            
            // Check if target user needs more prekeys and notify them
            try {
              const remaining = PrekeyDatabase.countAvailableOneTimePreKeys(target);
              if (remaining < 10) {
                console.log(`[SERVER] User ${target} has low prekey count (${remaining}), will be notified on next connection`);
                // Note: We can't directly notify the target user here unless they're online
                // The client should periodically check their prekey count or check after bundle delivery
              }
            } catch (e) {
              console.warn('[SERVER] Failed to check prekey count:', e);
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
              await ConnectionStateManager.updateState(sessionId, {
                hasPassedAccountLogin: true,
                username: result.username
              });
              // Username stored in Redis-based session state for scalability

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
                const currentState = await ConnectionStateManager.getState(sessionId);
                console.log(`[SERVER] User '${currentState?.username || 'unknown'}' completed account authentication`);
              }
            } else {
              const currentState = await ConnectionStateManager.getState(sessionId);
              console.error(`[SERVER] Login failed for user: ${currentState?.username || 'unknown'}`);
              ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Login failed' }));
            }
            break;
          }

          case SignalType.PASSPHRASE_HASH:
          case SignalType.PASSPHRASE_HASH_NEW: {
            const state = await ConnectionStateManager.getState(sessionId);
            console.log(`[SERVER] Processing passphrase hash for user: ${state?.username || 'unknown'}`);
            if (!state?.username) {
              console.error('[SERVER] Username not set for passphrase submission');
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Username not set' }));
            }
            if (!parsed.passphraseHash) {
              console.error('[SERVER] Passphrase hash missing');
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Passphrase hash missing' }));
            }

            await authHandler.handlePassphrase(
              ws,
              state.username,
              parsed.passphraseHash,
              parsed.type === SignalType.PASSPHRASE_HASH_NEW
            );

            const successMessage = parsed.type === SignalType.PASSPHRASE_HASH_NEW
              ? 'Passphrase saved successfully'
              : 'Passphrase verified successfully';
            console.log(`[SERVER] Sending passphrase success to user: ${state.username}`);
            ws.send(
              JSON.stringify({
                type: SignalType.PASSPHRASE_SUCCESS,
                message: successMessage,
              })
            );
            break;
          }

          case SignalType.SERVER_LOGIN: {
            const state = await ConnectionStateManager.getState(sessionId);
            console.log(`[SERVER] Processing server login for user: ${state?.username || 'unknown'}`);
            if (!state?.hasPassedAccountLogin) {
              console.error('[SERVER] Account login required first');
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Account login required first' }));
            }

            if (state?.hasAuthenticated) {
              console.error('[SERVER] User already authenticated');
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Already authenticated' }));
            }

            const success = await serverAuthHandler.handleServerAuthentication(ws, msg.toString(), state);
            if (success) {
              await ConnectionStateManager.updateState(sessionId, { hasAuthenticated: true });
              // AUTH_SUCCESS is already sent by ServerAuthHandler.handleServerAuthentication()
              console.log(`[SERVER] Server authentication successful for user: ${state.username}`);

              // No global public-key broadcast; keys are fetched on-demand per peer

              // Offline message delivery removed
              // Refresh online TTL after full auth
              try { await setOnline(state.username, 120); } catch {}

              // Auto-check prekey status after successful authentication
              try {
                const currentCount = PrekeyDatabase.countAvailableOneTimePreKeys(state.username);
                if (currentCount < 10) {
                  console.log(`[SERVER] User ${state.username} has low prekey count (${currentCount}), requesting generation`);
                  ws.send(JSON.stringify({ 
                    type: SignalType.CLIENT_GENERATE_PREKEYS,
                    message: 'Low prekey count detected. Please generate 100 one-time prekeys client-side',
                    requestedCount: 100,
                    currentCount: currentCount,
                    reason: 'post-auth-check'
                  }));
                }
              } catch (e) {
                console.warn('[SERVER] Failed to check prekey status after auth:', e);
              }
            } else {
              console.error(`[SERVER] Server authentication failed for user: ${state.username}`);
              ws.send(JSON.stringify({ type: SignalType.AUTH_ERROR, message: 'Server authentication failed' }));
            }
            break;
          }

          case SignalType.UPDATE_DB: {
            const state = await ConnectionStateManager.getState(sessionId);
            console.log(`[SERVER] Queuing message for batch database save from user: ${state?.username || 'unknown'}`);

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
            const state = await ConnectionStateManager.getState(sessionId);
            console.log(`[SERVER] Processing ${parsed.type} from user: ${state?.username || 'unknown'} to user: ${parsed.to}`);
            
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
            
            if (!state?.hasAuthenticated) {
              console.error('[SERVER] User not authenticated for message sending');
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Not authenticated yet' }));
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
              if (!(await rateLimitMiddleware.checkMessageLimit(ws, state.username))) {
                console.log(`[SERVER] Message blocked due to rate limiting for user: ${state.username}`);
                break;
              }
            } catch (error) {
              console.error(`[SERVER] Rate limiting error during message for user ${state.username}:`, error);
              break;
            }

            const toUser = parsed.to || parsed.encryptedPayload?.to;
            let messageToSend;
              if (parsed.type === SignalType.DR_SEND) {
                messageToSend = { type: SignalType.DR_SEND, from: state.username, to: toUser, payload: parsed.payload };
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
                const queueSuccess = MessageDatabase.queueOfflineMessage(parsed.to, {
                  type: parsed.type,
                  to: parsed.to,
                  encryptedPayload: parsed.encryptedPayload
                });
                if (queueSuccess) {
                  console.log(`[SERVER] Message successfully queued for offline user: ${parsed.to}`);
                  try { ws.send(JSON.stringify({ type: 'ok', message: 'queued' })); } catch {}
                } else {
                  console.error(`[SERVER] Failed to queue message for user: ${parsed.to}`);
                  try { ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Failed to queue message' })); } catch {}
                }
              } catch (qe) {
                console.error('[SERVER] Failed to queue offline message:', qe);
                try { ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Failed to queue message' })); } catch {}
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
            const state = await ConnectionStateManager.getState(sessionId);
            console.log(`[SERVER] Rate limit status request from user: ${state?.username || 'unknown'}`);
            const stats = rateLimitMiddleware.getStats();
            const globalStatus = await rateLimitMiddleware.getGlobalConnectionStatus();
            const userStatus = state?.username ? await rateLimitMiddleware.getUserStatus(state.username) : null;

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
            const state = await ConnectionStateManager.getState(sessionId);
            console.log(`[SERVER] Rate limit reset request from user: ${state?.username || 'unknown'}`);

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

          case SignalType.REQUEST_MESSAGE_HISTORY: {
            const state = await ConnectionStateManager.getState(sessionId);
            if (!state?.hasAuthenticated) {
              return ws.send(JSON.stringify({ type: SignalType.ERROR, message: 'Authentication required' }));
            }

            // Rate limiting: Track last history request time in session state
            const now = Date.now();
            const HISTORY_REQUEST_COOLDOWN = 1000; // 1 second between requests
            if (state.lastHistoryRequest && (now - state.lastHistoryRequest) < HISTORY_REQUEST_COOLDOWN) {
              return ws.send(JSON.stringify({ 
                type: SignalType.ERROR, 
                message: 'Rate limited: too many history requests',
                error: 'RATE_LIMITED'
              }));
            }
            await ConnectionStateManager.updateState(sessionId, { lastHistoryRequest: now });

            try {
              const { limit = 50, since } = parsed;
              const requestLimit = Math.min(Math.max(1, parseInt(limit) || 50), 100); // Cap at 100 messages
              
              // Validate and parse 'since' parameter
              let sinceTimestamp = null;
              if (since !== undefined) {
                const parsedSince = parseInt(since);
                if (isNaN(parsedSince) || !isFinite(parsedSince) || parsedSince < 0) {
                  return ws.send(JSON.stringify({ 
                    type: SignalType.ERROR, 
                    message: 'Invalid since parameter: must be a finite positive integer timestamp',
                    error: 'INVALID_SINCE_PARAMETER'
                  }));
                }
                sinceTimestamp = parsedSince;
              }
              
              console.log(`[SERVER] Fetching message history for user: ${state.username}, limit: ${requestLimit}, since: ${sinceTimestamp}`);
              
              // Get messages from database using top-level import
              const messages = await MessageDatabase.getMessagesForUser(state.username, requestLimit);
              
              // Filter by timestamp if 'since' parameter provided
              const filteredMessages = sinceTimestamp ? 
                messages.filter(msg => msg.timestamp > sinceTimestamp) : 
                messages;
              
              ws.send(JSON.stringify({
                type: SignalType.MESSAGE_HISTORY_RESPONSE,
                messages: filteredMessages,
                hasMore: messages.length === requestLimit, // Indicate if there might be more messages
                timestamp: Date.now()
              }));
              
              console.log(`[SERVER] Sent ${filteredMessages.length} historical messages to user: ${state.username}`);
            } catch (error) {
              console.error(`[SERVER] Error fetching message history for user ${state.username}:`, error);
              ws.send(JSON.stringify({ 
                type: SignalType.ERROR, 
                message: 'Failed to fetch message history',
                error: 'HISTORY_FETCH_FAILED'
              }));
            }
            break;
          }

          default:
            console.error(`[SERVER] Unknown message type: ${parsed.type}`);
            ws.send(JSON.stringify({ type: SignalType.ERROR, message: `Unknown message type: ${msg}` }));
        }
      } catch (err) {
        const state = await ConnectionStateManager.getState(sessionId);
        console.error(`[SERVER] Message handler error for user ${state?.username || 'unknown'}:`, err);
      }
    });

    ws.on('close', async () => {
      // Clean up Redis-based session state
      const state = await ConnectionStateManager.getState(sessionId);
      const username = state?.username;
      
      if (username) {
        try { await setOffline(username); } catch {}
        console.log(`[SERVER] User '${username}' disconnected`);
      }

      // Clean up session from Redis
      if (sessionId) {
        try { await ConnectionStateManager.deleteSession(sessionId); } catch {}
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

      // Log connection stats (minimal tracking)
      const connectionDuration = Date.now() - connectionTime;
      console.log(`[SERVER] Connection closed - Duration: ${connectionDuration}ms, Messages: ${messageCount}`);
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
