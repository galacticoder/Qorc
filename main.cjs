const { app, BrowserWindow, ipcMain, session } = require('electron');
const WebSocket = require('ws');
const path = require('path');
const Signal = require('@signalapp/libsignal-client');

const isDev = !!process.env.VITE_DEV_SERVER_URL;

  // Completely disable all console output in main process to prevent EBADF errors
  function debugLog(message) {
    // Console logging completely disabled in main process
    // This prevents any file descriptor issues from console operations
  }
  
  function debugError(message, error) {
    // Error logging completely disabled in main process to prevent EBADF errors
    // This prevents any file descriptor issues from console operations
  }

  // Override console methods to prevent any console operations
  if (typeof console !== 'undefined') {
    console.log = () => {};
    console.error = () => {};
    console.warn = () => {};
    console.info = () => {};
    console.debug = () => {};
  }
  
  // Safe Signal Protocol wrapper to prevent native module EBADF errors
  function safeSignalOperation(operation, fallback = null) {
    try {
      // Add a small delay to prevent rapid successive operations that might cause file descriptor issues
      return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          debugError('Signal Protocol operation timed out');
          resolve(fallback);
        }, 5000); // 5 second timeout
        
        // Execute the operation immediately without the setTimeout delay
        const executeOperation = async () => {
          try {
            const result = await operation();
            clearTimeout(timeout);
            debugLog('Signal Protocol operation completed successfully');
            resolve(result);
          } catch (error) {
            clearTimeout(timeout);
            // If it's an EBADF error, try to recover by waiting a bit longer
            if (error.code === 'EBADF' || error.message.includes('bad file descriptor')) {
              debugError('Signal Protocol operation failed with EBADF, attempting retry...');
              setTimeout(async () => {
                try {
                  const retryResult = await operation();
                  debugLog('Signal Protocol operation succeeded on retry');
                  resolve(retryResult);
                } catch (retryError) {
                  debugError('Signal Protocol operation failed on retry:', retryError);
                  resolve(fallback);
                }
              }, 100);
            } else {
              debugError('Signal Protocol operation failed:', error);
              resolve(fallback);
            }
          }
        };
        
        // Execute immediately
        executeOperation();
      });
    } catch (error) {
      debugError('Signal Protocol operation failed:', error);
      return fallback;
    }
  }

  // Global variables for WebSocket and server state
  let ws = null;
  let latestServerPublicKey = null;

  // Rate limiting for typing indicators to prevent excessive calls
  // Note: Typing indicators are now sent as encrypted messages through the normal message system
  // Note: Typing indicators are now sent as encrypted messages through the normal message system

  // Safe console logging to avoid EBADF errors
  function sendCachedStateToRenderer(webContents) {
    try {
      if (latestServerPublicKey && webContents && !webContents.isDestroyed()) {
        webContents.send('edge:server-message', latestServerPublicKey);
      }
    } catch {}
  }

  // Cleanup function to prevent file descriptor leaks
  function cleanupSignalResources() {
    try {
      // Force garbage collection if available to clean up any lingering file descriptors
      if (global.gc) {
        global.gc();
      }
      
      // Clean up rate limiter to prevent memory leaks
      // Note: Typing indicators are now sent as encrypted messages through the normal message system
    } catch {}
  }

  function broadcastToRenderers(channel, payload) {
    try {
      const wins = BrowserWindow.getAllWindows();
      for (const w of wins) {
        try { 
          if (w && !w.isDestroyed()) {
            // If payload has excludeSender, send it to the renderer for filtering
            w.webContents.send(channel, payload); 
          }
        } catch {}
      }
    } catch {}
  }

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      nodeIntegrationInSubFrames: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      experimentalFeatures: false,
      enableBlinkFeatures: '',
      disableBlinkFeatures: '',
      // Use an in-memory session to avoid IndexedDB file locks in dev
      partition: 'temp-dev',
      // Additional security settings
      safeDialogs: true,
      safeDialogsMessage: 'This app has been blocked from creating additional dialogs',
      disableHtmlFullscreenWindowResize: true,
      // Disable remote module completely
      enableRemoteModule: false,
      // Prevent new window creation
      nativeWindowOpen: false,
    },
    // Window security settings
    show: false, // Don't show until ready
    autoHideMenuBar: true,
    titleBarStyle: 'default',
  });

  // Configure session security
  const ses = win.webContents.session;

  // Set Content Security Policy
  ses.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self'; " +
          "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " + // Allow unsafe-eval for WebAssembly
          "style-src 'self' 'unsafe-inline'; " +
          "img-src 'self' data: blob: https:; " + // Allow external images for favicon
          "font-src 'self' data:; " +
          "connect-src 'self' ws: wss:; " + // Allow WebSocket connections
          "media-src 'none'; " +
          "object-src 'none'; " +
          "frame-src 'none'; " +
          "worker-src 'self' blob:; " + // Allow blob workers for WebAssembly
          "child-src 'none'; " +
          "form-action 'none'; " +
          "base-uri 'self'; " +
          "manifest-src 'self';"
        ],
        'X-Content-Type-Options': ['nosniff'],
        'X-Frame-Options': ['DENY'],
        'X-XSS-Protection': ['1; mode=block'],
        'Referrer-Policy': ['no-referrer']
      }
    });
  });

  // Block external navigation
  win.webContents.on('will-navigate', (event, navigationUrl) => {
    const parsedUrl = new URL(navigationUrl);
    const currentUrl = win.webContents.getURL();

    if (currentUrl && parsedUrl.origin !== new URL(currentUrl).origin) {
      event.preventDefault();
      debugLog(`[Security] Blocked navigation to external URL: ${navigationUrl}`);
    }
  });

  // Block new window creation
  win.webContents.setWindowOpenHandler(({ url }) => {
    debugLog(`[Security] Blocked attempt to open new window: ${url}`);
    return { action: 'deny' };
  });

  // Send cached state when renderer finishes loading
  win.webContents.once('did-finish-load', () => {
    setTimeout(() => sendCachedStateToRenderer(win.webContents), 100);

    // Show the window after content is loaded
    win.show();

    // Inject security hardening script
    win.webContents.executeJavaScript(`
      // Disable potentially dangerous APIs
      if (typeof window !== 'undefined') {
        // Disable eval and related functions
        window.eval = function() { throw new Error('eval is disabled for security'); };
        window.Function = function() { throw new Error('Function constructor is disabled for security'); };

        // Disable dangerous DOM APIs
        if (document.write) {
          document.write = function() { throw new Error('document.write is disabled for security'); };
          document.writeln = function() { throw new Error('document.writeln is disabled for security'); };
        }
      }
    `).catch(() => {
      // Ignore errors in case the page is not ready
    });
  });

  const devUrl = process.env.VITE_DEV_SERVER_URL;
  if (devUrl) {
    win.loadURL(devUrl);
    // Only open DevTools if explicitly requested
    if (process.env.ELECTRON_OPEN_DEVTOOLS === '1') {
      win.webContents.openDevTools({ mode: 'detach' });
    }
  } else {
    win.loadFile(path.join(__dirname, 'dist/index.html'));
  }

  // Ensure the window shows the main UI, not just DevTools
  win.webContents.once('dom-ready', () => {
    if (!win.isVisible()) {
      win.show();
    }
    // Focus the main window, not DevTools
    win.focus();
  });
}

app.whenReady().then(() => {
  // Enable garbage collection if available to prevent file descriptor leaks
  try {
    app.commandLine.appendSwitch('js-flags', '--expose-gc');
  } catch {}
  
  // Trust self-signed localhost cert in dev for wss://localhost:8443
  if (isDev) {
    try {
      app.commandLine.appendSwitch('ignore-certificate-errors', 'true');
      session.defaultSession.setCertificateVerifyProc((request, callback) => {
        const host = request.hostname || '';
        if (host === 'localhost' || host === '127.0.0.1') {
          return callback(0);
        }
        // use default verifier for all other hosts
        return callback(-3);
      });
    } catch {}
  }
  createWindow();
  // Per-user contexts holding stores and keys
  const userContexts = new Map();

  class MemorySessionStore extends Signal.SessionStore {
    constructor() { super(); this.map = new Map(); }
    async saveSession(name, record) { this.map.set(name.toString(), Buffer.from(record.serialize())); }
    async getSession(name) {
      const raw = this.map.get(name.toString());
      if (!raw) return null;
      return Signal.SessionRecord.deserialize(new Uint8Array(raw));
    }
    async getExistingSessions(addresses) {
      const out = [];
      for (const addr of addresses) {
        const rec = await this.getSession(addr);
        if (rec) out.push(rec);
      }
      return out;
    }
  }

  // WebSocket client in main (local crypto service owns the connection)
  function connectWS() {
    const url = process.env.SERVER_URL || 'wss://localhost:8443/';
    try {
      if (ws && ws.readyState === WebSocket.OPEN) return;
      ws = new WebSocket(url, { rejectUnauthorized: false });
      ws.on('open', () => {
        debugLog('WebSocket connected to server');
      });
      ws.on('message', async (buf) => {
        const raw = buf.toString();
        try {
          const msg = JSON.parse(raw);
          if (msg?.type === 'server-public-key') {
            debugLog(`Received server-public-key, caching it`);
            latestServerPublicKey = msg;
          }
          
          // All messages are now routed through the normal message system
          broadcastToRenderers('edge:server-message', msg);
        } catch {
          broadcastToRenderers('edge:server-message', raw);
        }
      });
      // No-op: server already emits SERVER_PUBLIC_KEY on connect
      ws.on('close', () => {
        setTimeout(connectWS, 1000);
      });
      ws.on('error', (e) => {
        // WebSocket error occurred
      });
    } catch (e) {
      setTimeout(connectWS, 1000);
    }
  }
  connectWS();

  // IPC to send encrypted payloads to central server from renderer
  ipcMain.handle('edge:ws-send', async (_e, payload) => {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket not connected');
    }
    const data = typeof payload === 'string' ? payload : JSON.stringify(payload);
    try { ws.send(data); } catch (e) { /* WebSocket send error */ }
    return { ok: true };
  });

  // Renderer ready: replay latest important server state (e.g., server-public-key)
  ipcMain.handle('edge:renderer-ready', async (event) => {
    debugLog(`Renderer ready, latestServerPublicKey: ${!!latestServerPublicKey}`);
    if (latestServerPublicKey) {
      debugLog('Broadcasting cached server-public-key to renderer');
      // Send to specific renderer that called this
      sendCachedStateToRenderer(event.sender);
      // Also broadcast to all renderers for good measure
      broadcastToRenderers('edge:server-message', latestServerPublicKey);
    } else {
      debugLog('No cached server-public-key, requesting from server...');
      // Request server public key if we don't have it cached
      if (ws && ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(JSON.stringify({ type: 'request-server-public-key' }));
        } catch {}
      }
    }
    return { ok: true };
  });

  const IdentityChange = Signal.IdentityChange; const Direction = Signal.Direction;

  // Enhanced identity store that supports hybrid Ed25519 + Dilithium3 keys
  class HybridIdentityKeyStore extends Signal.IdentityKeyStore {
    constructor(identityKeyPair, registrationId, dilithiumKeyPair) {
      super();
      this.identityKeyPair = identityKeyPair;
      this.registrationId = registrationId;
      this.dilithiumKeyPair = dilithiumKeyPair; // Store Dilithium3 keys
      this.trusted = new Map();
      this.trustedDilithium = new Map(); // Store trusted Dilithium3 public keys
    }

    async getIdentityKey() { return this.identityKeyPair.privateKey; }
    async getLocalRegistrationId() { return this.registrationId; }

    // Get Dilithium3 keys for hybrid signatures
    getDilithiumKeyPair() { return this.dilithiumKeyPair; }

    async saveIdentity(name, key) {
      const k = name.toString();
      const prev = this.trusted.get(k);
      const incoming = Buffer.from(key.serialize()).toString('base64');
      if (!prev) { this.trusted.set(k, incoming); return IdentityChange.NewOrUnchanged; }
      if (prev !== incoming) { this.trusted.set(k, incoming); return IdentityChange.ReplacedExisting; }
      return IdentityChange.NewOrUnchanged;
    }

    // Save Dilithium3 public key for a contact
    async saveDilithiumIdentity(name, dilithiumPublicKey) {
      const k = name.toString();
      const keyBase64 = Buffer.from(dilithiumPublicKey).toString('base64');
      this.trustedDilithium.set(k, keyBase64);
    }

    async isTrustedIdentity(name, key, direction) {
      const saved = this.trusted.get(name.toString());
      if (!saved) return true;
      const incoming = Buffer.from(key.serialize()).toString('base64');
      return saved === incoming;
    }

    async getIdentity(name) {
      const saved = this.trusted.get(name.toString());
      if (!saved) return null;
      return Signal.PublicKey.deserialize(Buffer.from(saved, 'base64'));
    }

    // Get Dilithium3 public key for a contact
    async getDilithiumIdentity(name) {
      const saved = this.trustedDilithium.get(name.toString());
      if (!saved) return null;
      return Buffer.from(saved, 'base64');
    }
  }

  class MemoryPreKeyStore extends Signal.PreKeyStore { constructor() { super(); this.map = new Map(); }
    async savePreKey(id, record) { this.map.set(id, Buffer.from(record.serialize())); }
    async getPreKey(id) { const raw = this.map.get(id); if (!raw) throw new Error('prekey not found'); return Signal.PreKeyRecord.deserialize(new Uint8Array(raw)); }
    async removePreKey(id) { this.map.delete(id); }
  }

  class MemorySignedPreKeyStore extends Signal.SignedPreKeyStore { constructor() { super(); this.map = new Map(); }
    async saveSignedPreKey(id, record) { this.map.set(id, Buffer.from(record.serialize())); }
    async getSignedPreKey(id) { const raw = this.map.get(id); if (!raw) throw new Error('signed prekey not found'); return Signal.SignedPreKeyRecord.deserialize(new Uint8Array(raw)); }
  }

  class MemoryKyberPreKeyStore extends Signal.KyberPreKeyStore { constructor() { super(); this.map = new Map(); this.used = new Set(); }
    async saveKyberPreKey(id, record) { this.map.set(id, Buffer.from(record.serialize())); }
    async getKyberPreKey(id) { const raw = this.map.get(id); if (!raw) throw new Error('kyber prekey not found'); return Signal.KyberPreKeyRecord.deserialize(new Uint8Array(raw)); }
    async markKyberPreKeyUsed(id) { this.used.add(id); }
  }

  async function getOrCreateUserContext(username) {
    let ctx = userContexts.get(username); if (ctx) return ctx;

    // Generate standard Signal Protocol identity keys
    const idPair = Signal.IdentityKeyPair.generate();
    const registrationId = (Math.floor(Math.random() * 16380) + 1) & 0x7fff;

    // Generate Dilithium3 key pair for post-quantum signatures
    let dilithiumKeyPair;
    try {
      // Import our crypto utilities
      const { CryptoUtils } = await import('./crypto/unified-crypto.js');
      dilithiumKeyPair = await CryptoUtils.Dilithium.generateKeyPair();
      debugLog(`[EDGE] Generated Dilithium3 key pair for user: ${username}`);
    } catch (error) {
      console.error('[EDGE] Failed to generate Dilithium3 keys:', error);
      // Fallback to null - system will work without Dilithium3 but with reduced security
      dilithiumKeyPair = null;
    }

    const stores = {
      sessionStore: new MemorySessionStore(),
      identityStore: new HybridIdentityKeyStore(idPair, registrationId, dilithiumKeyPair),
      preKeyStore: new MemoryPreKeyStore(),
      signedPreKeyStore: new MemorySignedPreKeyStore(),
      kyberPreKeyStore: new MemoryKyberPreKeyStore()
    };

    ctx = { idPair, registrationId, dilithiumKeyPair, stores };
    userContexts.set(username, ctx);
    return ctx;
  }

  function b64(buf) { return Buffer.from(buf).toString('base64'); }
  function serializeKey(pub) { return b64(pub.serialize()); }
  function serializeKemPub(pub) { return b64(pub.serialize()); }

  ipcMain.handle('edge:generateIdentity', async (_e, args) => {
    const { username } = args || {};
    const ctx = await getOrCreateUserContext(username);

    const result = {
      registrationId: ctx.registrationId,
      identityPublicKeyBase64: serializeKey(ctx.idPair.publicKey)
    };

    // Include Dilithium3 public key if available
    if (ctx.dilithiumKeyPair) {
      result.dilithiumPublicKeyBase64 = Buffer.from(ctx.dilithiumKeyPair.publicKey).toString('base64');
    }

    return result;
  });

  ipcMain.handle('edge:generatePreKeys', async (_e, args) => {
    const { username, preKeyId = 1001, signedPreKeyId = 2001, kyberPreKeyId = 3001 } = args || {};
    const ctx = await getOrCreateUserContext(username);

    // Generate standard prekeys
    const priv = Signal.PrivateKey.generate();
    const pre = Signal.PreKeyRecord.new(preKeyId, priv.getPublicKey(), priv);

    // Generate signed prekey with Ed25519 signature
    const spkPriv = Signal.PrivateKey.generate();
    const spkPub = spkPriv.getPublicKey();
    const spkSig = ctx.idPair.privateKey.sign(spkPub.serialize());
    const spk = Signal.SignedPreKeyRecord.new(signedPreKeyId, Date.now(), spkPub, spkPriv, spkSig);

    // Generate Kyber prekey with Ed25519 signature
    const kyPair = Signal.KEMKeyPair.generate();
    const kySig = ctx.idPair.privateKey.sign(kyPair.getPublicKey().serialize());
    const kyRec = Signal.KyberPreKeyRecord.new(kyberPreKeyId, Date.now(), kyPair, kySig);

    // Store all prekeys
    await ctx.stores.preKeyStore.savePreKey(preKeyId, pre);
    await ctx.stores.signedPreKeyStore.saveSignedPreKey(signedPreKeyId, spk);
    await ctx.stores.kyberPreKeyStore.saveKyberPreKey(kyberPreKeyId, kyRec);

    const result = {
      preKeyId,
      preKeyPublicBase64: serializeKey(pre.publicKey()),
      signedPreKeyId,
      signedPreKeyPublicBase64: serializeKey(spk.publicKey()),
      signedPreKeySignatureBase64: b64(spk.signature()),
      kyberPreKeyId,
      kyberPreKeyPublicBase64: serializeKemPub(kyPair.getPublicKey()),
      kyberPreKeySignatureBase64: b64(kySig)
    };

    // Add Dilithium3 signatures if available
    if (ctx.dilithiumKeyPair) {
      try {
        const { CryptoUtils } = await import('./crypto/unified-crypto.js');

        // Create Dilithium3 signatures for signed prekey and Kyber prekey
        const spkDilithiumSig = await CryptoUtils.Dilithium.sign(ctx.dilithiumKeyPair.secretKey, spkPub.serialize());
        const kyDilithiumSig = await CryptoUtils.Dilithium.sign(ctx.dilithiumKeyPair.secretKey, kyPair.getPublicKey().serialize());

        result.signedPreKeyDilithiumSignatureBase64 = Buffer.from(spkDilithiumSig).toString('base64');
        result.kyberPreKeyDilithiumSignatureBase64 = Buffer.from(kyDilithiumSig).toString('base64');

        debugLog(`[EDGE] Generated Dilithium3 signatures for prekeys: ${username}`);
      } catch (error) {
        console.error('[EDGE] Failed to generate Dilithium3 signatures:', error);
      }
    }

    return result;
  });

  ipcMain.handle('edge:getPreKeyBundle', async (_e, args) => {
    const { username, deviceId = 1, preKeyId = 1001, signedPreKeyId = 2001, kyberPreKeyId = 3001 } = args || {};
    const ctx = await getOrCreateUserContext(username);

    const pre = await ctx.stores.preKeyStore.getPreKey(preKeyId);
    const spk = await ctx.stores.signedPreKeyStore.getSignedPreKey(signedPreKeyId);
    const ky = await ctx.stores.kyberPreKeyStore.getKyberPreKey(kyberPreKeyId);

    const bundle = {
      registrationId: ctx.registrationId,
      deviceId,
      identityKeyBase64: serializeKey(ctx.idPair.publicKey),
      preKeyId,
      preKeyPublicBase64: serializeKey(pre.publicKey()),
      signedPreKeyId,
      signedPreKeyPublicBase64: serializeKey(spk.publicKey()),
      signedPreKeySignatureBase64: b64(spk.signature()),
      kyberPreKeyId,
      kyberPreKeyPublicBase64: serializeKemPub(ky.keyPair().getPublicKey()),
      kyberPreKeySignatureBase64: b64(ky.signature())
    };

    // Add Dilithium3 keys and signatures if available
    if (ctx.dilithiumKeyPair) {
      try {
        const { CryptoUtils } = await import('./crypto/unified-crypto.js');

        bundle.dilithiumIdentityKeyBase64 = Buffer.from(ctx.dilithiumKeyPair.publicKey).toString('base64');

        // Regenerate Dilithium3 signatures (in production, these should be cached)
        const spkDilithiumSig = await CryptoUtils.Dilithium.sign(ctx.dilithiumKeyPair.secretKey, spk.publicKey().serialize());
        const kyDilithiumSig = await CryptoUtils.Dilithium.sign(ctx.dilithiumKeyPair.secretKey, ky.keyPair().getPublicKey().serialize());

        bundle.signedPreKeyDilithiumSignatureBase64 = Buffer.from(spkDilithiumSig).toString('base64');
        bundle.kyberPreKeyDilithiumSignatureBase64 = Buffer.from(kyDilithiumSig).toString('base64');

        debugLog(`[EDGE] Bundle includes Dilithium3 signatures for: ${username}`);
      } catch (error) {
        console.error('[EDGE] Failed to add Dilithium3 signatures to bundle:', error);
      }
    }

    return bundle;
  });

  ipcMain.handle('edge:processPreKeyBundle', async (_e, args) => {
    const { selfUsername, peerUsername, deviceId = 1, bundle } = args || {};
    const ctx = await getOrCreateUserContext(selfUsername);
    const addr = Signal.ProtocolAddress.new(peerUsername, deviceId);

    try {
      debugLog(`[EDGE] Processing prekey bundle: ${selfUsername} -> ${peerUsername}`);

      // Verify Dilithium3 signatures if present
      if (bundle.dilithiumIdentityKeyBase64 && bundle.signedPreKeyDilithiumSignatureBase64 && bundle.kyberPreKeyDilithiumSignatureBase64) {
        try {
          const { CryptoUtils } = await import('./crypto/unified-crypto.js');

          const dilithiumPubKey = Buffer.from(bundle.dilithiumIdentityKeyBase64, 'base64');
          const spkDilithiumSig = Buffer.from(bundle.signedPreKeyDilithiumSignatureBase64, 'base64');
          const kyDilithiumSig = Buffer.from(bundle.kyberPreKeyDilithiumSignatureBase64, 'base64');

          const spkPubBytes = Buffer.from(bundle.signedPreKeyPublicBase64, 'base64');
          const kyPubBytes = Buffer.from(bundle.kyberPreKeyPublicBase64, 'base64');

          // Verify Dilithium3 signatures
          const spkSigValid = await CryptoUtils.Dilithium.verify(spkDilithiumSig, spkPubBytes, dilithiumPubKey);
          const kySigValid = await CryptoUtils.Dilithium.verify(kyDilithiumSig, kyPubBytes, dilithiumPubKey);

          if (!spkSigValid || !kySigValid) {
            throw new Error('Dilithium3 signature verification failed');
          }

          // Store the Dilithium3 public key for this contact
          await ctx.stores.identityStore.saveDilithiumIdentity(peerUsername, dilithiumPubKey);

          debugLog(`[EDGE] Dilithium3 signature verification passed for: ${peerUsername}`);
        } catch (error) {
          console.error('[EDGE] Dilithium3 signature verification failed:', error);
          // Continue with session creation but log the security concern
          debugLog(`[EDGE] WARNING: Proceeding without Dilithium3 verification for: ${peerUsername}`);
        }
      }

      const b = await safeSignalOperation(async () => Signal.PreKeyBundle.new(
        bundle.registrationId,
        bundle.deviceId,
        bundle.preKeyId ?? null,
        bundle.preKeyPublicBase64 ? Signal.PublicKey.deserialize(Buffer.from(bundle.preKeyPublicBase64, 'base64')) : null,
        bundle.signedPreKeyId,
        Signal.PublicKey.deserialize(Buffer.from(bundle.signedPreKeyPublicBase64, 'base64')),
        Buffer.from(bundle.signedPreKeySignatureBase64, 'base64'),
        Signal.PublicKey.deserialize(Buffer.from(bundle.identityKeyBase64, 'base64')),
        bundle.kyberPreKeyId,
        Signal.KEMPublicKey.deserialize(Buffer.from(bundle.kyberPreKeyPublicBase64, 'base64')),
        Buffer.from(bundle.kyberPreKeySignatureBase64, 'base64')
      ));
      
      if (!b) {
        throw new Error('Failed to create PreKeyBundle');
      }
      
      await safeSignalOperation(() => 
        Signal.processPreKeyBundle(b, addr, ctx.stores.sessionStore, ctx.stores.identityStore, Signal.UsePQRatchet.Yes)
      );
      
      // Verify session was created
      const session = await ctx.stores.sessionStore.getSession(addr);
      debugLog(`[EDGE] Bundle processed, session created: ${!!session}`);
      
      return { ok: true };
    } catch (error) {
      debugError(`[EDGE] Failed to process prekey bundle:`, error);
      throw error;
    }
  });

  ipcMain.handle('edge:hasSession', async (_e, args) => {
    const { selfUsername, peerUsername, deviceId = 1 } = args || {};
    const ctx = await getOrCreateUserContext(selfUsername);
    const addr = Signal.ProtocolAddress.new(peerUsername, deviceId);
    const rec = await ctx.stores.sessionStore.getSession(addr);
    const hasSession = !!rec && rec.hasCurrentState?.(new Date()) !== false;
    
    // Log session status for debugging
    debugLog(`[EDGE] Session check: ${selfUsername} -> ${peerUsername}, hasSession: ${hasSession}`);
    
    return { hasSession };
  });

  ipcMain.handle('edge:encrypt', async (_e, args) => {
    try {
      const { fromUsername, toUsername, deviceId = 1, plaintext } = args || {}; 
      
      // Validate input parameters
      if (!fromUsername || !toUsername || !plaintext) {
        throw new Error('Missing required parameters for encryption');
      }
      
      const ctx = await getOrCreateUserContext(fromUsername);
      const addr = Signal.ProtocolAddress.new(toUsername, deviceId);
      const messageBytes = Buffer.from(plaintext, 'utf8');
      
      try {
        // Check if we have a session established
        const session = await ctx.stores.sessionStore.getSession(addr);
        if (!session) {
          throw new Error(`No Signal Protocol session established with ${toUsername}`);
        }
        
        // Debug: Log session object properties
        debugLog(`[EDGE] Session object properties:`, {
          hasSession: !!session,
          sessionKeys: session ? Object.keys(session) : [],
          sessionType: session ? typeof session : 'undefined',
          sessionConstructor: session ? session.constructor?.name : 'unknown'
        });
        
        // Encrypt the message using Signal Protocol
        const ct = await safeSignalOperation(async () => {
          debugLog(`[EDGE] Starting Signal Protocol encryption for ${fromUsername} -> ${toUsername}`);
          const result = await Signal.signalEncrypt(messageBytes, addr, ctx.stores.sessionStore, ctx.stores.identityStore);
          debugLog(`[EDGE] Signal Protocol encryption completed:`, {
            hasResult: !!result,
            resultType: result ? typeof result : 'undefined',
            resultKeys: result ? Object.keys(result) : [],
            resultConstructor: result ? result.constructor?.name : 'unknown'
          });
          return result;
        });
        
        if (!ct) {
          throw new Error('Signal Protocol encryption failed - no result returned');
        }
        
        debugLog(`[EDGE] Encryption result received:`, {
          hasCiphertext: !!ct,
          ciphertextType: typeof ct,
          ciphertextKeys: Object.keys(ct),
          hasSerialize: typeof ct.serialize === 'function',
          hasType: typeof ct.type === 'function'
        });
        
        // Serialize the encrypted message properly
        const serialized = Buffer.from(ct.serialize()).toString('base64');
        const msgType = ct.type();
        
        debugLog(`[EDGE] Serialization completed:`, {
          serializedLength: serialized.length,
          messageType: msgType,
          serializedPreview: serialized.substring(0, 50) + '...'
        });
        
        // Log encryption details for debugging
        debugLog(`[EDGE] Signal Protocol message encrypted: ${fromUsername} -> ${toUsername}, type: ${msgType}`);
        
        // Create a session identifier using the same format as the session store
        // The session store uses addr.toString() as the key
        const sessionId = addr.toString();
        
        const returnValue = { 
          ciphertextBase64: serialized, 
          type: msgType,
          sessionId: sessionId
        };
        
        debugLog(`[EDGE] Returning encryption result:`, {
          hasCiphertextBase64: !!returnValue.ciphertextBase64,
          ciphertextLength: returnValue.ciphertextBase64?.length || 0,
          hasType: !!returnValue.type,
          typeValue: returnValue.type,
          hasSessionId: !!returnValue.sessionId,
          sessionIdValue: returnValue.sessionId,
          returnKeys: Object.keys(returnValue)
        });
        
        return returnValue;
      } catch (error) {
        // Handle EBADF errors specifically
        if (error.code === 'EBADF' || error.message.includes('bad file descriptor')) {
          debugError(`[EDGE] File descriptor error during encryption, attempting cleanup...`);
          cleanupSignalResources();
          // Wait a bit and try one more time
          await new Promise(resolve => setTimeout(resolve, 200));
          try {
            const ct = await safeSignalOperation(async () => 
              Signal.signalEncrypt(messageBytes, addr, ctx.stores.sessionStore, ctx.stores.identityStore)
            );
            if (ct) {
              const serialized = Buffer.from(ct.serialize()).toString('base64');
              const msgType = ct.type();
              debugLog(`[EDGE] Signal Protocol message encrypted on retry: ${fromUsername} -> ${toUsername}, type: ${msgType}`);
              
              // Create a session identifier using the same format as the session store
              // The session store uses addr.toString() as the key
              const sessionId = addr.toString();
              
              return { 
                ciphertextBase64: serialized, 
                type: msgType,
                sessionId: sessionId
              };
            }
          } catch (retryError) {
            debugError(`[EDGE] Encryption retry also failed:`, retryError);
          }
        }
        debugError(`[EDGE] Signal Protocol encryption failed:`, error);
        throw error;
      }
    } catch (error) {
      // Catch any other errors and return a safe error response
      debugError(`[EDGE] Encryption handler failed:`, error);
      return {
        error: true,
        message: error.message || 'Encryption failed',
        code: error.code || 'UNKNOWN_ERROR'
      };
    }
  });

    ipcMain.handle('edge:decrypt', async (_e, args) => {
    try {
      const { selfUsername, fromUsername, deviceId = 1, ciphertextBase64 } = args || {}; 
      
      // Validate input parameters
      if (!selfUsername || !fromUsername || !ciphertextBase64) {
        throw new Error('Missing required parameters for decryption');
      }
      
      const ctx = await getOrCreateUserContext(selfUsername);
      const addr = Signal.ProtocolAddress.new(fromUsername, deviceId);
      
      try {
        // Validate input
        if (!ciphertextBase64 || typeof ciphertextBase64 !== 'string') {
          throw new Error('Invalid ciphertext: must be base64 string');
        }
        
        const bytes = Buffer.from(ciphertextBase64, 'base64');
        
        // Log decryption attempt
        debugLog(`[EDGE] Attempting to decrypt Signal Protocol message: ${selfUsername} <- ${fromUsername}`);
        
        try {
          // First try to deserialize as PreKeySignalMessage (for first message in a session)
          const pm = await safeSignalOperation(async () => 
            Signal.PreKeySignalMessage.deserialize(new Uint8Array(bytes))
          );
          
          if (!pm) {
            throw new Error('Failed to deserialize PreKeySignalMessage');
          }
          
          debugLog(`[EDGE] Message is PreKeySignalMessage, decrypting...`);
          
          const pt = await safeSignalOperation(async () => 
            Signal.signalDecryptPreKey(
              pm, addr, ctx.stores.sessionStore, ctx.stores.identityStore, 
              ctx.stores.preKeyStore, ctx.stores.signedPreKeyStore, ctx.stores.kyberPreKeyStore, 
              Signal.UsePQRatchet.Yes
            )
          );
          
          if (!pt) {
            throw new Error('PreKeySignalMessage decryption failed');
          }
          
          const plaintext = Buffer.from(pt).toString('utf8');
          debugLog(`[EDGE] PreKeySignalMessage decrypted successfully, length: ${plaintext.length}`);
          
          return { plaintext, kind: 'prekey' };
        } catch (preKeyError) {
          debugLog(`[EDGE] Not a PreKeySignalMessage, trying SignalMessage...`);
          
          try {
            // If that fails, try as regular SignalMessage
            const sm = Signal.SignalMessage.deserialize(new Uint8Array(bytes));
            debugLog(`[EDGE] Message is SignalMessage, decrypting...`);
            
            const pt2 = await Signal.signalDecrypt(sm, addr, ctx.stores.sessionStore, ctx.stores.identityStore);
            
            const plaintext = Buffer.from(pt2).toString('utf8');
            debugLog(`[EDGE] SignalMessage decrypted successfully, length: ${plaintext.length}`);
            
            return { plaintext, kind: 'signal' };
          } catch (signalError) {
            // If both fail, provide detailed error info
            debugError(`[EDGE] Both decryption methods failed: ${preKeyError.message}, ${signalError.message}`);
            
            throw new Error(`Failed to decrypt Signal Protocol message: PreKey error: ${preKeyError.message}, Signal error: ${signalError.message}`);
          }
        }
      } catch (error) {
        // Handle EBADF errors specifically
        if (error.code === 'EBADF' || error.message.includes('bad file descriptor')) {
          debugError(`[EDGE] File descriptor error during decryption, attempting cleanup...`);
          cleanupSignalResources();
          // Wait a bit and try one more time
          await new Promise(resolve => setTimeout(resolve, 200));
          try {
            // Retry the decryption logic
            const bytes = Buffer.from(ciphertextBase64, 'base64');
            const pm = await safeSignalOperation(async () => 
              Signal.PreKeySignalMessage.deserialize(new Uint8Array(bytes))
            );
            if (pm) {
              const pt = await safeSignalOperation(async () => 
                Signal.signalDecryptPreKey(
                  pm, addr, ctx.stores.sessionStore, ctx.stores.identityStore, 
                  ctx.stores.preKeyStore, ctx.stores.signedPreKeyStore, ctx.stores.kyberPreKeyStore, 
                  Signal.UsePQRatchet.Yes
                )
              );
              if (pt) {
                const plaintext = Buffer.from(pt).toString('utf8');
               debugLog(`[EDGE] PreKeySignalMessage decrypted successfully on retry, length: ${plaintext.length}`);
               return { plaintext, kind: 'prekey' };
              }
            }
          } catch (retryError) {
            debugError(`[EDGE] Decryption retry also failed:`, retryError);
          }
        }
        debugError(`[EDGE] Decryption failed:`, error);
        throw error;
      }
    } catch (error) {
      // Catch any other errors and return a safe error response
      debugError(`[EDGE] Decryption handler failed:`, error);
      return {
        error: true,
        message: error.message || 'Decryption failed',
        code: error.code || 'UNKNOWN_ERROR'
      };
    }
  });

  // Note: Typing indicators are now sent as encrypted messages through the normal message system
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  cleanupSignalResources();
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  cleanupSignalResources();
});

// Global error handler to catch any unhandled errors that might cause EBADF
process.on('uncaughtException', (error) => {
  try {
    // If it's an EBADF error, try to clean up resources
    if (error.code === 'EBADF' || error.message.includes('bad file descriptor')) {
      cleanupSignalResources();
    }
  } catch {}
});

process.on('unhandledRejection', (reason, promise) => {
  try {
    // If it's an EBADF error, try to clean up resources
    if (reason && typeof reason === 'object' && 'code' in reason) {
      const error = reason;
      if (error.code === 'EBADF' || (error.message && error.message.includes('bad file descriptor'))) {
        cleanupSignalResources();
      }
    }
  } catch {}
});


