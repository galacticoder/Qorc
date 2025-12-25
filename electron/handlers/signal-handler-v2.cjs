/**
 * Quantum-Resistant Signal Protocol Handler
 */

const { pathToFileURL } = require('url');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { app } = require('electron');
const { SignalProtocolStore } = require('./signal-storage.cjs');

let _libsignal = null;
let _libsignalPromise = null;
async function _loadLibsignal() {
  if (_libsignal) return _libsignal;
  if (!_libsignalPromise) {
    _libsignalPromise = (async () => {
      const pkgJsonPath = require.resolve('@signalapp/libsignal-client/package.json');
      const pkgDir = require('path').dirname(pkgJsonPath);
      const prevCwd = process.cwd();
      try {
        if (prevCwd !== pkgDir) process.chdir(pkgDir);
        const m = await import('@signalapp/libsignal-client');
        const mod = m?.default ? m.default : m;
        if (!mod || typeof mod.IdentityKeyPair?.generate !== 'function') {
          throw new Error('libsignal-client loaded but missing expected API');
        }
        return mod;
      } finally {
        try { if (process.cwd() !== prevCwd) process.chdir(prevCwd); } catch (_) { }
      }
    })().catch((err) => {
      console.error('[SIGNAL-V2] Failed to load libsignal-client:', err);
      _libsignalPromise = null;
      throw err;
    });
  }
  _libsignal = await _libsignalPromise;
  return _libsignal;
}

class QuantumResistantSignalHandler {
  constructor(securityMiddleware) {
    this.securityMiddleware = securityMiddleware;

    // Signal Protocol storage
    this.store = new SignalProtocolStore();

    // Post-quantum bridge
    this.pqBridge = null;
    this.pqBridgePromise = null;

    // PQ outer-layer keys
    this.pqKyberKeyPairs = new Map();
    this.staticMlkemKeys = new Map();
    this.peerKyberPublicKeys = new Map();

    // Session locks for thread safety
    this.sessionLocks = new Map();

    try {
      this._loadPersistedPqKeys();
    } catch (e) { }

    try {
      this._loadPersistedPeerKyberKeys();
    } catch (e) { }

    this._libsignalCache = null;
  }

  /**
   * Load post-quantum cryptography bridge
   */
  async loadPQBridge() {
    if (this.pqBridge) return this.pqBridge;

    if (!this.pqBridgePromise) {
      const bridgePath = path.join(__dirname, '../post-quantum-bridge.mjs');
      const bridgeUrl = pathToFileURL(bridgePath).href;

      this.pqBridgePromise = import(bridgeUrl)
        .then((module) => {
          if (!module?.KEM || !module?.AEAD || !module?.Hash || !module?.Signature || !module?.Random) {
            throw new Error('PQ bridge validation failed');
          }
          this.pqBridge = module;
          return this.pqBridge;
        })
        .catch((error) => {
          console.error('[SIGNAL-V2] PQ bridge load failed');
          this.pqBridgePromise = null;
          throw error;
        });
    }

    return this.pqBridgePromise;
  }

  /**
   * Acquire lock for session ops
   */
  async acquireSessionLock(key, timeout = 5000) {
    const startTime = Date.now();
    while (this.sessionLocks.get(key)) {
      if (Date.now() - startTime > timeout) {
        throw new Error('Session lock timeout');
      }
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    this.sessionLocks.set(key, true);
  }

  /**
   * Release session lock
   */
  releaseSessionLock(key) {
    this.sessionLocks.delete(key);
  }

  /**
   * Validate username
   */
  validateUsername(username) {
    if (!username || typeof username !== 'string') {
      throw new Error('Invalid username');
    }
    // Accept both regular usernames and pseudonymized ones (32+ char hex)
    const isPseudonym = /^[a-f0-9]{32,}$/i.test(username);
    if (!isPseudonym && !/^[a-zA-Z0-9_-]+$/.test(username)) {
      throw new Error('Username contains invalid characters');
    }
    if (username.length > 128 || username.length < 1) {
      throw new Error('Username length invalid');
    }
  }

  /**
   * Generate Signal Protocol identity and keys for a user
   */
  async generateIdentity(username) {
    const libsignal = await _loadLibsignal();
    try {
      this.validateUsername(username);

      const existing = await this.store.getIdentityKeyPair(username);
      const existingReg = await this.store.getLocalRegistrationId(username);
      if (existing && existingReg) {
        return {
          success: true,
          identityKey: Buffer.from(existing.pubKey).toString('base64'),
          registrationId: existingReg
        };
      }

      const registrationId = SignalProtocolStore.generateRegistrationId();
      const identityKeyPair = libsignal.IdentityKeyPair.generate();

      this.store.storeIdentityKeyPair(username, {
        pubKey: identityKeyPair.publicKey.serialize(),
        privKey: identityKeyPair.privateKey.serialize()
      }, registrationId);

      return {
        success: true,
        identityKey: Buffer.from(identityKeyPair.publicKey.serialize()).toString('base64'),
        registrationId
      };
    } catch (error) {
      console.error('[SIGNAL-V2] Identity generation failed');
      return { success: false, error: 'Identity generation failed' };
    }
  }

  /**
   * Generate pre-keys for a user
   */
  async generatePreKeys(username, startId = 1, count = 100) {
    const libsignal = await _loadLibsignal();
    try {
      this.validateUsername(username);

      const preKeys = [];

      for (let i = 0; i < count; i++) {
        const keyId = startId + i;
        const preKey = libsignal.PrivateKey.generate();

        await this.store.storePreKey(username, keyId, {
          pubKey: preKey.getPublicKey().serialize(),
          privKey: preKey.serialize()
        });

        preKeys.push({
          keyId,
          publicKey: Buffer.from(preKey.getPublicKey().serialize()).toString('base64')
        });
      }

      return { success: true, preKeys };
    } catch (error) {
      console.error('[SIGNAL-V2] PreKey generation failed');
      return { success: false, error: 'PreKey generation failed' };
    }
  }

  /**
   * Generate signed pre-key
   */
  async generateSignedPreKey(username, keyId) {
    const libsignal = await _loadLibsignal();
    try {
      this.validateUsername(username);

      const identityKeyPair = await this.store.getIdentityKeyPair(username);
      if (!identityKeyPair) {
        throw new Error('No identity key pair found');
      }

      const signedPreKey = libsignal.PrivateKey.generate();
      const identityPrivateKey = libsignal.PrivateKey.deserialize(Buffer.from(identityKeyPair.privKey));

      // Sign the pre-key
      const signature = identityPrivateKey.sign(signedPreKey.getPublicKey().serialize());

      await this.store.storeSignedPreKey(username, keyId, {
        pubKey: signedPreKey.getPublicKey().serialize(),
        privKey: signedPreKey.serialize()
      }, signature, Date.now());

      return {
        success: true,
        keyId,
        publicKey: Buffer.from(signedPreKey.getPublicKey().serialize()).toString('base64'),
        signature: Buffer.from(signature).toString('base64')
      };
    } catch (error) {
      console.error('[SIGNAL-V2] Signed PreKey failed');
      return { success: false, error: 'Signed PreKey failed' };
    }
  }

  /**
   * Generate Kyber pre-key for Signal Protocol (libsignal-native Kyber)
   */
  async generateKyberPreKey(username, keyId) {
    const libsignal = await _loadLibsignal();
    try {
      const identityKeyPair = await this.store.getIdentityKeyPair(username);
      if (!identityKeyPair) throw new Error('Identity required for Kyber pre-key');
      const identityPrivateKey = libsignal.PrivateKey.deserialize(Buffer.from(identityKeyPair.privKey));

      const kyberKeyPair = libsignal.KEMKeyPair.generate();
      const timestamp = Date.now();
      const pubBytes = kyberKeyPair.getPublicKey().serialize();
      const signature = identityPrivateKey.sign(pubBytes);
      const kyberRecord = libsignal.KyberPreKeyRecord.new(Number(keyId), Number(timestamp), kyberKeyPair, signature);

      // Store in our storage for later retrieval
      await this.store.storeKyberPreKey(username, keyId, kyberRecord.serialize(), timestamp, false);

      // Also keep accessible for outer PQ layer decapsulation if needed
      if (!this.kyberKeys) this.kyberKeys = new Map();
      this.kyberKeys.set(`${username}:${keyId}`, {
        keyPair: kyberKeyPair,
        publicKey: kyberKeyPair.getPublicKey(),
        secretKey: kyberKeyPair.getSecretKey(),
        signature,
        timestamp
      });

      return {
        success: true,
        keyId,
        publicKey: Buffer.from(pubBytes).toString('base64'),
        signature: Buffer.from(signature).toString('base64')
      };
    } catch (error) {
      console.error('[SIGNAL-V2] Kyber PreKey failed');
      return { success: false, error: 'Kyber PreKey failed' };
    }
  }

  async generatePqKyberPreKey(username, keyId) {
    try {
      const bridge = await this.loadPQBridge();
      const kp = bridge.KEM.generateKeyPair();
      this.pqKyberKeyPairs.set(`${username}:${keyId}`, { publicKey: kp.publicKey, secretKey: kp.secretKey });
      this._savePersistedPqKeys();
      return { success: true, keyId, publicKeyBase64: Buffer.from(kp.publicKey).toString('base64') };
    } catch (error) {
      console.error('[SIGNAL-V2] PQ Kyber PreKey failed');
      return { success: false, error: 'PQ Kyber PreKey failed' };
    }
  }

  /**
   * Create pre-key bundle for distribution
   */
  async createPreKeyBundle(username) {
    const libsignal = await _loadLibsignal();
    try {
      this.validateUsername(username);

      let registrationId = await this.store.getLocalRegistrationId(username);
      if (!registrationId) {
        const identityResult = await this.generateIdentity(username);
        if (!identityResult.success) {
          throw new Error('Failed to generate identity: ' + (identityResult.error || 'Unknown error'));
        }
        registrationId = identityResult.registrationId;
      }

      const identityKeyPair = await this.store.getIdentityKeyPair(username);
      if (!identityKeyPair) {
        throw new Error('No identity key pair found');
      }

      let preKey = await this.store.loadPreKey(username, 1);
      if (!preKey) {
        await this.generatePreKeys(username, 1, 1);
        preKey = await this.store.loadPreKey(username, 1);
        if (!preKey) throw new Error('Failed to generate pre-key');
      }

      let signedPreKey = await this.store.loadSignedPreKey(username, 1);
      if (!signedPreKey) {
        await this.generateSignedPreKey(username, 1);
        signedPreKey = await this.store.loadSignedPreKey(username, 1);
        if (!signedPreKey) throw new Error('Failed to generate signed pre-key');
      }

      let kyberPreKey = await this.store.loadKyberPreKey(username, 1);
      if (!kyberPreKey) {
        const gen = await this.generateKyberPreKey(username, 1);
        if (!gen.success) throw new Error(gen.error || 'Failed to generate Kyber pre-key');
        kyberPreKey = await this.store.loadKyberPreKey(username, 1);
      }

      let pqKyber = this.pqKyberKeyPairs.get(`${username}:1`);
      if (!pqKyber) {
        const pqGen = await this.generatePqKyberPreKey(username, 1);
        if (!pqGen.success) throw new Error(pqGen.error || 'Failed to generate PQ Kyber pre-key');
        pqKyber = this.pqKyberKeyPairs.get(`${username}:1`);
      }

      const kyberRecordBuf = kyberPreKey.record;
      const kyberRecord = libsignal.KyberPreKeyRecord.deserialize(kyberRecordBuf);

      const bundle = {
        registrationId,
        deviceId: 1,
        identityKeyBase64: Buffer.from(identityKeyPair.pubKey).toString('base64'),
        preKey: {
          keyId: 1,
          publicKeyBase64: Buffer.from(preKey.keyPair.pubKey).toString('base64')
        },
        signedPreKey: {
          keyId: 1,
          publicKeyBase64: Buffer.from(signedPreKey.keyPair.pubKey).toString('base64'),
          signatureBase64: Buffer.from(signedPreKey.signature).toString('base64')
        },
        kyberPreKey: {
          keyId: 1,
          publicKeyBase64: Buffer.from(kyberRecord.publicKey().serialize()).toString('base64'),
          signatureBase64: Buffer.from(kyberRecord.signature()).toString('base64')
        },
        pqKyber: {
          keyId: 1,
          publicKeyBase64: Buffer.from(pqKyber.publicKey).toString('base64')
        }
      };

      return { success: true, bundle };
    } catch (error) {
      console.error('[SIGNAL-V2] Bundle creation failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Process incoming pre-key bundle and establish session
   */
  async processPreKeyBundle(selfUsername, peerUsername, bundle) {
    const libsignal = await _loadLibsignal();
    const sessionKey = `${selfUsername}:${peerUsername}.1`;

    try {
      this.validateUsername(selfUsername);
      this.validateUsername(peerUsername);

      await this.acquireSessionLock(sessionKey);

      // If a session exists delete it first
      const existingSession = await this.store.loadSession(selfUsername, `${peerUsername}.1`);
      if (existingSession) {
        await this.store.deleteSession(selfUsername, `${peerUsername}.1`);
        await this.store.removeIdentity(selfUsername, peerUsername);
      }

      const peerIdentityKey = libsignal.PublicKey.deserialize(
        Buffer.from(bundle.identityKeyBase64, 'base64')
      );
      const peerPreKey = libsignal.PublicKey.deserialize(
        Buffer.from(bundle.preKey.publicKeyBase64, 'base64')
      );
      const peerSignedPreKey = libsignal.PublicKey.deserialize(
        Buffer.from(bundle.signedPreKey.publicKeyBase64, 'base64')
      );
      const signature = Buffer.from(bundle.signedPreKey.signatureBase64, 'base64');

      if (!peerIdentityKey.verify(peerSignedPreKey.serialize(), signature)) {
        throw new Error('Invalid signed pre-key signature');
      }

      const peerAddress = libsignal.ProtocolAddress.new(peerUsername, bundle.deviceId || 1);

      const ourIdentityKeyPair = await this.store.getIdentityKeyPair(selfUsername);
      if (!ourIdentityKeyPair) {
        throw new Error('No local identity key pair');
      }

      const preKeyId = bundle.preKey?.keyId != null ? Number(bundle.preKey.keyId) : null;
      const registrationId = Number(bundle.registrationId);
      const deviceId = Number(bundle.deviceId || 1);
      const signedPreKeyId = Number(bundle.signedPreKey.keyId);

      if (!Number.isInteger(registrationId) || !Number.isInteger(deviceId) || !Number.isInteger(signedPreKeyId)) {
        throw new Error(`Invalid bundle integers: reg=${registrationId}, dev=${deviceId}, spk=${signedPreKeyId}`);
      }

      if (preKeyId !== null && !Number.isInteger(preKeyId)) {
        throw new Error(`Invalid preKeyId: ${preKeyId}`);
      }

      const kyberPreKeyId = Number(bundle.kyberPreKey?.keyId || 1);
      const kyberPublicKeyBytes = Buffer.from(bundle.kyberPreKey?.publicKeyBase64 || '', 'base64');
      const kyberSignature = Buffer.from(bundle.kyberPreKey?.signatureBase64 || '', 'base64');
      const kyberPublicKey = libsignal.KEMPublicKey.deserialize(kyberPublicKeyBytes);

      const preKeyBundle = libsignal.PreKeyBundle.new(
        registrationId,
        deviceId,
        preKeyId,
        preKeyId !== null ? peerPreKey : null,
        signedPreKeyId,
        peerSignedPreKey,
        signature,
        peerIdentityKey,
        kyberPreKeyId,
        kyberPublicKey,
        kyberSignature
      );

      // Process bundle and create session
      const sessionStore = await this._createSessionStore(selfUsername);
      const identityStore = await this._createIdentityKeyStore(selfUsername);

      try {
        await libsignal.processPreKeyBundle(
          preKeyBundle,
          peerAddress,
          sessionStore,
          identityStore,
          new Date()
        );
      } catch (bundleError) {
        if (bundleError.code === 3 || bundleError.name === 'UntrustedIdentity') {

          const addressUsernameOnly = peerUsername;
          const newIdentityBytes = peerIdentityKey.serialize();

          await this.store.trustPeerIdentity(selfUsername, addressUsernameOnly);
          await this.store.saveIdentity(selfUsername, addressUsernameOnly, newIdentityBytes);

          const savedIdentity = await this.store.getIdentity(selfUsername, addressUsernameOnly);
          const freshIdentityStore = await this._createIdentityKeyStore(selfUsername);

          try {
            await libsignal.processPreKeyBundle(
              preKeyBundle,
              peerAddress,
              sessionStore,
              freshIdentityStore,
              new Date()
            );
          } catch (retryError) {
            console.error('[SIGNAL-V2] Retry failed after saving identity:', retryError);
            console.error('[SIGNAL-V2] Retry error code:', retryError.code);
            console.error('[SIGNAL-V2] Retry error name:', retryError.name);
            throw retryError;
          }
        } else {
          throw bundleError;
        }
      }

      return { success: true };
    } catch (error) {
      console.error('[SIGNAL-V2] Bundle processing failed:', error);
      return { success: false, error: error.message };
    } finally {
      this.releaseSessionLock(sessionKey);
    }
  }

  /**
   * Check if session exists
   */
  async hasSession(selfUsername, peerUsername, deviceId = 1) {
    try {
      const address = `${peerUsername}.${deviceId}`;
      const hasSession = this.store.hasSession(selfUsername, address);
      return { success: true, hasSession };
    } catch (error) {
      return { success: false, hasSession: false, error: error.message };
    }
  }

  /**
   * Encrypt with Signal Protocol
   */
  async encryptWithSignalProtocol(fromUsername, toUsername, plaintext) {
    const libsignal = await _loadLibsignal();
    const toAddress = libsignal.ProtocolAddress.new(toUsername, 1);

    const sessionStore = await this._createSessionStore(fromUsername);
    const identityStore = await this._createIdentityKeyStore(fromUsername);
    const message = await libsignal.signalEncrypt(
      Buffer.from(plaintext, 'utf8'),
      toAddress,
      sessionStore,
      identityStore,
      new Date()
    );

    return {
      type: message.type(),
      body: Buffer.from(message.serialize()).toString('base64')
    };
  }

  /**
   * Wrap with Post-Quantum Hybrid Encryption
   */
  async wrapWithPQHybrid(signalMessage, fromUsername, toUsername, options = {}) {
    const bridge = await this.loadPQBridge();

    let peerPqKey = null;
    const overrideB64 = typeof options?.recipientKyberPublicKey === 'string' ? options.recipientKyberPublicKey : null;
    if (overrideB64) {
      const buf = Buffer.from(overrideB64, 'base64');
      if (buf.length !== bridge.KEM.sizes.publicKey) {
        throw new Error(`Invalid recipientKyberPublicKey length: expected ${bridge.KEM.sizes.publicKey}, got ${buf.length}`);
      }
      peerPqKey = new Uint8Array(buf);
    }

    if (!peerPqKey) {
      const storedKey = this.peerKyberPublicKeys.get(toUsername);
      if (storedKey && storedKey.length === bridge.KEM.sizes.publicKey) {
        peerPqKey = storedKey;
      }
    }

    if (!peerPqKey) throw new Error('No static ML-KEM public key for recipient');

    const { ciphertext: kemCiphertext, sharedSecret } = bridge.KEM.encapsulate(peerPqKey);

    const salt = bridge.Random.randomBytes(32);
    const info = Buffer.from(`pq-envelope:${fromUsername}->${toUsername}`, 'utf8');
    const kdfInput = Buffer.concat([Buffer.from(sharedSecret), Buffer.from(salt), Buffer.from(info)]);
    const keyMaterial = bridge.Hash.blake3(kdfInput, { dkLen: 64 });
    const aesKey = keyMaterial.slice(0, 32);
    const macKey = keyMaterial.slice(32, 64);

    const nonce = bridge.Random.randomBytes(24);
    const aad = Buffer.from(`pq-envelope:${fromUsername}->${toUsername}`, 'utf8');
    const payload = Buffer.from(JSON.stringify(signalMessage), 'utf8');
    const { ciphertext, tag } = bridge.AEAD.encrypt(payload, aesKey, aad, nonce);

    const macInput = Buffer.concat([
      Buffer.from(kemCiphertext),
      Buffer.from(nonce),
      Buffer.from(ciphertext),
      Buffer.from(tag),
      Buffer.from(aad)
    ]);
    const mac = bridge.Hash.blake3(macInput, { key: macKey, dkLen: 32 });

    sharedSecret.fill(0); aesKey.fill(0); macKey.fill(0); keyMaterial.fill(0);

    return {
      version: 'signal-pq-v1',
      pqKeyId: 1,
      kemCiphertext: Buffer.from(kemCiphertext).toString('base64'),
      nonce: Buffer.from(nonce).toString('base64'),
      ciphertext: Buffer.from(ciphertext).toString('base64'),
      tag: Buffer.from(tag).toString('base64'),
      mac: Buffer.from(mac).toString('base64'),
      aad: aad.toString('base64'),
      salt: Buffer.from(salt).toString('base64')
    };
  }

  async encrypt(fromUsername, toUsername, plaintext, options = {}) {
    const sessionKey = `${fromUsername}:${toUsername}`;

    try {
      this.validateUsername(fromUsername);
      this.validateUsername(toUsername);

      await this.acquireSessionLock(sessionKey);

      const signalEncrypted = await this.encryptWithSignalProtocol(fromUsername, toUsername, plaintext);
      const wrapped = await this.wrapWithPQHybrid(signalEncrypted, fromUsername, toUsername, options);

      return { success: true, encryptedPayload: wrapped };
    } catch (error) {
      console.error('[SIGNAL-V2] Encryption failed:', error);
      return { success: false, error: error.message };
    } finally {
      this.releaseSessionLock(sessionKey);
    }
  }

  /**
   * Full decryption
   */
  async decrypt(fromUsername, toUsername, encryptedData) {
    const libsignal = await _loadLibsignal();
    const sessionKey = `${toUsername}:${fromUsername}`;

    try {
      this.validateUsername(fromUsername);
      this.validateUsername(toUsername);

      await this.acquireSessionLock(sessionKey);

      // Unwrap PQ outer layer
      const bridge = await this.loadPQBridge();
      const kemCiphertext = Buffer.from(encryptedData.kemCiphertext, 'base64');
      const salt = Buffer.from(encryptedData.salt, 'base64');
      const aad = Buffer.from(encryptedData.aad, 'base64');
      const nonce = Buffer.from(encryptedData.nonce, 'base64');
      const ciphertext = Buffer.from(encryptedData.ciphertext, 'base64');
      const tag = Buffer.from(encryptedData.tag, 'base64');
      const mac = Buffer.from(encryptedData.mac, 'base64');

      let mySecret = null;
      let ourKeyFingerprint = 'unknown';
      const staticEntry = this.staticMlkemKeys.get(toUsername);
      if (staticEntry && staticEntry.secretKey && staticEntry.publicKey) {
        mySecret = staticEntry.secretKey;
        ourKeyFingerprint = Buffer.from(staticEntry.publicKey).toString('hex').slice(0, 16);
      }
      if (!mySecret) throw new Error('No static ML-KEM secret key registered for recipient');

      const sharedSecret = bridge.KEM.decapsulate(kemCiphertext, mySecret);

      const info = Buffer.from(`pq-envelope:${fromUsername}->${toUsername}`, 'utf8');
      const kdfInput = Buffer.concat([Buffer.from(sharedSecret), Buffer.from(salt), Buffer.from(info)]);
      const keyMaterial = bridge.Hash.blake3(kdfInput, { dkLen: 64 });
      const aesKey = keyMaterial.slice(0, 32);
      const macKey = keyMaterial.slice(32, 64);

      const macInput = Buffer.concat([
        Buffer.from(kemCiphertext),
        Buffer.from(nonce),
        Buffer.from(ciphertext),
        Buffer.from(tag),
        Buffer.from(aad)
      ]);
      const computedMac = bridge.Hash.blake3(macInput, { key: macKey, dkLen: 32 });
      if (!crypto.timingSafeEqual(mac, computedMac)) {
        const error = new Error('PQ_MAC_VERIFICATION_FAILED');
        error.code = 'SESSION_KEYS_INVALID';
        error.requiresKeyRefresh = true;
        throw error;
      }

      const signalMessageBytesPayload = bridge.AEAD.decrypt(ciphertext, nonce, tag, aesKey, aad);
      const signalMessage = JSON.parse(Buffer.from(signalMessageBytesPayload).toString('utf8'));

      sharedSecret.fill(0); aesKey.fill(0); macKey.fill(0); keyMaterial.fill(0);

      const fromAddress = libsignal.ProtocolAddress.new(fromUsername, 1);
      const messageBytes = Buffer.from(signalMessage.body, 'base64');

      let plaintext;
      let usedPreKeyId = null;
      if (signalMessage.type === 3) {
        const preKeyMessage = libsignal.PreKeySignalMessage.deserialize(messageBytes);

        try {
          usedPreKeyId = preKeyMessage.preKeyId();
        } catch { }

        const sessionStore = await this._createSessionStore(toUsername);
        const identityStore = await this._createIdentityKeyStore(toUsername);
        const preKeyStore = await this._createPreKeyStore(toUsername);
        const signedPreKeyStore = await this._createSignedPreKeyStore(toUsername);
        const kyberPreKeyStore = await this._createKyberPreKeyStore(toUsername);

        try {
          plaintext = await libsignal.signalDecryptPreKey(
            preKeyMessage,
            fromAddress,
            sessionStore,
            identityStore,
            preKeyStore,
            signedPreKeyStore,
            kyberPreKeyStore
          );
        } catch (preKeyError) {
          console.error('[SIGNAL-V2] PreKey decryption failed, marking for session reset:', preKeyError.message);
          const error = new Error(preKeyError.message);
          error.code = 'SESSION_KEYS_INVALID';
          error.requiresKeyRefresh = true;
          throw error;
        }

        if (usedPreKeyId != null) {
          await this.store.removePreKey(toUsername, usedPreKeyId);
          if (usedPreKeyId === 1) {
            await this.generatePreKeys(toUsername, 1, 1);
          }
        }
      } else {
        const signalMessageObj = libsignal.SignalMessage.deserialize(messageBytes);
        const sessionStore = await this._createSessionStore(toUsername);
        const identityStore = await this._createIdentityKeyStore(toUsername);

        try {
          plaintext = await libsignal.signalDecrypt(
            signalMessageObj,
            fromAddress,
            sessionStore,
            identityStore
          );
        } catch (signalError) {
          console.error('[SIGNAL-V2] Signal message decryption failed, marking for session reset:', signalError.message);
          const error = new Error(signalError.message);
          error.code = 'SESSION_KEYS_INVALID';
          error.requiresKeyRefresh = true;
          throw error;
        }
      }

      return {
        success: true,
        plaintext: Buffer.from(plaintext).toString('utf8')
      };
    } catch (error) {
      console.error('[SIGNAL-V2] Decryption failed:', error);
      return {
        success: false,
        error: error.message,
        code: error.code,
        requiresKeyRefresh: error.requiresKeyRefresh || false
      };
    } finally {
      this.releaseSessionLock(sessionKey);
    }
  }

  /**
   * Delete session with a peer 
   */
  async deleteSession(selfUsername, peerUsername, deviceId = 1) {
    try {
      this.validateUsername(selfUsername);
      this.validateUsername(peerUsername);
      const address = `${peerUsername}.${deviceId}`;
      await this.store.deleteSession(selfUsername, address);
      return { success: true };
    } catch (error) {
      console.error('[SIGNAL-V2] Delete session failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Delete all sessions with a peer
   */
  async deleteAllSessions(selfUsername, peerUsername) {
    try {
      this.validateUsername(selfUsername);
      this.validateUsername(peerUsername);

      // Delete main device session
      await this.store.deleteSession(selfUsername, `${peerUsername}.1`);

      // Delete any sub-device sessions
      const subDevices = await this.store.getSubDeviceSessions(selfUsername, peerUsername);
      for (const deviceId of subDevices) {
        await this.store.deleteSession(selfUsername, `${peerUsername}.${deviceId}`);
      }

      return { success: true };
    } catch (error) {
      console.error('[SIGNAL-V2] Delete all sessions failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Set the static ML-KEM-1024 keypair for the given user
   */
  async setStaticMlkemKeys(username, publicKeyBase64, secretKeyBase64) {
    try {
      this.validateUsername(username);
      if (typeof publicKeyBase64 !== 'string' || typeof secretKeyBase64 !== 'string') {
        throw new Error('Missing ML-KEM keys');
      }
      const bridge = await this.loadPQBridge();
      const pub = Buffer.from(publicKeyBase64, 'base64');
      const sec = Buffer.from(secretKeyBase64, 'base64');
      if (pub.length !== bridge.KEM.sizes.publicKey) {
        throw new Error(`Invalid ML-KEM public key length: ${pub.length}`);
      }
      if (sec.length !== bridge.KEM.sizes.secretKey) {
        throw new Error(`Invalid ML-KEM secret key length: ${sec.length}`);
      }
      this.staticMlkemKeys.set(username, { publicKey: new Uint8Array(pub), secretKey: new Uint8Array(sec) });
      return { success: true };
    } catch (error) {
      console.error('[SIGNAL-V2] Failed to set static ML-KEM keys:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Create store wrappers for libsignal
   */
  async _createSessionStore(username) {
    const libsignal = await _loadLibsignal();
    const outerStore = this.store;
    class SessionStoreImpl extends libsignal.SessionStore {
      constructor() { super(); }
      async saveSession(name, record) {
        const idx = name.name() + '.' + name.deviceId();
        await outerStore.storeSession(username, idx, record.serialize());
      }
      async getSession(name) {
        const idx = name.name() + '.' + name.deviceId();
        const buf = await outerStore.loadSession(username, idx);
        return buf ? libsignal.SessionRecord.deserialize(buf) : null;
      }
      async getExistingSessions(addresses) {
        const out = [];
        for (const a of addresses) {
          const idx = a.name() + '.' + a.deviceId();
          const buf = await outerStore.loadSession(username, idx);
          if (buf) out.push(libsignal.SessionRecord.deserialize(buf));
        }
        return out;
      }
    }
    return new SessionStoreImpl();
  }

  async _createIdentityKeyStore(username) {
    const libsignal = await _loadLibsignal();
    const outerStore = this.store;
    class IdentityKeyStoreImpl extends libsignal.IdentityKeyStore {
      constructor() { super(); }
      async getIdentityKey() {
        const pair = await outerStore.getIdentityKeyPair(username);
        if (!pair) throw new Error('Missing identity key pair');
        return libsignal.PrivateKey.deserialize(Buffer.from(pair.privKey));
      }
      async getLocalRegistrationId() {
        const id = await outerStore.getLocalRegistrationId(username);
        if (typeof id !== 'number') throw new Error('Missing registration ID');
        return id;
      }
      async isTrustedIdentity(address, identityKey, direction) {
        return await outerStore.isTrustedIdentity(username, address.name(), identityKey.serialize(), direction);
      }
      async saveIdentity(address, identityKey) {
        const existing = await outerStore.getIdentity(username, address.name());
        await outerStore.saveIdentity(username, address.name(), identityKey.serialize());
        if (!existing) return libsignal.IdentityChange.NewOrUnchanged;
        const changed = !Buffer.from(existing).equals(identityKey.serialize());
        return changed ? libsignal.IdentityChange.ReplacedExisting : libsignal.IdentityChange.NewOrUnchanged;
      }
      async getIdentity(address) {
        const key = await outerStore.getIdentity(username, address.name());
        return key ? libsignal.PublicKey.deserialize(key) : null;
      }
    }
    return new IdentityKeyStoreImpl();
  }

  async _createPreKeyStore(username) {
    const libsignal = await _loadLibsignal();
    const outerStore = this.store;
    class PreKeyStoreImpl extends libsignal.PreKeyStore {
      constructor() { super(); }
      async savePreKey(preKeyId, record) {
        const pub = record.publicKey();
        const priv = record.privateKey();
        await outerStore.storePreKey(username, preKeyId, {
          pubKey: pub.serialize(),
          privKey: priv.serialize()
        });
      }
      async getPreKey(preKeyId) {
        const data = await outerStore.loadPreKey(username, preKeyId);
        if (!data) throw new Error('Missing prekey ' + preKeyId);
        const pub = libsignal.PublicKey.deserialize(Buffer.from(data.keyPair.pubKey));
        const priv = libsignal.PrivateKey.deserialize(Buffer.from(data.keyPair.privKey));
        return libsignal.PreKeyRecord.new(preKeyId, pub, priv);
      }
      async removePreKey(preKeyId) {
        await outerStore.removePreKey(username, preKeyId);
      }
    }
    return new PreKeyStoreImpl();
  }

  async _createSignedPreKeyStore(username) {
    const libsignal = await _loadLibsignal();
    const outerStore = this.store;
    class SignedPreKeyStoreImpl extends libsignal.SignedPreKeyStore {
      constructor() { super(); }
      async saveSignedPreKey(id, record) {
        const pub = record.publicKey();
        const priv = record.privateKey();
        const sig = record.signature();
        const ts = Number(record.timestamp());
        await outerStore.storeSignedPreKey(username, id, {
          pubKey: pub.serialize(),
          privKey: priv.serialize()
        }, sig, ts);
      }
      async getSignedPreKey(id) {
        const data = await outerStore.loadSignedPreKey(username, id);
        if (!data) throw new Error('Missing signed prekey ' + id);
        const pub = libsignal.PublicKey.deserialize(Buffer.from(data.keyPair.pubKey));
        const priv = libsignal.PrivateKey.deserialize(Buffer.from(data.keyPair.privKey));
        return libsignal.SignedPreKeyRecord.new(id, Number(data.timestamp), pub, priv, Buffer.from(data.signature));
      }
    }
    return new SignedPreKeyStoreImpl();
  }

  async _createKyberPreKeyStore(username) {
    const libsignal = await _loadLibsignal();
    const outerStore = this.store;
    class KyberPreKeyStoreImpl extends libsignal.KyberPreKeyStore {
      constructor() { super(); }
      async saveKyberPreKey(id, record) {
        const ts = Number(record.timestamp());
        await outerStore.storeKyberPreKey(username, id, record.serialize(), ts, false);
      }
      async getKyberPreKey(id) {
        const data = await outerStore.loadKyberPreKey(username, id);
        if (!data) throw new Error('Missing kyber prekey ' + id);
        return libsignal.KyberPreKeyRecord.deserialize(Buffer.from(data.record));
      }
      async markKyberPreKeyUsed(kyberPreKeyId, signedPreKeyId, baseKey) {
        await outerStore.markKyberPreKeyUsed(username, kyberPreKeyId);
      }
    }
    return new KyberPreKeyStoreImpl();
  }

  // Persistence helpers
  _getPqStorePath() {
    const base = app.getPath('userData');
    return path.join(base, 'pq-kyber-keys.json');
  }

  _loadPersistedPqKeys() {
    const storePath = this._getPqStorePath();
    if (!fs.existsSync(storePath)) return;
    const rawText = fs.readFileSync(storePath, 'utf8');
    let obj;
    try {
      const raw = JSON.parse(rawText);
      if (raw && raw.version === 'enc-v1') {
        const storage = require('./signal-storage.cjs');
        const key = storage.getStorageKeyRaw && storage.getStorageKeyRaw();
        if (!key) {
          return;
        }

        const iv = Buffer.from(raw.nonce, 'base64');
        const tag = Buffer.from(raw.tag, 'base64');
        const ciphertext = Buffer.from(raw.ciphertext, 'base64');
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAAD(Buffer.from('pq-kyber-v1', 'utf8'));
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        obj = JSON.parse(plaintext.toString('utf8'));
      } else {
        return;
      }
    } catch (e) {
      return;
    }
    if (!obj || typeof obj !== 'object') return;
    for (const key of Object.keys(obj)) {
      const entry = obj[key];
      if (!entry || typeof entry.publicKeyBase64 !== 'string' || typeof entry.secretKeyBase64 !== 'string') continue;
      try {
        const pub = Buffer.from(entry.publicKeyBase64, 'base64');
        const sec = Buffer.from(entry.secretKeyBase64, 'base64');
        if (pub.length > 0 && sec.length > 0) {
          this.pqKyberKeyPairs.set(key, { publicKey: new Uint8Array(pub), secretKey: new Uint8Array(sec) });
        }
      } catch { }
    }
  }

  _savePersistedPqKeys() {
    const storePath = this._getPqStorePath();
    const obj = {};
    for (const [key, val] of this.pqKyberKeyPairs.entries()) {
      obj[key] = {
        publicKeyBase64: Buffer.from(val.publicKey).toString('base64'),
        secretKeyBase64: Buffer.from(val.secretKey).toString('base64')
      };
    }
    try {
      fs.mkdirSync(path.dirname(storePath), { recursive: true });
      const storage = require('./signal-storage.cjs');
      const key = storage.getStorageKeyRaw && storage.getStorageKeyRaw();
      if (key) {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        cipher.setAAD(Buffer.from('pq-kyber-v1', 'utf8'));
        const ct = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(obj), 'utf8')), cipher.final()]);
        const tag = cipher.getAuthTag();
        const enc = { version: 'enc-v1', aead: 'aes-256-gcm', nonce: iv.toString('base64'), tag: tag.toString('base64'), ciphertext: ct.toString('base64') };
        fs.writeFileSync(storePath, JSON.stringify(enc, null, 2), { encoding: 'utf8', mode: 0o600 });
      } else {
        return;
      }
    } catch (e) {
      console.error('[SIGNAL-V2] Failed to persist PQ keys:', e);
    }
  }

  // Persistence helpers (Peer Kyber public keys)
  _getPeerKyberStorePath() {
    const base = app.getPath('userData');
    return path.join(base, 'peer-kyber-keys.json');
  }

  _loadPersistedPeerKyberKeys() {
    const storePath = this._getPeerKyberStorePath();
    if (!fs.existsSync(storePath)) return;
    const rawText = fs.readFileSync(storePath, 'utf8');
    let obj;
    try {
      const raw = JSON.parse(rawText);
      if (raw && raw.version === 'enc-v1') {
        const storage = require('./signal-storage.cjs');
        const key = storage.getStorageKeyRaw && storage.getStorageKeyRaw();
        if (!key) return;
        const iv = Buffer.from(raw.nonce, 'base64');
        const tag = Buffer.from(raw.tag, 'base64');
        const ciphertext = Buffer.from(raw.ciphertext, 'base64');
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAAD(Buffer.from('peer-kyber-v1', 'utf8'));
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        obj = JSON.parse(plaintext.toString('utf8'));
      } else {
        return;
      }
    } catch (e) {
      return;
    }
    if (!obj || typeof obj !== 'object') return;
    for (const peerUsername of Object.keys(obj)) {
      const keyBase64 = obj[peerUsername];
      if (typeof keyBase64 !== 'string') continue;
      try {
        const keyBytes = Buffer.from(keyBase64, 'base64');
        if (keyBytes.length > 0) {
          this.peerKyberPublicKeys.set(peerUsername, new Uint8Array(keyBytes));
        }
      } catch { }
    }
  }

  _savePersistedPeerKyberKeys() {
    const storePath = this._getPeerKyberStorePath();
    const obj = {};
    for (const [peerUsername, keyBytes] of this.peerKyberPublicKeys.entries()) {
      obj[peerUsername] = Buffer.from(keyBytes).toString('base64');
    }
    try {
      fs.mkdirSync(path.dirname(storePath), { recursive: true });
      const storage = require('./signal-storage.cjs');
      const key = storage.getStorageKeyRaw && storage.getStorageKeyRaw();
      if (key) {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        cipher.setAAD(Buffer.from('peer-kyber-v1', 'utf8'));
        const ct = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(obj), 'utf8')), cipher.final()]);
        const tag = cipher.getAuthTag();
        const enc = { version: 'enc-v1', aead: 'aes-256-gcm', nonce: iv.toString('base64'), tag: tag.toString('base64'), ciphertext: ct.toString('base64') };
        fs.writeFileSync(storePath, JSON.stringify(enc, null, 2), { encoding: 'utf8', mode: 0o600 });
      }
    } catch (e) {
      console.error('[SIGNAL-V2] Failed to persist peer Kyber keys:', e);
    }
  }

  /**
   * Set a peers Kyber public key
   */
  setPeerKyberPublicKey(peerUsername, kyberPublicKeyBase64) {
    if (!peerUsername || !kyberPublicKeyBase64) return { success: false, error: 'Missing parameters' };
    try {
      const keyBytes = Buffer.from(kyberPublicKeyBase64, 'base64');
      if (keyBytes.length === 0) return { success: false, error: 'Empty key' };
      this.peerKyberPublicKeys.set(peerUsername, new Uint8Array(keyBytes));
      this._savePersistedPeerKyberKeys();
      return { success: true };
    } catch (e) {
      return { success: false, error: e?.message || String(e) };
    }
  }

  /**
   * Check if we have a peers Kyber public key
   */
  hasPeerKyberPublicKey(peerUsername) {
    return this.peerKyberPublicKeys.has(peerUsername);
  }

  /**
   * Trust a peer's identity key
   */
  async trustPeerIdentity(selfUsername, peerUsername, deviceId = 1) {
    try {
      const address = `${peerUsername}.${deviceId}`;
      await this.store.trustPeerIdentity(selfUsername, address);
      return { success: true };
    } catch (e) {
      console.error('[SIGNAL-V2] Failed to trust peer identity:', e);
      return { success: false, error: e?.message || String(e) };
    }
  }

  /**
   * Clean up all data
   */
  clearAll() {
    this.store.clearAllData();
    this.pqKyberKeyPairs.clear();
    this.staticMlkemKeys.clear();
    this.peerKyberPublicKeys.clear();
    this.sessionLocks.clear();
  }
}

module.exports = { QuantumResistantSignalHandler };
