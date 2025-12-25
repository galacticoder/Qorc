/**
 * Signal Protocol Storage
 * 
 * Storage interfaces for libsignal-client with encrypted persistence:
 * - IdentityKeyStore
 * - PreKeyStore
 * - SignedPreKeyStore
 * - SessionStore
 * - KyberPreKeyStore
 * - SenderKeyStore
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { app } = require('electron');

// In-memory storage encryption key (32 bytes).
let STORAGE_KEY = null; // Buffer | null
const STORE_INSTANCES = [];

function setStorageKey(opts) {
  try {
    if (!opts || typeof opts !== 'object') throw new Error('Invalid args');
    const b64 = opts.keyBase64;
    if (!b64 || typeof b64 !== 'string') throw new Error('keyBase64 required');
    const raw = Buffer.from(b64, 'base64');
    if (raw.length !== 32) throw new Error('storage key must be 32 bytes');
    STORAGE_KEY = Buffer.from(raw);
    try {
      for (const inst of STORE_INSTANCES) {
        try { inst._loadSessions(); } catch { }
        try { inst._loadTrusted(); } catch { }
        try { inst._loadIdentities(); } catch { }
      }

      for (const inst of STORE_INSTANCES) {
        try { inst._saveSessions(); } catch { }
        try { inst._saveTrusted(); } catch { }
        try { inst._saveIdentities(); } catch { }
      }
    } catch { }
    return { success: true };
  } catch (e) {
    return { success: false, error: e?.message || String(e) };
  }
}

function hasStorageKey() { return !!STORAGE_KEY; }
function getStorageKeyRaw() { return STORAGE_KEY; }

function _encryptJSON(obj, label) {
  if (!STORAGE_KEY) throw new Error('storage key not set');
  const json = Buffer.from(JSON.stringify(obj), 'utf8');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', STORAGE_KEY, iv);
  if (label) cipher.setAAD(Buffer.from(String(label), 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(json), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    version: 'enc-v1',
    aead: 'aes-256-gcm',
    nonce: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64')
  };
}

function _decryptJSON(wrapper, label) {
  if (!STORAGE_KEY) throw new Error('storage key not set');
  if (!wrapper || wrapper.version !== 'enc-v1') throw new Error('invalid encrypted wrapper');
  const iv = Buffer.from(wrapper.nonce, 'base64');
  const tag = Buffer.from(wrapper.tag, 'base64');
  const ciphertext = Buffer.from(wrapper.ciphertext, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', STORAGE_KEY, iv);
  if (label) decipher.setAAD(Buffer.from(String(label), 'utf8'));
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

function _atomicWriteJSON(filePath, dataObj) {
  const dir = path.dirname(filePath);
  try { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); } catch { }
  const tmp = filePath + '.tmp';
  const buf = Buffer.from(JSON.stringify(dataObj, null, 2), 'utf8');
  fs.writeFileSync(tmp, buf, { mode: 0o600 });
  try { fs.renameSync(tmp, filePath); } finally {
    try { fs.unlinkSync(tmp); } catch { }
  }
}

function _readJSON(filePath) {
  const txt = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(txt);
}

class SignalProtocolStore {
  constructor() {
    STORE_INSTANCES.push(this);
    // Persistence paths
    this._storeDir = this._getStoreDir();
    this._sessionsPath = path.join(this._storeDir, 'signal-sessions.json');
    this._trustedPath = path.join(this._storeDir, 'signal-trusted-identities.json');
    this._identityPath = path.join(this._storeDir, 'signal-identity-keys.json');

    this.identityKeys = new Map(); // username -> { publicKey, privateKey, registrationId }
    this.preKeys = new Map(); // username:keyId -> { keyPair, keyId }
    this.signedPreKeys = new Map(); // username:keyId -> { keyPair, keyId, signature, timestamp }
    this.sessions = new Map(); // username:address -> sessionRecord
    this.kyberPreKeys = new Map(); // username:keyId -> { record: Buffer, used: boolean, timestamp }
    this.senderKeys = new Map(); // sender:distributionId -> senderKeyRecord
    this.trustedIdentities = new Map(); // address -> identityKey

    // Load persisted trusted identities, sessions, and identity keys
    try { this._loadTrusted(); } catch (e) { /* ignore */ }
    try { this._loadSessions(); } catch (e) { /* ignore */ }
    try { this._loadIdentities(); } catch (e) { /* ignore */ }
  }

  // Identity Key Store
  async getIdentityKeyPair(username) {
    const identity = this.identityKeys.get(username);
    if (!identity) {
      return null;
    }
    return {
      pubKey: identity.publicKey,
      privKey: identity.privateKey
    };
  }

  async getLocalRegistrationId(username) {
    const identity = this.identityKeys.get(username);
    return identity ? identity.registrationId : null;
  }

  async saveIdentity(username, address, identityKey) {
    this._ensureStoreDir();
    const key = `${username}:${address}`;
    this.trustedIdentities.set(key, Buffer.from(identityKey));
    try { this._saveTrusted(); } catch { }
    return true;
  }

  async isTrustedIdentity(username, address, identityKey, direction) {
    const key = `${username}:${address}`;
    const trusted = this.trustedIdentities.get(key);

    if (!trusted) {
      await this.saveIdentity(username, address, identityKey);
      return true;
    }

    const incomingBytes = Buffer.from(identityKey);
    const matches = incomingBytes.equals(trusted);

    if (!matches) {
      return false;
    }

    return true;
  }

  async getIdentity(username, address) {
    const key = `${username}:${address}`;
    return this.trustedIdentities.get(key) || null;
  }

  async trustPeerIdentity(username, address) {
    this._ensureStoreDir();
    const key = `${username}:${address}`;
    this.trustedIdentities.delete(key);
    try { this._saveTrusted(); } catch { }
    return true;
  }

  async removeIdentity(username, address) {
    this._ensureStoreDir();
    const key = `${username}:${address}`;
    this.trustedIdentities.delete(key);
    try { this._saveTrusted(); } catch { }
    return true;
  }

  // Store identity key pair for a user
  storeIdentityKeyPair(username, keyPair, registrationId) {
    this.identityKeys.set(username, {
      publicKey: Buffer.from(keyPair.pubKey),
      privateKey: Buffer.from(keyPair.privKey),
      registrationId
    });
    try { this._saveIdentities(); } catch { }
  }

  // PreKey Store
  async loadPreKey(username, keyId) {
    const key = `${username}:${keyId}`;
    return this.preKeys.get(key) || null;
  }

  async storePreKey(username, keyId, keyPair) {
    const key = `${username}:${keyId}`;
    this.preKeys.set(key, {
      keyPair: {
        pubKey: Buffer.from(keyPair.pubKey),
        privKey: Buffer.from(keyPair.privKey)
      },
      keyId
    });
  }

  async removePreKey(username, keyId) {
    const key = `${username}:${keyId}`;
    this.preKeys.delete(key);
  }

  // Signed PreKey Store
  async loadSignedPreKey(username, keyId) {
    const key = `${username}:${keyId}`;
    return this.signedPreKeys.get(key) || null;
  }

  async storeSignedPreKey(username, keyId, keyPair, signature, timestamp) {
    const key = `${username}:${keyId}`;
    this.signedPreKeys.set(key, {
      keyPair: {
        pubKey: Buffer.from(keyPair.pubKey),
        privKey: Buffer.from(keyPair.privKey)
      },
      keyId,
      signature: Buffer.from(signature),
      timestamp: timestamp || Date.now()
    });
  }

  async removeSignedPreKey(username, keyId) {
    const key = `${username}:${keyId}`;
    this.signedPreKeys.delete(key);
  }

  // Kyber PreKey Store
  async loadKyberPreKey(username, keyId) {
    const key = `${username}:${keyId}`;
    return this.kyberPreKeys.get(key) || null;
  }

  async storeKyberPreKey(username, keyId, recordBuffer, timestamp, used = false) {
    const key = `${username}:${keyId}`;
    this.kyberPreKeys.set(key, {
      record: Buffer.from(recordBuffer),
      timestamp: timestamp || Date.now(),
      used: !!used
    });
  }

  async markKyberPreKeyUsed(username, keyId) {
    const key = `${username}:${keyId}`;
    const existing = this.kyberPreKeys.get(key);
    if (existing) {
      existing.used = true;
      this.kyberPreKeys.set(key, existing);
    }
  }

  // Session Store
  async loadSession(username, address) {
    const key = `${username}:${address}`;
    const session = this.sessions.get(key);
    return session || null;
  }

  async storeSession(username, address, sessionRecord) {
    this._ensureStoreDir();
    const key = `${username}:${address}`;
    this.sessions.set(key, Buffer.from(sessionRecord));
    try { this._saveSessions(); } catch { }
  }

  async getSubDeviceSessions(username, name) {
    const prefix = `${username}:${name}.`;
    const sessions = [];

    for (const [key, session] of this.sessions.entries()) {
      if (key.startsWith(prefix)) {
        const deviceId = parseInt(key.split('.').pop(), 10);
        if (!isNaN(deviceId) && deviceId !== 1) {
          sessions.push(deviceId);
        }
      }
    }

    return sessions;
  }

  async deleteSession(username, address) {
    this._ensureStoreDir();
    const key = `${username}:${address}`;
    this.sessions.delete(key);
    try { this._saveSessions(); } catch { }
  }

  async deleteAllSessions(username, name) {
    this._ensureStoreDir();
    const prefix = `${username}:${name}`;
    const keysToDelete = [];

    for (const key of this.sessions.keys()) {
      if (key.startsWith(prefix)) {
        keysToDelete.push(key);
      }
    }

    for (const key of keysToDelete) {
      this.sessions.delete(key);
    }
    try { this._saveSessions(); } catch { }
  }

  // Sender Key Store
  async loadSenderKey(sender, distributionId) {
    const key = `${sender}:${distributionId}`;
    return this.senderKeys.get(key) || null;
  }

  async storeSenderKey(sender, distributionId, senderKeyRecord) {
    const key = `${sender}:${distributionId}`;
    this.senderKeys.set(key, Buffer.from(senderKeyRecord));
  }

  // Utility methods
  clearAllData() {
    this._ensureStoreDir();
    this.identityKeys.clear();
    this.preKeys.clear();
    this.signedPreKeys.clear();
    this.sessions.clear();
    this.senderKeys.clear();
    this.trustedIdentities.clear();
    this.kyberPreKeys.clear();
    try { this._saveSessions(); } catch { }
    try { this._saveTrusted(); } catch { }
  }

  hasSession(username, address) {
    const key = `${username}:${address}`;
    return this.sessions.has(key);
  }

  _saveIdentities() {
    if (!STORAGE_KEY) {
      return;
    }
    const obj = {};
    for (const [username, entry] of this.identityKeys.entries()) {
      obj[username] = {
        publicKeyBase64: Buffer.from(entry.publicKey).toString('base64'),
        privateKeyBase64: Buffer.from(entry.privateKey).toString('base64'),
        registrationId: entry.registrationId
      };
    }
    const enc = _encryptJSON(obj, 'identity-v1');
    _atomicWriteJSON(this._identityPath, enc);
  }

  _loadIdentities() {
    if (!fs.existsSync(this._identityPath)) return;
    const raw = _readJSON(this._identityPath);
    if (!raw || raw.version !== 'enc-v1' || !STORAGE_KEY) {
      return;
    }
    const obj = _decryptJSON(raw, 'identity-v1');
    for (const username of Object.keys(obj || {})) {
      const e = obj[username];
      if (!e) continue;
      const pub = typeof e.publicKeyBase64 === 'string' ? Buffer.from(e.publicKeyBase64, 'base64') : null;
      const prv = typeof e.privateKeyBase64 === 'string' ? Buffer.from(e.privateKeyBase64, 'base64') : null;
      const reg = typeof e.registrationId === 'number' ? e.registrationId : null;
      if (pub && pub.length && prv && prv.length && reg) {
        this.identityKeys.set(username, { publicKey: pub, privateKey: prv, registrationId: reg });
      }
    }
  }

  // Generate a unique registration ID
  static generateRegistrationId() {
    return crypto.randomInt(1, 16380);
  }

  _getStoreDir() {
    try {
      return path.join(app.getPath('userData'), 'signal-store');
    } catch {
      return path.join(process.cwd(), 'signal-store');
    }
  }

  _ensureStoreDir() {
    try { fs.mkdirSync(this._storeDir, { recursive: true }); } catch { }
  }

  _saveSessions() {
    if (!STORAGE_KEY) {
      return;
    }
    const obj = {};
    for (const [key, value] of this.sessions.entries()) {
      obj[key] = Buffer.from(value).toString('base64');
    }
    const label = 'sessions-v1';
    const enc = _encryptJSON(obj, label);
    _atomicWriteJSON(this._sessionsPath, enc);
  }

  _loadSessions() {
    if (!fs.existsSync(this._sessionsPath)) return;
    const raw = _readJSON(this._sessionsPath);
    if (!raw || raw.version !== 'enc-v1' || !STORAGE_KEY) {
      return;
    }
    const obj = _decryptJSON(raw, 'sessions-v1');
    for (const k of Object.keys(obj || {})) {
      const b64 = obj[k];
      if (typeof b64 === 'string') {
        this.sessions.set(k, Buffer.from(b64, 'base64'));
      }
    }
  }

  _saveTrusted() {
    if (!STORAGE_KEY) {
      return;
    }
    const obj = {};
    for (const [key, value] of this.trustedIdentities.entries()) {
      obj[key] = Buffer.from(value).toString('base64');
    }
    const label = 'trusted-v1';
    if (STORAGE_KEY) {
      const enc = _encryptJSON(obj, label);
      _atomicWriteJSON(this._trustedPath, enc);
    } else {
      return;
    }
  }
  _loadTrusted() {
    if (!fs.existsSync(this._trustedPath)) return;
    const raw = _readJSON(this._trustedPath);
    if (!raw || raw.version !== 'enc-v1' || !STORAGE_KEY) {
      return;
    }
    const obj = _decryptJSON(raw, 'trusted-v1');
    for (const k of Object.keys(obj || {})) {
      const b64 = obj[k];
      if (typeof b64 === 'string') {
        this.trustedIdentities.set(k, Buffer.from(b64, 'base64'));
      }
    }
  }
}

module.exports = { SignalProtocolStore, setStorageKey, hasStorageKey, getStorageKeyRaw };
