/**
 * Electron Secure Storage using Quantum-Secure Storage
 * Double AEAD encryption (AES-256-GCM + XChaCha20-Poly1305)
 * SHA3-512 KDF, BLAKE3 MAC
 */

const qss = require('./secure-storage.cjs');

class ElectronSecureStorage {
  constructor(serviceName = 'Qor-Chat-App') {
    this.serviceName = serviceName;
    this.initialized = false;
  }

// Initialize secure storage
  async initialize(installPath) {
    if (this.initialized) return;

    await qss.init({ installPath });
    this.initialized = true;
  }

// Sanitize and validate key
  sanitizeKey(key) {
    if (typeof key !== 'string' || !key || key.length > 128) {
      throw new Error('Invalid key');
    }
    if (key.includes('/') || key.includes('\\') || key.includes('..') || key.includes('\0')) {
      throw new Error('Invalid key characters');
    }
    return key;
  }

  getPathForKey(key) {
    return qss.pathForKey(key);
  }

  async setItem(key, value) {
    if (!this.initialized) {
      throw new Error('Storage not initialized');
    }
    this.sanitizeKey(key);
    if (typeof value !== 'string' || !value || value.length > 1024 * 1024) {
      throw new Error('Invalid value');
    }

    await qss.setItem(key, value);
  }

  async getItem(key) {
    if (!this.initialized) {
      throw new Error('Storage not initialized');
    }
    this.sanitizeKey(key);
    
    const buffer = await qss.getItem(key);
    if (!buffer) {
      return null;
    }
    return buffer.toString('utf8');
  }

  async removeItem(key) {
    if (!this.initialized) {
      throw new Error('Storage not initialized');
    }
    this.sanitizeKey(key);
    await qss.removeItem(key);
  }
}

module.exports = { ElectronSecureStorage };
