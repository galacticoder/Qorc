/**
 * Secure Storage Handler
 * Handles all secure storage operations
 */


class StorageHandler {
  constructor(app, securityMiddleware) {
    this.app = app;
    this.securityMiddleware = securityMiddleware;
    this.secureStorage = null;
    this.initialized = false;
  }

  async initialize() {
    if (this.initialized) {
      return { success: true };
    }

    try {
      const installPath = this.app.getAppPath();
      const { ElectronSecureStorage } = require('./electron-secure-storage.cjs');
      this.secureStorage = new ElectronSecureStorage();
      await this.secureStorage.initialize(installPath);
      this.initialized = true;
      return { success: true };
    } catch (err) {
      return { success: false, error: 'Storage initialization failed' };
    }
  }

  validateKey(key) {
    if (typeof key !== 'string' || key.length === 0 || key.length > 512) {
      throw new Error('Invalid key format');
    }
    
    // Prevent path traversal in keys
    if (key.includes('/') || key.includes('\\') || key.includes('..')) {
      throw new Error('Invalid key characters');
    }
  }

  validateValue(value) {
    if (typeof value !== 'string' || value.length === 0 || value.length > 65536) {
      throw new Error('Invalid value format');
    }
  }

  async setItem(key, value) {
    try {
      await this.securityMiddleware.validateRequest('secure:set', [key, value]);
      
      if (!this.secureStorage) throw new Error('Storage not initialized');
      
      this.validateKey(key);
      this.validateValue(value);
      
      await this.secureStorage.setItem(key, value);
      return { success: true };
    } catch (e) {
      return { success: false, error: 'Storage operation failed' };
    }
  }

  async getItem(key) {
    try {
      await this.securityMiddleware.validateRequest('secure:get', [key]);
      
      if (!this.secureStorage) throw new Error('Storage not initialized');
      
      this.validateKey(key);
      
      const value = await this.secureStorage.getItem(key);
      return { success: true, value: value || null };
    } catch (e) {
      return { success: false, error: 'Retrieval failed', value: null };
    }
  }

  async removeItem(key) {
    try {
      await this.securityMiddleware.validateRequest('secure:remove', [key]);
      
      if (!this.secureStorage) throw new Error('Storage not initialized');
      
      this.validateKey(key);
      
      await this.secureStorage.removeItem(key);
      return { success: true };
    } catch (e) {
      return { success: false, error: 'Removal failed' };
    }
  }

  async persistServerUrl(url) {
    if (!url || typeof url !== 'string' || url.length > 2048) {
      throw new Error('Invalid URL');
    }
    // Require wss:// only
    if (!/^wss:\/\/.+/i.test(url)) {
      throw new Error('Only secure WebSocket (wss://) allowed');
    }
    try {
      const parsed = new URL(url);
      if (parsed.username || parsed.password) {
        throw new Error('Credentials in URL not allowed');
      }
    } catch (e) {
      throw new Error('Invalid URL format');
    }
    if (!this.secureStorage) {
      throw new Error('Secure storage not initialized');
    }
    await this.secureStorage.setItem('server-url', url);
  }

  async loadServerUrl() {
    if (!this.secureStorage) {
      throw new Error('Secure storage not initialized');
    }
    const storedUrl = await this.secureStorage.getItem('server-url');
    if (storedUrl && typeof storedUrl === 'string' && storedUrl.length > 0) {
      return storedUrl;
    }
    return null;
  }

  sanitizeError(err) {
    if (!err) return 'Unknown error';
    // Remove potentially sensitive information from error messages
    const message = err.message || String(err);
    return message.replace(/\/[^\s]+/g, '[PATH]').substring(0, 200);
  }

  isInitialized() {
    return this.initialized;
  }
}

module.exports = { StorageHandler };