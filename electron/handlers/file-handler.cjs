/**
 * File Operations Handler
 * Provides secure async file operations with validation and resource limits
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

class FileHandler {
  constructor(securityMiddleware) {
    this.securityMiddleware = securityMiddleware;
    
    // File operation limits
    this.maxFileSize = 100 * 1024 * 1024; // 100 MB default
    this.maxPathLength = 4096;
    this.allowedExtensions = new Set([
      '.txt', '.json', '.log', '.dat', '.key', '.pem'
    ]);
    
    // Permitted base directories
    this.basePaths = new Set();
    this.initialized = false;
  }

  /**
   * Initialize with configuration
   */
  initialize(config = {}) {
    const {
      maxFileSize = 100 * 1024 * 1024,
      allowedExtensions = null,
      basePaths = []
    } = config;

    this.maxFileSize = Math.max(1024, Math.min(1024 * 1024 * 1024, maxFileSize));
    
    if (allowedExtensions && Array.isArray(allowedExtensions)) {
      this.allowedExtensions = new Set(allowedExtensions.map(ext => 
        ext.startsWith('.') ? ext : `.${ext}`
      ));
    }

    if (Array.isArray(basePaths)) {
      for (const basePath of basePaths) {
        this.basePaths.add(path.resolve(basePath));
      }
    }

    this.initialized = true;
    return { success: true };
  }

  /**
   * Validate and sanitize file path
   */
  async validatePath(filePath) {
    if (!filePath || typeof filePath !== 'string') {
      throw new Error('Invalid file path');
    }

    // Check length
    if (filePath.length > this.maxPathLength) {
      throw new Error('Path too long');
    }

    // Normalize and resolve
    const normalized = path.normalize(filePath);
    const resolved = path.resolve(normalized);

    // Prevent path traversal
    if (normalized.includes('..') || normalized.includes('~')) {
      throw new Error('Path traversal detected');
    }

    // Check against base paths if configured
    if (this.basePaths.size > 0) {
      let allowed = false;
      for (const basePath of this.basePaths) {
        if (resolved.startsWith(basePath)) {
          allowed = true;
          break;
        }
      }
      
      if (!allowed) {
        throw new Error('Path outside allowed directories');
      }
    }

    // Check extension
    const ext = path.extname(resolved).toLowerCase();
    if (this.allowedExtensions.size > 0 && !this.allowedExtensions.has(ext)) {
      throw new Error(`File extension not allowed: ${ext}`);
    }

    return resolved;
  }

  /**
   * Read file with size limits
   */
  async readFile(filePath, options = {}) {
    try {
      const validPath = await this.validatePath(filePath);
      
      // Check file exists and get stats
      const stats = await fs.stat(validPath);
      
      if (!stats.isFile()) {
        throw new Error('Path is not a file');
      }

      if (stats.size > this.maxFileSize) {
        throw new Error('File too large');
      }

      const content = await fs.readFile(validPath, { encoding: options.encoding || 'utf8' });

      return {
        success: true,
        content,
        size: stats.size,
        modified: stats.mtime
      };
    } catch (error) {
      return { success: false, error: 'Read failed' };
    }
  }

  /**
   * Write file with atomic operations
   */
  async writeFile(filePath, content, options = {}) {
    if (!this.initialized) {
      throw new Error('File handler not initialized');
    }
    try {
      const validPath = await this.validatePath(filePath);
      
      // Validate content
      if (content === null || content === undefined) {
        throw new Error('Invalid content');
      }

      const contentStr = typeof content === 'string' ? content : JSON.stringify(content);
      const contentBuffer = Buffer.from(contentStr, options.encoding || 'utf8');

      // Check size limit
      if (contentBuffer.length > this.maxFileSize) {
        throw new Error('Content too large');
      }

      // Ensure directory exists
      const dir = path.dirname(validPath);
      await fs.mkdir(dir, { recursive: true, mode: 0o700 });

      // Write atomically using temp file
      const tempPath = `${validPath}.tmp.${crypto.randomBytes(8).toString('hex')}`;
      
      try {
        await fs.writeFile(tempPath, contentBuffer, {
          mode: options.mode || 0o600,
          flag: 'w'
        });

        await fs.rename(tempPath, validPath);

        return {
          success: true,
          path: validPath,
          size: contentBuffer.length
        };
      } catch (error) {
        try {
          await fs.unlink(tempPath);
        } catch (cleanupError) {}
        throw error;
      }
    } catch (error) {
      return { success: false, error: 'Write failed' };
    }
  }

  /**
   * Append to file
   */
  async appendFile(filePath, content, options = {}) {
    try {
      const validPath = await this.validatePath(filePath);
      
      // Check if file exists and get current size
      let currentSize = 0;
      try {
        const stats = await fs.stat(validPath);
        currentSize = stats.size;
      } catch (error) {
        // File doesn't exist, will be created
      }

      const contentStr = typeof content === 'string' ? content : JSON.stringify(content);
      const contentBuffer = Buffer.from(contentStr, options.encoding || 'utf8');

      // Check combined size limit
      if (currentSize + contentBuffer.length > this.maxFileSize) {
        throw new Error('File would exceed size limit');
      }

      // Ensure directory exists
      const dir = path.dirname(validPath);
      await fs.mkdir(dir, { recursive: true, mode: 0o700 });

      await fs.appendFile(validPath, contentBuffer, {
        mode: options.mode || 0o600
      });

      return {
        success: true,
        size: contentBuffer.length
      };
    } catch (error) {
      return { success: false, error: 'Append failed' };
    }
  }

  /**
   * Delete file
   */
  async deleteFile(filePath) {
    try {
      const validPath = await this.validatePath(filePath);
      
      // Check file exists
      const stats = await fs.stat(validPath);
      
      if (!stats.isFile()) {
        throw new Error('Path is not a file');
      }

      await fs.unlink(validPath);
      return { success: true };
    } catch (error) {
      return { success: false, error: 'Delete failed' };
    }
  }

  /**
   * Check if file exists
   */
  async exists(filePath) {
    try {
      const validPath = await this.validatePath(filePath);
      
      try {
        await fs.access(validPath, fs.constants.F_OK);
        return { success: true, exists: true };
      } catch (error) {
        return { success: true, exists: false };
      }
    } catch (error) {
      return { success: false, error: 'Check failed' };
    }
  }

  async getStats(filePath) {
    try {
      const validPath = await this.validatePath(filePath);
      const stats = await fs.stat(validPath);

      return {
        success: true,
        stats: {
          size: stats.size,
          created: stats.birthtime,
          modified: stats.mtime,
          accessed: stats.atime,
          isFile: stats.isFile(),
          isDirectory: stats.isDirectory()
        }
      };
    } catch (error) {
      return { success: false, error: 'Stats failed' };
    }
  }

  async listDirectory(dirPath, options = {}) {
    try {
      const validPath = await this.validatePath(dirPath);
      
      const stats = await fs.stat(validPath);
      if (!stats.isDirectory()) {
        throw new Error('Not a directory');
      }

      const entries = await fs.readdir(validPath, { withFileTypes: true });
      
      const files = [];
      for (const entry of entries) {
        if (options.filesOnly && !entry.isFile()) continue;
        
        files.push({
          name: entry.name,
          isFile: entry.isFile(),
          isDirectory: entry.isDirectory()
        });
      }

      return { success: true, files };
    } catch (error) {
      return { success: false, error: 'List failed' };
    }
  }

  async createDirectory(dirPath, options = {}) {
    try {
      const validPath = await this.validatePath(dirPath);
      
      await fs.mkdir(validPath, {
        recursive: options.recursive !== false,
        mode: options.mode || 0o700
      });

      return { success: true };
    } catch (error) {
      return { success: false, error: 'Create failed' };
    }
  }

  /**
   * Delete directory
   */
  async deleteDirectory(dirPath, options = {}) {
    try {
      const validPath = await this.validatePath(dirPath);
      
      const stats = await fs.stat(validPath);
      
      if (!stats.isDirectory()) {
        throw new Error('Path is not a directory');
      }

      await fs.rm(validPath, {
        recursive: options.recursive !== false,
        force: options.force === true
      });

      return { success: true };
    } catch (error) {
      console.error('[FILE] Delete directory failed:', this.sanitizeError(error));
      return { success: false, error: 'Failed to delete directory' };
    }
  }

  /**
   * Copy file
   */
  async copyFile(sourcePath, destPath, options = {}) {
    try {
      const validSource = await this.validatePath(sourcePath);
      const validDest = await this.validatePath(destPath);
      
      // Check source exists and is file
      const stats = await fs.stat(validSource);
      
      if (!stats.isFile()) {
        throw new Error('Source is not a file');
      }

      // Check size limit
      if (stats.size > this.maxFileSize) {
        throw new Error('File too large to copy');
      }

      // Ensure destination directory exists
      const destDir = path.dirname(validDest);
      await fs.mkdir(destDir, { recursive: true, mode: 0o700 });

      await fs.copyFile(
        validSource,
        validDest,
        options.overwrite === false ? fs.constants.COPYFILE_EXCL : 0
      );

      return { success: true, size: stats.size };
    } catch (error) {
      console.error('[FILE] Copy file failed:', this.sanitizeError(error));
      return { success: false, error: 'Failed to copy file' };
    }
  }

  sanitizeError(err) {
    if (!err) return 'Unknown error';
    const message = err.message || String(err);
    return message.replace(/\/[^\s]+/g, '[PATH]').substring(0, 200);
  }
}

module.exports = { FileHandler };