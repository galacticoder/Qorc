/**
 * Secure File I/O Utilities
 * Provides atomic writes, strict permissions, and safe file operations
 */

const fs = require('fs').promises;
const path = require('path');

/**
 * Ensure directory exists with specified mode
 */
async function ensureDir(dirPath, mode = 0o700) {
  try {
    await fs.mkdir(dirPath, { recursive: true, mode });
    // Verify and fix permissions if needed
    const stats = await fs.stat(dirPath);
    if ((stats.mode & 0o777) !== mode) {
      await fs.chmod(dirPath, mode);
    }
  } catch (err) {
    if (err.code !== 'EEXIST') {
      throw err;
    }
  }
}

/**
 * Atomic write: write to temp file, fsync, then rename
 */
async function atomicWrite(filePath, data, mode = 0o600) {
  const dir = path.dirname(filePath);
  const tmpPath = path.join(dir, `.${path.basename(filePath)}.tmp.${process.pid}.${Date.now()}`);
  
  try {
    // Write to temp file with strict permissions
    const fd = await fs.open(tmpPath, 'w', mode);
    try {
      await fd.write(data);
      await fd.sync(); // Ensure data is on disk
    } finally {
      await fd.close();
    }
    
    // Atomic rename
    await fs.rename(tmpPath, filePath);
    
    // Verify final permissions
    await fs.chmod(filePath, mode);
  } catch (err) {
    // Clean up temp file on failure
    try {
      await fs.unlink(tmpPath);
    } catch (_) {}
    throw err;
  }
}

/**
 * Read file as Buffer
 */
async function readFile(filePath) {
  return await fs.readFile(filePath);
}

/**
 * Remove file safely
 */
async function removeFile(filePath) {
  try {
    await fs.unlink(filePath);
  } catch (err) {
    if (err.code !== 'ENOENT') {
      throw err;
    }
  }
}

/**
 * List files in directory
 */
async function listFiles(dirPath) {
  try {
    return await fs.readdir(dirPath);
  } catch (err) {
    if (err.code === 'ENOENT') {
      return [];
    }
    throw err;
  }
}

/**
 * Convert key to safe filename using hex encoding
 */
function toSafeFileName(key) {
  if (typeof key !== 'string' || !key) {
    throw new Error('Key must be a non-empty string');
  }
  if (key.includes('/') || key.includes('\\') || key.includes('..') || key.includes('\0')) {
    throw new Error('Invalid key characters');
  }
  // Use hex encoding for predictable, filesystem-safe names
  return Buffer.from(key, 'utf8').toString('hex');
}

/**
 * Decode safe filename back to key
 */
function fromSafeFileName(filename) {
  try {
    return Buffer.from(filename, 'hex').toString('utf8');
  } catch (_) {
    return filename; // Return as-is if decoding fails
  }
}

module.exports = {
  ensureDir,
  atomicWrite,
  readFile,
  removeFile,
  listFiles,
  toSafeFileName,
  fromSafeFileName
};
