/**
 * Secure File I/O Utilities
 */

const fs = require('fs').promises;
const path = require('path');

// Ensure directory exists with specified mode
async function ensureDir(dirPath, mode = 0o700) {
  try {
    await fs.mkdir(dirPath, { recursive: true, mode });
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

// Atomic write
async function atomicWrite(filePath, data, mode = 0o600) {
  const dir = path.dirname(filePath);
  const tmpPath = path.join(dir, `.${path.basename(filePath)}.tmp.${process.pid}.${Date.now()}`);
  
  try {
    const fd = await fs.open(tmpPath, 'w', mode);
    try {
      await fd.write(data);
      await fd.sync();
    } finally {
      await fd.close();
    }
    
    await fs.rename(tmpPath, filePath);
    
    await fs.chmod(filePath, mode);
  } catch (err) {
    try {
      await fs.unlink(tmpPath);
    } catch (_) {}
    throw err;
  }
}

// Read file as Buffer
async function readFile(filePath) {
  return await fs.readFile(filePath);
}

// Remove file
async function removeFile(filePath) {
  try {
    await fs.unlink(filePath);
  } catch (err) {
    if (err.code !== 'ENOENT') {
      throw err;
    }
  }
}

// List files in directory
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

// Convert key to safe filename using hex encoding
function toSafeFileName(key) {
  if (typeof key !== 'string' || !key) {
    throw new Error('Key must be a non-empty string');
  }
  if (key.includes('/') || key.includes('\\') || key.includes('..') || key.includes('\0')) {
    throw new Error('Invalid key characters');
  }

  return Buffer.from(key, 'utf8').toString('hex');
}

// Decode filename back to key
function fromSafeFileName(filename) {
  try {
    return Buffer.from(filename, 'hex').toString('utf8');
  } catch (_) {
    return filename;
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
