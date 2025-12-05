/**
 * Secure Storage
 * Double AEAD: AES-256-GCM + XChaCha20-Poly1305
 * KDF: SHA3-512
 * MAC: BLAKE3 keyed authentication
 * 
 * Security properties:
 * - Double encryption layers
 * - Machine-bound keys
 * - Atomic writes with 0600 permissions
 * - Memory zeroization
 * - Timing-safe comparisons
 */

const crypto = require('crypto');
const path = require('path');
const os = require('os');
const { ensureDir, atomicWrite, readFile, removeFile, listFiles, toSafeFileName, fromSafeFileName } = require('./secure-file.cjs');
const { getMachineContext } = require('./machine-entropy.cjs');

const CONFIG_DIR = path.join(os.homedir(), '.config', 'Qor-chat-client');
const STORE_DIR = path.join(CONFIG_DIR, 'secure-store');
const MASTER_KEY_FILE = path.join(CONFIG_DIR, 'master.key');

const NONCE_SIZE = 36; // 12 bytes for AES-GCM + 24 bytes for XChaCha20
const MAC_SIZE = 32;
let noble = null;
let kAES = null;
let kXChaCha = null;
let kMAC = null;
let initialized = false;

async function loadNoble() {
  if (!noble) {
    const ciphers = await import('@noble/ciphers/chacha.js');
    const sha3m = await import('@noble/hashes/sha3.js');
    const b3 = await import('@noble/hashes/blake3.js');
    noble = {
      xchacha20poly1305: ciphers.xchacha20poly1305,
      sha3_512: sha3m.sha3_512,
      blake3: b3.blake3
    };
  }
}

function sha3(buf) {
  return Buffer.from(noble.sha3_512(buf));
}

function blake3k(key, msg) {
  const ctx = noble.blake3.create({ key });
  ctx.update(msg);
  return Buffer.from(ctx.digest());
}

function zeroize(...buffers) {
  for (const buf of buffers) {
    try {
      if (buf && buf.fill) {
        buf.fill(0);
      }
    } catch (_) {}
  }
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

/**
 * Initialize the secure storage system
 */
async function init({ installPath, logger }) {
  if (initialized) {
    return;
  }

  await loadNoble();

  // Ensure directories exist with strict permissions
  await ensureDir(CONFIG_DIR, 0o700);
  await ensureDir(STORE_DIR, 0o700);

  // Load or generate master key
  let masterKey;
  try {
    masterKey = await readFile(MASTER_KEY_FILE);
    if (masterKey.length !== 64) {
      throw new Error('Invalid master key length');
    }
  } catch (err) {
    if (err.code === 'ENOENT' || err.message.includes('Invalid master key')) {
      masterKey = crypto.randomBytes(64);
      await atomicWrite(MASTER_KEY_FILE, masterKey, 0o600);
    } else {
      throw err;
    }
  }

  // Get machine-specific entropy
  const machineContext = await getMachineContext(installPath);

  // Derive root key from master key + machine context
  const root = sha3(Buffer.concat([
    Buffer.from('QSSv1/ROOT', 'utf8'),
    masterKey,
    machineContext
  ]));

  // Derive subkeys for each encryption layer
  const aesKeyMaterial = sha3(Buffer.concat([
    Buffer.from('QSSv1/AES-256-GCM', 'utf8'),
    root
  ]));
  const xchachaKeyMaterial = sha3(Buffer.concat([
    Buffer.from('QSSv1/XCHACHA20-POLY1305', 'utf8'),
    root
  ]));
  const macKeyMaterial = sha3(Buffer.concat([
    Buffer.from('QSSv1/BLAKE3-MAC', 'utf8'),
    root
  ]));

  kAES = aesKeyMaterial.subarray(0, 32);
  kXChaCha = xchachaKeyMaterial.subarray(0, 32);
  kMAC = macKeyMaterial.subarray(0, 32);

  // Zeroize sensitive intermediate data
  zeroize(masterKey, machineContext, root, aesKeyMaterial, xchachaKeyMaterial, macKeyMaterial);

  initialized = true;
}

/**
 * Get file path for a key
 */
function filePathForKey(key) {
  const safeName = toSafeFileName(key);
  return path.join(STORE_DIR, `${safeName}.bin`);
}

/**
 * Encrypt and store a value
 */
async function setItem(key, value) {
  if (!initialized) {
    throw new Error('Storage not initialized');
  }

  const data = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
  
  // Generate random nonce: 12 bytes for AES-GCM + 24 bytes for XChaCha20
  const nonce = crypto.randomBytes(NONCE_SIZE);
  const nAES = nonce.subarray(0, 12);
  const nXChaCha = nonce.subarray(12, 36);

  // Additional authenticated data for each layer (binds nonces)
  const aad1 = Buffer.concat([Buffer.from('QSSv1 L1', 'utf8'), nXChaCha]);
  const aad2 = Buffer.concat([Buffer.from('QSSv1 L2', 'utf8'), nAES]);

  let layer1Ciphertext, authTag1, layer1, layer2, mac, fileData;

  try {
    // Layer 1: AES-256-GCM encryption
    const cipher = crypto.createCipheriv('aes-256-gcm', kAES, nAES, { authTagLength: 16 });
    cipher.setAAD(aad1);
    layer1Ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
    authTag1 = cipher.getAuthTag();
    layer1 = Buffer.concat([layer1Ciphertext, authTag1]);

    // Layer 2: XChaCha20-Poly1305 encryption (requires pre-allocated output buffer)
    const xchacha = noble.xchacha20poly1305(kXChaCha, nXChaCha);
    layer2 = Buffer.alloc(layer1.length + 16); // plaintext + 16-byte Poly1305 tag
    xchacha.encrypt(layer1, layer2, aad2);

    // Layer 3: BLAKE3 MAC for authentication
    const macInput = Buffer.concat([Buffer.from('QSSv1', 'utf8'), nonce, layer2]);
    mac = blake3k(kMAC, macInput).subarray(0, MAC_SIZE);

    // Final file format: [nonce(36) | layer2_ciphertext | mac(32)]
    fileData = Buffer.concat([nonce, layer2, mac]);

    // Atomic write with strict permissions
    await atomicWrite(filePathForKey(key), fileData, 0o600);

    return true;
  } finally {
    // Zeroize all intermediate buffers
    zeroize(nonce, nAES, nXChaCha, aad1, aad2, layer1Ciphertext, authTag1, layer1, layer2, mac, fileData);
  }
}

/**
 * Retrieve and decrypt a value
 */
async function getItem(key) {
  if (!initialized) {
    throw new Error('Storage not initialized');
  }

  const filePath = filePathForKey(key);

  let fileData;
  try {
    fileData = await readFile(filePath);
  } catch (err) {
    if (err.code === 'ENOENT') {
      return null;
    }
    throw err;
  }

  // Validate file size
  const minSize = NONCE_SIZE + 16 + MAC_SIZE; // nonce + min ciphertext + mac
  if (fileData.length < minSize) {
    throw new Error('Invalid encrypted file: too small');
  }

  // Parse file format: [nonce(36) | ciphertext | mac(32)]
  const nonce = fileData.subarray(0, NONCE_SIZE);
  const mac = fileData.subarray(fileData.length - MAC_SIZE);
  const layer2 = fileData.subarray(NONCE_SIZE, fileData.length - MAC_SIZE);

  const nAES = nonce.subarray(0, 12);
  const nXChaCha = nonce.subarray(12, 36);

  const aad1 = Buffer.concat([Buffer.from('QSSv1 L1', 'utf8'), nXChaCha]);
  const aad2 = Buffer.concat([Buffer.from('QSSv1 L2', 'utf8'), nAES]);

  let macCheck, layer1, authTag1, layer1Ciphertext, plaintext;

  try {
    // Verify BLAKE3 MAC
    const macInput = Buffer.concat([Buffer.from('QSSv1', 'utf8'), nonce, layer2]);
    macCheck = blake3k(kMAC, macInput).subarray(0, MAC_SIZE);

    if (!timingSafeEqual(mac, macCheck)) {
      throw new Error('MAC verification failed: data may be tampered');
    }

    // Layer 2: Decrypt XChaCha20-Poly1305 (requires pre-allocated output buffer)
    const xchacha = noble.xchacha20poly1305(kXChaCha, nXChaCha);
    layer1 = Buffer.alloc(layer2.length - 16); // ciphertext - 16-byte Poly1305 tag
    xchacha.decrypt(layer2, layer1, aad2);

    if (!layer1 || layer1.length < 16) {
      throw new Error('Layer 2 decryption failed');
    }

    // Split Layer 1 into ciphertext and auth tag
    authTag1 = layer1.subarray(layer1.length - 16);
    layer1Ciphertext = layer1.subarray(0, layer1.length - 16);

    // Layer 1: Decrypt AES-256-GCM
    const decipher = crypto.createDecipheriv('aes-256-gcm', kAES, nAES);
    decipher.setAAD(aad1);
    decipher.setAuthTag(authTag1);
    plaintext = Buffer.concat([decipher.update(layer1Ciphertext), decipher.final()]);

    return plaintext;
  } finally {
    // Zeroize all intermediate buffers
    zeroize(nonce, nAES, nXChaCha, aad1, aad2, macCheck, layer1, authTag1, layer1Ciphertext);
  }
}

/**
 * Remove a stored value
 */
async function removeItem(key) {
  if (!initialized) {
    throw new Error('Storage not initialized');
  }

  const filePath = filePathForKey(key);
  await removeFile(filePath);
}

/**
 * List all stored keys
 */
async function listKeys() {
  if (!initialized) {
    throw new Error('Storage not initialized');
  }

  const files = await listFiles(STORE_DIR);
  return files
    .filter(f => f.endsWith('.bin'))
    .map(f => fromSafeFileName(f.slice(0, -4)));
}

module.exports = {
  init,
  setItem,
  getItem,
  removeItem,
  listKeys,
  pathForKey: filePathForKey
};
