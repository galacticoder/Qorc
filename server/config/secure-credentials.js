#!/usr/bin/env node
/**
 * Quantum-Secure Credentials Manager for HAProxy
 * 
 * Uses ML-KEM-1024 (Kyber) and ML-DSA-87 (Dilithium) for post-quantum encryption
 * Generates and manages its own dedicated keypair (separate from server keys)
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const CREDS_FILE = path.join(__dirname, '.haproxy-stats-creds.pqc');
const KEY_ENC_FILE = path.join(__dirname, '.haproxy-keys.enc');

/**
 * Generate dedicated keypair for credential encryption (independent of server keys)
 */
async function deriveKEK(username, password, salt) {
  const { kek, salt: usedSalt } = await CryptoUtils.KDF.deriveUsernamePasswordKEK(
    username,
    password,
    { salt }
  );
  const usernameBytes = Buffer.from(String(username), 'utf8');
  const usernameHash = Buffer.from(blake3(usernameBytes));
  return { kek: Buffer.from(kek), usernameHash, salt: Buffer.from(usedSalt) };
}

async function generateAndProtectKeypair(username, password) {
  const kemKP = ml_kem1024.keygen();
  const kemPublicKey = kemKP.publicKey;
  const kemSecretKey = kemKP.secretKey;

  const dilithiumSeed = crypto.randomBytes(32);
  const dilithiumKeypair = ml_dsa87.keygen(dilithiumSeed);
  const x25519SecretKey = crypto.randomBytes(32);
  const x25519PublicKey = x25519.getPublicKey(x25519SecretKey);

  const keypair = {
    kyber: {
      publicKey: kemPublicKey,
      secretKey: kemSecretKey,
    },
    dilithium: {
      publicKey: dilithiumKeypair.publicKey,
      secretKey: dilithiumKeypair.secretKey,
    },
    x25519: {
      publicKey: x25519PublicKey,
      secretKey: x25519SecretKey,
    },
  };

  const { kek, usernameHash, salt } = await deriveKEK(username, password);

  const keysBlob = Buffer.from(JSON.stringify({
    kyberSecretKey: Buffer.from(keypair.kyber.secretKey).toString('base64'),
    dilithiumSecretKey: Buffer.from(keypair.dilithium.secretKey).toString('base64'),
    x25519SecretKey: Buffer.from(keypair.x25519.secretKey).toString('base64'),
    kyberPublicKey: Buffer.from(keypair.kyber.publicKey).toString('base64'),
    dilithiumPublicKey: Buffer.from(keypair.dilithium.publicKey).toString('base64'),
    x25519PublicKey: Buffer.from(keypair.x25519.publicKey).toString('base64'),
  }), 'utf8');

  const aead = new CryptoUtils.PostQuantumAEAD(kek);
  const nonce = CryptoUtils.Random.generateRandomBytes(36);
  const aad = new TextEncoder().encode('haproxy-secure-keys-v2');
  const { ciphertext, tag } = aead.encrypt(keysBlob, nonce, aad);

  const payload = {
    version: 2,
    kdf: {
      algorithm: 'argon2id+quantumHKDF',
      salt: salt.toString('base64'),
    },
    usernameHash: usernameHash.toString('base64'),
    enc: {
      nonce: Buffer.from(nonce).toString('base64'),
      tag: Buffer.from(tag).toString('base64'),
      ciphertext: Buffer.from(ciphertext).toString('base64'),
    }
  };

  fs.writeFileSync(KEY_ENC_FILE, JSON.stringify(payload, null, 2), { mode: 0o600 });

  console.log('[SECURE] All keypairs generated');
  console.log('[SECURE] Encrypted key material saved to:', KEY_ENC_FILE);

  return keypair;
}

export async function unlockKeypair(username, password) {
  if (!fs.existsSync(KEY_ENC_FILE)) {
    throw new Error('Encrypted key file not found');
  }
  const data = JSON.parse(fs.readFileSync(KEY_ENC_FILE, 'utf8'));

  if (data.version !== 2) {
    throw new Error('Unsupported encrypted key version');
  }

  const salt = Buffer.from(data.kdf?.salt || '', 'base64');
  const { kek, usernameHash } = await deriveKEK(username, password, salt);

  const suppliedHash = usernameHash;
  const storedHash = Buffer.from(String(data.usernameHash || ''), 'base64');
  if (suppliedHash.length !== storedHash.length || !crypto.timingSafeEqual(suppliedHash, storedHash)) {
    throw new Error('Username does not match encrypted keyset');
  }

  const nonce = Buffer.from(data.enc?.nonce || '', 'base64');
  const tag = Buffer.from(data.enc?.tag || '', 'base64');
  const ciphertext = Buffer.from(data.enc?.ciphertext || '', 'base64');

  const aead = new CryptoUtils.PostQuantumAEAD(kek);
  const aad = new TextEncoder().encode('haproxy-secure-keys-v2');
  const decrypted = aead.decrypt(ciphertext, nonce, tag, aad);
  const keys = JSON.parse(Buffer.from(decrypted).toString('utf8'));

  return {
    kyber: {
      publicKey: Buffer.from(keys.kyberPublicKey, 'base64'),
      secretKey: Buffer.from(keys.kyberSecretKey, 'base64'),
    },
    dilithium: {
      publicKey: Buffer.from(keys.dilithiumPublicKey, 'base64'),
      secretKey: Buffer.from(keys.dilithiumSecretKey, 'base64'),
    },
    x25519: {
      publicKey: Buffer.from(keys.x25519PublicKey, 'base64'),
      secretKey: Buffer.from(keys.x25519SecretKey, 'base64'),
    },
  };
}

/**
 * Encrypt credentials 
 */
async function encryptCredentials(username, password) {
  const keypair = await generateAndProtectKeypair(username, password);
  
  const credentials = {
    username,
    password,
    timestamp: Date.now(),
    version: 2,
  };
  const plaintext = JSON.stringify(credentials);
  
  const ephemeralX25519Secret = crypto.randomBytes(32);
  const ephemeralX25519Public = x25519.getPublicKey(ephemeralX25519Secret);
  
  const x25519SharedSecret = x25519.getSharedSecret(ephemeralX25519Secret, keypair.x25519.publicKey);
  
  const kemEnc = ml_kem1024.encapsulate(keypair.kyber.publicKey);
  const kyberSharedSecret = kemEnc.sharedSecret;
  const kyberCiphertext = kemEnc.ciphertext || kemEnc.cipherText;
  
  const rawSecret = Buffer.concat([
    Buffer.from(kyberSharedSecret),
    Buffer.from(x25519SharedSecret),
  ]);
  const info = new TextEncoder().encode('haproxy-credentials-v2');
  const aeadKey = await CryptoUtils.KDF.quantumHKDF(
    new Uint8Array(rawSecret),
    CryptoUtils.Hash.shake256(rawSecret, 64),
    info,
    32
  );

  const aead = new CryptoUtils.PostQuantumAEAD(aeadKey);
  const nonce = CryptoUtils.Random.generateRandomBytes(36);
  const aad = new TextEncoder().encode('haproxy-credentials-v2');
  const { ciphertext, tag } = aead.encrypt(Buffer.from(plaintext, 'utf8'), nonce, aad);
  
  const encryptedPackage = {
    kyberCiphertext: Buffer.from(kyberCiphertext).toString('base64'),
    x25519EphemeralPublic: Buffer.from(ephemeralX25519Public).toString('base64'),
    nonce: Buffer.from(nonce).toString('base64'),
    tag: Buffer.from(tag).toString('base64'),
    ciphertext: Buffer.from(ciphertext).toString('base64'),
  };
  
  const packageBytes = Buffer.from(JSON.stringify(encryptedPackage));
  const signature = ml_dsa87.sign(packageBytes, keypair.dilithium.secretKey);
  
  return {
    version: 2,
    encrypted: encryptedPackage,
    signature: Buffer.from(signature).toString('base64'),
    algorithm: 'ML-KEM-1024 + X25519 + PostQuantumAEAD + ML-DSA-87',
  };
}

/**
 * Decrypt credentials 
 */
async function decryptCredentials(encryptedObj, { username, password } = {}) {
  const keypair = await unlockKeypair(username, password);
  const encryptedPackage = encryptedObj.encrypted;
  
  if (encryptedObj.version !== 2) {
    throw new Error('Unsupported credentials version; regenerate credentials with the current scheme');
  }

  const packageBytes = Buffer.from(JSON.stringify(encryptedPackage));
  const signatureBuffer = Buffer.from(encryptedObj.signature, 'base64');
  
  const isValid = ml_dsa87.verify(
    signatureBuffer,
    packageBytes,
    keypair.dilithium.publicKey
  );
  
  if (!isValid) {
    throw new Error('SECURITY: Credential signature verification failed - data may be tampered');
  }
  
  const kyberCiphertext = Buffer.from(encryptedPackage.kyberCiphertext, 'base64');
  const x25519EphemeralPublic = Buffer.from(encryptedPackage.x25519EphemeralPublic, 'base64');
  const nonce = Buffer.from(encryptedPackage.nonce, 'base64');
  const ciphertext = Buffer.from(encryptedPackage.ciphertext, 'base64');
  const tag = Buffer.from(encryptedPackage.tag, 'base64');
  const kyberSharedSecret = ml_kem1024.decapsulate(kyberCiphertext, keypair.kyber.secretKey);
  const x25519SharedSecret = x25519.getSharedSecret(keypair.x25519.secretKey, x25519EphemeralPublic);
  
  const rawSecret = Buffer.concat([
    Buffer.from(kyberSharedSecret),
    Buffer.from(x25519SharedSecret),
  ]);
  const info = new TextEncoder().encode('haproxy-credentials-v2');
  const aeadKey = await CryptoUtils.KDF.quantumHKDF(
    new Uint8Array(rawSecret),
    CryptoUtils.Hash.shake256(rawSecret, 64),
    info,
    32
  );
  
  const aead = new CryptoUtils.PostQuantumAEAD(aeadKey);
  const aad = new TextEncoder().encode('haproxy-credentials-v2');
  const plaintext = aead.decrypt(ciphertext, nonce, tag, aad);
  
  return JSON.parse(Buffer.from(plaintext).toString('utf8'));
}

/**
 * Save encrypted credentials to file
 */
export async function saveCredentials(username, password) {
  if (!username || !password) {
    throw new Error('Username and password are required');
  }
  
  console.log('[SECURE] Encrypting credentials...');
  const encrypted = await encryptCredentials(username, password);
  
  // Save with restrictive permissions
  fs.writeFileSync(CREDS_FILE, JSON.stringify(encrypted, null, 2), { mode: 0o600 });
  
  console.log(`[SECURE] Credentials encrypted and saved to: (${CREDS_FILE})`);
}

/**
 * Load and decrypt credentials from file
 */
export async function loadCredentials({ username, password } = {}) {
  if (!fs.existsSync(CREDS_FILE)) {
    return null;
  }
  
  const encrypted = JSON.parse(fs.readFileSync(CREDS_FILE, 'utf8'));
  
  console.log('[SECURE] Decrypting credentials...');
  const credentials = await decryptCredentials(encrypted, { username, password });
  console.log('[SECURE] Credentials decrypted successfully');
  
  return credentials;
}

/**
 * Verify provided credentials against stored (constant-time)
 */
export async function verifyCredentials(username, password) {
  const stored = await loadCredentials({ username, password });
  if (!stored) throw new Error('No credentials stored');
  
  // Use constant-time comparison
  const uA = Buffer.from(String(username) || '', 'utf8');
  const uB = Buffer.from(String(stored.username) || '', 'utf8');
  const pA = Buffer.from(String(password) || '', 'utf8');
  const pB = Buffer.from(String(stored.password) || '', 'utf8');
  
  const userMatch = (uA.length === uB.length) && crypto.timingSafeEqual(uA, uB);
  const passMatch = (pA.length === pB.length) && crypto.timingSafeEqual(pA, pB);
  
  if (!userMatch || !passMatch) {
    return false;
  }
  return true;
}

/**
 * Delete credentials file
 */
export function deleteCredentials() {
  if (fs.existsSync(CREDS_FILE)) {
    fs.unlinkSync(CREDS_FILE);
    console.log('[SECURE] Credentials file deleted');
  }
  
  if (fs.existsSync(KEY_ENC_FILE)) {
    try { fs.unlinkSync(KEY_ENC_FILE); } catch {}
    console.log('[SECURE] Encrypted key file deleted');
  }
}

// CLI mode
if (import.meta.url === `file://${process.argv[1]}`) {
  const command = process.argv[2];
  
  (async () => {
    try {
      switch (command) {
      case 'save':
        if (process.argv.length < 5) {
          console.error('Usage: node secure-credentials.js save <username> <password>');
          process.exit(1);
        }
        await saveCredentials(process.argv[3], process.argv[4]);
        break;
        
      case 'load':
        console.error('Usage: node secure-credentials.js load-unlocked <username> <password>');
        process.exit(2);
        
      case 'load-unlocked':
        if (process.argv.length < 5) {
          console.error('Usage: node secure-credentials.js load-unlocked <username> <password>');
          process.exit(2);
        }
        const creds = await loadCredentials({ username: process.argv[3], password: process.argv[4] });
        if (creds) {
          console.log('');
          console.log('Credentials:');
          console.log('\tUsername:', creds.username);
          console.log('\tPassword:', '********');
          console.log('\tStored:', new Date(creds.timestamp).toISOString());
        } else {
          console.log('No credentials found');
        }
        break;
        
      case 'delete':
        deleteCredentials();
        break;
      
      case 'verify':
        if (process.argv.length < 5) {
          console.error('Usage: node secure-credentials.js verify <username> <password>');
          process.exit(2);
        }
        if (await verifyCredentials(process.argv[3], process.argv[4])) {
          console.log('OK');
          process.exit(0);
        } else {
          console.log('MISMATCH');
          process.exit(1);
        }
        
      default:
        console.log('Credentials Manager for HAProxy\n');
        console.log('');
        console.log('Usage:');
        console.log('\tnode secure-credentials.js save <username> <password>');
        console.log('\tnode secure-credentials.js load');
        console.log('\tnode secure-credentials.js delete');
        console.log('');
        process.exit(1);
    }
  } catch (error) {
    console.error('[ERROR]', error.message);
    process.exit(1);
  }
  })();
}
