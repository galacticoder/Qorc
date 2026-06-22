import * as argon2 from "argon2-wasm";
import { ml_kem1024 as kyber } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { PrivacyPassOps, OPAQUEOps } from './crypto-ops';
import { WORKER_MAX_KEYS, PQ_AEAD_NONCE_SIZE, PQ_AEAD_GCM_IV_SIZE, PQ_AEAD_MAC_SIZE } from '../constants';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { gcm } from '@noble/ciphers/aes.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

const activeKeys = new Map();

let AUTH_TOKEN = new Uint8Array(32);
crypto.getRandomValues(AUTH_TOKEN);

// Initialize worker with token
self.postMessage({
  type: 'auth-token-init',
  token: Array.from(AUTH_TOKEN, (b) => b.toString(16).padStart(2, '0')).join(''),
  timestamp: Date.now()
});

function isPlainObject(value: any): value is Record<string, any> {
  if (typeof value !== 'object' || value === null) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function hasPrototypePollutionKeys(data: any): boolean {
  if (!data || typeof data !== 'object') return false;
  const keys = Object.keys(data);
  return keys.some(key => key === '__proto__' || key === 'constructor' || key === 'prototype');
}

function secureRandomId(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function authenticateEnvelope(auth: string): void {
  const expected = Array.from(AUTH_TOKEN, (b) => b.toString(16).padStart(2, '0')).join('');
  if (auth !== expected) {
    throw new Error('Unauthorized request');
  }
}

function storeKey(keyId: string, secretKey: Uint8Array, origin: string): void {
  if (activeKeys.size >= WORKER_MAX_KEYS) {
    const entries = Array.from(activeKeys.entries()).sort((a, b) => a[1].timestamp - b[1].timestamp);
    const [oldestKeyId, oldestKeyData] = entries[0];
    oldestKeyData.key.fill(0);
    activeKeys.delete(oldestKeyId);
  }
  activeKeys.set(keyId, { key: secretKey, timestamp: Date.now(), origin });
}

self.addEventListener('message', async (event: MessageEvent<any>) => {
  try {
    const data = event.data;
    if (!isPlainObject(data) || hasPrototypePollutionKeys(data)) {
      throw new Error('Invalid message format');
    }

    const { id, type, auth } = data;
    if (!id || !type || auth === undefined) {
      throw new Error('Malformed worker request');
    }

    authenticateEnvelope(auth);

    switch (type) {
      case 'kem.generateKeyPair': {
        const keyPair = kyber.keygen();
        const keyId = secureRandomId();
        storeKey(keyId, keyPair.secretKey, event.origin ?? 'unknown');
        self.postMessage({
          id,
          success: true,
          result: {
            publicKey: keyPair.publicKey,
            secretKey: keyPair.secretKey,
            keyId
          }
        });
        break;
      }
      case 'kem.encapsulate': {
        if (!data.publicKey) throw new Error('Public key required');
        const result = kyber.encapsulate(data.publicKey);
        self.postMessage({
          id,
          success: true,
          result: {
            ciphertext: result.cipherText,
            sharedSecret: result.sharedSecret
          }
        });
        break;
      }
      case 'kem.decapsulate': {
        if (!data.ciphertext) throw new Error('Ciphertext required');
        let secretKey = data.secretKey;
        if (!secretKey && data.keyId) {
          const keyData = activeKeys.get(data.keyId);
          if (keyData) secretKey = keyData.key;
        }
        if (!secretKey) throw new Error('Secret key required');

        const sharedSecret = kyber.decapsulate(data.ciphertext, secretKey);
        self.postMessage({
          id,
          success: true,
          result: { sharedSecret }
        });
        break;
      }
      case 'kem.destroyKey': {
        const { keyId } = data;
        const secretKeyData = activeKeys.get(keyId);
        if (secretKeyData?.key) {
          secretKeyData.key.fill(0);
          activeKeys.delete(keyId);
        }
        self.postMessage({ id, success: true, result: { destroyed: true } });
        break;
      }
      case 'sig.generateKeyPair': {
        const seed = crypto.getRandomValues(new Uint8Array(32));
        const kp = await ml_dsa87.keygen(seed);
        self.postMessage({
          id,
          success: true,
          result: {
            publicKey: kp.publicKey,
            secretKey: kp.secretKey
          }
        });
        break;
      }
      case 'sig.sign': {
        const signature = await ml_dsa87.sign(data.message, data.secretKey);
        self.postMessage({ id, success: true, result: { signature } });
        break;
      }
      case 'sig.verify': {
        const verified = await ml_dsa87.verify(data.signature, data.message, data.publicKey);
        self.postMessage({ id, success: true, result: { verified } });
        break;
      }
      case 'pp.generateTokenBatch': {
        const resBatch = PrivacyPassOps.generateTokenBatch(data.count, data.purpose);
        self.postMessage({
          id,
          success: true,
          result: resBatch
        });
        break;
      }
      case 'pp.unblindTokens': {
        try {
          const completedTokens = PrivacyPassOps.unblindTokens(
            data.tokenSecrets,
            data.signedBlindedTokens,
            data.proof,
            data.serverPublicKey
          );
          self.postMessage({ id, success: true, result: { completedTokens } });
        } catch (err: any) {
          throw new Error(`PrivacyPass unblind failed: ${err.message}`);
        }
        break;
      }
      case 'opaque.startRegistration': {
        const resReg = OPAQUEOps.startRegistration(data.passwordBytes);
        self.postMessage({
          id,
          success: true,
          result: resReg
        });
        break;
      }
      case 'opaque.finishRegistration': {
        const resFinReg = OPAQUEOps.finishRegistration(data.passwordBytes, data.blindingFactor, data.clientSecretKey, data.serverResponse);
        self.postMessage({ id, success: true, result: resFinReg });
        break;
      }
      case 'opaque.startLogin': {
        const resLogin = OPAQUEOps.startLogin(data.passwordBytes);
        self.postMessage({ id, success: true, result: resLogin });
        break;
      }
      case 'opaque.finishLogin': {
        try {
          const resFinLogin = OPAQUEOps.finishLogin(data.passwordBytes, data.blindingFactor, data.serverResponse);
          self.postMessage({ id, success: true, result: resFinLogin });
        } catch (err: any) {
          self.postMessage({ id, success: true, result: { success: false, error: err.message } });
        }
        break;
      }
      case 'opaque.startOTLogin': {
        try {
          const resOTLogin = OPAQUEOps.startOTLogin(data.passwordBytes, data.shardSize, data.myIndex);
          self.postMessage({ id, success: true, result: resOTLogin });
        } catch (err: any) {
          self.postMessage({ id, success: false, error: `startOTLogin failed: ${err.message}` });
        }
        break;
      }
      case 'opaque.finishOTLogin': {
        try {
          const resFinOTLogin = OPAQUEOps.finishOTLogin(
            data.passwordBytes,
            data.blindingFactor,
            data.myPrivKey,
            data.otRecords,
            data.myIndex,
            data.evaluatedElement,
            data.serverNonce
          );
          self.postMessage({ id, success: true, result: resFinOTLogin });
        } catch (err: any) {
          self.postMessage({ id, success: true, result: { success: false, error: err.message } });
        }
        break;
      }
      case 'argon2.hash': {
        argon2.hash(data.params).then((resultHash) => {
          self.postMessage({ id, success: true, result: { hash: resultHash.hash, encoded: resultHash.encoded } });
        }).catch((err) => {
          self.postMessage({ id, success: false, error: `Argon2 hash failed: ${err.message}` });
        });
        break;
      }
      case 'argon2.verify': {
        argon2.verify(data.params).then((resultVerify) => {
          self.postMessage({ id, success: true, result: { verified: resultVerify.verified === true } });
        }).catch((err) => {
          self.postMessage({ id, success: false, error: `Argon2 verify failed: ${err.message}` });
        });
        break;
      }
      case 'aead.encrypt': {
        if (!data.plaintext || !(data.plaintext instanceof Uint8Array)) throw new Error('plaintext required');
        if (!data.key || !(data.key instanceof Uint8Array) || data.key.length !== 32) throw new Error('32-byte key required');

        const encNonce = (data.explicitNonce && data.explicitNonce instanceof Uint8Array)
          ? data.explicitNonce
          : crypto.getRandomValues(new Uint8Array(PQ_AEAD_NONCE_SIZE));
        if (encNonce.length !== PQ_AEAD_NONCE_SIZE) throw new Error(`Nonce must be ${PQ_AEAD_NONCE_SIZE} bytes`);

        const encAad = (data.additionalData && data.additionalData instanceof Uint8Array)
          ? data.additionalData : new Uint8Array(0);

        const encExpanded = sha3_512(data.key);
        const encK1 = encExpanded.slice(0, 32);
        const encK2 = encExpanded.slice(32, 64);
        const encMacKeyInput = new Uint8Array(new TextEncoder().encode('quantum-secure-mac-v1').length + data.key.length);
        encMacKeyInput.set(new TextEncoder().encode('quantum-secure-mac-v1'), 0);
        encMacKeyInput.set(data.key, new TextEncoder().encode('quantum-secure-mac-v1').length);
        const encMacKey = blake3(encMacKeyInput, { dkLen: 32 });

        try {
          const encIv = encNonce.slice(0, PQ_AEAD_GCM_IV_SIZE);
          const encCipher = gcm(encK1, encIv, encAad);
          const encLayer1 = encCipher.encrypt(data.plaintext);

          const encXnonce = encNonce.slice(PQ_AEAD_GCM_IV_SIZE, PQ_AEAD_NONCE_SIZE);
          const encXchacha = xchacha20poly1305(encK2, encXnonce, encAad);
          const encLayer2 = encXchacha.encrypt(encLayer1);

          const encMacInput = new Uint8Array(encLayer2.length + encAad.length + encNonce.length);
          encMacInput.set(encLayer2, 0);
          encMacInput.set(encAad, encLayer2.length);
          encMacInput.set(encNonce, encLayer2.length + encAad.length);
          const encMac = blake3(encMacInput, { key: encMacKey });

          self.postMessage({
            id,
            success: true,
            result: { ciphertext: encLayer2, nonce: encNonce, tag: encMac }
          });
        } finally {
          encK1.fill(0); encK2.fill(0); encMacKey.fill(0);
        }
        break;
      }
      case 'aead.decrypt': {
        if (!data.ciphertext || !(data.ciphertext instanceof Uint8Array)) throw new Error('ciphertext required');
        if (!data.key || !(data.key instanceof Uint8Array) || data.key.length !== 32) throw new Error('32-byte key required');
        if (!data.nonce || !(data.nonce instanceof Uint8Array) || data.nonce.length !== PQ_AEAD_NONCE_SIZE) throw new Error(`Nonce must be ${PQ_AEAD_NONCE_SIZE} bytes`);
        if (!data.tag || !(data.tag instanceof Uint8Array) || data.tag.length !== PQ_AEAD_MAC_SIZE) throw new Error(`Tag must be ${PQ_AEAD_MAC_SIZE} bytes`);

        const decAad = (data.additionalData && data.additionalData instanceof Uint8Array)
          ? data.additionalData : new Uint8Array(0);

        const decExpanded = sha3_512(data.key);
        const decK1 = decExpanded.slice(0, 32);
        const decK2 = decExpanded.slice(32, 64);
        const decMacKeyInput = new Uint8Array(new TextEncoder().encode('quantum-secure-mac-v1').length + data.key.length);
        decMacKeyInput.set(new TextEncoder().encode('quantum-secure-mac-v1'), 0);
        decMacKeyInput.set(data.key, new TextEncoder().encode('quantum-secure-mac-v1').length);
        const decMacKey = blake3(decMacKeyInput, { dkLen: 32 });

        try {
          // Verify BLAKE3 MAC first
          const decMacInput = new Uint8Array(data.ciphertext.length + decAad.length + data.nonce.length);
          decMacInput.set(data.ciphertext, 0);
          decMacInput.set(decAad, data.ciphertext.length);
          decMacInput.set(data.nonce, data.ciphertext.length + decAad.length);
          const expectedMac = blake3(decMacInput, { key: decMacKey });

          // Constant-time MAC comparison
          if (data.tag.length !== expectedMac.length) throw new Error('BLAKE3 MAC verification failed');
          let diff = 0;
          for (let i = 0; i < data.tag.length; i++) {
            diff |= data.tag[i] ^ expectedMac[i];
          }
          if (diff !== 0) throw new Error('BLAKE3 MAC verification failed');

          // Layer 2: XChaCha20-Poly1305 decrypt
          const decXnonce = data.nonce.slice(PQ_AEAD_GCM_IV_SIZE, PQ_AEAD_NONCE_SIZE);
          const decXchacha = xchacha20poly1305(decK2, decXnonce, decAad);
          const decLayer1 = decXchacha.decrypt(data.ciphertext);

          // Layer 1: AES-256-GCM decrypt
          const decIv = data.nonce.slice(0, PQ_AEAD_GCM_IV_SIZE);
          const decDecipher = gcm(decK1, decIv, decAad);
          const decPlaintext = decDecipher.decrypt(decLayer1);

          self.postMessage({ id, success: true, result: { plaintext: decPlaintext } });
        } finally {
          decK1.fill(0); decK2.fill(0); decMacKey.fill(0);
        }
        break;
      }
      default: {
        throw new Error(`Unsupported worker operation: ${type}`);
      }
    }
  } catch (error: any) {
    self.postMessage({
      id: (event.data && event.data.id ? event.data.id : 'unknown'),
      success: false,
      error: error instanceof Error ? error.message : String(error)
    });
  }
});

export { };
