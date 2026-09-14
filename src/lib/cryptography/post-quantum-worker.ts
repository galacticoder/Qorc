import * as argon2 from "argon2-wasm";
import { ml_kem1024 as kyber } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { PrivacyPassOps, OPAQUEOps } from './crypto-ops';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { gcm } from '@noble/ciphers/aes.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { validateWorkerRequest } from './worker-request-validation';
import { isPlainObject } from '../sanitizers';
import { wipeBinaryValues } from './wipe';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { AES_GCM_NONCE_BYTES, HASH_OUTPUT_BYTES, POST_QUANTUM_AEAD_NONCE_BYTES } from '../../../shared/crypto-sizes.js';

let AUTH_TOKEN = new Uint8Array(32);
crypto.getRandomValues(AUTH_TOKEN);

// Initialize worker with token
self.postMessage({
  type: 'auth-token-init',
  token: Array.from(AUTH_TOKEN, (b) => b.toString(16).padStart(2, '0')).join(''),
  timestamp: Date.now()
});

/**
 * Build an outbound response whose binary values have their own backing
 * buffers. Those buffers are transferred to the renderer, so the worker never
 * wipes memory that the receiver still depends on. The worker-owned originals
 * remain available for immediate zeroization after postMessage returns.
 *
 * This is intentionally limited to the plain structured-clone shapes emitted
 * by this worker. Cryptographic responses must not contain class instances or
 * other objects with behavior.
 */
function cloneResponseForTransfer(root: unknown, transfers: Transferable[]): unknown {
  if (root instanceof Uint8Array) {
    const copy = new Uint8Array(root.length);
    copy.set(root);
    transfers.push(copy.buffer);
    return copy;
  }
  if (Array.isArray(root)) {
    return root.map((entry) => cloneResponseForTransfer(entry, transfers));
  }
  if (isPlainObject(root)) {
    const copy: Record<string, unknown> = Object.create(null);
    for (const [key, value] of Object.entries(root)) {
      copy[key] = cloneResponseForTransfer(value, transfers);
    }
    return copy;
  }
  return root;
}

function postSuccess(id: string, result: unknown): void {
  const transfers: Transferable[] = [];
  const outboundResult = cloneResponseForTransfer(result, transfers);
  let transferred = false;
  try {
    self.postMessage({ id, success: true, result: outboundResult }, { transfer: transfers });
    transferred = true;
  } finally {
    wipeBinaryValues(result);
    if (!transferred) wipeBinaryValues(outboundResult);
  }
}

function authenticateEnvelope(auth: string): void {
  const expected = Array.from(AUTH_TOKEN, (b) => b.toString(16).padStart(2, '0')).join('');
  if (auth !== expected) {
    throw new Error('Unauthorized request');
  }
}

self.addEventListener('message', async (event: MessageEvent<any>) => {
  let responseId = 'unknown';
  try {
    const data = event.data;
    validateWorkerRequest(data);
    const { id, type, auth } = data;
    responseId = id;

    authenticateEnvelope(auth);

    switch (type) {
      case 'kem.generateKeyPair': {
        const keyPair = kyber.keygen();
        postSuccess(id, {
          publicKey: keyPair.publicKey,
          secretKey: keyPair.secretKey
        });
        break;
      }
      case 'kem.encapsulate': {
        if (!data.publicKey) throw new Error('Public key required');
        const result = kyber.encapsulate(data.publicKey);
        postSuccess(id, {
          ciphertext: result.cipherText,
          sharedSecret: result.sharedSecret
        });
        break;
      }
      case 'kem.decapsulate': {
        if (!data.ciphertext) throw new Error('Ciphertext required');
        const secretKey = data.secretKey;
        if (!secretKey) throw new Error('Secret key required');

        const sharedSecret = kyber.decapsulate(data.ciphertext, secretKey);
        postSuccess(id, { sharedSecret });
        break;
      }
      case 'sig.generateKeyPair': {
        const seed = crypto.getRandomValues(new Uint8Array(32));
        let kp;
        try {
          kp = await ml_dsa87.keygen(seed);
        } finally {
          seed.fill(0);
        }
        postSuccess(id, {
          publicKey: kp.publicKey,
          secretKey: kp.secretKey
        });
        break;
      }
      case 'sig.sign': {
        const signature = await ml_dsa87.sign(data.message, data.secretKey);
        postSuccess(id, { signature });
        break;
      }
      case 'sig.verify': {
        const verified = await ml_dsa87.verify(data.signature, data.message, data.publicKey);
        postSuccess(id, { verified });
        break;
      }
      case 'pp.generateTokenBatch': {
        const resBatch = PrivacyPassOps.generateTokenBatch(data.count, data.purpose);
        postSuccess(id, resBatch);
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
          postSuccess(id, { completedTokens });
        } catch (err: any) {
          throw new Error(`PrivacyPass unblind failed: ${err.message}`);
        }
        break;
      }
      case 'opaque.startRegistration': {
        const resReg = OPAQUEOps.startRegistration(data.passwordBytes);
        postSuccess(id, resReg);
        break;
      }
      case 'opaque.finishRegistration': {
        const resFinReg = OPAQUEOps.finishRegistration(data.passwordBytes, data.blindingFactor, data.serverResponse);
        postSuccess(id, resFinReg);
        break;
      }
      case 'opaque.startLogin': {
        const resLogin = OPAQUEOps.startLogin(data.passwordBytes);
        postSuccess(id, resLogin);
        break;
      }
      case 'opaque.finishLogin': {
        try {
          const resFinLogin = OPAQUEOps.finishLogin(
            data.passwordBytes,
            data.blindingFactor,
            data.serverResponse,
            data.authChannelBinding
          );
          postSuccess(id, resFinLogin);
        } catch (err: any) {
          self.postMessage({ id, success: true, result: { success: false, error: err.message } });
        }
        break;
      }
      case 'argon2.hash': {
        try {
          const resultHash = await argon2.hash(data.params);
          postSuccess(id, { hash: resultHash.hash, encoded: resultHash.encoded });
        } catch (err: any) {
          self.postMessage({ id, success: false, error: `Argon2 hash failed: ${err.message}` });
        }
        break;
      }
      case 'argon2.verify': {
        try {
          const resultVerify = await argon2.verify(data.params);
          postSuccess(id, { verified: resultVerify.verified === true });
        } catch (err: any) {
          self.postMessage({ id, success: false, error: `Argon2 verify failed: ${err.message}` });
        }
        break;
      }
      case 'aead.encrypt': {
        if (!data.plaintext || !(data.plaintext instanceof Uint8Array)) throw new Error('plaintext required');
        if (!data.key || !(data.key instanceof Uint8Array) || data.key.length !== 32) throw new Error('32-byte key required');

        const encNonce: Uint8Array = (data.explicitNonce && data.explicitNonce instanceof Uint8Array)
          ? data.explicitNonce
          : crypto.getRandomValues(new Uint8Array(POST_QUANTUM_AEAD_NONCE_BYTES));
        if (encNonce.length !== POST_QUANTUM_AEAD_NONCE_BYTES) throw new Error(`Nonce must be ${POST_QUANTUM_AEAD_NONCE_BYTES} bytes`);

        const encAad = (data.additionalData && data.additionalData instanceof Uint8Array)
          ? data.additionalData : new Uint8Array(0);
        let encExpanded: Uint8Array | null = null;
        let encK1: Uint8Array | null = null;
        let encK2: Uint8Array | null = null;
        let encMacKeyInput: Uint8Array | null = null;
        let encMacKey: Uint8Array | null = null;
        let encIv: Uint8Array | null = null;
        let encLayer1: Uint8Array | null = null;
        let encXnonce: Uint8Array | null = null;
        let encLayer2: Uint8Array | null = null;
        let encMacInput: Uint8Array | null = null;
        let encMac: Uint8Array | null = null;
        try {
          encExpanded = sha3_512(data.key);
          encK1 = encExpanded.slice(0, 32);
          encK2 = encExpanded.slice(32, 64);
          const macLabel = new TextEncoder().encode(PROTOCOL_KEYS.UNIFIED_CRYPTO_MAC);
          encMacKeyInput = new Uint8Array(macLabel.length + data.key.length);
          encMacKeyInput.set(macLabel, 0);
          encMacKeyInput.set(data.key, macLabel.length);
          encMacKey = blake3(encMacKeyInput, { dkLen: 32 });

          encIv = encNonce.slice(0, AES_GCM_NONCE_BYTES);
          const encCipher = gcm(encK1, encIv, encAad);
          encLayer1 = encCipher.encrypt(data.plaintext);

          encXnonce = encNonce.slice(AES_GCM_NONCE_BYTES, POST_QUANTUM_AEAD_NONCE_BYTES);
          const encXchacha = xchacha20poly1305(encK2, encXnonce, encAad);
          encLayer2 = encXchacha.encrypt(encLayer1);

          encMacInput = new Uint8Array(encLayer2.length + encAad.length + encNonce.length);
          encMacInput.set(encLayer2, 0);
          encMacInput.set(encAad, encLayer2.length);
          encMacInput.set(encNonce, encLayer2.length + encAad.length);
          encMac = blake3(encMacInput, { key: encMacKey });

          postSuccess(id, { ciphertext: encLayer2, nonce: encNonce, tag: encMac });
        } finally {
          encExpanded?.fill(0);
          encK1?.fill(0);
          encK2?.fill(0);
          encMacKeyInput?.fill(0);
          encMacKey?.fill(0);
          encIv?.fill(0);
          encLayer1?.fill(0);
          encXnonce?.fill(0);
          encLayer2?.fill(0);
          encMacInput?.fill(0);
          encMac?.fill(0);
          if (!(data.explicitNonce instanceof Uint8Array)) encNonce.fill(0);
          if (!(data.additionalData instanceof Uint8Array)) encAad.fill(0);
        }
        break;
      }
      case 'aead.decrypt': {
        if (!data.ciphertext || !(data.ciphertext instanceof Uint8Array)) throw new Error('ciphertext required');
        if (!data.key || !(data.key instanceof Uint8Array) || data.key.length !== 32) throw new Error('32-byte key required');
        if (!data.nonce || !(data.nonce instanceof Uint8Array) || data.nonce.length !== POST_QUANTUM_AEAD_NONCE_BYTES) throw new Error(`Nonce must be ${POST_QUANTUM_AEAD_NONCE_BYTES} bytes`);
        if (!data.tag || !(data.tag instanceof Uint8Array) || data.tag.length !== HASH_OUTPUT_BYTES) throw new Error(`Tag must be ${HASH_OUTPUT_BYTES} bytes`);

        const decAad = (data.additionalData && data.additionalData instanceof Uint8Array)
          ? data.additionalData : new Uint8Array(0);
        let decExpanded: Uint8Array | null = null;
        let decK1: Uint8Array | null = null;
        let decK2: Uint8Array | null = null;
        let decMacKeyInput: Uint8Array | null = null;
        let decMacKey: Uint8Array | null = null;
        let decMacInput: Uint8Array | null = null;
        let expectedMac: Uint8Array | null = null;
        let decXnonce: Uint8Array | null = null;
        let decLayer1: Uint8Array | null = null;
        let decIv: Uint8Array | null = null;
        let decPlaintext: Uint8Array | null = null;
        try {
          decExpanded = sha3_512(data.key);
          decK1 = decExpanded.slice(0, 32);
          decK2 = decExpanded.slice(32, 64);
          const macLabel = new TextEncoder().encode(PROTOCOL_KEYS.UNIFIED_CRYPTO_MAC);
          decMacKeyInput = new Uint8Array(macLabel.length + data.key.length);
          decMacKeyInput.set(macLabel, 0);
          decMacKeyInput.set(data.key, macLabel.length);
          decMacKey = blake3(decMacKeyInput, { dkLen: 32 });

          // Verify BLAKE3 MAC first
          decMacInput = new Uint8Array(data.ciphertext.length + decAad.length + data.nonce.length);
          decMacInput.set(data.ciphertext, 0);
          decMacInput.set(decAad, data.ciphertext.length);
          decMacInput.set(data.nonce, data.ciphertext.length + decAad.length);
          expectedMac = blake3(decMacInput, { key: decMacKey });

          if (data.tag.length !== expectedMac.length) throw new Error('BLAKE3 MAC verification failed');
          let diff = 0;
          for (let i = 0; i < data.tag.length; i++) {
            diff |= data.tag[i] ^ expectedMac[i];
          }
          if (diff !== 0) throw new Error('BLAKE3 MAC verification failed');

          // XChaCha20-Poly1305 decrypt
          decXnonce = data.nonce.slice(AES_GCM_NONCE_BYTES, POST_QUANTUM_AEAD_NONCE_BYTES);
          const decXchacha = xchacha20poly1305(decK2, decXnonce, decAad);
          decLayer1 = decXchacha.decrypt(data.ciphertext);

          // AES-256-GCM decrypt
          decIv = data.nonce.slice(0, AES_GCM_NONCE_BYTES);
          const decDecipher = gcm(decK1, decIv, decAad);
          decPlaintext = decDecipher.decrypt(decLayer1);

          postSuccess(id, { plaintext: decPlaintext });
        } finally {
          decExpanded?.fill(0);
          decK1?.fill(0);
          decK2?.fill(0);
          decMacKeyInput?.fill(0);
          decMacKey?.fill(0);
          decMacInput?.fill(0);
          expectedMac?.fill(0);
          decXnonce?.fill(0);
          decLayer1?.fill(0);
          decIv?.fill(0);
          decPlaintext?.fill(0);
          if (!(data.additionalData instanceof Uint8Array)) decAad.fill(0);
        }
        break;
      }
      default: {
        throw new Error(`Unsupported worker operation: ${type}`);
      }
    }
  } catch (error: any) {
    const errorMessage = error instanceof Error ? error.message.slice(0, 512) : 'Worker operation failed';
    self.postMessage({
      id: responseId,
      success: false,
      error: errorMessage
    });
  } finally {
    wipeBinaryValues(event.data);
  }
});

export { };
