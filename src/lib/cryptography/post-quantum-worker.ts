import * as argon2 from "argon2-wasm";
import { ml_kem1024 as kyber } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { PrivacyPassOps, OPAQUEOps } from './crypto-ops';
import { WORKER_MAX_KEYS } from '../constants';

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
        const resBatch = PrivacyPassOps.generateTokenBatch(data.count);
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
        } catch (err) {
          self.postMessage({ id, success: true, result: { success: false } });
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
          self.postMessage({ id, success: false, error: `finishOTLogin failed: ${err.message}` });
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