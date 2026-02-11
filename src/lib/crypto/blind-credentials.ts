/**
 * Client-side Blind Signature Utilities (RSABSSA-PSS)
 */

import { PostQuantumUtils } from '../utils/pq-utils';

export type BlindPublicKey = {
  kid: string;
  n: string; // base64 big-endian
  e: string; // base64 big-endian
  modulusLength: number; // bits
  hash: string; // e.g. 'SHA-256'
  saltLength: number; // bytes
  scheme: string; // 'RSABSSA-PSS'
};

const HASH_NAME = 'SHA-256';
const HASH_SIZE = 32;

function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = PostQuantumUtils.bytesToHex(bytes);
  if (!hex) return 0n;
  return BigInt('0x' + hex);
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  let hex = value.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const raw = PostQuantumUtils.hexToBytes(hex);
  if (raw.length > length) throw new Error('value too large');
  const out = new Uint8Array(length);
  out.set(raw, length - raw.length);
  return out;
}

function gcd(a: bigint, b: bigint): bigint {
  let x = a;
  let y = b;
  while (y !== 0n) {
    const t = x % y;
    x = y;
    y = t;
  }
  return x;
}

function modInverse(a: bigint, m: bigint): bigint {
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];

  while (r !== 0n) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }

  if (old_r !== 1n) throw new Error('No modular inverse');
  return (old_s % m + m) % m;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let res = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) res = (res * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return res;
}

function i2osp(num: number, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = num & 0xff;
    num >>>= 8;
  }
  return out;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest(HASH_NAME, data);
  return new Uint8Array(digest);
}

async function mgf1(seed: Uint8Array, maskLen: number): Promise<Uint8Array> {
  const hLen = HASH_SIZE;
  const count = Math.ceil(maskLen / hLen);
  const out = new Uint8Array(maskLen);
  let offset = 0;
  for (let i = 0; i < count; i++) {
    const c = i2osp(i, 4);
    const digest = await sha256(PostQuantumUtils.concatBytes(seed, c));
    const take = Math.min(hLen, maskLen - offset);
    out.set(digest.subarray(0, take), offset);
    offset += take;
  }
  return out;
}

async function emsaPssEncode(mHash: Uint8Array, emBits: number, saltLength: number): Promise<Uint8Array> {
  if (mHash.length !== HASH_SIZE) throw new Error('Invalid hash size');
  const emLen = Math.ceil(emBits / 8);
  if (emLen < HASH_SIZE + saltLength + 2) {
    throw new Error('Encoding error');
  }

  const salt = new Uint8Array(saltLength);
  crypto.getRandomValues(salt);

  const prefix = new Uint8Array(8);
  const mPrime = PostQuantumUtils.concatBytes(prefix, mHash, salt);
  const h = await sha256(mPrime);

  const psLen = emLen - saltLength - HASH_SIZE - 2;
  const ps = new Uint8Array(psLen);
  const db = PostQuantumUtils.concatBytes(ps, new Uint8Array([0x01]), salt);
  const dbMask = await mgf1(h, emLen - HASH_SIZE - 1);
  const maskedDb = new Uint8Array(db.length);
  for (let i = 0; i < db.length; i++) maskedDb[i] = db[i] ^ dbMask[i];

  const unusedBits = 8 * emLen - emBits;
  maskedDb[0] &= 0xff >> unusedBits;

  return PostQuantumUtils.concatBytes(maskedDb, h, new Uint8Array([0xbc]));
}

function assertBlindKey(key: BlindPublicKey): void {
  if (!key || typeof key !== 'object') throw new Error('Missing blind public key');
  if (key.scheme !== 'RSABSSA-PSS') throw new Error('Unsupported scheme');
  if (key.hash !== 'SHA-256') throw new Error('Unsupported hash');
  if (!key.n || !key.e) throw new Error('Missing key parameters');
  if (!Number.isFinite(key.modulusLength) || key.modulusLength < 2048) {
    throw new Error('Invalid modulus length');
  }
  if (!Number.isFinite(key.saltLength) || key.saltLength < 16) {
    throw new Error('Invalid salt length');
  }
}

/**
 * Blind a message for the server to sign
 */
export async function blindMessage(message: string, serverPublicKey: BlindPublicKey) {
  assertBlindKey(serverPublicKey);

  const n = PostQuantumUtils.base64ToUint8Array(serverPublicKey.n);
  const e = PostQuantumUtils.base64ToUint8Array(serverPublicKey.e);
  const nBig = bytesToBigInt(n);
  const eBig = bytesToBigInt(e);
  const modulusBits = serverPublicKey.modulusLength;
  const emBits = modulusBits - 1;
  const emLen = Math.ceil(emBits / 8);
  const modulusLenBytes = Math.ceil(modulusBits / 8);

  if (n.length !== modulusLenBytes) {
    throw new Error('Invalid modulus size');
  }

  const msgBytes = new TextEncoder().encode(message);
  const mHash = await sha256(msgBytes);
  const em = await emsaPssEncode(mHash, emBits, serverPublicKey.saltLength);

  const mBig = bytesToBigInt(em);
  if (mBig >= nBig) throw new Error('Encoded message too large');

  let r: bigint = 0n;
  while (r === 0n) {
    const randomBytes = new Uint8Array(modulusLenBytes);
    crypto.getRandomValues(randomBytes);
    r = bytesToBigInt(randomBytes);
    if (r <= 1n || r >= nBig) {
      r = 0n;
      continue;
    }
    if (gcd(r, nBig) !== 1n) {
      r = 0n;
      continue;
    }
  }

  const rExp = modPow(r, eBig, nBig);
  const mPrime = (mBig * rExp) % nBig;

  return {
    blindedMsg: PostQuantumUtils.uint8ArrayToBase64(bigIntToBytes(mPrime, modulusLenBytes)),
    blindingFactor: PostQuantumUtils.uint8ArrayToBase64(bigIntToBytes(r, modulusLenBytes)),
    n: serverPublicKey.n,
    kid: serverPublicKey.kid,
    modulusLength: serverPublicKey.modulusLength,
    hash: serverPublicKey.hash,
    saltLength: serverPublicKey.saltLength,
    scheme: serverPublicKey.scheme
  };
}

/**
 * Unblind a signed message
 */
export function unblindSignature(
  signedBlindedMsgBase64: string,
  blindingFactorBase64: string,
  nBase64: string,
  modulusLength: number
) {
  if (!signedBlindedMsgBase64 || !blindingFactorBase64 || !nBase64) {
    throw new Error('Missing unblind parameters');
  }

  const sPrime = PostQuantumUtils.base64ToUint8Array(signedBlindedMsgBase64);
  const rBytes = PostQuantumUtils.base64ToUint8Array(blindingFactorBase64);
  const nBytes = PostQuantumUtils.base64ToUint8Array(nBase64);

  const modulusLenBytes = Math.ceil(modulusLength / 8);
  if (sPrime.length !== modulusLenBytes) throw new Error('Invalid signature length');
  if (rBytes.length !== modulusLenBytes) throw new Error('Invalid blinding factor length');
  if (nBytes.length !== modulusLenBytes) throw new Error('Invalid modulus size');

  const sPrimeBig = bytesToBigInt(sPrime);
  const rBig = bytesToBigInt(rBytes);
  const nBig = bytesToBigInt(nBytes);

  if (gcd(rBig, nBig) !== 1n) throw new Error('Blinding factor not invertible');

  const rInv = modInverse(rBig, nBig);
  const sBig = (sPrimeBig * rInv) % nBig;
  const sBytes = bigIntToBytes(sBig, modulusLenBytes);

  return PostQuantumUtils.uint8ArrayToBase64(sBytes);
}
