import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const DEFAULT_MODULUS_BITS = 4096;
const DEFAULT_SALT_LENGTH = 32; // bytes for SHA-256
const DEFAULT_HASH = 'sha256';
const DEFAULT_HASH_LABEL = 'SHA-256';
const DEFAULT_ROTATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const DEFAULT_RETIRE_MS = 90 * 24 * 60 * 60 * 1000; // 90 days

const KEY_STORE_PATH = process.env.BLIND_SIGNATURE_KEY_PATH ||
  path.join(process.cwd(), 'server', 'config', 'blind-signature-keys.json');

const ensureDir = (filePath) => {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
  } catch { }
};

const nowMs = () => Date.now();

const base64UrlToBase64 = (b64url) => {
  const normalized = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4 ? '='.repeat(4 - (normalized.length % 4)) : '';
  return normalized + pad;
};

const computeKeyId = (publicKeyPem) => {
  return crypto.createHash('sha256').update(publicKeyPem).digest('base64url').slice(0, 22);
};

const bytesToBigInt = (buf) => BigInt('0x' + buf.toString('hex'));

const leftPad = (buf, length) => {
  if (buf.length === length) return buf;
  if (buf.length > length) return null;
  const padded = Buffer.alloc(length);
  buf.copy(padded, length - buf.length);
  return padded;
};

class BlindSignatureIssuer {
  static #keyStore = null;

  static #loadKeyStore() {
    if (this.#keyStore) return this.#keyStore;

    let parsed = null;
    try {
      const raw = fs.readFileSync(KEY_STORE_PATH, 'utf8');
      parsed = JSON.parse(raw);
    } catch { }

    if (!parsed || typeof parsed !== 'object') {
      parsed = { currentKid: null, keys: [] };
    }

    if (!Array.isArray(parsed.keys)) parsed.keys = [];

    this.#keyStore = parsed;
    return parsed;
  }

  static #saveKeyStore(store) {
    ensureDir(KEY_STORE_PATH);
    fs.writeFileSync(KEY_STORE_PATH, JSON.stringify(store, null, 2));
  }

  static #generateKey() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: DEFAULT_MODULUS_BITS,
      publicExponent: 0x10001,
    });

    const publicKeyPem = publicKey.export({ type: 'pkcs1', format: 'pem' });
    const privateKeyPem = privateKey.export({ type: 'pkcs1', format: 'pem' });

    const jwk = crypto.createPublicKey(publicKeyPem).export({ format: 'jwk' });
    const n = Buffer.from(base64UrlToBase64(jwk.n), 'base64').toString('base64');
    const e = Buffer.from(base64UrlToBase64(jwk.e), 'base64').toString('base64');

    const kid = computeKeyId(publicKeyPem);
    const createdAt = nowMs();

    return {
      kid,
      createdAt,
      notAfter: createdAt + DEFAULT_RETIRE_MS,
      publicKeyPem,
      privateKeyPem,
      n,
      e,
      modulusLength: DEFAULT_MODULUS_BITS,
      hash: DEFAULT_HASH_LABEL,
      saltLength: DEFAULT_SALT_LENGTH,
      scheme: 'RSABSSA-PSS'
    };
  }

  static #rotateIfNeeded(store) {
    const current = store.keys.find((k) => k.kid === store.currentKid) || null;
    const needsRotation = !current || (nowMs() - current.createdAt) > DEFAULT_ROTATION_MS;

    if (needsRotation) {
      const next = this.#generateKey();
      store.keys.push(next);
      store.currentKid = next.kid;
    }

    // Drop expired keys
    store.keys = store.keys.filter((k) => typeof k.notAfter === 'number' && nowMs() <= k.notAfter);

    // Ensure current key still exists
    if (!store.keys.find((k) => k.kid === store.currentKid)) {
      const fallback = this.#generateKey();
      store.keys.push(fallback);
      store.currentKid = fallback.kid;
    }

    this.#saveKeyStore(store);
    return store;
  }

  static #getActiveKey() {
    const store = this.#rotateIfNeeded(this.#loadKeyStore());
    return store.keys.find((k) => k.kid === store.currentKid) || null;
  }

  static #getKeyById(kid) {
    if (!kid) return null;
    const store = this.#loadKeyStore();
    return store.keys.find((k) => k.kid === kid) || null;
  }

  static async getPublicKey() {
    const key = this.#getActiveKey();
    if (!key) throw new Error('Blind signature key unavailable');

    return {
      kid: key.kid,
      n: key.n,
      e: key.e,
      modulusLength: key.modulusLength,
      hash: key.hash,
      saltLength: key.saltLength,
      scheme: key.scheme
    };
  }

  static async signBlindedMessage(blindedMsgBase64) {
    if (!blindedMsgBase64) throw new Error('Missing blinded message');

    const key = this.#getActiveKey();
    if (!key) throw new Error('Blind signature key unavailable');

    const modulusLengthBytes = Math.ceil(key.modulusLength / 8);
    let blinded = Buffer.from(blindedMsgBase64, 'base64');
    const padded = leftPad(blinded, modulusLengthBytes);
    if (!padded) throw new Error('Invalid blinded message length');

    const nBig = bytesToBigInt(Buffer.from(key.n, 'base64'));
    const mBig = bytesToBigInt(padded);
    if (mBig >= nBig) {
      throw new Error('Blinded message must be smaller than modulus');
    }

    const signature = crypto.privateEncrypt(
      { key: key.privateKeyPem, padding: crypto.constants.RSA_NO_PADDING },
      padded
    );

    return {
      signature: signature.toString('base64'),
      kid: key.kid,
    };
  }

  static async verifySignature(message, signatureBase64, kid) {
    const key = this.#getKeyById(kid) || this.#getActiveKey();
    if (!key) return false;
    if (!signatureBase64) return false;

    const modulusLengthBytes = Math.ceil(key.modulusLength / 8);
    const sig = Buffer.from(signatureBase64, 'base64');
    if (sig.length !== modulusLengthBytes) {
      return false;
    }

    return crypto.verify(
      DEFAULT_HASH,
      Buffer.from(String(message), 'utf8'),
      {
        key: key.publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: key.saltLength,
      },
      sig
    );
  }
}

export { BlindSignatureIssuer };
