import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { sha3_256, sha3_512, shake256 } from "@noble/hashes/sha3.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { gcm } from "@noble/ciphers/aes.js";
import { x25519 } from "@noble/curves/ed25519.js";

// Validate input is Uint8Array
function ensureUint8Array(value, name, expectedLength) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
  if (!(value.buffer instanceof ArrayBuffer)) {
    throw new TypeError(`${name} buffer must be an ArrayBuffer`);
  }
  const tag = Object.prototype.toString.call(value.buffer);
  if (tag === "[object SharedArrayBuffer]") {
    throw new TypeError(`${name} must not use SharedArrayBuffer backing`);
  }
  if (typeof expectedLength === "number" && value.length !== expectedLength) {
    throw new Error(`${name} must be ${expectedLength} bytes`);
  }
  return value;
}

// Key encryption and decryption class
var PostQuantumKEM = class {
  static kyber = ml_kem1024;

  static SIZES = {
    publicKey: 1568,
    secretKey: 3168,
    ciphertext: 1568,
    sharedSecret: 32,
  };

  // Generate new encryption key pair
  static generateKeyPair() {
    const kp = this.kyber.keygen();
    if (!kp || typeof kp !== "object") {
      throw new Error("KEM key generation failed");
    }

    const publicKey = ensureUint8Array(
      kp.publicKey,
      "PostQuantumKEM.generateKeyPair.publicKey",
      this.SIZES.publicKey,
    );
    const secretKey = ensureUint8Array(
      kp.secretKey,
      "PostQuantumKEM.generateKeyPair.secretKey",
      this.SIZES.secretKey,
    );

    return { publicKey, secretKey };
  }

  static generateKeyPairFromSeed(_seed) {
    throw new Error(
      "Deterministic ML-KEM key generation is not supported by the underlying library",
    );
  }

  static encapsulate(publicKey) {
    const kemPublicKey = ensureUint8Array(
      publicKey,
      "PostQuantumKEM.encapsulate.publicKey",
      this.SIZES.publicKey,
    );

    const result = this.kyber.encapsulate(kemPublicKey);
    if (!result || typeof result !== "object") {
      throw new Error("KEM encapsulation failed");
    }

    const ciphertext = ensureUint8Array(
      result.cipherText,
      "PostQuantumKEM.encapsulate.ciphertext",
      this.SIZES.ciphertext,
    );
    const sharedSecret = ensureUint8Array(
      result.sharedSecret,
      "PostQuantumKEM.encapsulate.sharedSecret",
      this.SIZES.sharedSecret,
    );

    return { ciphertext, sharedSecret };
  }

  static decapsulate(ciphertext, secretKey) {
    const kemCiphertext = ensureUint8Array(
      ciphertext,
      "PostQuantumKEM.decapsulate.ciphertext",
      this.SIZES.ciphertext,
    );
    const kemSecretKey = ensureUint8Array(
      secretKey,
      "PostQuantumKEM.decapsulate.secretKey",
      this.SIZES.secretKey,
    );

    const sharedSecret = this.kyber.decapsulate(kemCiphertext, kemSecretKey);
    return ensureUint8Array(
      sharedSecret,
      "PostQuantumKEM.decapsulate.sharedSecret",
      this.SIZES.sharedSecret,
    );
  }

  static get sizes() {
    return this.SIZES;
  }
};

var PostQuantumSignature = class {
  static dilithium = ml_dsa87;

  static generateKeyPair() {
    const keyPair = this.dilithium.keygen();
    if (!keyPair || typeof keyPair !== "object") {
      throw new Error("Dilithium key generation failed");
    }

    const publicKey = ensureUint8Array(
      keyPair.publicKey,
      "PostQuantumSignature.generateKeyPair.publicKey",
      this.sizes.publicKey,
    );
    const secretKey = ensureUint8Array(
      keyPair.secretKey,
      "PostQuantumSignature.generateKeyPair.secretKey",
      this.sizes.secretKey,
    );

    return { publicKey, secretKey };
  }

  static sign(message, secretKey) {
    const msg = ensureUint8Array(message, "PostQuantumSignature.sign.message");
    const sk = ensureUint8Array(
      secretKey,
      "PostQuantumSignature.sign.secretKey",
      this.sizes.secretKey,
    );

    const signature = this.dilithium.sign(sk, msg);
    return ensureUint8Array(
      signature,
      "PostQuantumSignature.sign.signature",
      this.sizes.signature,
    );
  }

  static verify(signature, message, publicKey) {
    const sig = ensureUint8Array(
      signature,
      "PostQuantumSignature.verify.signature",
      this.sizes.signature,
    );
    const msg = ensureUint8Array(
      message,
      "PostQuantumSignature.verify.message",
    );
    const pk = ensureUint8Array(
      publicKey,
      "PostQuantumSignature.verify.publicKey",
      this.sizes.publicKey,
    );

    return this.dilithium.verify(pk, msg, sig) === true;
  }

  static get sizes() {
    return { publicKey: 2592, secretKey: 4896, signature: 4627 };
  }
};

var HybridKeyExchange = class {
  static generateKeyPair() {
    const postQuantum = PostQuantumKEM.generateKeyPair();
    const classicalSecretKey = ensureUint8Array(
      x25519.utils.randomPrivateKey(),
      "HybridKeyExchange.generateKeyPair.classical.secretKey",
      32,
    );

    const classicalPublicKey = ensureUint8Array(
      x25519.getPublicKey(classicalSecretKey),
      "HybridKeyExchange.generateKeyPair.classical.publicKey",
      32,
    );

    return {
      postQuantum,
      classical: {
        secretKey: classicalSecretKey,
        publicKey: classicalPublicKey,
      },
    };
  }
  static keyExchange(myKeys, theirKeys, kemCiphertext) {
    const myPQSecretKey = ensureUint8Array(
      myKeys?.postQuantum?.secretKey,
      "HybridKeyExchange.keyExchange.myKeys.postQuantum.secretKey",
      PostQuantumKEM.sizes.secretKey,
    );

    const myClassicalSecretKey = ensureUint8Array(
      myKeys?.classical?.secretKey,
      "HybridKeyExchange.keyExchange.myKeys.classical.secretKey",
      32,
    );

    const theirPQPublicKey = ensureUint8Array(
      theirKeys?.postQuantum?.publicKey,
      "HybridKeyExchange.keyExchange.theirKeys.postQuantum.publicKey",
      PostQuantumKEM.sizes.publicKey,
    );
    const theirClassicalPublicKey = ensureUint8Array(
      theirKeys?.classical?.publicKey,
      "HybridKeyExchange.keyExchange.theirKeys.classical.publicKey",
      32,
    );
    let pqSecret = null;
    let returnCiphertext = null;
    try {
      if (kemCiphertext) {
        const providedCipher = ensureUint8Array(
          kemCiphertext,
          "HybridKeyExchange.keyExchange.kemCiphertext",
          PostQuantumKEM.sizes.ciphertext,
        );
        pqSecret = PostQuantumKEM.decapsulate(providedCipher, myPQSecretKey);
      } else {
        const kemResult = PostQuantumKEM.encapsulate(theirPQPublicKey);
        pqSecret = kemResult.sharedSecret;
        returnCiphertext = kemResult.ciphertext;
      }
      const classicalSecret = ensureUint8Array(
        x25519.getSharedSecret(myClassicalSecretKey, theirClassicalPublicKey),
        "HybridKeyExchange.keyExchange.classicalSecret",
        32,
      );
      const combinedLength = pqSecret.length + classicalSecret.length;
      const combined = new Uint8Array(combinedLength);
      combined.set(pqSecret, 0);
      combined.set(classicalSecret, pqSecret.length);
      const sharedSecret = blake3(combined);
      PostQuantumUtils.clearMemory(classicalSecret);
      PostQuantumUtils.clearMemory(combined);
      return {
        sharedSecret: ensureUint8Array(
          sharedSecret,
          "HybridKeyExchange.keyExchange.sharedSecret",
        ),
        kemCiphertext: returnCiphertext,
      };
    } finally {
      if (pqSecret) {
        PostQuantumUtils.clearMemory(pqSecret);
      }
    }
  }
};

var PostQuantumHash = class {
  static blake3(data, options) {
    return blake3(data, options);
  }
  static sha3_256(data) {
    return sha3_256(data);
  }
  static sha3_512(data) {
    return sha3_512(data);
  }
  static shake256(data, dkLen) {
    return shake256(data, { dkLen });
  }
  static deriveKey(inputKey, salt, info, length = 32) {
    const infoBytes = new TextEncoder().encode(info || "");
    return hkdf(blake3, inputKey, salt, infoBytes, length);
  }
};

var PostQuantumAEAD = class _PostQuantumAEAD {
  static NONCE_SIZE = 24;
  static GCM_IV_SIZE = 12;
  static TAG_SIZE = 16;
  static extractNonceContext(nonce) {
    if (nonce.length !== _PostQuantumAEAD.NONCE_SIZE) {
      throw new Error(`Nonce must be ${_PostQuantumAEAD.NONCE_SIZE} bytes`);
    }
    return nonce.slice(_PostQuantumAEAD.GCM_IV_SIZE);
  }
  static encrypt(plaintext, key, additionalData, explicitNonce) {
    const data = ensureUint8Array(
      plaintext,
      "PostQuantumAEAD.encrypt.plaintext",
    );

    const encryptionKey = ensureUint8Array(
      key,
      "PostQuantumAEAD.encrypt.key",
      32,
    );

    const nonce = ensureUint8Array(
      explicitNonce ??
        PostQuantumRandom.randomBytes(_PostQuantumAEAD.NONCE_SIZE),
      "PostQuantumAEAD.encrypt.nonce",
      _PostQuantumAEAD.NONCE_SIZE,
    );

    const associatedData = additionalData
      ? ensureUint8Array(
          additionalData,
          "PostQuantumAEAD.encrypt.additionalData",
        )
      : undefined;
    const paddingLength = PostQuantumRandom.randomBytes(1)[0];
    const paddedLength = data.length + 1 + paddingLength;
    const padded = new Uint8Array(paddedLength);
    padded[0] = paddingLength;
    padded.set(data, 1);

    if (paddingLength > 0) {
      padded.set(
        PostQuantumRandom.randomBytes(paddingLength),
        paddedLength - paddingLength,
      );
    }
    const iv = nonce.slice(0, _PostQuantumAEAD.GCM_IV_SIZE);
    const cipher = gcm(encryptionKey, iv, associatedData);
    const encryptedWithTag = cipher.encrypt(padded);
    const ciphertext = ensureUint8Array(
      encryptedWithTag.slice(
        0,
        encryptedWithTag.length - _PostQuantumAEAD.TAG_SIZE,
      ),
      "PostQuantumAEAD.encrypt.ciphertext",
    );
    const tag = ensureUint8Array(
      encryptedWithTag.slice(-_PostQuantumAEAD.TAG_SIZE),
      "PostQuantumAEAD.encrypt.tag",
      _PostQuantumAEAD.TAG_SIZE,
    );
    PostQuantumUtils.clearMemory(padded);
    return { ciphertext, nonce, tag };
  }

  static decrypt(ciphertext, nonce, tag, key, additionalData) {
    const encryptionKey = ensureUint8Array(
      key,
      "PostQuantumAEAD.decrypt.key",
      32,
    );
    const nonceBytes = ensureUint8Array(
      nonce,
      "PostQuantumAEAD.decrypt.nonce",
      _PostQuantumAEAD.NONCE_SIZE,
    );
    const tagBytes = ensureUint8Array(
      tag,
      "PostQuantumAEAD.decrypt.tag",
      _PostQuantumAEAD.TAG_SIZE,
    );
    const cipherBytes = ensureUint8Array(
      ciphertext,
      "PostQuantumAEAD.decrypt.ciphertext",
    );
    const associatedData = additionalData
      ? ensureUint8Array(
          additionalData,
          "PostQuantumAEAD.decrypt.additionalData",
        )
      : undefined;
    const iv = nonceBytes.slice(0, _PostQuantumAEAD.GCM_IV_SIZE);
    const decipher = gcm(encryptionKey, iv, associatedData);
    const encryptedWithTag = new Uint8Array(
      cipherBytes.length + tagBytes.length,
    );
    encryptedWithTag.set(cipherBytes, 0);
    encryptedWithTag.set(tagBytes, cipherBytes.length);
    const decrypted = decipher.decrypt(encryptedWithTag);
    const paddingLength = decrypted[0];

    if (paddingLength >= decrypted.length) {
      throw new Error("Invalid padding length");
    }

    const messageLength = decrypted.length - 1 - paddingLength;
    if (messageLength < 0) {
      throw new Error("Invalid padding structure");
    }

    const message = decrypted.slice(1, 1 + messageLength);
    return ensureUint8Array(message, "PostQuantumAEAD.decrypt.plaintext");
  }
};

var PostQuantumRandom = class _PostQuantumRandom {
  static ensureSecureRandom() {
    if (
      typeof globalThis === "undefined" ||
      !globalThis.crypto ||
      typeof globalThis.crypto.getRandomValues !== "function"
    ) {
      throw new Error(
        "Secure random number generator not available. Requires a secure context (HTTPS).",
      );
    }
  }

  static randomBytes(length) {
    if (!Number.isInteger(length) || length <= 0) {
      throw new Error("Length must be a positive integer");
    }
    if (length > 1048576) {
      throw new Error("Requested random byte length exceeds 1MB limit");
    }
    _PostQuantumRandom.ensureSecureRandom();
    const bytes = new Uint8Array(length);
    globalThis.crypto.getRandomValues(bytes);

    return bytes;
  }

  static randomUUID() {
    _PostQuantumRandom.ensureSecureRandom();
    if (typeof globalThis.crypto?.randomUUID === "function") {
      return globalThis.crypto.randomUUID();
    }
    const uuidBytes = shake256(_PostQuantumRandom.randomBytes(32), {
      dkLen: 16,
    });
    uuidBytes[6] = (uuidBytes[6] & 15) | 64;
    uuidBytes[8] = (uuidBytes[8] & 63) | 128;
    const hex = Array.from(uuidBytes, (b) =>
      b.toString(16).padStart(2, "0"),
    ).join("");

    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
  }
};

function timingSafeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
    return false;
  }
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

var PostQuantumUtils = class _PostQuantumUtils {
  static MAX_DATA_SIZE = 10 * 1024 * 1024;
  static timingSafeEqual = timingSafeEqual;
  static clearMemory(data) {
    if (!data) {
      return;
    }
    if (!(data instanceof Uint8Array)) {
      throw new TypeError("PostQuantumUtils.clearMemory expects Uint8Array");
    }
    for (let i = 0; i < 3; i++) {
      data.fill(i & 1);
    }
    const buffer = data.buffer;
    if (buffer && typeof buffer.transfer === "function") {
      try {
        buffer.transfer(0);
      } catch {}
    }
  }

  static stringToBytes(str) {
    return new TextEncoder().encode(str);
  }

  static bytesToString(bytes) {
    return new TextDecoder().decode(bytes);
  }

  static bytesToHex(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new Error("Bytes input required");
    }
    if (bytes.length > _PostQuantumUtils.MAX_DATA_SIZE) {
      throw new Error(`Data too large: ${bytes.length} bytes exceeds limit`);
    }
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
      "",
    );
  }

  static hexToBytes(hex) {
    if (typeof hex !== "string") {
      throw new Error("Hex input must be a string");
    }
    const clean = hex.replace(/\s+/g, "");
    if (!/^[0-9a-fA-F]*$/.test(clean)) {
      throw new Error("Invalid hex characters");
    }
    if (clean.length % 2 !== 0) {
      throw new Error("Hex string must have even length");
    }
    if (clean.length > _PostQuantumUtils.MAX_DATA_SIZE * 2) {
      throw new Error(
        `Hex string too long: ${clean.length} chars exceeds limit`,
      );
    }
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
      const byteStr = clean.slice(i, i + 2);
      const val = parseInt(byteStr, 16);
      if (Number.isNaN(val)) {
        throw new Error(`Invalid hex byte: ${byteStr}`);
      }
      bytes[i / 2] = val;
    }
    return bytes;
  }
};

var PostQuantumSession = class _PostQuantumSession {
  static DEFAULT_TIMEOUT = 30 * 60 * 1e3;
  static sessions = /* @__PURE__ */ new Map();
  static createSession(
    sessionId,
    keys,
    timeoutMs = _PostQuantumSession.DEFAULT_TIMEOUT,
  ) {
    if (
      !sessionId ||
      typeof sessionId !== "string" ||
      sessionId.length !== 32 ||
      !/^[0-9a-f]{32}$/i.test(sessionId)
    ) {
      throw new Error("Session ID must be a 32-character hexadecimal string");
    }
    const now = Date.now();
    _PostQuantumSession.sessions.set(sessionId, {
      keys,
      created: now,
      lastUsed: now,
    });
    _PostQuantumSession.cleanup(timeoutMs);
  }

  static getSession(
    sessionId,
    timeoutMs = _PostQuantumSession.DEFAULT_TIMEOUT,
  ) {
    const record = _PostQuantumSession.sessions.get(sessionId);
    if (!record) {
      return null;
    }
    const now = Date.now();
    if (now - record.created > timeoutMs) {
      _PostQuantumSession.destroySession(sessionId);
      return null;
    }
    record.lastUsed = now;
    return record.keys;
  }

  static destroySession(sessionId) {
    const record = _PostQuantumSession.sessions.get(sessionId);
    if (record) {
      try {
        const keys = record.keys;
        if (keys && typeof keys === "object") {
          const candidates = [
            keys.secretKey,
            keys.privateKey,
            keys.sharedSecret,
          ];
          for (const candidate of candidates) {
            if (candidate instanceof Uint8Array) {
              PostQuantumUtils.clearMemory(candidate);
            }
          }
        }
      } finally {
        _PostQuantumSession.sessions.delete(sessionId);
      }
    }
  }

  static cleanup(timeoutMs) {
    const now = Date.now();
    for (const [sessionId, record] of _PostQuantumSession.sessions.entries()) {
      if (now - record.lastUsed > timeoutMs) {
        _PostQuantumSession.destroySession(sessionId);
      }
    }
  }
};

var PostQuantumWorker = class _PostQuantumWorker {
  static worker = null;
  static pending = /* @__PURE__ */ new Map();
  static trackedKeys = /* @__PURE__ */ new Map();
  static ensureWorker() {
    if (_PostQuantumWorker.worker || typeof Worker === "undefined") {
      return;
    }
    let workerUrl;
    if (
      typeof import.meta !== "undefined" &&
      typeof import.meta.url === "string"
    ) {
      workerUrl = new URL("./post-quantum-worker.ts", import.meta.url);
    } else {
      const base =
        typeof document !== "undefined"
          ? (document.currentScript?.src ?? window.location.href)
          : self.location.href;
      workerUrl = new URL("./post-quantum-worker.ts", base);
    }
    const worker = new Worker(workerUrl, { type: "module" });
    worker.addEventListener("message", (event) => {
      const { id } = event.data;
      const pending = _PostQuantumWorker.pending.get(id);
      if (!pending) {
        return;
      }
      _PostQuantumWorker.pending.delete(id);
      if (!event.data.success) {
        pending.reject(new Error(event.data.error));
        return;
      }
      if ("destroyed" in event.data.result) {
        pending.resolve(event.data.result);
        return;
      }
      pending.resolve(event.data.result);
      if (event.data.result?.keyId) {
        _PostQuantumWorker.trackedKeys.set(
          event.data.result.keyId,
          event.data.result.keyId,
        );
      }
    });
    worker.addEventListener("error", (error) => {
      for (const [id, pending] of _PostQuantumWorker.pending.entries()) {
        pending.reject(error);
        _PostQuantumWorker.pending.delete(id);
      }
      _PostQuantumWorker.worker = null;
    });
    _PostQuantumWorker.worker = worker;
  }

  static supportsWorkers() {
    return typeof Worker !== "undefined";
  }

  static async generateKemKeyPair() {
    if (!_PostQuantumWorker.supportsWorkers()) {
      throw new Error(
        "Web Workers required for secure key generation. Enable Worker support.",
      );
    }
    _PostQuantumWorker.ensureWorker();
    if (!_PostQuantumWorker.worker) {
      throw new Error("Failed to initialize secure post-quantum worker");
    }
    const id = PostQuantumRandom.randomUUID();
    const request = { id, type: "kem.generateKeyPair" };
    return await new Promise((resolve, reject) => {
      _PostQuantumWorker.pending.set(id, { resolve, reject });
      try {
        _PostQuantumWorker.worker.postMessage(request);
      } catch (error) {
        _PostQuantumWorker.pending.delete(id);
        reject(error);
      }
    });
  }

  static async destroyKey(keyId) {
    if (
      !_PostQuantumWorker.worker ||
      !keyId ||
      !_PostQuantumWorker.trackedKeys.has(keyId)
    ) {
      return;
    }
    const id = PostQuantumRandom.randomUUID();
    const request = { id, type: "kem.destroyKey", keyId };
    return await new Promise((resolve, reject) => {
      _PostQuantumWorker.pending.set(id, {
        resolve: (result) => {
          _PostQuantumWorker.trackedKeys.delete(keyId);
          resolve(result);
        },
        reject: (error) => {
          _PostQuantumWorker.trackedKeys.delete(keyId);
          reject(error);
        },
      });
      try {
        _PostQuantumWorker.worker.postMessage(request);
      } catch (error) {
        _PostQuantumWorker.pending.delete(id);
        _PostQuantumWorker.trackedKeys.delete(keyId);
        reject(error);
      }
    });
  }
};

var ClientServerProtocol = class _ClientServerProtocol {
  static MAX_MESSAGE_AGE_MS = 5 * 60 * 1e3;
  static CLIENT_SALT = blake3(
    new TextEncoder().encode("client-server-protocol-v1-salt-client"),
  );
  static SERVER_SALT = blake3(
    new TextEncoder().encode("client-server-protocol-v1-salt-server"),
  );
  static seenNonces = /* @__PURE__ */ new Map();
  static sessionSendSecrets = /* @__PURE__ */ new Map();
  static pendingHandshakeSecrets = /* @__PURE__ */ new Map();
  static purgeExpiredNonces(now = Date.now()) {
    for (const [key, timestamp] of _ClientServerProtocol.seenNonces.entries()) {
      if (now - timestamp > _ClientServerProtocol.MAX_MESSAGE_AGE_MS) {
        _ClientServerProtocol.seenNonces.delete(key);
      }
    }
  }

  static purgeExpiredSendSecrets(now = Date.now()) {
    for (const [
      sessionId,
      entry,
    ] of _ClientServerProtocol.sessionSendSecrets.entries()) {
      if (!entry || entry.expiresAt <= now) {
        if (entry?.secret instanceof Uint8Array) {
          PostQuantumUtils.clearMemory(entry.secret);
        }
        _ClientServerProtocol.sessionSendSecrets.delete(sessionId);
      }
    }
  }

  static cleanupPendingHandshakes(now = Date.now()) {
    for (const [
      sessionId,
      entry,
    ] of _ClientServerProtocol.pendingHandshakeSecrets.entries()) {
      if (!entry || entry.expiresAt <= now) {
        if (entry?.secret instanceof Uint8Array) {
          PostQuantumUtils.clearMemory(entry.secret);
        }
        _ClientServerProtocol.pendingHandshakeSecrets.delete(sessionId);
      }
    }
  }

  static registerSendSecret(sessionId, secret, now = Date.now()) {
    if (!(secret instanceof Uint8Array) || secret.length === 0) {
      return;
    }
    _ClientServerProtocol.purgeExpiredSendSecrets(now);
    _ClientServerProtocol.sessionSendSecrets.set(sessionId, {
      secret: secret.slice(),
      expiresAt: now + _ClientServerProtocol.MAX_MESSAGE_AGE_MS,
    });
  }

  static consumeSendSecret(sessionId, now = Date.now()) {
    _ClientServerProtocol.purgeExpiredSendSecrets(now);
    if (typeof sessionId !== "string" || sessionId.length !== 32) {
      return null;
    }
    const entry = _ClientServerProtocol.sessionSendSecrets.get(sessionId);
    if (!entry) {
      return null;
    }
    _ClientServerProtocol.sessionSendSecrets.delete(sessionId);
    return { sessionId, secret: entry.secret };
  }

  static registerPendingHandshake(sessionId, secret, now = Date.now()) {
    if (!(secret instanceof Uint8Array) || secret.length === 0) {
      return;
    }
    _ClientServerProtocol.cleanupPendingHandshakes(now);
    _ClientServerProtocol.pendingHandshakeSecrets.set(sessionId, {
      secret: secret.slice(),
      expiresAt: now + _ClientServerProtocol.MAX_MESSAGE_AGE_MS,
    });
  }

  static async encryptForServer(message, serverPublicKey, additionalData) {
    const plaintext = ensureUint8Array(
      message,
      "ClientServerProtocol.encryptForServer.message",
    );
    let aad;
    let options = null;
    if (additionalData instanceof Uint8Array) {
      aad = ensureUint8Array(
        additionalData,
        "ClientServerProtocol.encryptForServer.additionalData",
      );
    } else if (additionalData && typeof additionalData === "object") {
      if (additionalData.aad) {
        aad = ensureUint8Array(
          additionalData.aad,
          "ClientServerProtocol.encryptForServer.additionalData",
        );
      }
      options = additionalData;
    }
    const sessionIdHint = typeof options?.sessionIdHint === "string" ? options.sessionIdHint : null;
    const serverKey = ensureUint8Array(
      serverPublicKey,
      "ClientServerProtocol.encryptForServer.serverPublicKey",
      PostQuantumKEM.sizes.publicKey,
    );
    const now = Date.now();
    let sessionId;
    let forwardSecret = null;
    let handshakeMode = false;
    if (typeof sessionIdHint === "string" && sessionIdHint.length === 32) {
      sessionId = sessionIdHint.toLowerCase();
      const consumedSecret = _ClientServerProtocol.consumeSendSecret(
        sessionId,
        now,
      );
      if (!consumedSecret) {
        throw new Error("Unknown session identifier for secure channel");
      }
      forwardSecret = ensureUint8Array(
        consumedSecret.secret,
        "ClientServerProtocol.encryptForServer.forwardSecret",
        32,
      );
    } else {
      sessionId = PostQuantumRandom.randomUUID()
        .replace(/-/g, "")
        .toLowerCase();
      handshakeMode = true;
      if (plaintext.length !== 0) {
        throw new Error(
          "Forward-secure channel not established; handshake payload must be empty",
        );
      }
    }
    const { ciphertext: serverCiphertext, sharedSecret: staticShared } =
      PostQuantumKEM.encapsulate(serverKey);
    const staticBinding = PostQuantumHash.blake3(staticShared, { dkLen: 16 });
    const ephemeralKeys = await PostQuantumWorker.generateKemKeyPair();
    const clientEphemeralPublicKey = ensureUint8Array(
      ephemeralKeys.publicKey,
      "ClientServerProtocol.encryptForServer.clientKemPublicKey",
      PostQuantumKEM.sizes.publicKey,
    );
    const clientEphemeralSecretKey = ensureUint8Array(
      ephemeralKeys.secretKey,
      "ClientServerProtocol.encryptForServer.clientKemSecretKey",
      PostQuantumKEM.sizes.secretKey,
    );
    let encryptionKey;
    if (handshakeMode) {
      const infoLabel = `client-handshake:${sessionId}`;
      encryptionKey = PostQuantumHash.deriveKey(
        clientEphemeralSecretKey,
        _ClientServerProtocol.CLIENT_SALT,
        infoLabel,
        32,
      );
    } else {
      const infoLabel = `client-to-server-forward-secret:${sessionId}:${PostQuantumUtils.bytesToHex(staticBinding)}`;
      encryptionKey = PostQuantumHash.deriveKey(
        forwardSecret,
        _ClientServerProtocol.CLIENT_SALT,
        infoLabel,
        32,
      );
    }
    try {
      const { ciphertext, nonce, tag } = PostQuantumAEAD.encrypt(
        plaintext,
        encryptionKey,
        aad,
      );
      if (handshakeMode) {
        _ClientServerProtocol.registerPendingHandshake(
          sessionId,
          clientEphemeralSecretKey,
          now,
        );
      }
      return {
        sessionId,
        kemCiphertext: serverCiphertext,
        clientKemPublicKey: clientEphemeralPublicKey,
        aeadCiphertext: ciphertext,
        aeadNonce: nonce,
        aeadTag: tag,
        timestamp: Date.now(),
      };
    } finally {
      _ClientServerProtocol.purgeExpiredNonces(now);
      PostQuantumUtils.clearMemory(staticShared);
      PostQuantumUtils.clearMemory(staticBinding);
      PostQuantumUtils.clearMemory(encryptionKey);
      PostQuantumUtils.clearMemory(clientEphemeralSecretKey);
      if (forwardSecret) {
        PostQuantumUtils.clearMemory(forwardSecret);
      }
    }
  }

  static async decryptFromServer(
    encryptedMessage,
    mySecretKey,
    additionalData,
  ) {
    if (!encryptedMessage || typeof encryptedMessage !== "object") {
      throw new Error("Encrypted message payload required");
    }
    const sessionId = encryptedMessage.sessionId;
    if (typeof sessionId !== "string" || sessionId.length !== 32) {
      throw new Error("Invalid session ID format");
    }
    const structureValid =
      encryptedMessage.kemCiphertext &&
      encryptedMessage.clientKemPublicKey &&
      encryptedMessage.aeadCiphertext &&
      encryptedMessage.aeadNonce &&
      encryptedMessage.aeadTag &&
      typeof encryptedMessage.timestamp === "number";
    if (!structureValid) {
      throw new Error("Invalid encrypted message structure");
    }
    const now = Date.now();
    const age = now - encryptedMessage.timestamp;
    const isTooOld = age > _ClientServerProtocol.MAX_MESSAGE_AGE_MS;
    const serverSecretKey = ensureUint8Array(
      mySecretKey,
      "ClientServerProtocol.decryptFromServer.secretKey",
      PostQuantumKEM.sizes.secretKey,
    );
    const serverCiphertext = ensureUint8Array(
      encryptedMessage.kemCiphertext,
      "ClientServerProtocol.decryptFromServer.kemCiphertext",
      PostQuantumKEM.sizes.ciphertext,
    );
    const ratchetPublicField =
      encryptedMessage.serverKemPublicKey ||
      encryptedMessage.clientKemPublicKey ||
      null;
    const ratchetPublicKey = ratchetPublicField
      ? ensureUint8Array(
          ratchetPublicField,
          "ClientServerProtocol.decryptFromServer.ratchetPublicKey",
          PostQuantumKEM.sizes.publicKey,
        )
      : null;
    const ratchetCipherField = encryptedMessage.serverKemCiphertext
      ? ensureUint8Array(
          encryptedMessage.serverKemCiphertext,
          "ClientServerProtocol.decryptFromServer.serverKemCiphertext",
          PostQuantumKEM.sizes.ciphertext,
        )
      : null;
    const nonceKey = `${sessionId}:${PostQuantumUtils.bytesToHex(ensureUint8Array(encryptedMessage.aeadNonce, "ClientServerProtocol.decryptFromServer.aeadNonce", PostQuantumAEAD.NONCE_SIZE))}`;
    if (_ClientServerProtocol.seenNonces.has(nonceKey)) {
      throw new Error("Decryption failed");
    }
    _ClientServerProtocol.seenNonces.set(nonceKey, now);
    if (_ClientServerProtocol.seenNonces.size > 1024) {
      _ClientServerProtocol.purgeExpiredNonces(now);
    }
    let plaintext = null;
    let sharedSecret = null;
    let ratchetSharedSecret = null;
    let combinedSecret = null;
    let decryptionKey = null;
    try {
      sharedSecret = PostQuantumKEM.decapsulate(
        serverCiphertext,
        serverSecretKey,
      );
      if (ratchetCipherField) {
        ratchetSharedSecret = PostQuantumKEM.decapsulate(
          ratchetCipherField,
          serverSecretKey,
        );
      }
      const secretParts = [sharedSecret];
      if (ratchetSharedSecret) {
        secretParts.push(ratchetSharedSecret);
      }
      if (ratchetPublicKey) {
        secretParts.push(ratchetPublicKey);
      }
      const totalLength = secretParts.reduce(
        (sum, part) => sum + part.length,
        0,
      );
      combinedSecret = new Uint8Array(totalLength);
      let offset = 0;
      for (const part of secretParts) {
        combinedSecret.set(part, offset);
        offset += part.length;
      }
      const infoLabel = `server-to-client-forward-secret:${sessionId}`;
      decryptionKey = PostQuantumHash.deriveKey(
        combinedSecret,
        _ClientServerProtocol.SERVER_SALT,
        infoLabel,
        32,
      );
      plaintext = PostQuantumAEAD.decrypt(
        ensureUint8Array(
          encryptedMessage.aeadCiphertext,
          "ClientServerProtocol.decryptFromServer.aeadCiphertext",
        ),
        ensureUint8Array(
          encryptedMessage.aeadNonce,
          "ClientServerProtocol.decryptFromServer.aeadNonce",
          PostQuantumAEAD.NONCE_SIZE,
        ),
        ensureUint8Array(
          encryptedMessage.aeadTag,
          "ClientServerProtocol.decryptFromServer.aeadTag",
          PostQuantumAEAD.TAG_SIZE,
        ),
        decryptionKey,
        additionalData
          ? ensureUint8Array(
              additionalData,
              "ClientServerProtocol.decryptFromServer.additionalData",
            )
          : undefined,
      );
      if (isTooOld) {
        PostQuantumUtils.clearMemory(plaintext);
        throw new Error("Decryption failed");
      }
      return plaintext;
    } catch (error) {
      if (plaintext) {
        PostQuantumUtils.clearMemory(plaintext);
      }
      throw new Error("Decryption failed");
    } finally {
      if (sharedSecret) {
        PostQuantumUtils.clearMemory(sharedSecret);
      }
      if (ratchetSharedSecret) {
        PostQuantumUtils.clearMemory(ratchetSharedSecret);
      }
      if (combinedSecret) {
        PostQuantumUtils.clearMemory(combinedSecret);
      }
      if (decryptionKey) {
        PostQuantumUtils.clearMemory(decryptionKey);
      }
      setTimeout(() => {
        _ClientServerProtocol.seenNonces.delete(nonceKey);
      }, _ClientServerProtocol.MAX_MESSAGE_AGE_MS);
    }
  }
};

export {
  PostQuantumAEAD as AEAD,
  ClientServerProtocol,
  PostQuantumHash as Hash,
  HybridKeyExchange as Hybrid,
  HybridKeyExchange,
  PostQuantumKEM as KEM,
  PostQuantumAEAD,
  PostQuantumHash,
  PostQuantumKEM,
  PostQuantumRandom,
  PostQuantumSession,
  PostQuantumSignature,
  PostQuantumUtils,
  PostQuantumWorker,
  PostQuantumRandom as Random,
  PostQuantumSignature as Signature,
  PostQuantumUtils as Utils,
};