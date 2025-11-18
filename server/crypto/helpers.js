import { blake3 } from '@noble/hashes/blake3.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

const textEncoder = new TextEncoder();

const toUint8Array = (value, label) => {
  if (value instanceof Uint8Array) return value;
  if (typeof value === 'string') {
    const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
    if (!base64Regex.test(value) || (value.length % 4 !== 0)) {
      throw new Error(`${label} must be base64 or Uint8Array`);
    }
    const decoded = Buffer.from(value, 'base64');
    const reencoded = decoded.toString('base64');
    if (reencoded.replace(/=+$/, '') !== value.replace(/=+$/, '')) {
      throw new Error(`${label} must be base64 or Uint8Array`);
    }
    return new Uint8Array(decoded.buffer, decoded.byteOffset, decoded.byteLength);
  }
  if (Buffer.isBuffer(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new Error(`${label} must be a Uint8Array or base64 string`);
};

const fromUint8Array = (value) => Buffer.from(value).toString('base64');

const canonicalizeExtras = (value) => {
  if (Array.isArray(value)) return value.map(canonicalizeExtras);
  if (value && typeof value === 'object') {
    const entries = Object.entries(value).sort(([a], [b]) => a.localeCompare(b));
    const out = {};
    for (const [key, val] of entries) out[key] = canonicalizeExtras(val);
    return out;
  }
  return value;
};

const canonicalizeRoutingHeader = (header) => JSON.stringify({
  to: header.to,
  from: header.from,
  type: header.type,
  timestamp: header.timestamp,
  size: header.size,
  ...(header.extras ? { extras: canonicalizeExtras(header.extras) } : {})
});

const computeRoutingDigest = (header) => blake3(textEncoder.encode(canonicalizeRoutingHeader(header)));

const buildRoutingHeader = (input) => {
  if (!input?.to || !input?.from || !input?.type) throw new Error('Routing header requires to, from, and type');
  if (!Number.isFinite(input.size) || input.size < 0) throw new Error('Routing header size must be non-negative');
  const timestamp = input.timestamp ?? Date.now();
  return {
    to: input.to,
    from: input.from,
    type: input.type,
    timestamp,
    size: Math.floor(input.size),
    ...(input.extras ? { extras: canonicalizeExtras(input.extras) } : {})
  };
};

const signRoutingHeader = async (header, dilithiumSecretKey) => {
  const message = textEncoder.encode(canonicalizeRoutingHeader(header));
  const secretKey = toUint8Array(dilithiumSecretKey, 'dilithiumSecretKey');
  const signature = await ml_dsa87.sign(message, secretKey);
  return fromUint8Array(signature);
};

const verifyRoutingHeader = async (header, signatureBase64, dilithiumPublicKey) => {
  const message = textEncoder.encode(canonicalizeRoutingHeader(header));
  const signature = toUint8Array(signatureBase64, 'signature');
  const publicKey = toUint8Array(dilithiumPublicKey, 'dilithiumPublicKey');
  if (process.env.COMPAT_DEBUG === 'true') {
    console.log('[HELPERS][DEBUG] verify pk len', publicKey.length, 'sig len', signature.length, 'msg len', message.length);
  }
  return ml_dsa87.verify(signature, message, publicKey);
};

const normalizePayload = (payload) => {
  if (payload instanceof Uint8Array) return { bytes: new Uint8Array(payload), type: 'binary' };
  if (payload instanceof ArrayBuffer) return { bytes: new Uint8Array(payload), type: 'binary' };
  if (typeof payload === 'string') return { bytes: textEncoder.encode(payload), type: 'text', text: payload };
  const jsonSafe = payload ?? {};
  const text = JSON.stringify(jsonSafe);
  return { bytes: textEncoder.encode(text), type: 'json', text, json: jsonSafe };
};

export {
  canonicalizeRoutingHeader,
  buildRoutingHeader,
  computeRoutingDigest,
  normalizePayload,
  signRoutingHeader,
  verifyRoutingHeader,
  toUint8Array as base64ToUint8Array,
  fromUint8Array as uint8ArrayToBase64
};
