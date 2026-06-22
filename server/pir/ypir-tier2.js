// YPIR tier 2 layer for discovery. lets a client obliviously fetch the discovery blob at its tier 1 slot without revealing the handle

import http from 'http';
import https from 'https';

const WORKER_URL = (process.env.YPIR_TIER2_WORKER_URL || '').replace(/\/+$/, '');
const BLOB_LEN = Math.max(256, parseInt(process.env.YPIR_TIER2_BLOB_LEN || '65536', 10));
const LEN_PREFIX = 4;

export function ypirTier2Enabled() {
  return WORKER_URL.length > 0;
}

export function ypirTier2BlobLen() {
  return BLOB_LEN;
}

function encodeSlot(blobStr) {
  const out = Buffer.alloc(BLOB_LEN);
  if (typeof blobStr !== 'string' || blobStr.length === 0) return out;
  const bytes = Buffer.from(blobStr, 'utf8');
  if (bytes.length + LEN_PREFIX > BLOB_LEN) return null;
  out.writeUInt32LE(bytes.length, 0);
  bytes.copy(out, LEN_PREFIX);
  return out;
}

/**
 * Upload the slot indexed blobs
 */
let ypirUploadInFlight = false;
let ypirLastUploadAt = 0;
const YPIR_MIN_UPLOAD_INTERVAL_MS = Math.max(0, parseInt(process.env.YPIR_MIN_UPLOAD_INTERVAL_MS || '60000', 10) || 60000);

export async function uploadYpirTier2Database(blobsBySlot, { epochId } = {}) {
  if (!ypirTier2Enabled() || !Array.isArray(blobsBySlot) || blobsBySlot.length === 0) return false;
  if (ypirUploadInFlight) {
    console.log('[ypir-tier2] skip upload: a build is already in flight');
    return false;
  }
  if (Date.now() - ypirLastUploadAt < YPIR_MIN_UPLOAD_INTERVAL_MS) {
    return false;
  }

  ypirUploadInFlight = true;
  try {
    const body = Buffer.alloc(blobsBySlot.length * BLOB_LEN);
    let oversized = 0;
    for (let i = 0; i < blobsBySlot.length; i += 1) {
      const slot = encodeSlot(blobsBySlot[i]);
      if (slot === null) { oversized += 1; continue; }
      slot.copy(body, i * BLOB_LEN);
    }
    if (oversized > 0) {
      console.warn(`[ypir-tier2] ${oversized} blob(s) exceeded YPIR_TIER2_BLOB_LEN=${BLOB_LEN}; raise it`);
    }
    await postBinary(`${WORKER_URL}/v1/databases`, body);
    ypirLastUploadAt = Date.now();
    console.log(`[ypir-tier2] uploaded epoch ${epochId || '?'}: ${blobsBySlot.length} slots, ${body.length} bytes`);
    return true;
  } catch (e) {
    console.warn('[ypir-tier2] upload failed (tier-1 unaffected):', e?.message);
    return false;
  } finally {
    ypirUploadInFlight = false;
  }
}

function postBinary(url, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname,
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': body.length },
        timeout: 180_000
      },
      (res) => {
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end', () => (res.statusCode && res.statusCode < 300 ? resolve(data) : reject(new Error(`HTTP ${res.statusCode}`))));
      }
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.write(body);
    req.end();
  });
}

/**
 * Forward a client serialized YPIR query to the worker
 */
export async function queryYpirWorker(requestBytes) {
  if (!ypirTier2Enabled()) throw new Error('ypir_disabled');
  return postBinaryGetBinary(`${WORKER_URL}/v1/query`, requestBytes);
}

function postBinaryGetBinary(url, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname,
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': body.length },
        timeout: 60_000
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => (res.statusCode && res.statusCode < 300 ? resolve(Buffer.concat(chunks)) : reject(new Error(`HTTP ${res.statusCode}`))));
      }
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.write(body);
    req.end();
  });
}
