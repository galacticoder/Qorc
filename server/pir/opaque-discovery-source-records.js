/**
 * Discovery PIR source records
 */
import crypto from 'crypto';

export function buildOpaqueDiscoverySourceRecords(rows, config, options = {}) {
  const maxRecords = Math.max(0, Math.trunc(Number(options.maxRecords ?? config?.maxSourceRecords) || 0));
  if (!Array.isArray(rows) || maxRecords <= 0) {
    return [];
  }

  const out = [];
  for (const row of rows) {
    const encryptedBlob = row?.encryptedBlob;
    const bucketId = Number.isInteger(row?.bucketId) ? row.bucketId : Number.parseInt(row?.bucketId, 10);
    if (typeof encryptedBlob !== 'string' || encryptedBlob.length === 0) continue;
    if (!Number.isInteger(bucketId) || bucketId < 0) continue;
    const slotKey = crypto.createHash('sha256').update('discovery-cover-slot-v1').update('\0').update(encryptedBlob).digest('hex');
    out.push({
      slotKey,
      bucketId,
      encryptedBlob,
      expiresAt: Number.isFinite(row?.expiresAt) ? Math.trunc(row.expiresAt) : 0
    });
    if (out.length >= maxRecords) break;
  }
  return out;
}
