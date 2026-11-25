/**
 * Retrieval of detected spool entries by PIR
 */

import { PIR_FETCH_INDEX_LENGTH_LIMIT } from '../constants';
import { anonymousHttpFetch } from '../transport/pq-anonymous-http';
import { pir } from '../tauri-bindings';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { SPOOL_PIR_AUDIENCE } from '../config/audiences';
import {
  SPOOL_PIR_EPOCH_UNAVAILABLE,
  SPOOL_PIR_RECORD_BYTES,
  SPOOL_PIR_ROW_BYTES,
  SPOOL_PIR_ROWS_PER_RECORD,
  spoolPirDatabaseRows,
  spoolPirRecordRowPositions,
} from '../../../shared/spool-pir-layout.js';
import { Base64, tryDecodeCanonicalBase64 } from '../cryptography/base64';
import { SPOOL_PIR_LAYOUT } from '../../../shared/protocol-keys.js';
import { ML_KEM_1024_CIPHERTEXT_BYTES, SEALED_NONCE_BYTES } from '../../../shared/crypto-sizes.js';

interface PirFetchRequest {
  epoch: number;
  indexPosition: number;
  indexLength: number;
}

export interface RetrievedSealedEnvelope {
  version: string;
  ciphertext: string;
  ephemeralKey: string;
  nonce: string;
  tag: string;
  probe: string;
}

async function fetchSpoolEntryByIndex(
  serverUrl: string,
  request: PirFetchRequest,
  signal: AbortSignal,
): Promise<Uint8Array | null> {
  const { epoch, indexPosition, indexLength } = request;
  if (
    !Number.isSafeInteger(epoch) || epoch < 0 ||
    !Number.isSafeInteger(indexLength) || indexLength <= 0 ||
    !Number.isSafeInteger(indexPosition) || indexPosition < 0 || indexPosition >= indexLength
  ) return null;

  signal.throwIfAborted();
  if (indexLength > PIR_FETCH_INDEX_LENGTH_LIMIT) return null;
  const databaseRows = spoolPirDatabaseRows(indexLength);
  if (databaseRows > (1 << 20)) return null;
  const targetRows = spoolPirRecordRowPositions(indexPosition);

  let sessionId = 0;
  try {
    const generated = await pir.generateBatchQuery(
      databaseRows,
      SPOOL_PIR_ROW_BYTES,
      targetRows
    );
    if (
      !generated?.query || !generated.pubParams ||
      !Number.isSafeInteger(generated.sessionId) || generated.sessionId <= 0
    ) return null;
    sessionId = generated.sessionId;
    signal.throwIfAborted();

    const raw = await anonymousHttpFetch(
      SPOOL_PIR_AUDIENCE,
      {
        layout: SPOOL_PIR_LAYOUT,
        epoch,
        query: generated.query,
        pubParams: generated.pubParams
      },
      serverUrl,
      { signal },
    ) as Record<string, unknown> | null;
    if (!raw || raw.ok !== true || typeof raw.response !== 'string') {
      if (raw?.error === SPOOL_PIR_EPOCH_UNAVAILABLE) {
        throw new Error(SPOOL_PIR_EPOCH_UNAVAILABLE);
      }
      return null;
    }

    signal.throwIfAborted();
    const decoded = await pir.decodeBatchResponse(raw.response, sessionId);
    signal.throwIfAborted();
    if (typeof decoded !== 'string' || decoded.length === 0) return null;
    const rows = tryDecodeCanonicalBase64(
      decoded,
      'PIR record rows',
      { exactBytes: SPOOL_PIR_ROWS_PER_RECORD * SPOOL_PIR_ROW_BYTES }
    );
    if (!rows) return null;
    return rows.subarray(0, SPOOL_PIR_RECORD_BYTES);
  } finally {
    if (sessionId > 0) await pir.discardQuery(sessionId).catch(() => undefined);
  }
}

// Rebuilds sealed envelope from a retrieved record
export function sealedEnvelopeFromRecord(
  record: Uint8Array,
  tag: string,
  probe: string
): RetrievedSealedEnvelope | null {
  if (record.length !== SPOOL_PIR_RECORD_BYTES) return null;
  const ephemeralKey = record.subarray(0, ML_KEM_1024_CIPHERTEXT_BYTES);
  const nonce = record.subarray(ML_KEM_1024_CIPHERTEXT_BYTES, ML_KEM_1024_CIPHERTEXT_BYTES + SEALED_NONCE_BYTES);
  const ciphertext = record.subarray(ML_KEM_1024_CIPHERTEXT_BYTES + SEALED_NONCE_BYTES);
  return {
    version: PROTOCOL_KEYS.SEALED_ENVELOPE_PROTOCOL,
    ciphertext: Base64.arrayBufferToBase64(ciphertext),
    ephemeralKey: Base64.arrayBufferToBase64(ephemeralKey),
    nonce: Base64.arrayBufferToBase64(nonce),
    tag,
    probe,
  };
}

export async function fetchSpoolEntries(
  serverUrl: string,
  epoch: number,
  indexLength: number,
  positions: readonly number[],
  signal: AbortSignal,
): Promise<Map<number, Uint8Array>> {
  const out = new Map<number, Uint8Array>();
  for (const indexPosition of positions) {
    signal.throwIfAborted();
    try {
      const bytes = await fetchSpoolEntryByIndex(serverUrl, { epoch, indexPosition, indexLength }, signal);
      if (bytes) out.set(indexPosition, bytes);
    } catch (error) {
      signal.throwIfAborted();
      if (error instanceof Error && error.message === SPOOL_PIR_EPOCH_UNAVAILABLE) break;
    }
  }
  return out;
}
