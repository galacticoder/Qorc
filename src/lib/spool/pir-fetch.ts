/**
 * Retrieval of detected spool entries by PIR
 */

import { anonymousHttpFetch } from '../transport/pq-anonymous-http';
import { pir } from '../tauri-bindings';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { SPOOL_PIR_AUDIENCE } from '../config/audiences';
import {
  SPOOL_PIR_LAYOUT,
  SPOOL_PIR_RECORD_BYTES,
  SPOOL_PIR_ROW_BYTES,
  SPOOL_PIR_ROWS_PER_RECORD,
  spoolPirDatabaseRows,
  spoolPirRowPosition,
} from '../../../shared/spool-pir-layout.js';
import { Base64, tryDecodeCanonicalBase64 } from '../cryptography/base64';

const KEM_CIPHERTEXT_BYTES = 1568;
const NONCE_BYTES = 12;

const PIR_ROW_CONCURRENCY = 4;
const PIR_RECORD_CONCURRENCY = 4;
let activePirRows = 0;
const pirRowWaiters: Array<() => void> = [];

async function acquirePirRowSlot(): Promise<() => void> {
  if (activePirRows < PIR_ROW_CONCURRENCY) {
    activePirRows += 1;
    return releasePirRowSlot;
  }
  await new Promise<void>((resolve) => pirRowWaiters.push(resolve));
  return releasePirRowSlot;
}

function releasePirRowSlot(): void {
  const next = pirRowWaiters.shift();
  if (next) {
    next();
    return;
  }
  activePirRows = Math.max(0, activePirRows - 1);
}

export interface PirFetchRequest {
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

export async function fetchSpoolEntryByIndex(
  serverUrl: string,
  request: PirFetchRequest
): Promise<Uint8Array | null> {
  const { epoch, indexPosition, indexLength } = request;
  if (
    !Number.isSafeInteger(epoch) || epoch < 0 ||
    !Number.isSafeInteger(indexLength) || indexLength <= 0 ||
    !Number.isSafeInteger(indexPosition) || indexPosition < 0 || indexPosition >= indexLength
  ) return null;

  const startedAt = Date.now();
  const databaseRows = spoolPirDatabaseRows(indexLength);
  if (databaseRows <= 0 || databaseRows > (1 << 20)) return null;
  console.log('[SPOOL-PIR] fetch started', {
    indexPosition,
    indexLength,
    databaseRows,
    rowsPerRecord: SPOOL_PIR_ROWS_PER_RECORD,
    epoch
  });

  const record = new Uint8Array(SPOOL_PIR_RECORD_BYTES);
  const fetchRow = async (row: number): Promise<boolean> => {
    const releaseRowSlot = await acquirePirRowSlot();
    let sessionId = 0;
    try {
      const targetRow = spoolPirRowPosition(indexPosition, row);
      const generated = await pir.generateQuery(databaseRows, SPOOL_PIR_ROW_BYTES, targetRow);
      if (
        !generated?.query || !generated.pubParams ||
        !Number.isSafeInteger(generated.sessionId) || generated.sessionId <= 0
      ) return false;
      sessionId = generated.sessionId;
      console.log('[SPOOL-PIR] native query ready', {
        indexPosition,
        row: row + 1,
        rows: SPOOL_PIR_ROWS_PER_RECORD,
        elapsedMs: Date.now() - startedAt
      });

      const raw = await anonymousHttpFetch(
        SPOOL_PIR_AUDIENCE,
        {
          layout: SPOOL_PIR_LAYOUT,
          epoch,
          query: generated.query,
          pubParams: generated.pubParams
        },
        serverUrl
      ) as Record<string, unknown> | null;
      if (!raw || raw.ok !== true || typeof raw.response !== 'string') {
        console.warn('[SPOOL-PIR] server did not return a PIR answer', {
          indexPosition,
          row: row + 1,
          error: typeof raw?.error === 'string' ? raw.error : 'invalid_response',
          elapsedMs: Date.now() - startedAt
        });
        return false;
      }
      console.log('[SPOOL-PIR] encrypted answer received', {
        indexPosition,
        row: row + 1,
        rows: SPOOL_PIR_ROWS_PER_RECORD,
        elapsedMs: Date.now() - startedAt
      });

      const decoded = await pir.decodeResponse(raw.response, sessionId);
      if (typeof decoded !== 'string' || decoded.length === 0) return false;
      const bytes = tryDecodeCanonicalBase64(
        decoded,
        'PIR row',
        { exactBytes: SPOOL_PIR_ROW_BYTES }
      );
      if (!bytes) return false;
      const offset = row * SPOOL_PIR_ROW_BYTES;
      record.set(bytes.subarray(0, Math.min(bytes.length, record.length - offset)), offset);
      return true;
    } finally {
      if (sessionId > 0) await pir.discardQuery(sessionId).catch(() => undefined);
      releaseRowSlot();
    }
  };

  let nextRow = 0;
  let failed = false;
  const runRowWorker = async (): Promise<void> => {
    while (!failed) {
      const row = nextRow;
      nextRow += 1;
      if (row >= SPOOL_PIR_ROWS_PER_RECORD) return;
      if (!await fetchRow(row)) failed = true;
    }
  };
  const workers = Array.from(
    { length: Math.min(PIR_ROW_CONCURRENCY, SPOOL_PIR_ROWS_PER_RECORD) },
    () => runRowWorker()
  );
  const results = await Promise.allSettled(workers);
  if (
    failed ||
    results.some((result) => result.status === 'rejected') ||
    nextRow < SPOOL_PIR_ROWS_PER_RECORD
  ) {
    return null;
  }
  console.log('[SPOOL-PIR] record decoded', {
    indexPosition,
    elapsedMs: Date.now() - startedAt
  });
  return record;
}

// Rebuilds the sealed envelope from a retrieved record
export function sealedEnvelopeFromRecord(
  record: Uint8Array,
  tag: string,
  probe: string
): RetrievedSealedEnvelope | null {
  if (record.length !== SPOOL_PIR_RECORD_BYTES) return null;
  const ephemeralKey = record.subarray(0, KEM_CIPHERTEXT_BYTES);
  const nonce = record.subarray(KEM_CIPHERTEXT_BYTES, KEM_CIPHERTEXT_BYTES + NONCE_BYTES);
  const ciphertext = record.subarray(KEM_CIPHERTEXT_BYTES + NONCE_BYTES);
  return {
    version: PROTOCOL_KEYS.SEALED_ENVELOPE_VERSION,
    ciphertext: Base64.arrayBufferToBase64(ciphertext),
    ephemeralKey: Base64.arrayBufferToBase64(ephemeralKey),
    nonce: Base64.arrayBufferToBase64(nonce),
    tag,
    probe,
  };
}

//Fetches several detected positions
export async function fetchSpoolEntries(
  serverUrl: string,
  epoch: number,
  indexLength: number,
  positions: readonly number[]
): Promise<Map<number, Uint8Array>> {
  const out = new Map<number, Uint8Array>();
  let nextPosition = 0;
  const runRecordWorker = async (): Promise<void> => {
    while (nextPosition < positions.length) {
      const indexPosition = positions[nextPosition];
      nextPosition += 1;
      try {
        const bytes = await fetchSpoolEntryByIndex(serverUrl, {
          epoch,
          indexPosition,
          indexLength
        });
        if (bytes) out.set(indexPosition, bytes);
      } catch (error) {
        console.warn('[SPOOL-PIR] fetch failed for one position', {
          indexPosition,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }
  };
  await Promise.all(Array.from(
    { length: Math.min(PIR_RECORD_CONCURRENCY, positions.length) },
    () => runRecordWorker()
  ));
  return out;
}
