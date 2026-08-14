/**
 * Internal PIR matrix layout for durable spool
 */

import { ML_KEM_1024_CIPHERTEXT_BYTES } from './crypto-sizes.js';

export const SPOOL_PIR_LAYOUT = 'qor-spool-pir-chunked-v1';

export const SPOOL_PIR_RECORD_BYTES = ML_KEM_1024_CIPHERTEXT_BYTES + 12 + (131072 + 16);
export const SPOOL_PIR_ROW_BYTES = 16 * 1024;
export const SPOOL_PIR_ROWS_PER_RECORD = Math.ceil(
  SPOOL_PIR_RECORD_BYTES / SPOOL_PIR_ROW_BYTES
);

export function spoolPirDatabaseRows(logicalRecordCount) {
  if (!Number.isSafeInteger(logicalRecordCount) || logicalRecordCount < 0) {
    throw new Error('Invalid logical PIR record count');
  }
  const rows = logicalRecordCount * SPOOL_PIR_ROWS_PER_RECORD;
  if (!Number.isSafeInteger(rows)) throw new Error('PIR row count overflow');
  return rows;
}

export function spoolPirRowPosition(logicalPosition, rowWithinRecord) {
  if (
    !Number.isSafeInteger(logicalPosition) || logicalPosition < 0 ||
    !Number.isSafeInteger(rowWithinRecord) ||
    rowWithinRecord < 0 || rowWithinRecord >= SPOOL_PIR_ROWS_PER_RECORD
  ) {
    throw new Error('Invalid PIR row position');
  }
  const position = logicalPosition * SPOOL_PIR_ROWS_PER_RECORD + rowWithinRecord;
  if (!Number.isSafeInteger(position)) throw new Error('PIR row position overflow');
  return position;
}

export function splitSpoolPirRecord(record) {
  if (!(record instanceof Uint8Array) || record.length !== SPOOL_PIR_RECORD_BYTES) {
    throw new Error('Invalid fixed-width PIR spool record');
  }
  const rows = [];
  for (let row = 0; row < SPOOL_PIR_ROWS_PER_RECORD; row += 1) {
    const start = row * SPOOL_PIR_ROW_BYTES;
    const output = new Uint8Array(SPOOL_PIR_ROW_BYTES);
    output.set(record.subarray(start, Math.min(start + SPOOL_PIR_ROW_BYTES, record.length)));
    rows.push(output);
  }
  return rows;
}
