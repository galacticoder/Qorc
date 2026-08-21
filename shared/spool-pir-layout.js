/**
 * Internal PIR matrix layout for durable spool
 */

import { ML_KEM_1024_CIPHERTEXT_BYTES } from './crypto-sizes.js';

export const SPOOL_PIR_LAYOUT = 'qor-spool-pir-v2';
export const SPOOL_PIR_EPOCH_UNAVAILABLE = 'spool_pir_epoch_unavailable';

export const SPOOL_PIR_RECORD_BYTES = ML_KEM_1024_CIPHERTEXT_BYTES + 12 + (131072 + 16);
export const SPOOL_PIR_ROW_BYTES = 16 * 1024;
export const SPOOL_PIR_ROWS_PER_RECORD = Math.ceil(
  SPOOL_PIR_RECORD_BYTES / SPOOL_PIR_ROW_BYTES
);

export function spoolPirDatabaseRows(recordCount) {
  if (!Number.isSafeInteger(recordCount) || recordCount < 0) {
    throw new Error('Invalid PIR record count');
  }
  return recordCount * SPOOL_PIR_ROWS_PER_RECORD;
}

export function spoolPirRecordRowPositions(recordPosition) {
  if (!Number.isSafeInteger(recordPosition) || recordPosition < 0) {
    throw new Error('Invalid PIR record position');
  }
  const first = recordPosition * SPOOL_PIR_ROWS_PER_RECORD;
  return Array.from({ length: SPOOL_PIR_ROWS_PER_RECORD }, (_, index) => first + index);
}

export function splitSpoolPirRecord(record) {
  if (!(record instanceof Uint8Array) || record.length !== SPOOL_PIR_RECORD_BYTES) {
    throw new Error('Invalid fixed-width PIR spool record');
  }
  return Array.from({ length: SPOOL_PIR_ROWS_PER_RECORD }, (_, index) => {
    const row = new Uint8Array(SPOOL_PIR_ROW_BYTES);
    row.set(record.subarray(
      index * SPOOL_PIR_ROW_BYTES,
      Math.min((index + 1) * SPOOL_PIR_ROW_BYTES, record.length)
    ));
    return row;
  });
}
