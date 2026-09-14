/**
 * User Database
 * 
 * Stores private authentication records under server random opaque ids
 */

import { getPgPool, crypto, privateLookupId, withTransaction } from './core.js';
import { PRIVATE_AUTH_ANONYMITY_SET_SIZE } from '../../shared/private-auth-protocol.js';
import {
  ML_DSA_87_PUBLIC_KEY_BYTES,
  OPAQUE_ENVELOPE_BYTES,
  OPAQUE_SALT_BYTES,
} from '../../shared/crypto-sizes.js';
import { canonicalBase64Shape } from '../../shared/canonical-base64.js';
import {
  REGISTRATION_ATTEMPT_MISMATCH,
  REGISTRATION_RECEIPT_EXPIRED
} from '../config/error-codes.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { isCanonicalBase64Bytes } from '../utils/encoding.js';
import { hasExactPlainObjectKeys } from '../utils/validation.js';

const REGISTRATION_RECEIPT_TTL_MS = 15 * 60_000;
const PRIVATE_RECORD_ID_BYTES = 64;
const PRIVATE_AUTH_RECORD_MAX_BYTES = 4096;
const PRIVATE_AUTH_RECORD_KEYS = Object.freeze(['authPublicKey', 'envelope', 'salt']);

function isPrivateRecordId(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(value)) return false;
  try {
    const decoded = Buffer.from(value, 'base64url');
    return decoded.length === PRIVATE_RECORD_ID_BYTES && decoded.toString('base64url') === value;
  } catch {
    return false;
  }
}

function parsePrivateAuthRecord(value) {
  if (
    typeof value !== 'string' ||
    Buffer.byteLength(value, 'utf8') === 0 ||
    Buffer.byteLength(value, 'utf8') > PRIVATE_AUTH_RECORD_MAX_BYTES
  ) return null;

  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null;
  }
  if (
    !hasExactPlainObjectKeys(parsed, PRIVATE_AUTH_RECORD_KEYS) ||
    !canonicalBase64Shape(parsed.authPublicKey, { exactBytes: ML_DSA_87_PUBLIC_KEY_BYTES }) ||
    !canonicalBase64Shape(parsed.envelope, { exactBytes: OPAQUE_ENVELOPE_BYTES }) ||
    !canonicalBase64Shape(parsed.salt, { exactBytes: OPAQUE_SALT_BYTES })
  ) return null;
  return parsed;
}

function normalizeCredentialIndex(value) {
  const index = Number(value);
  if (!Number.isSafeInteger(index) || index < 0 || index >= PRIVATE_AUTH_ANONYMITY_SET_SIZE) {
    throw new Error('Invalid private authentication credential index');
  }
  return index;
}

function registrationError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

export class UserDatabase {
  static createRecordId(registrationAttemptId) {
    if (!isCanonicalBase64Bytes(registrationAttemptId, 32)) {
      throw new Error('Invalid registration attempt identifier');
    }
    return privateLookupId(PROTOCOL_KEYS.OPAQUE_REGISTRATION_ATTEMPT, registrationAttemptId);
  }

  static async stageUserRecord(userRecord) {
    const { recordId, opaqueRecord } = userRecord;

    if (!isPrivateRecordId(recordId)) {
      throw new Error('Invalid private authentication record ID');
    }

    if (!parsePrivateAuthRecord(opaqueRecord)) {
      throw new Error('Invalid private auth record');
    }

    const pool = await getPgPool();
    const client = await pool.connect();
    let stagedNewRecord = false;
    try {
      const output = await withTransaction(client, async () => {
        await client.query('LOCK TABLE users, pending_registrations IN SHARE ROW EXCLUSIVE MODE');
        // Sample expiry after admission: waiting for another registration's lock
        // must neither revive an expired receipt nor shorten a new receipt's TTL.
        const now = Date.now();
        const expiresAt = now + REGISTRATION_RECEIPT_TTL_MS;
        await client.query(
          'DELETE FROM pending_registrations WHERE "expiresAt" <= $1',
          [now]
        );

        const existingReceipt = await client.query(
          `
          SELECT "opaqueRecord", "credential_index", "expiresAt"
          FROM pending_registrations
          WHERE "recordId" = $1
        `,
          [recordId]
        );
        if (existingReceipt.rows.length === 1) {
          const receipt = existingReceipt.rows[0];
          if (!parsePrivateAuthRecord(receipt.opaqueRecord)) {
            throw new Error('Pending registration record is invalid');
          }
          const storedRecord = Buffer.from(String(receipt.opaqueRecord || ''), 'utf8');
          const suppliedRecord = Buffer.from(opaqueRecord, 'utf8');
          try {
            if (
              storedRecord.length === 0 ||
              storedRecord.length !== suppliedRecord.length ||
              !crypto.timingSafeEqual(storedRecord, suppliedRecord)
            ) {
              throw registrationError(
                'Registration retry does not match the staged credential',
                REGISTRATION_ATTEMPT_MISMATCH
              );
            }
          } finally {
            storedRecord.fill(0);
            suppliedRecord.fill(0);
          }
          return {
            credential_index: normalizeCredentialIndex(receipt.credential_index),
            expires_at: Number(receipt.expiresAt)
          };
        }

        const existingUser = await client.query(
          'SELECT "credential_index" FROM users WHERE "recordId" = $1',
          [recordId]
        );
        if (existingUser.rows.length > 0) {
          return {
            credential_index: normalizeCredentialIndex(existingUser.rows[0].credential_index),
            recovery_only: true,
            expires_at: null
          };
        }

        const { rows } = await client.query(
          `
          SELECT "credential_index" FROM users
          UNION
          SELECT "credential_index" FROM pending_registrations
          WHERE "expiresAt" > $1
          ORDER BY "credential_index"
        `,
          [now]
        );
        const occupied = new Set(rows.map((row) => Number(row.credential_index)));
        if (occupied.size >= PRIVATE_AUTH_ANONYMITY_SET_SIZE) {
          throw new Error('Private authentication capacity exhausted');
        }

        const slotStart = crypto.randomInt(0, PRIVATE_AUTH_ANONYMITY_SET_SIZE);
        let credential_index = null;
        for (let offset = 0; offset < PRIVATE_AUTH_ANONYMITY_SET_SIZE; offset += 1) {
          const candidate = (slotStart + offset) % PRIVATE_AUTH_ANONYMITY_SET_SIZE;
          if (!occupied.has(candidate)) {
            credential_index = candidate;
            break;
          }
        }
        if (credential_index === null) {
          throw new Error('Private authentication capacity exhausted');
        }

        const result = await client.query(
          `
        INSERT INTO pending_registrations (
          "recordId", "opaqueRecord", "credential_index", "expiresAt"
        )
        VALUES ($1, $2, $3, $4)
        RETURNING "credential_index", "expiresAt"
      `,
          [
            recordId,
            opaqueRecord,
            credential_index,
            expiresAt
          ],
        );

        stagedNewRecord = true;
        return {
          credential_index: Number(result.rows[0].credential_index),
          expires_at: Number(result.rows[0].expiresAt)
        };
      });
      if (stagedNewRecord) console.log('[DB] Staged private auth record');
      return output;
    } catch (error) {
      console.error('[DB] Error staging user record', { error: error?.message });
      throw error;
    } finally {
      client.release();
    }
  }

  static async confirmStagedUserRecord(recordId) {
    if (!isPrivateRecordId(recordId)) {
      throw new Error('Invalid private authentication record ID');
    }

    const pool = await getPgPool();
    const client = await pool.connect();
    const now = Date.now();
    let committedNewRecord = false;
    try {
      await client.query(
        'DELETE FROM pending_registrations WHERE "expiresAt" <= $1',
        [now]
      );
      const output = await withTransaction(client, async () => {
        await client.query('LOCK TABLE users, pending_registrations IN SHARE ROW EXCLUSIVE MODE');

        const receiptResult = await client.query(
          `
          SELECT "opaqueRecord", "credential_index"
          FROM pending_registrations
          WHERE "recordId" = $1 AND "expiresAt" > $2
        `,
          [recordId, Date.now()]
        );
        if (receiptResult.rows.length !== 1) {
          const committedUser = await client.query(
            'SELECT "credential_index" FROM users WHERE "recordId" = $1',
            [recordId]
          );
          if (committedUser.rows.length === 1) {
            return {
              credential_index: normalizeCredentialIndex(committedUser.rows[0].credential_index),
              already_committed: true
            };
          }
          throw registrationError('Registration retry receipt expired', REGISTRATION_RECEIPT_EXPIRED);
        }

        const receipt = receiptResult.rows[0];
        const credentialIndex = normalizeCredentialIndex(receipt.credential_index);
        if (!parsePrivateAuthRecord(receipt.opaqueRecord)) {
          throw new Error('Pending registration record is invalid');
        }
        await client.query(
          `
          INSERT INTO users ("recordId", "opaqueRecord", "credential_index")
          VALUES ($1, $2, $3)
        `,
          [recordId, receipt.opaqueRecord, credentialIndex]
        );
        await client.query(
          'DELETE FROM pending_registrations WHERE "recordId" = $1',
          [recordId]
        );
        committedNewRecord = true;
        return { credential_index: credentialIndex, already_committed: false };
      });
      if (committedNewRecord) console.log('[DB] Committed private auth record');
      return output;
    } catch (error) {
      console.error('[DB] Error confirming user record', { error: error?.message });
      throw error;
    } finally {
      client.release();
    }
  }

  static async getPrivateAuthRecords() {
    const pool = await getPgPool();
    const { rows } = await pool.query(
      `SELECT "opaqueRecord", "credential_index"
       FROM users
       ORDER BY "credential_index"
       LIMIT $1`,
      [PRIVATE_AUTH_ANONYMITY_SET_SIZE + 1]
    );
    if (rows.length > PRIVATE_AUTH_ANONYMITY_SET_SIZE) {
      throw new Error('Private authentication record capacity exceeded');
    }
    const seenIndexes = new Set();
    for (const row of rows) {
      const credentialIndex = normalizeCredentialIndex(row?.credential_index);
      if (
        seenIndexes.has(credentialIndex) ||
        !parsePrivateAuthRecord(row?.opaqueRecord)
      ) {
        throw new Error('Invalid private authentication database row');
      }
      seenIndexes.add(credentialIndex);
    }
    return rows;
  }
}
