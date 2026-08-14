import { sha3_512 } from '@noble/hashes/sha3.js';
import {
  KEY_TRANSPARENCY_DELTA_MAX_EPOCHS,
  KEY_TRANSPARENCY_DELTA_MAX_RECORDS,
  KEY_TRANSPARENCY_MAX_LOG_SIZE,
  isKeyTransparencyHash,
  isKeyTransparencyLabel,
  isKeyTransparencyRecord,
  keyTransparencyFoldRecord,
  keyTransparencyGenesisRoot,
} from '../../shared/key-transparency-protocol.js';
import { getPgPool, withTransaction } from './core.js';

const KEY_TRANSPARENCY_ADVISORY_LOCK = 1364157007;

function normalizeInteger(value, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) {
    throw new Error('Invalid key-transparency integer');
  }
  return number;
}

function normalizeStateRow(row) {
  if (!row) throw new Error('Key-transparency log state is missing');
  const state = {
    entryCount: normalizeInteger(row.entryCount, 0, KEY_TRANSPARENCY_MAX_LOG_SIZE),
    rootHash: row.rootHash,
  };
  if (!isKeyTransparencyHash(state.rootHash)) {
    throw new Error('Invalid key-transparency log root');
  }
  return state;
}

function normalizeRecordRow(row) {
  const record = {
    epoch: normalizeInteger(row.epoch, 0),
    epochLabel: row.epochLabel,
    recordHash: row.recordHash,
    version: normalizeInteger(row.version, 1, KEY_TRANSPARENCY_MAX_LOG_SIZE),
  };
  if (!isKeyTransparencyRecord(record)) {
    throw new Error('Invalid key-transparency record row');
  }
  return record;
}

export async function initializeKeyTransparencyDatabase() {
  const pool = await getPgPool();
  await pool.query(
    `INSERT INTO key_transparency_log_state (singleton, "entryCount", "rootHash")
     VALUES (TRUE, 0, $1)
     ON CONFLICT (singleton) DO NOTHING`,
    [keyTransparencyGenesisRoot(sha3_512)]
  );
  const { rows } = await pool.query(
    'SELECT "entryCount", "rootHash" FROM key_transparency_log_state WHERE singleton = TRUE'
  );
  const state = normalizeStateRow(rows[0]);
  if (state.entryCount === 0 && state.rootHash !== keyTransparencyGenesisRoot(sha3_512)) {
    throw new Error('Empty key-transparency log root is inconsistent');
  }
  return state;
}

export async function readKeyTransparencyLogState() {
  const pool = await getPgPool();
  const { rows } = await pool.query(
    'SELECT "entryCount", "rootHash" FROM key_transparency_log_state WHERE singleton = TRUE'
  );
  const state = normalizeStateRow(rows[0]);
  const genesis = await pool.query('SELECT MIN(epoch) AS "genesisEpoch" FROM key_transparency_log');
  const value = genesis.rows[0]?.genesisEpoch;
  return {
    ...state,
    genesisEpoch: value === null || value === undefined ? null : normalizeInteger(value, 0),
  };
}

// Append record and fold into running root
export async function appendKeyTransparencyRecord({ epoch, epochLabel, version, recordHash }) {
  const normalizedEpoch = normalizeInteger(epoch, 0);
  const record = {
    epoch: normalizedEpoch,
    epochLabel,
    recordHash,
    version: normalizeInteger(version, 1, KEY_TRANSPARENCY_MAX_LOG_SIZE),
  };
  if (!isKeyTransparencyLabel(epochLabel) || !isKeyTransparencyRecord(record)) {
    throw new Error('Invalid key-transparency record');
  }

  const pool = await getPgPool();
  const client = await pool.connect();
  try {
    return await withTransaction(client, async ({ rollback }) => {
      await client.query('SELECT pg_advisory_xact_lock($1)', [KEY_TRANSPARENCY_ADVISORY_LOCK]);
      const { rows } = await client.query(
        `SELECT "entryCount", "rootHash" FROM key_transparency_log_state
       WHERE singleton = TRUE FOR UPDATE`
      );
      const state = normalizeStateRow(rows[0]);
      if (state.entryCount >= KEY_TRANSPARENCY_MAX_LOG_SIZE) {
        throw new Error('Key-transparency log is full');
      }

      const duplicate = await client.query(
        'SELECT 1 FROM key_transparency_log WHERE epoch = $1 AND "epochLabel" = $2',
        [normalizedEpoch, record.epochLabel]
      );
      if (duplicate.rowCount > 0) {
        return rollback({ appended: false, reason: 'duplicate-epoch-label', state });
      }

      const rootHash = keyTransparencyFoldRecord(sha3_512, state.rootHash, record);
      await client.query(
        `INSERT INTO key_transparency_log
         ("logIndex", epoch, "epochLabel", version, "recordHash", "rootHash")
       VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          state.entryCount,
          normalizedEpoch,
          record.epochLabel,
          record.version,
          record.recordHash,
          rootHash,
        ]
      );
      await client.query(
        `UPDATE key_transparency_log_state
       SET "entryCount" = $1, "rootHash" = $2 WHERE singleton = TRUE`,
        [state.entryCount + 1, rootHash]
      );
      return {
        appended: true,
        state: { entryCount: state.entryCount + 1, rootHash },
      };
    });
  } finally {
    client.release();
  }
}

// Read every record appended
export async function readKeyTransparencyDelta(fromEpoch, toEpoch) {
  const start = normalizeInteger(fromEpoch, 0);
  const end = normalizeInteger(toEpoch, 0);
  if (end < start) throw new Error('Invalid key-transparency epoch range');
  if (end - start >= KEY_TRANSPARENCY_DELTA_MAX_EPOCHS) {
    throw new Error('Key-transparency epoch range is too wide');
  }

  const pool = await getPgPool();
  const { rows } = await pool.query(
    `SELECT "logIndex", epoch, "epochLabel", version, "recordHash"
     FROM key_transparency_log
     WHERE epoch >= $1 AND epoch <= $2
     ORDER BY "logIndex" ASC
     LIMIT $3`,
    [start, end, KEY_TRANSPARENCY_DELTA_MAX_RECORDS + 1]
  );
  if (rows.length > KEY_TRANSPARENCY_DELTA_MAX_RECORDS) {
    throw new Error('Key-transparency epoch range is too dense');
  }

  const firstLogIndex = rows.length > 0 ? normalizeInteger(rows[0].logIndex, 0) : null;
  return {
    fromEpoch: start,
    toEpoch: end,
    firstLogIndex,
    records: rows.map(normalizeRecordRow),
  };
}

export async function readKeyTransparencyEpochStart(epoch) {
  const normalizedEpoch = normalizeInteger(epoch, 0);
  const pool = await getPgPool();
  const { rows } = await pool.query(
    `SELECT COUNT(*)::bigint AS "priorCount"
     FROM key_transparency_log WHERE epoch < $1`,
    [normalizedEpoch]
  );
  return normalizeInteger(rows[0]?.priorCount ?? 0, 0, KEY_TRANSPARENCY_MAX_LOG_SIZE);
}
