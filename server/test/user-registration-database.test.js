import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test, { after, before, beforeEach } from 'node:test';

process.env.AUTH_ROOT_SEED ||= '39'.repeat(32);

const enabled = process.env.QORC_TEST_DATABASE === '1';
let UserDatabase;
let closePgPool;
let getPgPool;

before(async () => {
  ({ UserDatabase } = await import('../database/user-db.js'));
  ({ closePgPool, getPgPool } = await import('../database/core.js'));
  if (!enabled) return;
  const { initDatabase } = await import('../database/schema.js');
  await initDatabase();
});

beforeEach(async () => {
  if (!enabled) return;
  const pool = await getPgPool();
  await pool.query('TRUNCATE pending_registrations, users');
});

after(async () => {
  if (enabled) await closePgPool();
});

function recordId() {
  return crypto.randomBytes(64).toString('base64url');
}

function opaqueRecord(fill = 1) {
  return JSON.stringify({
    authPublicKey: Buffer.alloc(2592, fill).toString('base64'),
    envelope: Buffer.alloc(72, fill + 1).toString('base64'),
    salt: Buffer.alloc(32, fill + 2).toString('base64'),
  });
}

test('registration attempt IDs are deterministically hidden and strictly canonical', () => {
  const attempt = crypto.randomBytes(32).toString('base64');
  const first = UserDatabase.createRecordId(attempt);
  const second = UserDatabase.createRecordId(attempt);
  assert.equal(first, second);
  assert.notEqual(first, attempt);
  assert.throws(() => UserDatabase.createRecordId(attempt.slice(1)), /Invalid/);
  assert.throws(() => UserDatabase.createRecordId('A'.repeat(45)), /Invalid/);
  assert.throws(() => UserDatabase.createRecordId('A'.repeat(44)), /Invalid/);
  assert.throws(() => UserDatabase.createRecordId(new String(attempt)), /Invalid/);
});

test('registration storage rejects malformed IDs and credential records before database access', async () => {
  const validId = recordId();
  const validRecord = opaqueRecord();
  for (const candidate of [
    { recordId: `${'A'.repeat(85)}B`, opaqueRecord: validRecord },
    { recordId: `${validId.slice(0, -1)}=`, opaqueRecord: validRecord },
    { recordId: validId, opaqueRecord: '' },
    { recordId: validId, opaqueRecord: '{}' },
    { recordId: validId, opaqueRecord: JSON.stringify({
      authPublicKey: 'AAAA',
      envelope: Buffer.alloc(72).toString('base64'),
      salt: Buffer.alloc(32).toString('base64'),
    }) },
    { recordId: validId, opaqueRecord: JSON.stringify({
      authPublicKey: Buffer.alloc(2592).toString('base64'),
      envelope: Buffer.alloc(72).toString('base64'),
      salt: Buffer.alloc(32).toString('base64'),
      extra: true,
    }) },
  ]) {
    await assert.rejects(() => UserDatabase.stageUserRecord(candidate), /Invalid/);
  }
  await assert.rejects(() => UserDatabase.confirmStagedUserRecord('invalid'), /Invalid/);
});

test('parallel registration staging assigns unique bounded slots', { skip: !enabled }, async () => {
  const attempts = Array.from({ length: 96 }, (_, index) => ({
    recordId: recordId(),
    opaqueRecord: opaqueRecord((index % 250) + 1),
  }));
  const staged = await Promise.all(attempts.map((record) => UserDatabase.stageUserRecord(record)));
  const indexes = staged.map(({ credential_index }) => credential_index);
  assert.equal(new Set(indexes).size, attempts.length);
  assert.equal(indexes.every((index) => Number.isInteger(index) && index >= 0 && index < 2048), true);
});

test('an exact registration retry is idempotent but changed credentials are rejected', { skip: !enabled }, async () => {
  const stagedRecord = { recordId: recordId(), opaqueRecord: opaqueRecord(10) };
  const first = await UserDatabase.stageUserRecord(stagedRecord);
  const retry = await UserDatabase.stageUserRecord({ ...stagedRecord });
  assert.deepEqual(retry, first);

  await assert.rejects(
    () => UserDatabase.stageUserRecord({
      recordId: stagedRecord.recordId,
      opaqueRecord: opaqueRecord(11),
    }),
    (error) => error?.code === 'REGISTRATION_ATTEMPT_MISMATCH'
  );
  const pool = await getPgPool();
  const stored = await pool.query(
    'SELECT "opaqueRecord" FROM pending_registrations WHERE "recordId" = $1',
    [stagedRecord.recordId]
  );
  assert.equal(stored.rows[0].opaqueRecord, stagedRecord.opaqueRecord);
});

test('confirmation is atomic, replay-visible, and cannot restage a committed identity', { skip: !enabled }, async () => {
  const stagedRecord = { recordId: recordId(), opaqueRecord: opaqueRecord(12) };
  const staged = await UserDatabase.stageUserRecord(stagedRecord);
  assert.deepEqual(await UserDatabase.confirmStagedUserRecord(stagedRecord.recordId), {
    credential_index: staged.credential_index,
    already_committed: false,
  });
  assert.deepEqual(await UserDatabase.confirmStagedUserRecord(stagedRecord.recordId), {
    credential_index: staged.credential_index,
    already_committed: true,
  });
  assert.deepEqual(await UserDatabase.stageUserRecord(stagedRecord), {
    credential_index: staged.credential_index,
    recovery_only: true,
    expires_at: null,
  });

  const pool = await getPgPool();
  const counts = await pool.query(
    `SELECT
       (SELECT COUNT(*)::int FROM users) AS users,
       (SELECT COUNT(*)::int FROM pending_registrations) AS pending`
  );
  assert.deepEqual(counts.rows[0], { users: 1, pending: 0 });
});

test('expired receipts are deleted and cannot be committed', { skip: !enabled }, async () => {
  const stagedRecord = { recordId: recordId(), opaqueRecord: opaqueRecord(13) };
  await UserDatabase.stageUserRecord(stagedRecord);
  const pool = await getPgPool();
  await pool.query(
    'UPDATE pending_registrations SET "expiresAt" = $1 WHERE "recordId" = $2',
    [Date.now() - 1, stagedRecord.recordId]
  );
  await assert.rejects(
    () => UserDatabase.confirmStagedUserRecord(stagedRecord.recordId),
    (error) => error?.code === 'REGISTRATION_RECEIPT_EXPIRED'
  );
  const count = await pool.query('SELECT COUNT(*)::int AS count FROM pending_registrations');
  assert.equal(count.rows[0].count, 0);
});

test('full anonymity-set capacity fails closed without overwriting a record', { skip: !enabled }, async () => {
  const pool = await getPgPool();
  await pool.query(
    `INSERT INTO users ("recordId", "opaqueRecord", "credential_index")
     SELECT 'occupied-' || slot, 'opaque-' || slot, slot
     FROM generate_series(0, 2047) AS slot`
  );
  await assert.rejects(
    () => UserDatabase.stageUserRecord({ recordId: recordId(), opaqueRecord: opaqueRecord(14) }),
    /capacity exhausted/
  );
  const count = await pool.query('SELECT COUNT(*)::int AS count FROM users');
  assert.equal(count.rows[0].count, 2048);
});

test('confirmation cannot revive a receipt that expires while waiting for the table lock', { skip: !enabled }, async () => {
  const candidate = { recordId: recordId(), opaqueRecord: opaqueRecord(20) };
  await UserDatabase.stageUserRecord(candidate);
  const pool = await getPgPool();
  const originalNow = Date.now;
  let now = originalNow();
  const blocker = await pool.connect();
  try {
    await pool.query('UPDATE pending_registrations SET "expiresAt" = $1 WHERE "recordId" = $2', [now + 1000, candidate.recordId]);
    await blocker.query('BEGIN');
    // Compatible with DELETE's RowExclusiveLock; conflicts with the later
    // SHARE ROW EXCLUSIVE lock. This exercises the actual database boundary.
    await blocker.query('LOCK TABLE users, pending_registrations IN ROW EXCLUSIVE MODE');
    Date.now = () => now;
    const confirmation = UserDatabase.confirmStagedUserRecord(candidate.recordId);
    const outcome = confirmation.then(value => ({ value }), error => ({ error }));
    const deadline = originalNow() + 5000;
    let waiting = false;
    while (originalNow() < deadline) {
      const result = await blocker.query(`SELECT 1 FROM pg_stat_activity
        WHERE datname = current_database() AND wait_event_type = 'Lock'
        AND query = 'LOCK TABLE users, pending_registrations IN SHARE ROW EXCLUSIVE MODE'`);
      if (result.rowCount > 0) { waiting = true; break; }
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    now += 1001;
    await blocker.query('COMMIT');
    const result = await outcome;
    assert.equal(waiting, true, 'confirmation must reach the contested table lock');
    assert.equal(result.error?.code, 'REGISTRATION_RECEIPT_EXPIRED');
    const rows = await pool.query('SELECT 1 FROM users WHERE "recordId" = $1', [candidate.recordId]);
    assert.equal(rows.rowCount, 0);
  } finally {
    Date.now = originalNow;
    await blocker.query('ROLLBACK');
    blocker.release();
  }
});
