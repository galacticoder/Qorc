import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-haproxy-credentials-'));
const credentialsFile = path.join(directory, 'credentials.pqc');
const keysFile = path.join(directory, 'keys.enc');
process.env.HAPROXY_CREDENTIALS_FILE = credentialsFile;
process.env.HAPROXY_KEYS_FILE = keysFile;

const {
  loadCredentials,
  saveCredentials,
  unlockKeypair,
  verifyCredentials,
} = await import('../config/secure-credentials.js');

test.after(() => {
  fs.rmSync(directory, { force: true, recursive: true });
});

test('HAProxy credential files are private, exact, non-overwritable, and symlink safe', async () => {
  const username = 'stats-audit-user';
  const password = 'correct-horse-battery-staple-for-stats-tests';
  await saveCredentials(username, password);

  for (const filePath of [credentialsFile, keysFile]) {
    const stat = fs.statSync(filePath);
    assert.equal(stat.isFile(), true);
    assert.equal(stat.nlink, 1);
    assert.equal(stat.mode & 0o777, 0o600);
    assert.ok(stat.size > 0 && stat.size <= 64 * 1024);
  }
  await assert.rejects(
    saveCredentials(username, password),
    /refusing to overwrite/
  );
  assert.equal(await verifyCredentials(username, password), true);

  const preservedFiles = [credentialsFile, keysFile].map(file => fs.readFileSync(file));
  await assert.rejects(
    verifyCredentials(username, 'different-valid-password-for-stats-tests'),
    /MAC verification failed/
  );
  for (const [index, file] of [credentialsFile, keysFile].entries()) {
    assert.deepEqual(fs.readFileSync(file), preservedFiles[index]);
  }
  assert.equal(await verifyCredentials(username, password), true);

  const credentials = await loadCredentials({ username, password });
  assert.equal(credentials.username, username);
  assert.equal(credentials.password, password);
  credentials.username = '';
  credentials.password = '';

  const keypair = await unlockKeypair(username, password);
  assert.equal(keypair.kyber.secretKey.length, 3168);
  assert.equal(keypair.dilithium.secretKey.length, 4896);
  assert.equal(keypair.x25519.secretKey.length, 32);
  for (const family of Object.values(keypair)) {
    family.publicKey.fill(0);
    family.secretKey.fill(0);
  }

  const originalCredentials = fs.readFileSync(credentialsFile, 'utf8');
  const malformed = JSON.parse(originalCredentials);
  malformed.version = 3;
  fs.writeFileSync(credentialsFile, JSON.stringify(malformed), { mode: 0o600 });
  await assert.rejects(
    loadCredentials({ username, password }),
    /Invalid encrypted HAProxy credential file/
  );
  fs.writeFileSync(credentialsFile, originalCredentials, { mode: 0o600 });

  await assert.rejects(
    verifyCredentials(username, 'unsafe password with spaces'),
    /safe ASCII characters/
  );

  fs.unlinkSync(keysFile);
  fs.symlinkSync('/etc/passwd', keysFile);
  await assert.rejects(
    unlockKeypair(username, password),
    /Invalid encrypted HAProxy key file/
  );
});
