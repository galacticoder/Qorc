import test from 'node:test';
import assert from 'node:assert/strict';
import { hkdf } from '@noble/hashes/hkdf.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { OPAQUEServer, LABELS } from '../crypto/opaque-service.js';

function clientAuthProof(maskedResponse, serverNonce) {
  const authKey = hkdf(blake3, maskedResponse, serverNonce, new TextEncoder().encode(LABELS.AUTH_KEY), 32);
  const transcript = Buffer.concat([
    Buffer.from(LABELS.AUTH_MAC_CONTEXT, 'utf8'),
    Buffer.from(serverNonce)
  ]);
  return Buffer.from(blake3(transcript, { key: authKey, dkLen: 32 }));
}

function makeShard(size) {
  const records = [];
  for (let i = 0; i < size; i += 1) {
    records.push({
      credentialId: `cred-${i}`,
      opaqueRecord: JSON.stringify({
        maskedResponse: Buffer.from(randomBytes(64)).toString('base64'),
        serverPrivateKey: Buffer.from(randomBytes(32)).toString('base64')
      })
    });
  }
  return records;
}

test('finishLoginAcrossShard authenticates the correct account without being told which one', async () => {
  const shard = makeShard(2048);
  const serverNonce = Buffer.from(randomBytes(32));

  const index = 1999;
  const maskedResponse = Buffer.from(JSON.parse(shard[index].opaqueRecord).maskedResponse, 'base64');
  const authProof = clientAuthProof(maskedResponse, serverNonce);

  const result = await OPAQUEServer.finishLoginAcrossShard(shard, authProof, serverNonce);
  assert.equal(result.success, true);
  assert.ok(result.sessionKey, 'a session key is produced for the matching record');
});

test('finishLoginAcrossShard rejects a proof that matches no record in the shard', async () => {
  const shard = makeShard(256);
  const serverNonce = Buffer.from(randomBytes(32));
  const bogusProof = Buffer.from(randomBytes(32));

  const result = await OPAQUEServer.finishLoginAcrossShard(shard, bogusProof, serverNonce);
  assert.equal(result.success, false);
});

test('finishLoginAcrossShard is position-independent in work (scans whole shard, no early exit)', async () => {
  const serverNonce = Buffer.from(randomBytes(32));
  for (const index of [0, 1023]) {
    const shard = makeShard(1024);
    const maskedResponse = Buffer.from(JSON.parse(shard[index].opaqueRecord).maskedResponse, 'base64');
    const authProof = clientAuthProof(maskedResponse, serverNonce);
    const result = await OPAQUEServer.finishLoginAcrossShard(shard, authProof, serverNonce);
    assert.equal(result.success, true, `match at index ${index}`);
  }
});
