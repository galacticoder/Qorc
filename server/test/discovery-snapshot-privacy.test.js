import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildDiscoverySnapshotResponse,
  decodeDiscoverySnapshotResponse,
} from '../discovery/snapshot-service.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

test('discovery snapshot response is compressed, padded, and target-free', () => {
  process.env.DISCOVERY_SNAPSHOT_PADDING_FLOOR = '8';
  process.env.DISCOVERY_SNAPSHOT_DUMMY_BLOB_CHARS = '512';

  const rows = [
    { encryptedBlob: 'real-a', expiresAt: Date.now() + 60_000, publishedAt: 1000 },
    { encryptedBlob: 'real-b', expiresAt: Date.now() + 60_000, publishedAt: 2000 },
    { encryptedBlob: 'real-c', expiresAt: Date.now() + 60_000, publishedAt: 3000 },
  ];
  const response = buildDiscoverySnapshotResponse(rows, { now: 12_000, epochMs: 10_000 });

  assert.equal(Object.hasOwn(response, 'entries'), false);
  assert.equal(response.snapshot.version, 'qor-discovery-snapshot-gzip-v1');
  assert.equal(response.snapshot.encoding, 'base64url+gzip');
  assert.equal(response.snapshot.realCountHidden, true);
  assert.equal(response.snapshot.sourceCountHidden, true);
  assert.equal(response.snapshot.paddedEntryCount, 8);

  const decoded = decodeDiscoverySnapshotResponse(response.snapshot);
  assert.equal(decoded.version, 'qor-discovery-snapshot-v1');
  assert.equal(decoded.entries.length, 8);
  assert.equal(decoded.realCountHidden, true);
  for (const blob of rows.map((row) => row.encryptedBlob)) {
    assert.equal(decoded.entries.includes(blob), true);
  }
});

test('discovery delta snapshots remain padded and do not expose raw counts', () => {
  process.env.DISCOVERY_SNAPSHOT_PADDING_FLOOR = '8';
  process.env.DISCOVERY_SNAPSHOT_DUMMY_BLOB_CHARS = '512';

  const response = buildDiscoverySnapshotResponse([
    { encryptedBlob: 'old-real', expiresAt: Date.now() + 60_000, publishedAt: 1000 },
    { encryptedBlob: 'new-real', expiresAt: Date.now() + 60_000, publishedAt: 9000 },
  ], {
    now: 12_000,
    epochMs: 10_000,
    deltaSince: 5000,
  });

  const decoded = decodeDiscoverySnapshotResponse(response.snapshot);
  assert.equal(decoded.mode, 'delta');
  assert.equal(decoded.entries.length, 8);
  assert.equal(decoded.entries.includes('new-real'), true);
  assert.equal(decoded.entries.includes('old-real'), false);
  assert.equal(response.snapshot.realCountHidden, true);
});

test('publish-discovery queues delayed publication instead of immediate DB writes', () => {
  const serverSource = fs.readFileSync(path.join(repoRoot, 'server/server.js'), 'utf8');
  const publishCaseStart = serverSource.indexOf('case SignalType.PUBLISH_DISCOVERY');
  const publishCaseEnd = serverSource.indexOf('case SignalType.DISCOVERY_SNAPSHOT_REQUEST');
  assert.ok(publishCaseStart > -1 && publishCaseEnd > publishCaseStart);
  const publishCase = serverSource.slice(publishCaseStart, publishCaseEnd);

  assert.equal(publishCase.includes('enqueueDiscoveryPublication'), true);
  assert.equal(publishCase.includes('DiscoveryDB.store'), false);
  assert.equal(publishCase.includes('encryptedBlob'), true);
});

test('discovery publication relay does not write idle cover rows by default', () => {
  const relaySource = fs.readFileSync(path.join(repoRoot, 'server/discovery/publication-privacy.js'), 'utf8');

  assert.equal(relaySource.includes('DISCOVERY_PUBLICATION_IDLE_COVER_WRITES_MIN'), true);
  assert.equal(relaySource.includes('claimed.length > 0 ? COVER_WRITES_MIN : IDLE_COVER_WRITES_MIN'), true);
  assert.equal(relaySource.includes('claimed.length > 0 ? COVER_WRITES_MAX : IDLE_COVER_WRITES_MAX'), true);
});

test('discovery publication cover rows use a short default lease', () => {
  const relaySource = fs.readFileSync(path.join(repoRoot, 'server/discovery/publication-privacy.js'), 'utf8');
  const coverLeaseLine = relaySource
    .split('\n')
    .find((line) => line.includes('DISCOVERY_PUBLICATION_COVER_LEASE_MS')) || '';

  assert.equal(coverLeaseLine.includes('30 * 60 * 1000'), true);
  assert.equal(coverLeaseLine.includes('30 * 24 * 60 * 60 * 1000'), false);
});

test('post-PIR discovery snapshot cover is disabled rather than server-labelled', () => {
  const serverSource = fs.readFileSync(path.join(repoRoot, 'server/server.js'), 'utf8');
  const clientSource = fs.readFileSync(path.join(repoRoot, 'src/hooks/discovery/useDiscovery.ts'), 'utf8');

  assert.equal(serverSource.includes('normalizedMessage.coverOnly === true'), false);
  assert.equal(clientSource.includes('coverOnly: true'), false);
  assert.equal(clientSource.includes('snapshot-cover-disabled'), true);
});
