import test from 'node:test';
import assert from 'node:assert/strict';

function testDatabase() {
  return {
    manifest: {
      version: 1,
      kind: 'discovery',
      epochId: 'epoch-retry-test',
      schemeId: 'hintless-simplepir',
      parameterId: 'hintless-simplepir-rlwe64-v1',
      recordSize: 1,
      recordCount: 1,
      databaseDigest: 'digest-retry-test'
    },
    records: [Buffer.from([1])]
  };
}

test('uploadPirDatabase retries transient UND_ERR_SOCKET failures', async () => {
  const originalFetch = globalThis.fetch;
  const originalEnv = {
    PIR_WORKER_URL: process.env.PIR_WORKER_URL,
    PIR_WORKER_REQUEST_RETRIES: process.env.PIR_WORKER_REQUEST_RETRIES,
    PIR_WORKER_RETRY_BASE_MS: process.env.PIR_WORKER_RETRY_BASE_MS,
    PIR_WORKER_RETRY_MAX_MS: process.env.PIR_WORKER_RETRY_MAX_MS
  };

  process.env.PIR_WORKER_URL = 'http://pir-worker.test';
  process.env.PIR_WORKER_REQUEST_RETRIES = '1';
  process.env.PIR_WORKER_RETRY_BASE_MS = '1';
  process.env.PIR_WORKER_RETRY_MAX_MS = '1';

  let calls = 0;
  globalThis.fetch = async (url) => {
    calls += 1;
    assert.equal(url, 'http://pir-worker.test/v1/databases');
    if (calls === 1) {
      const error = new TypeError('fetch failed');
      error.cause = { code: 'UND_ERR_SOCKET' };
      throw error;
    }
    return new Response(JSON.stringify({
      accepted: true,
      epochId: 'epoch-retry-test',
      databaseDigest: 'digest-retry-test',
      publicParams: 'public-params'
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' }
    });
  };

  try {
    const { uploadPirDatabase } = await import(`../pir/pir-worker-client.js?retry-test=${Date.now()}`);
    const result = await uploadPirDatabase(testDatabase());

    assert.equal(calls, 2);
    assert.equal(result.uploaded, true);
    assert.equal(result.publicParams.publicParams, 'public-params');
  } finally {
    globalThis.fetch = originalFetch;
    for (const [key, value] of Object.entries(originalEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});
