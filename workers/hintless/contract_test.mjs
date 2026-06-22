// End-to-end contract test for the Qor hintless-SimplePIR binaries, driven from
// Node so it mirrors exactly what the real server (HTTP) and client (framed
// stdio daemon) will do:
//
//   1. POST /v1/databases     upload fixed-size records, build+preprocess epoch
//   2. daemon query-record    build the opaque request on the "device"
//   3. POST /v1/query         server answers the opaque request
//   4. daemon recover-record  device recovers the plaintext record
//   5. assert recovered == original, print real wire sizes
//
// Usage: node contract_test.mjs <worker_url> <client_binary>

import { spawn } from 'node:child_process';
import crypto from 'node:crypto';

const workerUrl = (process.argv[2] || 'http://127.0.0.1:8799').replace(/\/+$/, '');
const clientBin = process.argv[3] || 'bazel-bin/qor/qor_pir_client';
const PARAMETER_ID = 'hintless-simplepir-rlwe64-v1';

function b64urlDecode(s) {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

async function postJson(path, body) {
  const res = await fetch(`${workerUrl}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });
  const text = await res.text();
  let parsed;
  try { parsed = JSON.parse(text); } catch { parsed = { raw: text }; }
  return { status: res.status, body: parsed };
}

// Framed stdio client to the daemon: 4-byte BE length + JSON, both directions.
class Daemon {
  constructor(bin) {
    this.proc = spawn(bin, ['serve'], { stdio: ['pipe', 'pipe', 'inherit'] });
    this.buf = Buffer.alloc(0);
    this.waiters = [];
    this.proc.stdout.on('data', (chunk) => {
      this.buf = Buffer.concat([this.buf, chunk]);
      this.drain();
    });
    this.id = 1;
  }
  drain() {
    while (this.buf.length >= 4) {
      const n = this.buf.readUInt32BE(0);
      if (this.buf.length < 4 + n) return;
      const payload = this.buf.subarray(4, 4 + n);
      this.buf = this.buf.subarray(4 + n);
      const waiter = this.waiters.shift();
      if (waiter) waiter(JSON.parse(payload.toString('utf8')));
    }
  }
  call(obj) {
    const req = { ...obj, id: this.id++ };
    const json = Buffer.from(JSON.stringify(req), 'utf8');
    const len = Buffer.alloc(4);
    len.writeUInt32BE(json.length, 0);
    return new Promise((resolve) => {
      this.waiters.push(resolve);
      this.proc.stdin.write(Buffer.concat([len, json]));
    });
  }
  stop() { this.proc.kill(); }
}

function makeRecords(n, b) {
  const records = [];
  for (let i = 0; i < n; i++) {
    const r = Buffer.alloc(b);
    r[0] = 65 + (i % 26);
    for (let j = 1; j < b; j++) r[j] = (i * 131 + j * 7) & 0xff;
    records.push(r);
  }
  return records;
}

async function runCase(kind, epochId, n, b, target) {
  const records = makeRecords(n, b);
  const digest = crypto.createHash('sha256')
    .update(Buffer.concat(records.map((r) => crypto.createHash('sha256').update(r).digest())))
    .digest('base64url');

  const upload = await postJson('/v1/databases', {
    manifest: {
      version: 'v1', kind, epochId, schemeId: 'hintless-simplepir',
      parameterId: PARAMETER_ID, recordSize: b, recordCount: n, databaseDigest: digest
    },
    records: records.map((r) => r.toString('base64'))
  });
  if (upload.status !== 200 || upload.body.accepted !== true) {
    throw new Error(`upload failed: ${upload.status} ${JSON.stringify(upload.body)}`);
  }
  if (upload.body.databaseDigest !== digest) throw new Error('digest echo mismatch');
  const { publicParams, dbRows, dbCols } = upload.body;

  const daemon = new Daemon(clientBin);
  try {
    const q = await daemon.call({
      operation: 'query-record', parameterId: PARAMETER_ID,
      recordCount: n, recordSize: b, publicParams, index: target
    });
    if (!q.success) throw new Error(`query-record failed: ${q.error}`);

    const answer = await postJson('/v1/query', { kind, epochId, query: q.request });
    if (answer.status !== 200 || typeof answer.body.response !== 'string') {
      throw new Error(`query failed: ${answer.status} ${JSON.stringify(answer.body)}`);
    }

    const rec = await daemon.call({
      operation: 'recover-record', handle: q.handle, response: answer.body.response
    });
    if (!rec.success) throw new Error(`recover-record failed: ${rec.error}`);

    const got = b64urlDecode(rec.record).subarray(0, b);
    if (!got.equals(records[target])) throw new Error('recovered record mismatch');

    const qBytes = Buffer.byteLength(q.request, 'utf8');
    const aBytes = Buffer.byteLength(answer.body.response, 'utf8');
    console.log(
      `OK  ${kind} n=${n} b=${b} -> db ${dbRows}x${dbCols}  ` +
      `upload=${(qBytes / 1024).toFixed(1)}KiB  download=${(aBytes / 1024).toFixed(1)}KiB`
    );
  } finally {
    daemon.stop();
  }
}

async function main() {
  const health = await fetch(`${workerUrl}/health`).then((r) => r.json());
  if (!health.ok || health.parameterId !== PARAMETER_ID) {
    throw new Error(`health bad: ${JSON.stringify(health)}`);
  }
  // Small records (= few shards) keep preprocess/query fast; HintlessPIR cost
  // scales with record SIZE, not record COUNT, so we also prove a large DB.
  await runCase('discovery', 'epoch-a', 1000, 16, 501);
  await runCase('opaque', 'epoch-c', 200, 32, 137);
  await runCase('discovery', 'epoch-d', 1, 24, 0);
  await runCase('discovery', 'epoch-e', 200000, 8, 199999); // big DB, tiny record
  console.log('CONTRACT TEST PASS');
}

main().catch((e) => { console.error('CONTRACT TEST FAIL:', e.message); process.exit(1); });
