import assert from 'node:assert/strict';
import fs from 'node:fs';
import { performance } from 'node:perf_hooks';
import { setImmediate } from 'node:timers/promises';
import test from 'node:test';
import ts from 'typescript';
import { blake3 } from '@noble/hashes/blake3.js';
import { hasExactPlainObjectKeys } from '../utils/validation.js';
import { SEALED_STANDARD_CIPHERTEXT_BYTES, validateSealedEnvelope } from '../routing/sealed-sender.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { BASE64URL_32_RE } from '../../shared/patterns.js';
import { HASH_OUTPUT_BYTES, ML_KEM_1024_CIPHERTEXT_BYTES, SEALED_NONCE_BYTES } from '../../shared/crypto-sizes.js';
import { SPOOL_PIR_RECORD_BYTES, SPOOL_PIR_ROWS_PER_RECORD, SPOOL_PIR_ROW_BYTES, splitSpoolPirRecord } from '../../shared/spool-pir-layout.js';

const source = fs.readFileSync(new URL('../routing/blind-router.js', import.meta.url), 'utf8');
const ast = ts.createSourceFile('blind-router.js', source, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
const wanted = new Set(['parseGlobalSpoolStoredEntry', 'getEnvelopeHash', 'validateGlobalEnvelope', 'parseGlobalSpoolIndexMember', 'isCurrentGlobalSpoolRow', 'readGlobalMixPirSnapshot']);
const declarations = ast.statements.filter(node => ts.isFunctionDeclaration(node) && wanted.has(node.name?.text))
    .map(node => node.getText(ast).replace(/^export\s+/, '')).join('\n');
const indexPattern = /^([A-Za-z0-9_-]{43}):([1-9][0-9]{0,9}):([0-9a-f]{16}):([0-9a-f]{64})$/;

function records(count) {
    return Array.from({ length: count }, (_, index) => {
        const nonce = Buffer.alloc(SEALED_NONCE_BYTES);
        nonce.writeUInt32BE(index);
        const envelope = {
            version: PROTOCOL_KEYS.SEALED_ENVELOPE_PROTOCOL,
            ciphertext: Buffer.alloc(SEALED_STANDARD_CIPHERTEXT_BYTES, 0x41).toString('base64'),
            ephemeralKey: Buffer.alloc(ML_KEM_1024_CIPHERTEXT_BYTES, 0x42).toString('base64'),
            nonce: nonce.toString('base64'), tag: '44'.repeat(8), probe: '55'.repeat(32),
        };
        const canonical = JSON.stringify({ version: envelope.version, ciphertext: envelope.ciphertext, ephemeralKey: envelope.ephemeralKey, nonce: envelope.nonce });
        const hash = Buffer.from(blake3(Buffer.from(`${PROTOCOL_KEYS.GLOBAL_MIX_HASH}\0${canonical}`), { dkLen: HASH_OUTPUT_BYTES })).toString('base64url');
        const id = Buffer.from(blake3(Buffer.from(`${PROTOCOL_KEYS.GLOBAL_SPOOL_HASH}\0${hash}`), { dkLen: HASH_OUTPUT_BYTES })).toString('base64url');
        const raw = JSON.stringify({ id, envelope });
        return { id, raw, member: `${id}:${Buffer.byteLength(raw)}:${envelope.tag}:${envelope.probe}` };
    });
}

function reader(entries, mutate = value => value) {
    const values = new Map(entries.map(entry => [`${PROTOCOL_KEYS.MIXNET_SPOOL_ENTRY_REDIS_PREFIX}${entry.id}`, entry.raw]));
    const batches = [];
    const client = {
        async zrangebyscore() { return entries.map(entry => entry.member); },
        async mget(...keys) { batches.push(keys.length); return mutate(keys.map(key => values.get(key)), batches.length); },
    };
    const dependencies = {
        blake3, hasExactPlainObjectKeys, validateSealedEnvelope, PROTOCOL_KEYS, BASE64URL_32_RE, HASH_OUTPUT_BYTES,
        GLOBAL_MIX_SPOOL_MEMBER_BYTES: Buffer.byteLength(entries[0].raw), GLOBAL_MIX_SPOOL_INDEX_MEMBER_RE: indexPattern,
        GLOBAL_MIX_PUBLICATION_MAX_BYTES: 2 * 1024 * 1024, GLOBAL_MIX_SPOOL_TTL_SECONDS: 86400,
        GLOBAL_MIX_SPOOL_READ_EXPIRY_GUARD_MS: 30000, GLOBAL_MIX_SPOOL_READ_BATCH: 16,
        SEALED_STANDARD_CIPHERTEXT_BASE64_CHARS: Math.ceil(SEALED_STANDARD_CIPHERTEXT_BYTES / 3) * 4,
        setImmediate, withRedisClient: callback => callback(client), trimExpiredGlobalMixSpool: async () => {},
    };
    const read = new Function(...Object.keys(dependencies), declarations + '\nreturn readGlobalMixPirSnapshot;')(...Object.values(dependencies));
    return { read, batches };
}

test('PIR snapshot validation yields to timers and reads only bounded Redis batches', async () => {
    const entries = records(128);
    const fixture = reader(entries);
    let ticks = 0;
    let previous = performance.now();
    let maximumGap = 0;
    const timer = setInterval(() => {
        const now = performance.now();
        maximumGap = Math.max(maximumGap, now - previous);
        previous = now;
        ticks++;
    }, 10);
    let snapshot;
    try {
        snapshot = await fixture.read();
        assert.equal(snapshot.records.length, entries.length);
        assert.deepEqual(snapshot.ids, entries.map(entry => entry.id));
        assert.ok(fixture.batches.every(size => size <= 16));
        assert.equal(fixture.batches.length, 8);
        assert.ok(ticks >= 5);
        assert.ok(maximumGap < 250, `Snapshot blocked timers for ${maximumGap} ms`);
    } finally {
        clearInterval(timer);
        for (const record of snapshot?.records || []) record.fill(0);
    }
});

test('a malformed or expired later snapshot batch still rejects instead of publishing partial data', async () => {
    const entries = records(17);
    for (const bad of [null, '{']) {
        const fixture = reader(entries, (values, batch) => batch === 2 ? [bad] : values);
        await assert.rejects(fixture.read(), /invalid_global_mix_spool_entry|expired_during_pir_build/);
        assert.deepEqual(fixture.batches, [16, 1]);
    }
});

test('PIR row packing and temporary database output avoid full-database copies on the main thread', () => {
    const service = fs.readFileSync(new URL('../pir/pir-service.js', import.meta.url), 'utf8');
    const worker = fs.readFileSync(new URL('../pir/pir-worker-client.js', import.meta.url), 'utf8');
    assert.match(service, /rows = await pirRows\(source\.records\)/);
    assert.match(service, /Buffer\.from\(row\.buffer, row\.byteOffset, row\.byteLength\)/);
    assert.doesNotMatch(worker, /Buffer\.concat\(records\)/);
    assert.match(worker, /records\.slice\(offset, offset \+ 32\)/);
    assert.match(worker, /if \(created\) await fs\.rm\(file/);
});

function rowPacker(split = splitSpoolPirRecord) {
    const source = fs.readFileSync(new URL('../pir/pir-service.js', import.meta.url), 'utf8');
    const ast = ts.createSourceFile('pir-service.js', source, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
    const functions = ast.statements.filter(node => ts.isFunctionDeclaration(node) && ['validatePirRecords', 'pirRows'].includes(node.name?.text))
        .map(node => node.getText(ast)).join('\n');
    return new Function('SPOOL_PIR_RECORD_BYTES', 'splitSpoolPirRecord', 'setImmediate', functions + '\nreturn pirRows;')(
        SPOOL_PIR_RECORD_BYTES, split, setImmediate,
    );
}

test('yielding PIR row packing preserves every record byte and zero-pads only its last row', async () => {
    const source = [Buffer.alloc(SPOOL_PIR_RECORD_BYTES, 0x31), Buffer.alloc(SPOOL_PIR_RECORD_BYTES, 0x42)];
    const packed = await rowPacker()(source);
    assert.equal(packed.length, source.length * SPOOL_PIR_ROWS_PER_RECORD);
    for (let index = 0; index < source.length; index++) {
        const rows = packed.slice(index * SPOOL_PIR_ROWS_PER_RECORD, (index + 1) * SPOOL_PIR_ROWS_PER_RECORD);
        assert.ok(rows.every(row => Buffer.isBuffer(row) && row.length === SPOOL_PIR_ROW_BYTES));
        const joined = Buffer.concat(rows);
        assert.deepEqual(joined.subarray(0, SPOOL_PIR_RECORD_BYTES), source[index]);
        assert.ok(joined.subarray(SPOOL_PIR_RECORD_BYTES).every(byte => byte === 0));
    }
    for (const row of packed) row.fill(0);
    assert.ok(source[0].every(byte => byte === 0x31));
});

test('partially packed PIR rows are wiped if a later split fails', async () => {
    let calls = 0;
    let created;
    const pack = rowPacker(record => {
        if (++calls > 1) throw new Error('split failed');
        return created = splitSpoolPirRecord(record);
    });
    await assert.rejects(pack(Array(2).fill(Buffer.alloc(SPOOL_PIR_RECORD_BYTES, 0x31))), /split failed/);
    assert.ok(created.every(row => row.every(byte => byte === 0)));
});
