import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import test from 'node:test';
import { probeOnionHttps } from '../load-balancer/onion-health.js';

async function fixture(t, status = 200, socksStatus = 0) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-onion-health-'));
    const certificatePath = path.join(directory, 'certificate.crt');
    const keyPath = path.join(directory, 'private.key');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
        '-keyout', keyPath, '-out', certificatePath], { stdio: 'ignore', timeout: 10000 });
    fs.chmodSync(certificatePath, 0o644);
    const sockets = new Set();
    const requests = [];
    const server = https.createServer({ key: fs.readFileSync(keyPath), cert: fs.readFileSync(certificatePath),
        minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ecdhCurve: 'X25519MLKEM768' }, (req, res) => {
        requests.push({ path: req.url, host: req.headers.host });
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: status === 200 ? 'healthy' : 'unhealthy' }));
    });
    server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const proxyPath = path.join(directory, 'proxy.sock');
    const destinations = [];
    const proxy = net.createServer(socket => {
        sockets.add(socket);
        socket.once('close', () => sockets.delete(socket));
        socket.on('error', () => {});
        let buffer = Buffer.alloc(0);
        let greeting = false;
        const consume = chunk => {
            buffer = Buffer.concat([buffer, chunk]);
            if (!greeting) {
                if (buffer.length < 3) return;
                assert.deepEqual([...buffer.subarray(0, 3)], [5, 1, 0]);
                buffer = buffer.subarray(3);
                greeting = true;
                socket.write(Buffer.from([5]));
                queueMicrotask(() => socket.write(Buffer.from([0])));
            }
            if (buffer.length < 5 || buffer.length < 7 + buffer[4]) return;
            destinations.push({ host: buffer.subarray(5, 5 + buffer[4]).toString('ascii'), port: buffer.readUInt16BE(5 + buffer[4]) });
            socket.removeListener('data', consume);
            if (socksStatus !== 0) {
                socket.end(Buffer.from([5, socksStatus, 0, 1, 0, 0, 0, 0, 0, 0]));
                return;
            }
            const backend = net.connect(server.address().port, '127.0.0.1');
            sockets.add(backend);
            backend.once('close', () => sockets.delete(backend));
            backend.on('error', () => socket.destroy());
            socket.once('close', () => backend.destroy());
            backend.once('connect', () => {
                socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
                socket.pipe(backend).pipe(socket);
            });
        };
        socket.on('data', consume);
    });
    proxy.listen(proxyPath);
    await once(proxy, 'listening');
    t.after(async () => {
        for (const socket of sockets) socket.destroy();
        await Promise.all([new Promise(resolve => proxy.close(resolve)), new Promise(resolve => server.close(resolve))]);
        fs.rmSync(directory, { recursive: true, force: true });
    });
    return { certificatePath, proxyPath, requests, destinations, onionAddress: 'a'.repeat(56) + '.onion' };
}

test('onion health follows SOCKS through the private socket and verifies the configured hybrid TLS pin', async t => {
    const state = await fixture(t);
    const stages = [];
    t.mock.method(console, 'info', (_message, details) => stages.push(details));
    assert.equal(await probeOnionHttps({ ...state, timeoutMs: 2000 }), true);
    assert.deepEqual(state.destinations, [{ host: state.onionAddress, port: 443 }]);
    assert.deepEqual(state.requests, [{ path: '/api/health', host: state.onionAddress }]);
    assert.deepEqual(stages.map(entry => entry.phase), ['proxy-authentication', 'onion-connect', 'tls-handshake', 'backend-response']);
    assert.equal(stages[2].protocol, 'TLSv1.3');
    assert.equal(stages[3].status, 200);
    assert.equal(stages[3].reachable, true);
    for (const stage of stages) {
        assert.ok(stage.stageMs >= 0 && stage.elapsedMs >= stage.stageMs);
        assert.ok(Object.keys(stage).every(key => ['phase', 'stageMs', 'elapsedMs', 'protocol', 'status', 'reachable'].includes(key)));
    }
});

test('an unhealthy backend cannot authorize publication readiness', async t => {
    const state = await fixture(t, 503);
    assert.equal(await probeOnionHttps({ ...state, timeoutMs: 2000 }), false);
});

test('a substituted certificate cannot satisfy the onion health pin', async t => {
    const state = await fixture(t);
    const other = await fixture(t);
    await assert.rejects(probeOnionHttps({ ...state, certificatePath: other.certificatePath, timeoutMs: 2000 }));
});

test('a different leaf still fails the exact pin when its chain is trusted', async t => {
    const state = await fixture(t);
    const other = await fixture(t);
    const certificatePath = path.join(path.dirname(state.proxyPath), 'trusted-chain.crt');
    fs.writeFileSync(certificatePath, Buffer.concat([
        fs.readFileSync(other.certificatePath), fs.readFileSync(state.certificatePath),
    ]), { mode: 0o644 });
    await assert.rejects(probeOnionHttps({ ...state, certificatePath, timeoutMs: 2000 }), {
        code: 'CERT_PIN_MISMATCH',
    });
    assert.equal(state.requests.length, 0);
});

test('a Tor SOCKS failure records its stage and reply code without reaching TLS', async t => {
    const state = await fixture(t, 200, 4);
    const failures = [];
    t.mock.method(console, 'warn', (_message, details) => failures.push(details));
    await assert.rejects(probeOnionHttps({ ...state, timeoutMs: 2000 }), { code: 'SOCKS_4' });
    assert.equal(failures[0].phase, 'onion-connect');
    assert.equal(failures[0].errorCode, 'SOCKS_4');
    assert.equal(state.requests.length, 0);
});

test('an aborted onion probe stops immediately and cannot keep the process alive', async t => {
    const state = await fixture(t);
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(probeOnionHttps({ ...state, timeoutMs: 2000, signal: controller.signal }), /cancelled/);
});

test('a proxy that never responds is bounded by the health deadline', async t => {
    const state = await fixture(t);
    const failures = [];
    t.mock.method(console, 'warn', (_message, details) => failures.push(details));
    const stalled = net.createServer(socket => { socket.on('error', () => {}); t.after(() => socket.destroy()); });
    const proxyPath = path.join(path.dirname(state.proxyPath), 'stalled.sock');
    stalled.listen(proxyPath);
    await once(stalled, 'listening');
    t.after(() => { stalled.close(); });
    const began = Date.now();
    await assert.rejects(probeOnionHttps({ ...state, proxyPath, timeoutMs: 40 }));
    assert.ok(Date.now() - began < 1000);
    assert.equal(failures[0].phase, 'proxy-authentication');
    assert.equal(failures[0].errorCode, 'deadline');
});
