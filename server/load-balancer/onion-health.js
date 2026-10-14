import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';
import { readSecureTlsFile } from '../utils/secure-file.js';

function readBytes(socket, length) {
    return new Promise((resolve, reject) => {
        const cleanup = () => {
            socket.removeListener('readable', consume);
            socket.removeListener('error', fail);
            socket.removeListener('close', closed);
        };
        const fail = error => { cleanup(); reject(error); };
        const closed = () => fail(new Error('Onion health transport closed'));
        const consume = () => {
            const bytes = socket.read(length);
            if (bytes) { cleanup(); resolve(bytes); }
            else if (socket.destroyed) closed();
        };
        socket.on('readable', consume);
        socket.once('error', fail);
        socket.once('close', closed);
        consume();
    });
}

export async function probeOnionHttps({ proxyPath, onionAddress, certificatePath, timeoutMs, signal }) {
    if (!/^[a-z2-7]{56}\.onion$/.test(onionAddress)) throw new Error('Invalid health-check onion address');
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new Error('Invalid onion health timeout');
    const certificate = readSecureTlsFile(certificatePath);
    const pinned = new crypto.X509Certificate(certificate);
    const startedAt = performance.now();
    let phaseStartedAt = startedAt;
    let phase = 'proxy-authentication';
    let closeReason;
    const completed = (nextPhase, details = {}) => {
        const now = performance.now();
        console.info('[TOR-HEALTH] Transport stage completed', {
            phase,
            stageMs: Math.round(now - phaseStartedAt),
            elapsedMs: Math.round(now - startedAt),
            ...details,
        });
        phase = nextPhase;
        phaseStartedAt = now;
    };
    let encrypted;
    const socket = net.connect({ path: proxyPath });
    const close = () => {
        encrypted?.destroy();
        socket.destroy();
    };
    const timer = setTimeout(() => { closeReason = 'deadline'; close(); }, timeoutMs);
    timer.unref?.();
    const abort = () => { closeReason = 'cancelled'; close(); };
    signal?.addEventListener('abort', abort, { once: true });
    socket.on('error', () => {});
    try {
        if (signal?.aborted) {
            closeReason = 'cancelled';
            throw new Error('Onion health check cancelled');
        }
        socket.write(Buffer.from([5, 1, 0]));
        const greeting = await readBytes(socket, 2);
        if (greeting[0] !== 5 || greeting[1] !== 0) {
            const error = new Error('Onion health proxy authentication failed');
            error.code = 'SOCKS_AUTHENTICATION';
            throw error;
        }
        completed('onion-connect');
        const host = Buffer.from(onionAddress, 'ascii');
        socket.write(Buffer.concat([Buffer.from([5, 1, 0, 3, host.length]), host, Buffer.from([1, 187])]));
        const response = await readBytes(socket, 4);
        if (response[0] !== 5 || response[1] !== 0 || response[2] !== 0) {
            const error = new Error('Onion health proxy connection failed');
            error.code = response[0] === 5 && response[2] === 0 ? `SOCKS_${response[1]}` : 'SOCKS_PROTOCOL';
            throw error;
        }
        if (response[3] === 1) await readBytes(socket, 6);
        else if (response[3] === 4) await readBytes(socket, 18);
        else if (response[3] === 3) {
            const size = await readBytes(socket, 1);
            await readBytes(socket, size[0] + 2);
        } else throw new Error('Invalid onion health proxy response');
        completed('tls-handshake');
        encrypted = tls.connect({
            socket,
            servername: onionAddress,
            ca: certificate,
            rejectUnauthorized: true,
            minVersion: 'TLSv1.3',
            maxVersion: 'TLSv1.3',
            ecdhCurve: 'X25519MLKEM768',
            checkServerIdentity: (_hostname, peer) => {
                if (!peer.raw || peer.raw.length !== pinned.raw.length ||
                    !crypto.timingSafeEqual(peer.raw, pinned.raw)) {
                    const error = new Error('Onion health certificate does not match the configured pin');
                    error.code = 'CERT_PIN_MISMATCH';
                    return error;
                }
            },
        });
        encrypted.on('error', () => {});
        await new Promise((resolve, reject) => {
            const cleanup = () => {
                encrypted.removeListener('secureConnect', ready);
                encrypted.removeListener('error', failed);
                encrypted.removeListener('close', closed);
            };
            const ready = () => { cleanup(); resolve(); };
            const failed = error => { cleanup(); reject(error); };
            const closed = () => failed(new Error('Onion health TLS transport closed'));
            encrypted.once('secureConnect', ready);
            encrypted.once('error', failed);
            encrypted.once('close', closed);
        });
        completed('backend-response', { protocol: encrypted.getProtocol() });
        encrypted.write(`GET /api/health HTTP/1.1\r\nHost: ${onionAddress}\r\nConnection: close\r\n\r\n`);
        let header = '';
        while (header.length < 4096 && !header.includes('\r\n\r\n')) {
            header += (await readBytes(encrypted, 1)).toString('latin1');
        }
        const status = Number(header.match(/^HTTP\/1\.[01] ([0-9]{3})(?: |\r)/)?.[1]) || null;
        const reachable = header.includes('\r\n\r\n') && status === 200;
        completed('complete', { status, reachable });
        return reachable;
    } catch (error) {
        console.warn('[TOR-HEALTH] Transport stage failed', {
            phase,
            stageMs: Math.round(performance.now() - phaseStartedAt),
            elapsedMs: Math.round(performance.now() - startedAt),
            errorCode: closeReason || error.code || error.name,
        });
        throw error;
    } finally {
        clearTimeout(timer);
        signal?.removeEventListener('abort', abort);
        close();
        certificate.fill(0);
    }
}
