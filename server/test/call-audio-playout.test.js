import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import ts from 'typescript';
import { createRequire } from 'node:module';
import { createElement, memo, useCallback, useSyncExternalStore } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

function load(relative, dependencies = {}) {
    const source = fs.readFileSync(new URL(relative, import.meta.url), 'utf8');
    const ast = ts.createSourceFile(relative, source, ts.ScriptTarget.ES2022, true);
    const body = ast.statements.filter(node => !ts.isImportDeclaration(node)).map(node => node.getText(ast)).join('\n');
    const compiled = ts.transpileModule(body, { fileName: relative, compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX } }).outputText;
    const exports = {};
    new Function('exports', ...Object.keys(dependencies), compiled)(exports, ...Object.values(dependencies));
    return exports;
}

const { CallAudioPlayout } = load('../../src/lib/transport/call-audio-playout.ts', {
    SecureMemory: { zeroBuffer: bytes => bytes.fill(0) },
});

function packet(sequence, arrivedAt = 1000, discontinuity = false, dtx = false) {
    return { sequence: sequence >>> 0, capturedAt: 1_700_000_000_000 + sequence * 20,
        arrivedAt, discontinuity, packet: dtx ? Uint8Array.of(1) : Uint8Array.of(2, sequence & 255) };
}

function frame(buffer, now, nativeQueuedMs = 0) {
    const result = buffer.next(now, nativeQueuedMs);
    assert.ok(result);
    return result;
}

test('a stable audio path starts within sixty milliseconds without dropping any speech', () => {
    const buffer = new CallAudioPlayout();
    let firstOutputAt = null;
    const played = [];
    for (let sequence = 0; sequence < 30; sequence++) {
        const now = 1000 + sequence * 20;
        buffer.push(packet(sequence, now));
        const value = buffer.next(now, 0);
        if (!value) continue;
        firstOutputAt ??= now;
        played.push(value.packet[1]);
    }
    assert.ok(firstOutputAt - 1000 <= 60, `startup held audio for ${firstOutputAt - 1000} ms`);
    for (let now = 1600; played.length < 30; now += 20) played.push(frame(buffer, now).packet[1]);
    assert.deepEqual(played, Array.from({ length: 30 }, (_, sequence) => sequence));
    assert.equal(buffer.snapshot().rebufferCount, 0);
    assert.equal(buffer.snapshot().lateDrops, 0);
});

test('an empty encoded queue does not rebuffer while native playback still has audio', () => {
    const buffer = new CallAudioPlayout();
    for (let sequence = 0; sequence < 6; sequence++) buffer.push(packet(sequence, 1000 + sequence * 20));
    for (let sequence = 0; sequence < 6; sequence++) frame(buffer, 1120);
    assert.equal(buffer.next(1120, 60), null);
    assert.equal(buffer.snapshot().buffering, false);
    assert.equal(buffer.snapshot().rebufferCount, 0);
    buffer.push(packet(6, 1140));
    assert.equal(frame(buffer, 1140, 40).packet[1], 6);
    assert.equal(buffer.snapshot().rebufferCount, 0);
});

test('a real native underrun still enables bounded jitter rebuffering', () => {
    const buffer = new CallAudioPlayout();
    for (let sequence = 0; sequence < 6; sequence++) buffer.push(packet(sequence, 1000 + sequence * 20));
    for (let sequence = 0; sequence < 6; sequence++) frame(buffer, 1120);
    buffer.next(1120, 40);
    buffer.next(1160, 0);
    assert.equal(buffer.snapshot().buffering, true);
    assert.equal(buffer.snapshot().rebufferCount, 1);
    buffer.push(packet(6, 1300));
    assert.equal(buffer.next(1300, 0), null);
    assert.equal(frame(buffer, 1900).packet[1], 6);
    assert.equal(buffer.snapshot().lateDrops, 0);
});

test('normal Tor bursts retain all speech instead of clipping to five packets', () => {
    const buffer = new CallAudioPlayout();
    for (let sequence = 0; sequence < 24; sequence++) buffer.push(packet(sequence));
    assert.equal(buffer.snapshot().bufferedMs, 480);
    for (let sequence = 0; sequence < 24; sequence++) {
        const decoded = frame(buffer, 1200 + sequence * 20);
        assert.equal(decoded.packet[1], sequence);
        assert.equal(decoded.fec, false);
    }
    assert.equal(buffer.snapshot().lateDrops, 0);
    assert.equal(buffer.snapshot().overflowDrops, 0);
});

test('an empty arrival gap does not discard the next valid speech frames', () => {
    const buffer = new CallAudioPlayout();
    buffer.push(packet(0));
    assert.equal(frame(buffer, 1200).packet[1], 0);
    for (let now = 1220; now < 1800; now += 20) assert.equal(buffer.next(now, 0), null);
    for (let sequence = 1; sequence < 13; sequence++) buffer.push(packet(sequence, 1800));
    for (let sequence = 1; sequence < 13; sequence++) assert.equal(frame(buffer, 2400 + sequence * 20).packet[1], sequence);
    assert.equal(buffer.snapshot().lateDrops, 0);
    assert.ok(buffer.snapshot().targetMs > 100);
    assert.equal(buffer.snapshot().rebufferCount, 1);
});

test('discontinuities do not erase earlier buffered speech', () => {
    const buffer = new CallAudioPlayout();
    for (let sequence = 0; sequence < 10; sequence++) buffer.push(packet(sequence));
    buffer.push(packet(20, 1200, true));
    for (let sequence = 0; sequence < 10; sequence++) assert.equal(frame(buffer, 1500 + sequence * 20).packet[1], sequence);
    assert.equal(frame(buffer, 1750).packet[1], 20);
});

test('reordered frames get a bounded grace period before concealment', () => {
    const buffer = new CallAudioPlayout();
    buffer.push(packet(0));
    frame(buffer, 1200);
    buffer.push(packet(2, 1200));
    assert.equal(buffer.next(1210, 0), null);
    buffer.push(packet(1, 1220));
    assert.equal(frame(buffer, 1230).packet[1], 1);
    assert.equal(frame(buffer, 1250).packet[1], 2);
    assert.equal(buffer.snapshot().concealedFrames, 0);
});

test('FEC copies its packet so the next real frame remains playable after wiping', () => {
    const buffer = new CallAudioPlayout();
    buffer.push(packet(0));
    const following = packet(2);
    buffer.push(following);
    frame(buffer, 1200);
    const fec = frame(buffer, 1220);
    assert.equal(fec.fec, true);
    assert.notEqual(fec.packet, following.packet);
    fec.packet.fill(0);
    assert.equal(frame(buffer, 1240).packet[1], 2);
});

test('DTX silence uses the same jitter protection and codec timeline as speech', () => {
    const buffer = new CallAudioPlayout();
    buffer.push(packet(0, 1000, false, true));
    assert.equal(buffer.next(1000, 0), null);
    for (let sequence = 1; sequence < 20; sequence++) {
        buffer.push(packet(sequence, 1200, false, true));
    }
    for (let sequence = 0; sequence < 20; sequence++) {
        assert.equal(frame(buffer, 1200 + sequence * 20).packet.length, 1);
    }
    buffer.push(packet(20, 1600));
    assert.equal(frame(buffer, 1600).packet[1], 20);
    assert.equal(buffer.snapshot().concealedFrames, 0);
    assert.equal(buffer.snapshot().rebufferCount, 0);
});

test('wrapped sequences remain ordered and stale packets are wiped', () => {
    const buffer = new CallAudioPlayout();
    for (const sequence of [0xffff_fffe, 0xffff_ffff, 0, 1]) buffer.push(packet(sequence));
    for (const sequence of [254, 255, 0, 1]) assert.equal(frame(buffer, 1800).packet[1], sequence);
    const stale = packet(0xffff_ffff);
    assert.equal(buffer.push(stale), false);
    assert.ok(stale.packet.every(byte => byte === 0));
});

test('backlog is bounded and dropped or destroyed packets are wiped', () => {
    const buffer = new CallAudioPlayout();
    const packets = Array.from({ length: 80 }, (_, sequence) => packet(sequence));
    for (const value of packets) buffer.push(value);
    assert.equal(buffer.snapshot().bufferedMs, 1200);
    assert.equal(buffer.snapshot().overflowDrops, 20);
    assert.ok(packets.slice(0, 20).every(value => value.packet.every(byte => byte === 0)));
    buffer.clear();
    assert.ok(packets.every(value => value.packet.every(byte => byte === 0)));
});

test('bursty 50fps audio survives delayed UI timers without intentional speech drops', () => {
    const buffer = new CallAudioPlayout();
    const incoming = [];
    let sequence = 0;
    let delivery = 250;
    for (const batch of Array(100).fill([6, 12, 20, 8]).flat()) {
        delivery += batch * 20;
        for (let index = 0; index < batch; index++) incoming.push(packet(sequence++, delivery));
    }
    let cursor = 0;
    let queuedMs = 0;
    let played = 0;
    for (let now = 0; now <= delivery + 2000; now++) {
        queuedMs = Math.max(0, queuedMs - 1);
        while (cursor < incoming.length && incoming[cursor].arrivedAt <= now) buffer.push(incoming[cursor++]);
        if (now % 20 !== 0 || (now % 2000 > 1100 && now % 2000 < 1170)) continue;
        for (let count = 0; count < 4 && queuedMs < 80; count++) {
            const value = buffer.next(now, queuedMs);
            if (!value) break;
            assert.equal(value.packet[1], played & 255);
            played++;
            queuedMs += 20;
        }
    }
    assert.equal(played, incoming.length);
    assert.equal(buffer.snapshot().lateDrops, 0);
    assert.equal(buffer.snapshot().overflowDrops, 0);
});

for (const burstFrames of [1, 4, 5, 6]) {
    test(`${burstFrames * 20} ms arrival bursts keep bounded latency without speech loss or native underruns`, () => {
        const buffer = new CallAudioPlayout();
        const output = [];
        const delays = [];
        const total = 500;
        let queuedMs = 0;
        let received = 0;
        let played = 0;
        let underrunMs = 0;
        for (let now = 1000; now < 16000 && played < total; now++) {
            if (output.length) {
                const current = output[0];
                if (current.remaining === 20) delays.push(now - current.capturedAt);
                current.remaining--;
                queuedMs--;
                if (current.remaining === 0) {
                    output.shift();
                    played++;
                }
            } else if (delays.length) {
                underrunMs++;
            }
            if (played === total) break;
            let arrived = false;
            while (received < total && 1300 + (Math.floor(received / burstFrames) + 1) * burstFrames * 20 <= now) {
                const sequence = received++;
                buffer.push({ ...packet(sequence, now), capturedAt: 1000 + sequence * 20 });
                arrived = true;
            }
            if (now % 20 !== 0 && !arrived) continue;
            for (let count = 0; count < 4 && queuedMs < 80; count++) {
                const value = buffer.next(now, queuedMs);
                if (!value) break;
                const sequence = played + output.length;
                assert.equal(value.fec, false);
                assert.equal(value.packet[1], sequence & 255);
                output.push({ remaining: 20, capturedAt: 1000 + sequence * 20 });
                queuedMs += 20;
            }
        }
        assert.equal(played, total);
        assert.equal(underrunMs, 0);
        assert.equal(buffer.snapshot().overflowDrops, 0);
        assert.equal(buffer.snapshot().lateDrops, 0);
        assert.ok(Math.max(...delays) <= 300 + Math.max(60, burstFrames * 20) + 2);
    });
}

test('speaker levels are coalesced, silence-expiring, and isolated to the active call', t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const levels = load('../../src/lib/ui/call-speaker-level.ts');
    let updates = 0;
    const unsubscribe = levels.subscribeCallSpeakerLevel(() => updates++);
    levels.startCallSpeakerLevel('first');
    levels.updateCallSpeakerLevel('first', 0.001);
    t.mock.timers.tick(60);
    assert.equal(levels.getCallSpeakerLevel('first'), 0);
    levels.updateCallSpeakerLevel('first', 0.1);
    levels.updateCallSpeakerLevel('first', 0.2);
    t.mock.timers.tick(60);
    assert.ok(levels.getCallSpeakerLevel('first') > 0.8);
    assert.equal(updates, 1);
    t.mock.timers.tick(200);
    assert.equal(levels.getCallSpeakerLevel('first'), 0);
    levels.startCallSpeakerLevel('second');
    levels.updateCallSpeakerLevel('first', 1);
    t.mock.timers.tick(60);
    assert.equal(levels.getCallSpeakerLevel('second'), 0);
    levels.updateCallSpeakerLevel('second', 0.1);
    levels.clearCallSpeakerLevel('second');
    t.mock.timers.tick(1000);
    assert.equal(levels.getCallSpeakerLevel('second'), 0);
    unsubscribe();
});

function receiver(native, codec, overrides = {}) {
    const filename = new URL('../../src/lib/transport/secure-calling-service.ts', import.meta.url);
    const source = fs.readFileSync(filename, 'utf8');
    const ast = ts.createSourceFile('service.ts', source, ts.ScriptTarget.ES2022, true);
    const declaration = ast.statements.find(node => ts.isClassDeclaration(node) && node.name.text === 'SecureCallingService');
    const methods = declaration.members.filter(node => ['receiveAudioStream', 'switchSpeaker', 'startAudioStreaming'].includes(node.name?.getText(ast)));
    const helpers = ast.statements.filter(node => ts.isFunctionDeclaration(node) &&
        ['createAudioPacket', 'encodeCallAudioBatch'].includes(node.name?.text));
    const body = ts.transpileModule(`${helpers.map(node => node.getText(ast)).join('\n')}
        export class Receiver { ${methods.map(method => method.getText(ast)).join('\n')} }`, {
        compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
    }).outputText;
    const dependencies = { CallAudioPlayout, AUDIO_FRAME_DURATION_MS: 20, NATIVE_AUDIO_TARGET_MS: 80,
        AUDIO_PACKET_HEADER_BYTES: 14, AUDIO_BATCH_VERSION: 2, AUDIO_BATCH_HEADER_BYTES: 4,
        AUDIO_BATCH_ENTRY_BYTES: 2, MAX_AUDIO_BATCH_PACKETS: 4, MAX_AUDIO_BATCH_BYTES: 5172,
        MAX_AUDIO_PLAINTEXT_BYTES: 1290, OPUS_MAX_PACKET_BYTES: 1276, OPUS_PCM_BYTES: 3840,
        MAX_PENDING_AUDIO_CAPTURE_FRAMES: 5, AUDIO_SEND_DEADLINE_MS: 160, AUDIO_SEND_DEADLINE_MAX_MS: 320,
        SecureMemory: { zeroBuffer: value => value.fill(0) },
        nativeAudioPlayback: native, audioCodec: codec,
        decodeCallAudioBatch: () => Array.from({ length: 24 }, (_, sequence) => packet(sequence, Date.now())),
        startCallSpeakerLevel() {}, updateCallSpeakerLevel() {}, clearCallSpeakerLevel() {},
        isValidMediaDeviceId: () => true, updateAppSettingsAsync: async () => {},
        ...overrides,
    };
    const exports = {};
    new Function('exports', ...Object.keys(dependencies), body)(exports, ...Object.values(dependencies));
    return new exports.Receiver();
}

async function flush() {
    for (let count = 0; count < 40; count++) await Promise.resolve();
}

function incomingStream() {
    let close;
    return {
        async *[Symbol.asyncIterator]() { yield Uint8Array.of(1); await new Promise(resolve => { close = resolve; }); },
        close: () => close(),
    };
}

function configureReceiver(service, stream) {
    service.mediaGeneration = 0;
    service.audioOutputGeneration = 0;
    service.audioStream = stream;
    service.audioCodecSessionId = 'first';
    service.audioPlaybackSessionId = 'first';
    service.callTelemetry = null;
}

test('the real sender sends every DTX frame instead of suppressing the decoder timeline', async t => {
    t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: 1000 });
    const batches = [];
    const encoded = [];
    const service = receiver({}, {
        encode: async (_id, pcm) => {
            encoded.push(pcm);
            return Uint8Array.of(1);
        },
    }, {
        nativeMicrophone: {
            pull: async (_id, after) => new Promise(resolve => setTimeout(() => resolve({
                sequence: after + 1, capturedAt: Date.now(), pcm: new Uint8Array(3840).fill(7),
            }), 20)),
        },
    });
    configureReceiver(service, { write: async data => { batches.push(data.slice()); } });
    service.microphoneSwitchGeneration = 0;
    service.microphoneSessionId = 'first';
    service.nextAudioCaptureSequence = 0;
    await service.startAudioStreaming();
    for (let count = 0; count < 80; count++) {
        t.mock.timers.tick(20);
        await flush();
    }
    service.mediaGeneration++;
    t.mock.timers.tick(20);
    await flush();
    const sequences = [];
    for (const batch of batches) {
        const view = new DataView(batch.buffer, batch.byteOffset, batch.byteLength);
        let offset = 4;
        for (let index = 0; index < batch[1]; index++) {
            const length = view.getUint16(offset, false);
            offset += 2;
            assert.equal(length, 15);
            sequences.push(view.getUint32(offset + 2, false));
            offset += length;
        }
    }
    assert.deepEqual(sequences, Array.from({ length: 80 }, (_, index) => index));
    assert.equal(encoded.length, 80);
    assert.ok(encoded.every(bytes => bytes.every(byte => byte === 0)));
});

test('the real receiver replenishes from the native clock after a delayed timer tick', async t => {
    t.mock.timers.enable({ apis: ['Date', 'setInterval'], now: 1000 });
    let queuedMs = 0;
    let measuredAt = Date.now();
    const info = () => {
        queuedMs = Math.max(0, queuedMs - (Date.now() - measuredAt));
        measuredAt = Date.now();
        return { queuedMs, level: 0 };
    };
    const decoded = [];
    const service = receiver({ info: async () => info() }, {
        decodeToPlayback: async (_id, bytes) => { decoded.push(bytes[1]); info(); queuedMs += 20; return info(); },
    });
    const stream = incomingStream();
    configureReceiver(service, stream);
    const receiving = service.receiveAudioStream();
    await flush();
    assert.deepEqual(decoded, [0, 1, 2, 3]);
    t.mock.timers.tick(70);
    await flush();
    assert.deepEqual(decoded, [0, 1, 2, 3, 4, 5, 6, 7]);
    assert.ok(queuedMs >= 80);
    stream.close();
    await receiving;
});

test('the real receiver resumes arriving speech immediately while native playback is still buffered', async t => {
    t.mock.timers.enable({ apis: ['Date', 'setInterval'], now: 1000 });
    let queuedMs = 0;
    let measuredAt = Date.now();
    const info = () => {
        queuedMs = Math.max(0, queuedMs - (Date.now() - measuredAt));
        measuredAt = Date.now();
        return { queuedMs, level: 0 };
    };
    let releaseNext;
    let releaseEnd;
    const stream = {
        async *[Symbol.asyncIterator]() {
            yield Uint8Array.of(0);
            await new Promise(resolve => { releaseNext = resolve; });
            yield Uint8Array.of(1);
            await new Promise(resolve => { releaseEnd = resolve; });
        },
    };
    const decoded = [];
    const service = receiver({ info: async () => info() }, {
        decodeToPlayback: async (_id, bytes) => {
            decoded.push(bytes[1]);
            info();
            queuedMs += 20;
            return info();
        },
    }, {
        decodeCallAudioBatch: data => data[0] === 0
            ? Array.from({ length: 6 }, (_, sequence) => packet(sequence, Date.now()))
            : [packet(6, Date.now())],
    });
    configureReceiver(service, stream);
    const receiving = service.receiveAudioStream();
    try {
        await flush();
        t.mock.timers.tick(40);
        await flush();
        assert.deepEqual(decoded, [0, 1, 2, 3, 4, 5]);
        t.mock.timers.tick(20);
        await flush();
        assert.equal(info().queuedMs, 60);
        releaseNext();
        await flush();
        assert.deepEqual(decoded, [0, 1, 2, 3, 4, 5, 6]);
        assert.equal(info().queuedMs, 80);
    } finally {
        releaseEnd();
        await receiving;
    }
});

test('a stale native-output error during speaker switching cannot terminate the call', async t => {
    t.mock.timers.enable({ apis: ['Date', 'setInterval'], now: 1000 });
    let reject;
    const pending = new Promise((_resolve, fail) => { reject = fail; });
    let first = true;
    let ended = false;
    const service = receiver({ info: () => first ? (first = false, pending) : Promise.resolve({ queuedMs: 80, level: 0 }) }, {});
    const stream = incomingStream();
    configureReceiver(service, stream);
    service.endCall = () => { ended = true; };
    const receiving = service.receiveAudioStream();
    await flush();
    service.audioOutputGeneration++;
    service.audioPlaybackSessionId = null;
    reject(new Error('output is switching'));
    await flush();
    assert.equal(ended, false);
    service.audioPlaybackSessionId = 'first';
    t.mock.timers.tick(20);
    await flush();
    assert.equal(ended, false);
    stream.close();
    await receiving;
});

test('a decoder completing after stream teardown wipes packets without publishing stale activity', async t => {
    t.mock.timers.enable({ apis: ['Date', 'setInterval'], now: 1000 });
    let resolve;
    let decoding;
    let updates = 0;
    let telemetry = 0;
    const queued = Array.from({ length: 24 }, (_, sequence) => packet(sequence, Date.now()));
    const service = receiver({ info: async () => ({ queuedMs: 0, level: 0 }) }, {
        decodeToPlayback: async (_id, bytes) => {
            decoding = bytes;
            return new Promise(done => { resolve = done; });
        },
    }, {
        decodeCallAudioBatch: () => queued,
        updateCallSpeakerLevel: () => updates++,
    });
    const stream = incomingStream();
    configureReceiver(service, stream);
    service.callTelemetry = {
        noteReceive() {}, noteReceiveError: () => telemetry++,
        noteDecoderAdmitted: () => telemetry++, noteDecoded: () => telemetry++,
        noteDecode: () => telemetry++, noteAudioPlayout: () => telemetry++,
    };
    const receiving = service.receiveAudioStream();
    await flush();
    assert.ok(decoding);
    const beforeTeardown = updates;
    stream.close();
    await receiving;
    resolve({ queuedMs: 20, level: 0.8 });
    await flush();
    assert.equal(updates, beforeTeardown);
    assert.equal(telemetry, 0);
    assert.ok(queued.every(value => value.packet.every(byte => byte === 0)));
});

test('a speaker switch cannot restore an ended call or stop a replacement output', async () => {
    const starts = [];
    const stops = [];
    let resolve;
    const service = receiver({
        start: (id, device) => { starts.push([id, device]); return new Promise(done => { resolve = done; }); },
        stop: async id => { stops.push(id); },
    }, {});
    configureReceiver(service, null);
    service.currentCall = { id: 'first' };
    service.preferredSpeakerDeviceId = 'old-device';
    const switching = service.switchSpeaker('new-device');
    service.currentCall = { id: 'second' };
    service.audioCodecSessionId = 'second';
    service.audioPlaybackSessionId = 'second';
    resolve();
    await assert.rejects(switching, /Call changed/);
    assert.deepEqual(starts, [['first', 'new-device']]);
    assert.deepEqual(stops, ['first']);
    assert.equal(service.audioPlaybackSessionId, 'second');
});

test('a call fails instead of silently continuing when both speaker devices cannot start', async () => {
    const starts = [];
    let ended;
    const service = receiver({
        start: async (_id, device) => { starts.push(device); throw new Error('speaker unavailable'); },
    }, {});
    configureReceiver(service, null);
    service.currentCall = { id: 'first' };
    service.preferredSpeakerDeviceId = 'old-device';
    service.endCall = async reason => { ended = reason; };
    await assert.rejects(service.switchSpeaker('new-device'), /speaker unavailable/);
    assert.deepEqual(starts, ['new-device', 'old-device']);
    assert.equal(ended, 'failed');
    assert.equal(service.audioPlaybackSessionId, null);
});

test('speaking avatars use one circular ring with live amplitude and reduced-motion support', () => {
    let level = 0;
    const { CallSpeakingAvatar } = load('../../src/components/chat/calls/CallSpeakingAvatar.tsx', {
        require: createRequire(import.meta.url), memo, useCallback, useSyncExternalStore,
        UserAvatar: props => createElement('span', { 'data-avatar-size': props.size }, props.username),
        cn: (...values) => values.filter(Boolean).join(' '),
        subscribeCallSpeakerLevel: () => () => {}, getCallSpeakerLevel: () => level,
    });
    const render = active => renderToStaticMarkup(createElement(CallSpeakingAvatar, {
        active, callId: 'first', username: 'peer', size: 'xl',
    }));
    assert.match(render(true), /data-speaking="false"/);
    level = 0.8;
    const speaking = render(true);
    assert.match(speaking, /data-speaking="true"/);
    assert.match(speaking, /--qorc-speaking-level:0\.8/);
    assert.equal((speaking.match(/class="qorc-speaking-ring"/g) || []).length, 1);
    assert.doesNotMatch(speaking, /<svg|<path/);
    assert.match(speaking, /aria-hidden="true"/);
    assert.match(render(false), /data-speaking="false"/);
    const css = fs.readFileSync(new URL('../../src/index.css', import.meta.url), 'utf8');
    assert.match(css, /\.qorc-speaking-ring\s*\{[^}]*border-radius: 50%/);
    assert.match(css, /prefers-reduced-motion: reduce\)\s*\{\s*\.qorc-speaking-ring\s*\{\s*transform: none;\s*transition: none/);
    assert.doesNotMatch(css, /qorc-speaking-waves|qorc-speaking-flow/);
});
