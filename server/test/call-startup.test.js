import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const firstId = '00112233445566778899aabbccddeeff';
const secondId = 'ffeeddccbbaa99887766554433221100';
const SignalType = { CALL_SIGNAL: 'call-signal', SEALED_ENVELOPE: 'sealed-envelope', BLIND_ROUTE: 'blind-route' };
const quietConsole = { info() {}, warn() {}, error() {} };

function compile(body, dependencies) {
    const compiled = ts.transpileModule(body, {
        compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
    }).outputText;
    const exports = {};
    new Function('exports', ...Object.keys(dependencies), compiled)(exports, ...Object.values(dependencies));
    return exports;
}

function moduleSource(relative, dependencies) {
    const source = fs.readFileSync(new URL(relative, import.meta.url), 'utf8');
    const ast = ts.createSourceFile(relative, source, ts.ScriptTarget.ES2022, true);
    return compile(ast.statements.filter(node => !ts.isImportDeclaration(node))
        .map(node => node.getText(ast)).join('\n'), dependencies);
}

function fixture(relative, name, methods, dependencies, extra = '') {
    const source = fs.readFileSync(new URL(relative, import.meta.url), 'utf8');
    const ast = ts.createSourceFile(relative, source, ts.ScriptTarget.ES2022, true);
    const declaration = ast.statements.find(node => ts.isClassDeclaration(node) && node.name.text === name);
    const body = declaration.members.filter(node => methods.includes(node.name?.getText(ast)))
        .map(node => node.getText(ast)).join('\n');
    const exports = compile(`export class ${name} { ${extra} ${body} }`, dependencies);
    return new exports[name]();
}

function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
    return { promise, resolve, reject };
}

async function flush() {
    for (let count = 0; count < 30; count++) await Promise.resolve();
}

function calling(methods, dependencies = {}) {
    const service = fixture('../../src/lib/transport/secure-calling-service.ts', 'SecureCallingService', methods, {
        console: quietConsole, CALL_DEVICE_SETTLE_MS: 100, CAMERA_CAPTURE_WIDTH: 1280,
        CAMERA_CAPTURE_HEIGHT: 720, TARGET_FPS: 60, MAX_CLOSED_CALLS: 128,
        MAX_CALL_SIGNAL_CLOCK_SKEW_MS: 300_000,
        keyTransparencyClient: { isSecurityIncidentActive: () => false },
        blockingSystem: { isEnforcementReady: () => true, isBlockedSync: () => false },
        isExactCallSignal: () => true,
        ...dependencies,
    });
    Object.assign(service, {
        currentCall: { id: firstId, peer: 'bob', direction: 'incoming', type: 'video', status: 'connecting', localVideoEnabled: false, remoteVideoEnabled: false },
        localUsername: 'alice', closedCalls: new Map(), pendingIncomingCalls: new Map(),
        localMediaActive: false, cameraSessionId: null, microphoneSessionId: null,
        lastCaptureReleaseAt: 0, mediaGeneration: 0,
        teardownCallMediaElements() {}, notifyLocalMediaChange() {}, notifyCallState() {},
    });
    return service;
}

test('a camera-less video participant starts a microphone without camera permission or capture', async () => {
    const permissions = [];
    const microphones = [];
    const service = calling(['setupLocalMedia'], {
        nativeCamera: { devices: async () => [] },
        nativeMicrophone: { start: async id => microphones.push(id) },
        requireNativeMediaAccess: async kind => permissions.push(kind),
        readAppSettingsAsync: async () => ({}),
    });
    assert.equal(await service.setupLocalMedia('video', firstId), 'video');
    assert.deepEqual(permissions, ['microphone']);
    assert.deepEqual(microphones, [firstId]);
    assert.equal(service.localMediaActive, true);
    assert.equal(service.microphoneSessionId, firstId);
    assert.equal(service.cameraSessionId, null);
    assert.equal(service.currentCall.localVideoEnabled, false);
    assert.equal(service.currentCall.type, 'video');
});

test('a camera-less video participant receives video and starts audio without a video encoder', async () => {
    const service = calling(['startMediaStreaming']);
    let audio = 0;
    let receiving = 0;
    Object.assign(service, {
        localMediaActive: true, microphoneSessionId: firstId, audioCodecSessionId: firstId,
        audioPlaybackSessionId: firstId, callConnection: {}, videoStream: {},
        startAudioStreaming: async () => { audio++; },
        startVideoStreaming: async () => assert.fail('camera-less calls cannot start a local video encoder'),
        startReceivingMedia: () => { receiving++; },
    });
    await service.startMediaStreaming(firstId);
    assert.equal(audio, 1);
    assert.equal(receiving, 1);
});

test('a real camera is reported on only after its native capture starts', async () => {
    const start = deferred();
    const observed = [];
    const service = calling(['setupLocalMedia'], {
        nativeCamera: { devices: async () => [{ device_id: 'camera' }], start: () => start.promise },
        nativeMicrophone: { start: async () => {} },
        requireNativeMediaAccess: async () => {}, readAppSettingsAsync: async () => ({}),
    });
    service.notifyCallState = call => observed.push(call.localVideoEnabled);
    const pending = service.setupLocalMedia('video', firstId);
    await flush();
    assert.equal(service.currentCall.localVideoEnabled, false);
    start.resolve();
    await pending;
    assert.equal(service.currentCall.localVideoEnabled, true);
    assert.deepEqual(observed, [true]);
});

test('remote camera controls are scoped to the active call, connection, and stream', async () => {
    let callbacks;
    const streams = new Map();
    const connection = {
        state: 'connected',
        createStream: async options => {
            const stream = { id: options.id };
            streams.set(options.type, stream);
            return stream;
        },
    };
    const service = calling(['establishCallConnection'], {
        CALL_CONNECTION_ATTEMPTS: 1,
        CallTelemetry: class { constructor(...args) { callbacks = args; } },
    });
    const observed = [];
    Object.assign(service, {
        transport: { getConnection: () => connection },
        bindCallConnectionState() {}, notifyCallState: call => observed.push(call.remoteVideoEnabled),
    });
    await service.establishCallConnection('bob', firstId);
    callbacks[6](true);
    callbacks[6](true);
    callbacks[6](false);
    assert.deepEqual(observed, [true, false]);
    service.currentCall.localVideoEnabled = true;
    assert.equal(callbacks[7](), true);
    service.telemetryStream = { id: 'replacement-stream' };
    callbacks[6](true);
    assert.equal(service.currentCall.remoteVideoEnabled, false);
    service.telemetryStream = streams.get('call-telemetry');
    service.callConnection = { state: 'connected' };
    callbacks[6](true);
    assert.equal(service.currentCall.remoteVideoEnabled, false);
    service.callConnection = connection;
    service.currentCall = { id: secondId, remoteVideoEnabled: false, localVideoEnabled: true };
    callbacks[6](true);
    assert.equal(service.currentCall.remoteVideoEnabled, false);
    assert.equal(callbacks[7](), false);
});

test('camera toggles publish native capture state to local observers and the peer', async () => {
    const capture = [];
    const states = [];
    const published = [];
    const service = calling(['toggleVideo'], {
        nativeCamera: { setEnabled: async (id, enabled) => capture.push({ id, enabled }) },
    });
    Object.assign(service, {
        localMediaActive: true, cameraSessionId: firstId, videoStream: {},
        notifyCallState: call => states.push({ ...call }),
        callTelemetry: { sendCameraState: async () => published.push(service.currentCall.localVideoEnabled) },
    });
    service.currentCall.localVideoEnabled = true;
    assert.equal(await service.toggleVideo(), false);
    assert.equal(await service.toggleVideo(), true);
    assert.deepEqual(capture, [{ id: firstId, enabled: false }, { id: firstId, enabled: true }]);
    assert.deepEqual(states.map(call => call.localVideoEnabled), [false, true]);
    assert.deepEqual(published, [false, true]);
});

test('a camera-less participant never reports its camera as enabled', async () => {
    const service = calling(['toggleVideo'], {
        nativeCamera: { setEnabled: async () => assert.fail('no native camera exists') },
    });
    Object.assign(service, { localMediaActive: true, videoStream: {} });
    assert.equal(await service.toggleVideo(), false);
    assert.equal(service.currentCall.localVideoEnabled, false);
});

test('failed or canceled camera toggles cannot invent state or update a replacement call', async () => {
    const capture = deferred();
    const service = calling(['toggleVideo'], { nativeCamera: { setEnabled: () => capture.promise } });
    Object.assign(service, {
        localMediaActive: true, cameraSessionId: firstId, videoStream: {},
        notifyCallState: () => assert.fail('a stale camera toggle cannot notify the new call'),
    });
    const pending = service.toggleVideo();
    service.currentCall = { id: secondId, type: 'video', localVideoEnabled: false };
    service.cameraSessionId = secondId;
    capture.resolve();
    assert.equal(await pending, false);
    assert.equal(service.currentCall.localVideoEnabled, false);
    service.currentCall.localVideoEnabled = true;
    capture.promise = Promise.reject(new Error('capture failed'));
    await assert.rejects(service.toggleVideo(), /capture failed/);
    assert.equal(service.currentCall.localVideoEnabled, true);
});

test('late codec startup cannot install its session into a replacement call', async () => {
    const codecStart = deferred();
    const stopped = [];
    const service = calling(['startMediaStreaming'], {
        audioCodec: { start: () => codecStart.promise, stop: async id => stopped.push(id) },
        nativeAudioPlayback: { start: async () => assert.fail('a canceled call cannot start playback') },
    });
    Object.assign(service, { localMediaActive: true, microphoneSessionId: firstId, callConnection: {} });
    const pending = service.startMediaStreaming(firstId);
    service.currentCall = { id: secondId };
    service.mediaGeneration++;
    service.audioCodecSessionId = secondId;
    codecStart.resolve();
    await assert.rejects(pending, /Call ended while media was starting/);
    assert.deepEqual(stopped, [firstId]);
    assert.equal(service.audioCodecSessionId, secondId);
});

test('late playback startup cannot install its session into a replacement call', async () => {
    const playbackStart = deferred();
    const stopped = [];
    const service = calling(['startMediaStreaming'], {
        nativeAudioPlayback: { start: () => playbackStart.promise, stop: async id => stopped.push(id) },
    });
    Object.assign(service, {
        localMediaActive: true, microphoneSessionId: firstId,
        audioCodecSessionId: firstId, callConnection: {},
        startAudioStreaming: async () => assert.fail('a canceled call cannot start streaming'),
    });
    const pending = service.startMediaStreaming(firstId);
    service.currentCall = { id: secondId };
    service.mediaGeneration++;
    service.audioPlaybackSessionId = secondId;
    playbackStart.resolve();
    await assert.rejects(pending, /Call ended while media was starting/);
    assert.deepEqual(stopped, [firstId]);
    assert.equal(service.audioPlaybackSessionId, secondId);
});

test('a canceled permission prompt cannot start capture or erase a replacement microphone', async () => {
    const permission = deferred();
    let captures = 0;
    const service = calling(['setupLocalMedia'], {
        nativeMicrophone: { start: async () => { captures++; } },
        requireNativeMediaAccess: () => permission.promise,
    });
    const pending = service.setupLocalMedia('audio', firstId);
    service.currentCall = { id: secondId };
    service.microphoneSessionId = secondId;
    permission.resolve();
    await assert.rejects(pending, /cancelled/);
    assert.equal(captures, 0);
    assert.equal(service.microphoneSessionId, secondId);
});

test('late microphone capture releases only the canceled call session', async () => {
    const capture = deferred();
    const stopped = [];
    const service = calling(['setupLocalMedia'], {
        nativeMicrophone: { start: () => capture.promise, stop: async id => stopped.push(id) },
        requireNativeMediaAccess: async () => {}, readAppSettingsAsync: async () => ({}),
    });
    const pending = service.setupLocalMedia('audio', firstId);
    await flush();
    service.currentCall = { id: secondId };
    service.microphoneSessionId = secondId;
    capture.resolve();
    await assert.rejects(pending, /cancelled/);
    assert.deepEqual(stopped, [firstId]);
    assert.equal(service.microphoneSessionId, secondId);
});

test('releasing an old camera cannot tear down a replacement microphone', async () => {
    const cameraStop = deferred();
    const service = calling(['setupLocalMedia'], {
        nativeCamera: { stop: () => cameraStop.promise },
        nativeMicrophone: { stop: async () => assert.fail('a replacement microphone cannot be stopped') },
    });
    service.cameraSessionId = firstId;
    const pending = service.setupLocalMedia('audio', firstId);
    service.currentCall = { id: secondId };
    service.microphoneSessionId = secondId;
    cameraStop.resolve();
    await assert.rejects(pending, /cancelled/);
    assert.equal(service.microphoneSessionId, secondId);
});

test('the ringing timeout starts after offer delivery and belongs to that call only', async () => {
    const offer = deferred();
    const timers = [];
    const ended = [];
    const service = calling(['startCall'], {
        isValidCallingUsername: () => true, CALL_RING_TIMEOUT: 20_000,
        setTimeout: (run, ms) => { timers.push({ run, ms }); return 1; },
    });
    Object.assign(service, {
        currentCall: null, lifecycleGeneration: 0, initialize: async () => {},
        generateCallId: () => firstId, waitForSignalSession: async () => {},
        setupLocalMedia: async type => type, notifyCallState() {},
        sendCallSignal: () => offer.promise, endCall: async reason => ended.push(reason),
    });
    const starting = service.startCall('bob', 'audio');
    await flush();
    assert.equal(service.currentCall.status, 'ringing');
    assert.equal(timers.length, 0);
    offer.resolve();
    assert.equal(await starting, firstId);
    assert.equal(timers.length, 1);
    assert.equal(timers[0].ms, 20_000);
    service.currentCall = { id: secondId, status: 'ringing' };
    timers[0].run();
    assert.deepEqual(ended, []);
    service.currentCall = { id: firstId, status: 'ringing' };
    timers[0].run();
    assert.deepEqual(ended, ['timeout']);
});

test('a late offer result cannot end or arm a timeout for a replacement call', async () => {
    const offer = deferred();
    const service = calling(['startCall'], {
        isValidCallingUsername: () => true,
        setTimeout: () => assert.fail('an old call cannot arm another timer'),
    });
    Object.assign(service, {
        currentCall: null, lifecycleGeneration: 0, initialize: async () => {},
        generateCallId: () => firstId, waitForSignalSession: async () => {},
        setupLocalMedia: async type => type, notifyCallState() {},
        sendCallSignal: () => offer.promise,
        endCall: async () => assert.fail('an old failure cannot end the replacement call'),
    });
    const starting = service.startCall('bob', 'audio');
    await flush();
    service.currentCall = { id: secondId, peer: 'bob', status: 'ringing' };
    offer.resolve();
    await assert.rejects(starting, /Call ended while the offer was being delivered/);
    assert.equal(service.currentCall.id, secondId);
});

test('a failed start action does not clear UI state owned by the replacement call', async () => {
    const start = deferred();
    let visibleCall = firstId;
    const { createStartCall } = moduleSource('../../src/hooks/calling/actions.ts', {
        console: quietConsole, window: { isSecureContext: true },
        isValidCallingUsername: () => true, preparePeerTransport: async () => {},
        blockingSystem: { isEnforcementReady: () => true, isBlockedSync: () => false },
        unstable_batchedUpdates: run => run(),
        clearCallMediaState: () => { visibleCall = null; },
    });
    const action = createStartCall({
        serviceRef: { current: { startCall: () => start.promise } },
        checkPeerSession: async () => {},
    }, 'alice');
    const starting = action('bob');
    await flush();
    visibleCall = secondId;
    start.reject(new Error('first call canceled'));
    await assert.rejects(starting, /first call canceled/);
    assert.equal(visibleCall, secondId);
});

test('an authenticated cancellation received before its offer prevents ghost ringing', async () => {
    const service = calling(['handleCallSignal', 'rememberClosedCall']);
    service.currentCall = null;
    const offers = [];
    service.allowIncomingOffer = () => true;
    service.handleCallOffer = async offer => offers.push(offer.callId);
    const base = { callId: firstId, from: 'bob', to: 'alice', timestamp: Date.now() };
    await service.handleCallSignal({ ...base, type: 'end-call' });
    await service.handleCallSignal({ ...base, type: 'offer', data: { callType: 'audio' } });
    assert.deepEqual(offers, []);
    await service.handleCallSignal({ ...base, callId: secondId, type: 'offer', data: { callType: 'audio' } });
    assert.deepEqual(offers, [secondId]);
    for (let index = 1; index <= 200; index++) service.rememberClosedCall(index.toString(16).padStart(32, '0'), 'bob');
    assert.equal(service.closedCalls.size, 128);
});

test('retrying an already accepted offer cannot create a second incoming popup', async () => {
    const service = calling(['handleCallOffer']);
    service.currentCall.status = 'connected';
    service.queueIncomingCall = () => assert.fail('the active call cannot be queued again');
    await service.handleCallOffer({ callId: firstId, from: 'bob', type: 'offer' });
});

test('cold call signaling warms P2P without waiting for its handshake before server delivery', async () => {
    const { createPeerSignalSender } = moduleSource('../../src/lib/transport/peer-signal-sender.ts', { SignalType });
    const connection = deferred();
    let connected = false;
    let dials = 0;
    let sent = 0;
    const sender = createPeerSignalSender({
        isCurrent: () => true, isPeerConnected: () => connected,
        connectToPeer: async () => { dials++; await connection.promise; connected = true; },
        sendMessage: async () => { sent++; },
    });
    await assert.rejects(sender('bob', {}, SignalType.CALL_SIGNAL), /not ready for live call/);
    assert.equal(dials, 1);
    assert.equal(sent, 0);
    connection.resolve();
    await flush();
    await sender('bob', {}, SignalType.CALL_SIGNAL);
    assert.equal(sent, 1);
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(sender('bob', {}, SignalType.CALL_SIGNAL, controller.signal), { name: 'AbortError' });
    assert.equal(sent, 1);
});

function transport(methods, dependencies = {}) {
    const instance = fixture('../../src/lib/transport/unified-signal-transport.ts', 'UnifiedSignalTransport', methods, {
        SignalType, console: quietConsole, AUTH_USERNAME_REGEX: /^[a-z0-9._-]+$/,
        MAX_TOTAL_SEND_TASKS: 512, MAX_QUEUED_PRIORITY_SENDS: 256, MAX_QUEUED_SENDS_PER_PEER: 100,
        CALL_SIGNAL_QUEUE_MAX_WAIT_MS: 5000, MAX_CONCURRENT_SEND_TASKS: 8,
        MAX_PRIORITY_BURST: 8, WS_CONTROL_RESPONSE_TIMEOUT_MS: 1000,
        WS_CONTROL_SEND_TIMEOUT_MS: 1000, BLIND_ROUTE_ACK_LIVENESS_POLL_MS: 100,
        MAX_BLIND_ACK_WAITERS: 512, ML_KEM_1024_PUBLIC_KEY_BYTES: 1568,
        canonicalBase64Shape: () => true, isLiveOnlySignalType: () => true,
        LIVE_ONLY_DELIVERY_POLICY: 'live-only',
        ...dependencies,
    }, 'static PRIORITY_SEND_TYPES = new Set([SignalType.CALL_SIGNAL]);');
    Object.assign(instance, {
        accountGeneration: 0, totalSendTasks: 0, sendQueues: new Map(), blindAckWaiters: new Map(),
        recipientPolicyError: () => null, captureSendPolicy: () => ({}), preparePeer() {},
        validOutboundEnvelope: () => true, directP2PPayload: value => value, trackDeliveryAck: async () => {},
        encryptionProvider: async () => ({ messageId: firstId, encryptedPayload: {}, recipientKyberPublicBase64: 'key' }),
    });
    return instance;
}

test('aborting a queued call removes it without waiting for the occupied peer lane', async () => {
    const instance = transport(['send']);
    instance.drainSendQueue = () => {};
    const controller = new AbortController();
    const sending = instance.send('bob', {}, SignalType.CALL_SIGNAL, controller.signal);
    assert.equal(instance.totalSendTasks, 1);
    controller.abort();
    assert.equal((await sending).error, 'send-cancelled');
    assert.equal(instance.totalSendTasks, 0);
    assert.equal(instance.sendQueues.get('bob').high.length, 0);
});

test('canceling a call waiting for global send capacity releases its peer lane', async () => {
    const instance = transport(['send', 'drainSendQueue', 'acquireSendPermit']);
    Object.assign(instance, { activeSendTasks: 8, sendPermitWaiters: [] });
    const controller = new AbortController();
    const pending = instance.send('bob', {}, SignalType.CALL_SIGNAL, controller.signal);
    await flush();
    assert.equal(instance.sendPermitWaiters.length, 1);
    controller.abort();
    assert.equal((await pending).error, 'send-cancelled');
    await flush();
    assert.equal(instance.sendPermitWaiters.length, 0);
    assert.equal(instance.sendQueues.size, 0);
    assert.equal(instance.activeSendTasks, 8);
    assert.equal(instance.totalSendTasks, 0);
});

test('canceling during encryption cannot send an old call offer to P2P or the server', async () => {
    const instance = transport(['performSend']);
    const encryption = deferred();
    instance.encryptionProvider = () => encryption.promise;
    instance.p2pSender = async () => assert.fail('canceled offers cannot reach P2P');
    instance.sealForServer = async () => assert.fail('canceled offers cannot reach the server');
    const controller = new AbortController();
    const sending = instance.performSend('bob', {}, SignalType.CALL_SIGNAL, {}, controller.signal);
    controller.abort();
    encryption.resolve({ messageId: firstId, encryptedPayload: {} });
    assert.equal((await sending).error, 'send-cancelled');
});

test('canceling while delivery activates aborts the actual write and releases its acknowledgement waiter', async () => {
    const ready = deferred();
    let writes = 0;
    const instance = transport(['performSend', 'awaitBlindRouteAck'], {
        websocketClient: {
            captureConnectionPrivacyEpoch: () => 1, isConnectedToServer: () => true,
            registerConnectionWaiterCancel: () => () => {},
            checkDeliveryReadyForSend: () => ready.promise,
            sendReliable: async () => { writes++; return true; },
        },
    });
    instance.p2pSender = null;
    instance.checkBlindAckHandler = () => true;
    instance.sealForServer = async () => ({ sealed: {} });
    const controller = new AbortController();
    const sending = instance.performSend('bob', {}, SignalType.CALL_SIGNAL, {}, controller.signal);
    await flush();
    assert.equal(instance.blindAckWaiters.size, 1);
    controller.abort();
    assert.equal((await sending).error, 'send-cancelled');
    ready.resolve(true);
    await flush();
    assert.equal(writes, 0);
    assert.equal(instance.blindAckWaiters.size, 0);
});

test('a canceled P2P stream encryption never writes its result and wipes the buffer', async () => {
    const encrypted = new Uint8Array([1, 2, 3]);
    const encryption = deferred();
    const stream = fixture('../../src/lib/transport/p2p-transport.ts', 'P2PStream', ['write'], {});
    Object.assign(stream, {
        _closed: false, _writable: true, maxWriteBytes: 1024, lifecycleGeneration: 0,
        session: { encrypt: () => encryption.promise, isValid: () => true },
        transport: { sendData: async () => assert.fail('a canceled stream write cannot reach the native transport') },
    });
    const controller = new AbortController();
    const pending = stream.write(new Uint8Array([4]), { signal: controller.signal });
    controller.abort();
    encryption.resolve(encrypted);
    await assert.rejects(pending, { name: 'AbortError' });
    assert.deepEqual(encrypted, new Uint8Array(3));
});
