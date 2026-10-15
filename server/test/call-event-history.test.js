import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const EventType = {
    UI_CALL_LOG: 'ui-call-log', UI_CALL_STATUS: 'ui-call-status',
    UI_CALL_ENDED: 'ui-call-ended', UI_CALL_REQUEST: 'ui-call-request',
};

function load(relative, dependencies) {
    const source = fs.readFileSync(new URL(relative, import.meta.url), 'utf8');
    const ast = ts.createSourceFile(relative, source, ts.ScriptTarget.ES2022, true);
    const body = ast.statements.filter(node => !ts.isImportDeclaration(node))
        .map(node => node.getText(ast)).join('\n');
    const compiled = ts.transpileModule(body, {
        compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
    }).outputText;
    const exports = {};
    new Function('exports', ...Object.keys(dependencies), compiled)(exports, ...Object.values(dependencies));
    return exports;
}

test('an outgoing call logs its start once across dialing, ringing, and answer', () => {
    const { setupCallStateChangeCallback } = load('../../src/hooks/calling/callbacks.ts', {
        EventType, power: { start: async () => {}, stop: async () => {} },
        unstable_batchedUpdates: action => action(), clearCallMediaState() {},
    });
    let changed;
    const events = [];
    const refs = {
        everConnectedRef: { current: new Set() },
        eventDebouncer: { current: { enqueue: (name, detail) => events.push({ name, detail }) } },
    };
    const setters = { setCurrentCall() {}, setPendingIncomingCalls() {} };
    setupCallStateChangeCallback({ onCallStateChange: callback => { changed = callback; } }, refs, setters, 'alice');
    const call = { id: '00112233445566778899aabbccddeeff', peer: 'bob', direction: 'outgoing', type: 'audio' };
    for (const status of ['connecting', 'ringing', 'connecting', 'connecting', 'connected']) {
        changed({ ...call, status }, true);
    }
    const starts = () => events.filter(event => event.name === EventType.UI_CALL_LOG && event.detail.type === 'started');
    assert.equal(starts().length, 1);
    changed({ ...call, status: 'connecting' }, false);
    assert.equal(starts().length, 1);
    changed({ ...call, id: 'ffeeddccbbaa99887766554433221100', status: 'connecting' }, true);
    assert.equal(starts().length, 2);
    changed({ ...call, status: 'connecting' }, false);
    assert.equal(starts().length, 2);
});

test('answering an incoming call never logs it as an outgoing call', () => {
    const { setupCallStateChangeCallback } = load('../../src/hooks/calling/callbacks.ts', {
        EventType, power: { start: async () => {}, stop: async () => {} },
        unstable_batchedUpdates: action => action(), clearCallMediaState() {},
    });
    let changed;
    const events = [];
    setupCallStateChangeCallback({ onCallStateChange: callback => { changed = callback; } }, {
        everConnectedRef: { current: new Set() },
        eventDebouncer: { current: { enqueue: (name, detail) => events.push({ name, detail }) } },
    }, { setCurrentCall() {}, setPendingIncomingCalls() {} }, 'alice');
    for (const status of ['ringing', 'connecting', 'connected']) {
        changed({ id: '00112233445566778899aabbccddeeff', peer: 'bob', direction: 'incoming', type: 'audio', status }, true);
    }
    assert.equal(events.filter(event => event.name === EventType.UI_CALL_LOG && event.detail.type === 'started').length, 0);
});

test('replayed call events keep one chat message and one persisted message ID', () => {
    class CallEvent extends Event {
        constructor(type, options) { super(type); this.detail = options.detail; }
    }
    const target = new EventTarget();
    const cleanups = [];
    let messages = [];
    const stored = new Map();
    const { useCallEventHandlers } = load('../../src/hooks/app/useCallEventHandlers.ts', {
        EventType, window: target, CustomEvent: CallEvent,
        useCallback: callback => callback, useRef: current => ({ current }),
        useEffect: callback => { const cleanup = callback(); if (cleanup) cleanups.push(cleanup); },
        useLayoutEffect: callback => callback(),
        isPlainObject: value => value && Object.getPrototypeOf(value) === Object.prototype,
        hasPrototypePollutionKeys: () => false, truncateUsername: value => value,
        isValidCallId: value => /^[a-f0-9]{32}$/.test(value),
        isValidCallingUsername: value => /^[a-z0-9._-]+$/.test(value),
        LOCAL_EVENT_RATE_LIMIT_WINDOW_MS: 1000, LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS: 100,
    });
    useCallEventHandlers({
        currentUsername: 'alice', selectedConversation: 'bob',
        setMessages: update => { messages = update(messages); },
        saveMessageToLocalDB: async message => { stored.set(message.id, message); },
        startCall: async () => {}, callHistory: { addCallLog() {} },
    });
    const detail = { account: 'alice', peer: 'bob', callId: '00112233445566778899aabbccddeeff',
        at: Date.now() - 1000, type: 'started', isOutgoing: true, isVideo: false };
    target.dispatchEvent(new CallEvent(EventType.UI_CALL_LOG, { detail }));
    target.dispatchEvent(new CallEvent(EventType.UI_CALL_LOG, { detail: { ...detail, at: detail.at + 1 } }));
    assert.equal(messages.length, 1);
    assert.equal(stored.size, 1);
    assert.equal(JSON.parse(messages[0].content).label, 'Outgoing audio call');
    target.dispatchEvent(new CallEvent(EventType.UI_CALL_LOG, {
        detail: { ...detail, type: 'ended', at: Date.now(), durationMs: 1000 },
    }));
    assert.equal(messages.length, 2);
    assert.equal(stored.size, 2);
    for (const cleanup of cleanups) cleanup();
});
