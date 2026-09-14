import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { EventEmitter } from 'node:events';
import { hasPendingBroadcast, sendFlowControlledBroadcast } from '../routing/broadcast-flow-control.js';
import { sendPQEncryptedResponse } from '../messaging/pq-envelope-handler.js';
import { awaitMessageHandlerWithDeadline } from '../websocket/message-handler-deadline.js';
import { SignalType } from '../signals.js';

function makeSocket() {
  const session = {
    sessionId: 'a'.repeat(32),
    fingerprint: 'f'.repeat(64),
    sendKey: new Uint8Array(32).fill(7),
    sendCounter: 0,
    confirmed: true
  };
  return {
    readyState: 1,
    bufferedAmount: 0,
    _pqSessionId: session.sessionId,
    _pqSessionData: session,
    pending: [],
    terminations: 0,
    send(frame, callback) {
      this.pending.push({ frame, callback });
    },
    terminate() {
      this.terminations += 1;
      this.readyState = 3;
    }
  };
}

async function flushMicrotasks() {
  for (let index = 0; index < 20; index += 1) await Promise.resolve();
}

test('broadcast scheduling budgets never become socket write deadlines', () => {
  const router = fs.readFileSync(new URL('../routing/blind-router.js', import.meta.url), 'utf8');
  const transport = fs.readFileSync(new URL('../messaging/pq-envelope-handler.js', import.meta.url), 'utf8');
  assert.match(router, /const delivery = sendFlowControlledBroadcast\(ws, \(\) => sendToSocket\(ws, sealedEnvelope\)\)\.then/);
  assert.match(router, /hasPendingBroadcast\(ws\)/);
  assert.match(router, /await awaitMessageHandlerWithDeadline\(delivery, \{/);
  assert.match(router, /timeoutMs: waitBudgetMs/);
  assert.match(router, /Number\(pqSession.sendQueueCount \|\| 0\) > 0/);
  assert.doesNotMatch(router, /deliveryTimeoutMs|LOCAL_BROADCAST_SEND_TIMEOUT_MS/);
  assert.doesNotMatch(transport, /options\.deliveryTimeoutMs|boundedTimeoutMs/);
});

test('a slow broadcast retains its encrypted send turn after the scheduler moves on', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const ws = makeSocket();
  const delivery = sendPQEncryptedResponse(ws, ws._pqSessionData, {
    type: SignalType.SEALED_ENVELOPE,
    envelope: 'opaque'
  });
  const scheduledWait = awaitMessageHandlerWithDeadline(delivery, { timeoutMs: 2_000 });
  const budgetExpired = assert.rejects(scheduledWait, { code: 'WS_MESSAGE_HANDLER_TIMEOUT' });
  await flushMicrotasks();
  assert.equal(ws.pending.length, 1);
  const frame = ws.pending[0].frame;
  const originalFrame = Buffer.from(frame);

  t.mock.timers.tick(2_000);
  await budgetExpired;
  assert.equal(ws.readyState, 1);
  assert.equal(ws.terminations, 0);
  assert.equal(ws._pqSessionData.sendQueueCount, 1);
  assert.deepEqual(frame, originalFrame);

  const heartbeat = sendPQEncryptedResponse(ws, ws._pqSessionData, {
    type: SignalType.PQ_HEARTBEAT_PONG,
    sessionId: ws._pqSessionId,
    timestamp: Date.now()
  });
  await flushMicrotasks();
  assert.equal(ws.pending.length, 1);
  assert.equal(ws._pqSessionData.sendQueueCount, 2);

  t.mock.timers.tick(8_000);
  ws.pending[0].callback();
  assert.equal(await delivery, true);
  await flushMicrotasks();
  assert.equal(ws.pending.length, 2);
  assert.equal(ws._pqSessionData.sendQueueCount, 1);
  assert.equal(frame.every((byte) => byte === 0), true);
  ws.pending[1].callback();
  assert.equal(await heartbeat, true);
  assert.equal(ws._pqSessionData.sendQueueCount, 0);
  assert.equal(ws._pqSessionData.sendQueueBytes, 0);
  t.mock.timers.tick(60_000);
  assert.equal(ws.terminations, 0);
  originalFrame.fill(0);
});

test('a genuinely stalled write still terminates at the transport deadline and logs why', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const warning = t.mock.method(console, 'warn', () => {});
  const ws = makeSocket();
  const delivery = sendPQEncryptedResponse(ws, ws._pqSessionData, {
    type: SignalType.SEALED_ENVELOPE,
    envelope: 'opaque'
  });
  await flushMicrotasks();
  t.mock.timers.tick(29_999);
  assert.equal(ws.terminations, 0);
  assert.equal(ws._pqSessionData.sendQueueCount, 1);
  t.mock.timers.tick(1);
  assert.equal(await delivery, false);
  assert.equal(ws.terminations, 1);
  assert.equal(ws._pqSessionData.sendQueueCount, 0);
  assert.equal(ws._pqSessionData.sendQueueBytes, 0);
  assert.match(warning.mock.calls[0].arguments[0], /Transport write deadline exceeded/);
  assert.equal(warning.mock.calls[0].arguments[1].timeoutMs, 30_000);
  ws.pending[0].callback(new Error('WebSocket is not open'));
  t.mock.timers.tick(60_000);
  assert.equal(ws.terminations, 1);
});

test('a late write error after a broadcast wait expires is still observed', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let rejectDelivery;
  const delivery = new Promise((_, reject) => { rejectDelivery = reject; });
  const wait = awaitMessageHandlerWithDeadline(delivery, { timeoutMs: 2_000 });
  const expired = assert.rejects(wait, { code: 'WS_MESSAGE_HANDLER_TIMEOUT' });
  t.mock.timers.tick(2_000);
  await expired;
  rejectDelivery(new Error('Socket closed after scheduling budget expired'));
  await flushMicrotasks();
});

function makeBroadcastSocket() {
  const ws = Object.assign(new EventEmitter(), makeSocket());
  ws.pings = [];
  ws.ping = (payload, callback) => {
    ws.pings.push(Buffer.from(payload));
    callback();
  };
  return ws;
}

test('broadcasts wait for peer receipt instead of treating a local write as network drainage', async () => {
  const ws = makeBroadcastSocket();
  let sends = 0;
  const send = async () => { sends += 1; return true; };
  assert.equal(await sendFlowControlledBroadcast(ws, send), true);
  assert.equal(hasPendingBroadcast(ws), true);
  assert.equal(ws.pings.length, 1);
  for (let index = 0; index < 100; index += 1) {
    assert.equal(await sendFlowControlledBroadcast(ws, send), false);
  }
  assert.equal(sends, 1);
  ws.emit('pong', Buffer.alloc(0));
  ws.emit('pong', Buffer.alloc(16));
  assert.equal(hasPendingBroadcast(ws), true);
  ws.emit('pong', ws.pings[0]);
  assert.equal(hasPendingBroadcast(ws), false);
  assert.equal(ws.listenerCount('pong'), 0);
  assert.equal(await sendFlowControlledBroadcast(ws, send), true);
  assert.equal(sends, 2);
  ws.emit('pong', ws.pings[0]);
  assert.equal(hasPendingBroadcast(ws), true);
  ws.emit('pong', ws.pings[1]);
  assert.equal(hasPendingBroadcast(ws), false);
});

test('peer receipt probing starts only after every encrypted broadcast cell is written', async () => {
  const ws = makeBroadcastSocket();
  const delivery = sendFlowControlledBroadcast(ws, () => sendPQEncryptedResponse(ws, ws._pqSessionData, {
    type: SignalType.SEALED_ENVELOPE,
    envelope: 'x'.repeat(100_000)
  }));
  await flushMicrotasks();
  assert.equal(ws.pending.length, 1);
  assert.equal(ws.pings.length, 0);
  ws.pending[0].callback();
  await flushMicrotasks();
  assert.equal(ws.pending.length, 2);
  assert.equal(ws.pings.length, 0);
  ws.pending[1].callback();
  assert.equal(await delivery, true);
  assert.equal(ws.pings.length, 1);
  assert.equal(ws._pqSessionData.sendQueueCount, 0);
  assert.equal(hasPendingBroadcast(ws), true);
  ws.emit('pong', ws.pings[0]);
  assert.equal(hasPendingBroadcast(ws), false);
});

test('closed or failed broadcast writes release receipt listeners and cannot probe a retired socket', async () => {
  const ws = makeBroadcastSocket();
  let finish;
  const delivery = sendFlowControlledBroadcast(ws, () => new Promise((resolve) => { finish = resolve; }));
  ws.readyState = 3;
  ws.emit('close');
  assert.equal(hasPendingBroadcast(ws), false);
  finish(true);
  assert.equal(await delivery, false);
  assert.equal(ws.pings.length, 0);
  assert.equal(ws.listenerCount('pong'), 0);
  assert.equal(ws.listenerCount('error'), 0);
  assert.equal(ws.listenerCount('close'), 0);

  const failed = makeBroadcastSocket();
  await assert.rejects(sendFlowControlledBroadcast(failed, async () => { throw new Error('write failed'); }));
  assert.equal(hasPendingBroadcast(failed), false);
  assert.equal(failed.listenerCount('pong'), 0);
});
