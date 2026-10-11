import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { registerHooks } from 'node:module';
import test, { after } from 'node:test';
import { ristretto255_oprf as oprf } from '@noble/curves/ed25519.js';
import {
  PRIVATE_AUTH_PIR_QUERY_BYTES,
  PRIVATE_AUTH_PIR_PUBLIC_PARAMS_BYTES,
} from '../../shared/private-auth-protocol.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';

process.env.AUTH_ROOT_SEED = crypto.randomBytes(32).toString('hex');

const hooks = registerHooks({
  load(url, context, nextLoad) {
    if (url.endsWith('/server/messaging/pq-envelope-handler.js')) {
      return { format: 'module', shortCircuit: true, source: `
        export const bindings = new WeakMap();
        export const consumeVerifiedAuthChannelBinding = data => bindings.get(data) ?? null;
        export async function sendSecureMessage(ws, data) { ws.responses.push(data); return true; }
        export const sendSecureAuthResponse = sendSecureMessage;
      ` };
    }
    if (url.endsWith('/server/security/auth-throttle.js')) {
      return { format: 'module', shortCircuit: true, source: `
        export const applyAdaptiveAuthDelay = async () => {};
        export const recordAuthFailure = async () => {};
        export const getAuthVerificationDifficulty = async () => 4;
        export const getAuthPreflightDifficulty = async () => 4;
        export const recordAuthPreflightCompletion = async () => {};
        export const createPowChallenge = difficulty => ({ seed: 'challenge', difficulty });
        export const verifyPowSolution = (seed, difficulty, solution) => solution === 'accepted';
        export const throttleExpensiveAuthRequest = async () => () => {};
        export const acquireExpensiveAuthVerificationSlot = async () => () => {};
      ` };
    }
    if (url.endsWith('/server/authentication/private-auth-pir.js')) {
      return { format: 'module', shortCircuit: true, source: `
        export async function answerPrivateAuthPir() { return Buffer.alloc(128); }
      ` };
    }
    return nextLoad(url, context);
  },
});
const { AccountAuthHandler, SecureStateManager } = await import('../authentication/authentication.js');
const { bindings } = await import('../messaging/pq-envelope-handler.js');
const { OPAQUEServer } = await import('../crypto/opaque-service.js');
const { UserDatabase } = await import('../database/user-db.js');
const { SignalType } = await import('../signals.js');
hooks.deregister();
await OPAQUEServer.initialize();

const originalRecords = UserDatabase.getPrivateAuthRecords;
const originalStage = UserDatabase.stageUserRecord;
const originalConfirm = UserDatabase.confirmStagedUserRecord;
UserDatabase.getPrivateAuthRecords = async () => [];
UserDatabase.stageUserRecord = async () => ({ credential_index: 3 });
UserDatabase.confirmStagedUserRecord = async () => ({ credential_index: 3 });
after(() => {
  UserDatabase.getPrivateAuthRecords = originalRecords;
  UserDatabase.stageUserRecord = originalStage;
  UserDatabase.confirmStagedUserRecord = originalConfirm;
});

function connection() {
  return {
    responses: [], closed: false, _hasServerAuth: true,
    _connectionAbortSignal: new AbortController().signal,
    close() { this.closed = true; },
  };
}

function blindedElement() {
  const result = oprf.oprf.blind(crypto.randomBytes(32));
  result.blind.fill(0);
  return Buffer.from(result.blinded).toString('base64');
}

function loginRequest() {
  const blinded = blindedElement();
  const query = Buffer.alloc(PRIVATE_AUTH_PIR_QUERY_BYTES, 1);
  const pubParams = Buffer.alloc(PRIVATE_AUTH_PIR_PUBLIC_PARAMS_BYTES, 2);
  const hash = crypto.createHash('sha256');
  hash.update(PROTOCOL_KEYS.PRIVATE_AUTH_REQUEST);
  hash.update(Buffer.from(blinded, 'base64'));
  hash.update(query);
  hash.update(pubParams);
  return {
    initial: {
      type: SignalType.AUTH_PIR_REQUEST, authRequestId: crypto.randomUUID(),
      authChannelBinding: Buffer.alloc(64, 3).toString('base64'),
      blindedElement: blinded, requestCommitment: hash.digest('base64'),
    },
    query: query.toString('base64'), pubParams: pubParams.toString('base64'),
  };
}

async function completeLoginRequest(handler, ws, request = loginRequest()) {
  await handler.handlePIRSignIn(ws, request.initial);
  assert.equal(ws.responses.at(-1).preflightRequired, true);
  assert.equal(ws.responses.at(-1).authRequestId, request.initial.authRequestId);
  const proof = {
    ...request.initial, query: request.query, pubParams: request.pubParams,
    preflightPowSolution: 'accepted',
  };
  bindings.set(proof, new Uint8Array(64).fill(3));
  await handler.handlePIRSignIn(ws, proof);
  assert.equal(ws.responses.at(-1).type, SignalType.AUTH_PIR_RESPONSE);
  assert.equal(ws.responses.at(-1).serverNonce, ws._loginServerNonce);
  assert.equal(ws._loginAuthRequestId, request.initial.authRequestId);
  return { request, proof };
}

function registrationRequest() {
  return {
    type: SignalType.AUTH_REGISTER_REQUEST, authRequestId: crypto.randomUUID(),
    blindedElement: blindedElement(),
  };
}

async function completeRegistrationRequest(handler, ws) {
  const request = registrationRequest();
  await handler.handleRegisterRequest(ws, request);
  assert.equal(ws.responses.at(-1).preflightRequired, true);
  await handler.handleRegisterRequest(ws, { ...request, preflightPowSolution: 'accepted' });
  assert.equal(ws.responses.at(-1).type, SignalType.AUTH_REGISTER_RESPONSE);
  assert.ok(ws.responses.at(-1).evaluatedElement);
  assert.equal(SecureStateManager.getState(ws).registrationAuthRequestId, request.authRequestId);
  return request;
}

test('repeated locally rejected login attempts can restart immediately on the same connection', async () => {
  const handler = new AccountAuthHandler();
  const ws = connection();
  let previousBinding;
  for (let index = 0; index < 5; index += 1) {
    await completeLoginRequest(handler, ws);
    if (previousBinding) assert.ok(previousBinding.every(byte => byte === 0));
    previousBinding = ws._loginAuthChannelBinding;
    assert.equal(ws._hasServerAuth, true);
    assert.equal(ws.closed, false);
  }
  assert.equal(ws.responses.some(response => response.type === SignalType.AUTH_ERROR), false);
  assert.equal(ws.responses.some(response => response.authenticated === true), false);
});

test('registration completes after an unfinished login without reconnecting or waiting for expiry', async () => {
  const handler = new AccountAuthHandler();
  const ws = connection();
  await completeLoginRequest(handler, ws);
  const binding = ws._loginAuthChannelBinding;
  const request = await completeRegistrationRequest(handler, ws);
  assert.ok(binding.every(byte => byte === 0));
  assert.equal(ws._loginServerNonce, null);
  assert.equal(ws._loginPowSeed, null);
  assert.equal(ws._hasServerAuth, true);
  const registrationAttemptId = crypto.randomBytes(32).toString('base64');
  await handler.handleRegisterFinalize(ws, {
    type: SignalType.AUTH_REGISTER_FINALIZE, authRequestId: request.authRequestId,
    envelope: Buffer.alloc(72).toString('base64'),
    authPublicKey: Buffer.alloc(2592).toString('base64'), registrationAttemptId,
  });
  assert.equal(ws.responses.at(-1).type, SignalType.AUTH_REGISTER_READY);
  handler.ppServer = {
    validateIssuanceEpoch: epoch => epoch,
    issueAccountAuthTokenBatch: async (tokens, issuerEpoch) => ({
      signedBlindedTokens: tokens.map(token => new Uint8Array(token)),
      issuerEpoch, publicKey: new Uint8Array(32), proof: new Uint8Array(64),
    }),
  };
  const result = await handler.handleRegisterConfirm(ws, {
    type: SignalType.AUTH_REGISTER_CONFIRM, authRequestId: request.authRequestId,
    registrationAttemptId, tokenEpoch: 1,
    blindedTokens: Array.from({ length: 250 }, () => Buffer.alloc(32, 1).toString('base64')),
  });
  assert.equal(result.success, true);
  assert.equal(ws.responses.at(-1).registrationConfirmed, true);
  assert.equal(ws.responses.some(response => response.type === SignalType.AUTH_ERROR), false);
  assert.equal(ws.closed, false);
});

test('abandoned registration and staged receipt are replaceable without changing stored records', async () => {
  const handler = new AccountAuthHandler();
  const ws = connection();
  const old = await completeRegistrationRequest(handler, ws);
  const salt = SecureStateManager.getState(ws).registrationSalt;
  await completeLoginRequest(handler, ws);
  assert.ok(salt.every(byte => byte === 0));
  assert.equal(SecureStateManager.getState(ws).pendingRegistration, undefined);
  const fresh = await completeRegistrationRequest(handler, ws);
  SecureStateManager.setState(ws, {
    pendingRegistration: false, registrationReadyRecordId: 'staged-record',
    registrationReadyAuthRequestId: fresh.authRequestId, registrationReadyAt: Date.now(),
  });
  await completeLoginRequest(handler, ws);
  assert.equal(SecureStateManager.getState(ws).registrationReadyRecordId, undefined);
  await handler.handleRegisterFinalize(ws, { type: SignalType.AUTH_REGISTER_FINALIZE, authRequestId: old.authRequestId });
  assert.equal(ws.closed, false);
  assert.ok(ws._loginServerNonce);
});

test('fresh preflight replaces abandoned work but late proofs cannot replace newer work', async () => {
  const handler = new AccountAuthHandler();
  const ws = connection();
  const first = loginRequest();
  await handler.handlePIRSignIn(ws, first.initial);
  const next = registrationRequest();
  await handler.handleRegisterRequest(ws, next);
  const pending = ws._authPreflight;
  assert.equal(pending.authRequestId, next.authRequestId);
  await handler.handlePIRSignIn(ws, {
    ...first.initial, query: first.query, pubParams: first.pubParams,
    preflightPowSolution: 'accepted',
  });
  assert.equal(ws.responses.at(-1).code, 'AUTH_IN_PROGRESS');
  assert.equal(ws._authPreflight, pending);
  await handler.handleRegisterRequest(ws, { ...next, preflightPowSolution: 'accepted' });
  assert.ok(ws.responses.at(-1).evaluatedElement);
});

test('new attempts still require valid proof of work and cannot bypass authentication', async () => {
  const handler = new AccountAuthHandler();
  const ws = connection();
  await completeLoginRequest(handler, ws);
  const next = registrationRequest();
  await handler.handleRegisterRequest(ws, next);
  await handler.handleRegisterRequest(ws, { ...next, preflightPowSolution: 'incorrect' });
  assert.equal(ws.responses.at(-1).preflightRequired, true);
  assert.equal(SecureStateManager.getState(ws).pendingRegistration, undefined);
  assert.equal(ws.responses.some(response => response.authenticated === true), false);
});

test('busy or authenticated connections cannot be reset by a new request', async () => {
  const handler = new AccountAuthHandler();
  for (const field of ['_authenticated', '_loginRequestInProgress', 'registrationFinalizeInProgress', 'registrationConfirmInProgress']) {
    const ws = connection();
    const binding = new Uint8Array(64).fill(4);
    ws._loginServerNonce = 'pending-nonce';
    ws._loginAuthRequestId = crypto.randomUUID();
    ws._loginAuthChannelBinding = binding;
    if (field.startsWith('_')) ws[field] = true;
    else SecureStateManager.setState(ws, { [field]: true });
    await handler.handleRegisterRequest(ws, registrationRequest());
    assert.equal(ws.responses.at(-1).code, 'AUTH_IN_PROGRESS');
    assert.equal(ws._loginServerNonce, 'pending-nonce');
    assert.ok(binding.every(byte => byte === 4));
  }
});

test('superseded login finalization cannot consume the current nonce or binding', async () => {
  const handler = new AccountAuthHandler();
  const ws = connection();
  const old = await completeLoginRequest(handler, ws);
  await completeLoginRequest(handler, ws);
  const nonce = ws._loginServerNonce;
  const binding = ws._loginAuthChannelBinding;
  await handler.handleSignInFinalize(ws, {
    type: SignalType.AUTH_PIR_FINALIZE, authRequestId: old.request.initial.authRequestId,
  });
  assert.equal(ws.responses.at(-1).code, 'INVALID_FINALIZE_REQUEST');
  assert.equal(ws._loginServerNonce, nonce);
  assert.equal(ws._loginAuthChannelBinding, binding);
  assert.ok(binding.every(byte => byte === 3));
  assert.equal(ws.closed, false);
});

test('malformed messages from old attempts cannot erase a newer preflight', async () => {
  const handler = new AccountAuthHandler();
  const ws = connection();
  const oldLogin = loginRequest();
  await handler.handlePIRSignIn(ws, oldLogin.initial);
  const oldRegistration = registrationRequest();
  await handler.handleRegisterRequest(ws, oldRegistration);
  const next = loginRequest();
  await handler.handlePIRSignIn(ws, next.initial);
  const pending = ws._authPreflight;
  await handler.handlePIRSignIn(ws, { ...oldLogin.initial, unexpected: true });
  assert.equal(ws._authPreflight, pending);
  await handler.handleRegisterRequest(ws, { ...oldRegistration, unexpected: true });
  assert.equal(ws._authPreflight, pending);
  assert.equal(ws.closed, false);
});

test('late registration finalize and confirm cannot close or clear a newer registration', async () => {
  const handler = new AccountAuthHandler();
  const ws = connection();
  const old = await completeRegistrationRequest(handler, ws);
  const next = await completeRegistrationRequest(handler, ws);
  const pending = SecureStateManager.getState(ws);
  await handler.handleRegisterFinalize(ws, {
    type: SignalType.AUTH_REGISTER_FINALIZE, authRequestId: old.authRequestId,
  });
  await handler.handleRegisterConfirm(ws, {
    type: SignalType.AUTH_REGISTER_CONFIRM, authRequestId: old.authRequestId,
    registrationAttemptId: crypto.randomBytes(32).toString('base64'),
  });
  assert.equal(SecureStateManager.getState(ws), pending);
  assert.equal(pending.registrationAuthRequestId, next.authRequestId);
  assert.ok(pending.registrationSalt.some(byte => byte !== 0));
  assert.equal(ws.closed, false);
});
