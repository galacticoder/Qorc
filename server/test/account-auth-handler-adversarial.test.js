import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { registerHooks } from 'node:module';
import test, { after } from 'node:test';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

process.env.AUTH_ROOT_SEED = crypto.randomBytes(32).toString('hex');

// Replace only network delivery and Redis/work admission. Production handlers,
// parsers, one-time challenge state and the full ML-DSA scan run unchanged.
const hooks = registerHooks({
  load(url, context, nextLoad) {
    if (url.endsWith('/server/messaging/pq-envelope-handler.js')) {
      return { format: 'module', shortCircuit: true, source: `
        export const consumeVerifiedAuthChannelBinding = () => null;
        export async function sendSecureMessage(ws, data) { ws.responses.push(data); return ws.deliver !== false; }
        export const sendSecureAuthResponse = sendSecureMessage;
      ` };
    }
    if (url.endsWith('/server/security/auth-throttle.js')) {
      return { format: 'module', shortCircuit: true, source: `
        export const applyAdaptiveAuthDelay = async signal => { if (signal?.aborted) throw new Error('closed'); };
        export const recordAuthFailure = async () => {};
        export const getAuthVerificationDifficulty = async () => 22;
        export const getAuthPreflightDifficulty = async () => 22;
        export const recordAuthPreflightCompletion = async () => {};
        export const createPowChallenge = () => ({ seed: '', difficulty: 22 });
        export const verifyPowSolution = () => false;
        export const throttleExpensiveAuthRequest = async () => () => {};
        export const acquireExpensiveAuthVerificationSlot = async () => () => {};
      ` };
    }
    return nextLoad(url, context);
  },
});
const { AccountAuthHandler } = await import('../authentication/authentication.js');
const { ServerGatekeeper } = await import('../authentication/gatekeeper.js');
const { OPAQUEServer, LABELS } = await import('../crypto/opaque-service.js');
const { UserDatabase } = await import('../database/user-db.js');
const { SignalType } = await import('../signals.js');
hooks.deregister();
const originalRecords = UserDatabase.getPrivateAuthRecords;
after(() => { UserDatabase.getPrivateAuthRecords = originalRecords; });

const keys = ml_dsa87.keygen(crypto.randomBytes(32));
after(() => { keys.secretKey.fill(0); keys.publicKey.fill(0); });
const record = OPAQUEServer.createRegistrationRecord(new Uint8Array(72), keys.publicKey, new Uint8Array(32));
UserDatabase.getPrivateAuthRecords = async () => [{ credential_index: 2047, opaqueRecord: JSON.stringify(record) }];

function challenge() {
  const nonce = crypto.randomBytes(32);
  const binding = crypto.randomBytes(64);
  const requestId = crypto.randomUUID();
  const controller = new AbortController();
  const ws = {
    responses: [], close() {}, _connectionAbortSignal: controller.signal,
    _loginServerNonce: nonce.toString('base64'), _loginServerNonceAt: Date.now(),
    _loginAuthRequestId: requestId, _loginAuthChannelBinding: binding,
    _loginPowDifficulty: 0,
  };
  const transcript = Buffer.concat([Buffer.from(LABELS.AUTH_SIG_CONTEXT), nonce, binding]);
  const proof = ml_dsa87.sign(transcript, keys.secretKey);
  const message = {
    type: SignalType.AUTH_PIR_FINALIZE, authRequestId: requestId,
    authProof: Buffer.from(proof).toString('base64'), powSolution: '',
    tokenEpoch: Math.floor(Date.now() / 86400000),
    blindedTokens: Array.from({ length: 250 }, () => Buffer.alloc(32, 1).toString('base64')),
  };
  nonce.fill(0); transcript.fill(0); proof.fill(0);
  return { ws, message, controller };
}

function countingIssuer() {
  let calls = 0;
  return {
    get calls() { return calls; },
    validateIssuanceEpoch: epoch => epoch,
    async issueAccountAuthTokenBatch(tokens, epoch) {
      calls += 1;
      return { signedBlindedTokens: tokens.map(token => new Uint8Array(token)), issuerEpoch: epoch, publicKey: new Uint8Array(32), proof: new Uint8Array(64) };
    },
  };
}

test('full login handler issues exactly once for a genuine proof at the last anonymity slot', async () => {
  const handler = new AccountAuthHandler();
  const issuer = countingIssuer();
  handler.ppServer = issuer;
  const { ws, message } = challenge();
  const attempts = await Promise.all(Array.from({ length: 32 }, () => handler.handleSignInFinalize(ws, message)));
  assert.equal(attempts.filter(result => result?.success).length, 1);
  assert.equal(issuer.calls, 1);
  assert.equal(ws.responses.filter(response => response.authenticated === true).length, 1);
  assert.equal(ws.responses.find(response => response.authenticated === true).anonymousTokenBatch.signedBlindedTokens.length, 250);
  assert.equal(ws._loginServerNonce, null);
  assert.equal(ws._loginAuthChannelBinding, null);
});

test('login handler rejects forged, transplanted, expired, unbound and malformed attempts without issuance', async () => {
  const handler = new AccountAuthHandler();
  const issuer = countingIssuer();
  handler.ppServer = issuer;
  for (const mutate of [
    ({ message }) => { message.authProof = Buffer.alloc(4627).toString('base64'); },
    ({ ws }) => { ws._loginAuthChannelBinding = crypto.randomBytes(64); },
    ({ ws }) => { ws._loginServerNonceAt = Date.now() - 24 * 60 * 60 * 1000; },
    ({ ws }) => { ws._loginServerNonceAt = Date.now() + 10000; },
    ({ message }) => { message.authRequestId = crypto.randomUUID(); },
    ({ ws }) => { ws._loginAuthChannelBinding = null; },
    ({ ws }) => { ws._authenticated = true; },
    ({ ws }) => { ws._loginPowDifficulty = 22; },
    ({ controller }) => controller.abort(),
    ({ message }) => { message.blindedTokens = message.blindedTokens.slice(1); },
    ({ message }) => { message.blindedTokens.push(message.blindedTokens[0]); },
    ({ message }) => { message.username = 'alice'; },
    ({ message }) => { message.authProof += '\n'; },
  ]) {
    const attempt = challenge();
    mutate(attempt);
    await handler.handleSignInFinalize(attempt.ws, attempt.message);
    assert.equal(issuer.calls, 0);
    assert.equal(attempt.ws.responses.some(response => response.authenticated === true), false);
    assert.equal(attempt.ws._loginServerNonce, null);
  }
});

test('account refresh handler cannot amplify a spent token through concurrent commitments', async () => {
  const handler = new ServerGatekeeper();
  const issuer = countingIssuer();
  handler.ppServer = issuer;
  const ws = { _authenticated: true, _accountAuthViaAnonymousToken: true, responses: [] };
  const message = index => ({
    type: SignalType.ACCOUNT_AUTH_TOKEN_REFRESH, requestId: crypto.randomUUID(),
    tokenEpoch: Math.floor(Date.now() / 86400000), blindedTokens: [Buffer.alloc(32, index).toString('base64')],
  });
  const original = message(1);
  await Promise.all([handler.handleAccountAuthTokenRefresh(ws, original), ...Array.from({ length: 127 }, (_, i) => handler.handleAccountAuthTokenRefresh(ws, message(i + 2)))]);
  assert.equal(issuer.calls, 1);
  await handler.handleAccountAuthTokenRefresh(ws, { ...original, requestId: crypto.randomUUID() });
  assert.equal(issuer.calls, 1, 'an exact retry reuses the cached response');
  const responses = ws.responses.filter(response => response.signedBlindedTokens);
  assert.equal(responses.length, 2);
  assert.deepEqual(responses[0].signedBlindedTokens, responses[1].signedBlindedTokens);
});
