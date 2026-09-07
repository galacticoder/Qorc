import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { ristretto255_oprf as oprf } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { hkdf } from '@noble/hashes/hkdf.js';

process.env.AUTH_ROOT_SEED ||= '72'.repeat(32);
process.env.REDIS_URL ||= 'rediss://127.0.0.1:6379';
process.env.REDIS_QUIET_ERRORS = 'true';

const DAY_MS = 86_400_000;
const NULLIFIER_LABEL = new TextEncoder().encode('PrivacyPass-Nullifier-v1');
const MAC_LABEL = new TextEncoder().encode('PrivacyPass-Redemption-MAC-v1');
const PASSWORD_A = 'rotation-test-password-a';
const PASSWORD_B = 'rotation-test-password-b';

function createTokenSecret(epoch) {
  const secret = new Uint8Array(36);
  new DataView(secret.buffer).setUint32(0, epoch, false);
  secret.set(crypto.randomBytes(32), 4);
  return secret;
}

async function issueTokens(PrivacyPassServer, purpose, count) {
  const epoch = Math.floor(Date.now() / DAY_MS);
  const label = new TextEncoder().encode(`PrivacyPass-OPRF-Input-v3:${purpose}`);
  const states = [];
  let issuance = null;
  try {
    for (let index = 0; index < count; index += 1) {
      const tokenSecret = createTokenSecret(epoch);
      const input = hkdf(blake3, tokenSecret, new Uint8Array(0), label, 32);
      const blind = oprf.voprf.blind(input);
      states.push({ tokenSecret, input, blind });
    }
    issuance = await PrivacyPassServer.issueTokenBatch(
      states.map((state) => state.blind.blinded),
      purpose,
      epoch
    );
    const tokens = oprf.voprf.finalizeBatch(states.map((state, index) => ({
      input: state.input,
      blind: state.blind.blind,
      blinded: state.blind.blinded,
      evaluated: issuance.signedBlindedTokens[index],
    })), issuance.publicKey, issuance.proof);
    return states.map((state, index) => ({
      token: new Uint8Array(tokens[index]),
      tokenSecret: new Uint8Array(state.tokenSecret),
    }));
  } finally {
    for (const evaluated of issuance?.signedBlindedTokens || []) evaluated.fill(0);
    issuance?.proof?.fill(0);
    for (const state of states) {
      state.tokenSecret.fill(0);
      state.input.fill(0);
      state.blind.blind.fill(0);
      state.blind.blinded.fill(0);
    }
  }
}

function redemptionProof(token) {
  const nullifier = hkdf(blake3, token, new Uint8Array(0), NULLIFIER_LABEL, 32);
  const macKey = hkdf(blake3, token, nullifier, MAC_LABEL, 32);
  try {
    return { nullifier, mac: blake3(macKey, { dkLen: 32 }) };
  } finally {
    macKey.fill(0);
  }
}

function serializedRedemption(credential) {
  const proof = redemptionProof(credential.token);
  try {
    return {
      token: Buffer.from(credential.token).toString('base64'),
      nullifier: Buffer.from(proof.nullifier).toString('base64'),
      mac: Buffer.from(proof.mac).toString('base64'),
      tokenSecret: Buffer.from(credential.tokenSecret).toString('base64'),
    };
  } finally {
    proof.nullifier.fill(0);
    proof.mac.fill(0);
  }
}

async function redeem(PrivacyPassServer, credential, purpose) {
  const proof = redemptionProof(credential.token);
  try {
    return await PrivacyPassServer.redeemToken(
      credential.token,
      proof.nullifier,
      proof.mac,
      credential.tokenSecret,
      purpose
    );
  } finally {
    proof.nullifier.fill(0);
    proof.mac.fill(0);
  }
}

async function redeemBatch(PrivacyPassServer, credentials) {
  const redemptions = credentials.map(({ credential, purpose }) => {
    const proof = redemptionProof(credential.token);
    return {
      ...proof,
      token: credential.token,
      tokenSecret: credential.tokenSecret,
      expectedPurpose: purpose,
    };
  });
  try {
    return await PrivacyPassServer.redeemTokenBatch(redemptions);
  } finally {
    for (const redemption of redemptions) {
      redemption.nullifier.fill(0);
      redemption.mac.fill(0);
    }
  }
}

function wipeCredentials(credentials) {
  for (const credential of credentials) {
    credential.token.fill(0);
    credential.tokenSecret.fill(0);
  }
}

test('password rotation invalidates every server-entry token without invalidating account-auth tokens', async () => {
  const originalConsoleError = console.error;
  console.error = (...args) => {
    if (args[0] === 'Redis client error') return;
    originalConsoleError(...args);
  };
  let PrivacyPassServer = null;
  let ServerGatekeeper = null;
  const used = new Set();
  let blockNextMark = false;
  let notifyMarkStarted = () => { };
  let releaseBlockedMark = () => { };
  let blockedMark = Promise.resolve();
  const store = {
    async cleanup() { },
    async markUsed(nullifier) {
      if (blockNextMark) {
        blockNextMark = false;
        notifyMarkStarted();
        await blockedMark;
      }
      const key = Buffer.from(nullifier).toString('hex');
      if (used.has(key)) return false;
      used.add(key);
      return true;
    },
    async markUsedBatch(entries) {
      const keys = entries.map(({ nullifier }) => Buffer.from(nullifier).toString('hex'));
      if (new Set(keys).size !== keys.length || keys.some((key) => used.has(key))) return false;
      for (const key of keys) used.add(key);
      return true;
    },
  };
  let oldEntry = [];
  let newEntry = [];
  let accountAuth = [];

  try {
    const modules = await Promise.all([
      import('../authentication/privacy-pass-server.js'),
      import('../authentication/gatekeeper.js'),
    ]);
    PrivacyPassServer = modules[0].PrivacyPassServer;
    ServerGatekeeper = modules[1].ServerGatekeeper;
    await PrivacyPassServer.destroy();
    await ServerGatekeeper.destroy();
    assert.equal(await ServerGatekeeper.initializeExplicit(PASSWORD_A), true);
    const initialAuthorizationGeneration =
      ServerGatekeeper.getServerEntryAuthorizationGeneration();
    await PrivacyPassServer.initialize(store);
    oldEntry = await issueTokens(PrivacyPassServer, 'server-entry', 4);
    accountAuth = await issueTokens(PrivacyPassServer, 'account-auth', 3);

    assert.equal((await redeem(PrivacyPassServer, oldEntry[0], 'server-entry')).valid, true);
    assert.equal(await ServerGatekeeper.rotateExplicit(PASSWORD_A), false);
    assert.equal(
      ServerGatekeeper.getServerEntryAuthorizationGeneration(),
      initialAuthorizationGeneration
    );
    assert.equal((await redeem(PrivacyPassServer, oldEntry[1], 'server-entry')).valid, true);

    const markStarted = new Promise((resolve) => { notifyMarkStarted = resolve; });
    blockedMark = new Promise((resolve) => { releaseBlockedMark = resolve; });
    blockNextMark = true;
    const inFlightRedemption = new ServerGatekeeper().verifyEntryToken(
      serializedRedemption(oldEntry[3])
    );
    await markStarted;
    assert.equal(await ServerGatekeeper.rotateExplicit(PASSWORD_B), true);
    assert.ok(
      ServerGatekeeper.getServerEntryAuthorizationGeneration() > initialAuthorizationGeneration
    );
    releaseBlockedMark();
    const inFlightVerification = await inFlightRedemption;
    assert.equal(inFlightVerification.valid, false);
    assert.equal(
      ServerGatekeeper.isServerEntryAuthorizationGenerationCurrent(
        inFlightVerification.authorizationGeneration
      ),
      false
    );
    assert.equal((await redeem(PrivacyPassServer, oldEntry[2], 'server-entry')).valid, false);
    assert.equal((await redeem(PrivacyPassServer, accountAuth[0], 'account-auth')).valid, true);
    assert.equal((await redeemBatch(PrivacyPassServer, [
      { credential: accountAuth[1], purpose: 'account-auth' },
      { credential: oldEntry[2], purpose: 'server-entry' },
    ])).valid, false);

    newEntry = await issueTokens(PrivacyPassServer, 'server-entry', 2);
    assert.equal((await redeemBatch(PrivacyPassServer, [
      { credential: accountAuth[1], purpose: 'account-auth' },
      { credential: newEntry[0], purpose: 'server-entry' },
    ])).valid, true);
    assert.equal((await redeem(PrivacyPassServer, newEntry[1], 'server-entry')).valid, true);
  } finally {
    wipeCredentials(oldEntry);
    wipeCredentials(newEntry);
    wipeCredentials(accountAuth);
    try {
      await PrivacyPassServer?.destroy();
      await ServerGatekeeper?.destroy();
    } finally {
      console.error = originalConsoleError;
    }
  }
});

test('socket revocation clears authorization before closing every connection', async () => {
  const { revokeAllWebSocketConnections } = await import('../websocket/revoke-connections.js');
  const makeSocket = () => {
    const controller = new AbortController();
    return {
      _connectionAbortController: controller,
      _hasServerAuth: true,
      _authenticated: true,
      _accountAuthViaAnonymousToken: true,
      _unlinkedSession: true,
      _blindSocketId: 'stale-delivery-registration',
      _accountAuthRefreshState: { commitment: 'test', response: {} },
      _ingressQueueRejected: false,
      readyState: 1,
      closeCalls: [],
      close(code, reason) { this.closeCalls.push({ code, reason }); this.readyState = 3; },
      controller,
    };
  };
  const sockets = [makeSocket(), makeSocket()];
  assert.equal(revokeAllWebSocketConnections({ clients: new Set(sockets) }), 2);
  for (const socket of sockets) {
    assert.equal(socket._hasServerAuth, false);
    assert.equal(socket._authenticated, false);
    assert.equal(socket._accountAuthViaAnonymousToken, false);
    assert.equal(socket._unlinkedSession, undefined);
    assert.equal(socket._blindSocketId, undefined);
    assert.equal(socket._accountAuthRefreshState, undefined);
    assert.equal(socket._ingressQueueRejected, true);
    assert.equal(socket.controller.signal.aborted, true);
    assert.deepEqual(socket.closeCalls, [{
      code: 4001,
      reason: 'Server authorization changed',
    }]);
  }
});

test('environment-file password changes rotate once and honor the disconnect setting', async () => {
  const { startServerPasswordMonitor } = await import('../authentication/server-password-monitor.js');
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-password-rotation-'));
  const envPath = path.join(tempDir, '.env');
  fs.writeFileSync(
    envPath,
    `SERVER_PASSWORD=${PASSWORD_A}\nDISCONNECT_CLIENTS_ON_SERVER_PASSWORD_CHANGE=no\n`,
    { mode: 0o600 },
  );
  let activePassword = PASSWORD_A;
  const attemptedPasswords = [];
  const rotations = [];
  let monitor;
  try {
    monitor = await startServerPasswordMonitor({
      envPath,
      intervalMs: 20,
      logger: { info() { }, error() { } },
      async rotatePassword(password) {
        attemptedPasswords.push(password);
        if (password === activePassword) return false;
        activePassword = password;
        return true;
      },
      async onPasswordRotated(options) {
        rotations.push(options);
      },
    });
    fs.writeFileSync(envPath, `SERVER_PASSWORD=${PASSWORD_B}\nDISCONNECT_CLIENTS_ON_SERVER_PASSWORD_CHANGE=yes\n`);

    const deadline = Date.now() + 3000;
    while (rotations.length === 0 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.equal(activePassword, PASSWORD_B);
    assert.ok(attemptedPasswords.includes(PASSWORD_B));
    assert.deepEqual(rotations, [{ disconnectClients: true }]);
  } finally {
    await monitor?.stop();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('password monitor skips expensive rotation for an unchanged file revision', async () => {
  const { startServerPasswordMonitor } = await import('../authentication/server-password-monitor.js');
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-password-revision-'));
  const envPath = path.join(tempDir, '.env');
  fs.writeFileSync(envPath, `SERVER_PASSWORD=${PASSWORD_A}\n`, { mode: 0o600 });
  let attempts = 0;
  let monitor;
  try {
    monitor = await startServerPasswordMonitor({
      envPath,
      intervalMs: 20,
      logger: { info() { }, error() { } },
      async rotatePassword() {
        attempts += 1;
        return false;
      },
      async onPasswordRotated() {
      },
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(attempts, 1);

    fs.writeFileSync(envPath, `SERVER_PASSWORD=${PASSWORD_B}\n`, { mode: 0o600 });
    const deadline = Date.now() + 1000;
    while (attempts < 2 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.equal(attempts, 2);
  } finally {
    await monitor?.stop();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('password configuration rejects links and writable environment files', async () => {
  const { readServerPasswordConfiguration } = await import('../authentication/server-password-monitor.js');
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-password-config-'));
  const envPath = path.join(tempDir, '.env');
  const linkedPath = path.join(tempDir, '.env-link');
  const hardLinkedPath = path.join(tempDir, '.env-hard-link');
  try {
    fs.writeFileSync(envPath, `SERVER_PASSWORD=${PASSWORD_A}\n`, { mode: 0o600 });
    assert.deepEqual(readServerPasswordConfiguration(envPath), {
      password: PASSWORD_A,
      disconnectClients: false,
    });

    fs.symlinkSync(envPath, linkedPath);
    assert.throws(
      () => readServerPasswordConfiguration(linkedPath),
      /symbolic link|private regular file|ELOOP/i,
    );

    fs.linkSync(envPath, hardLinkedPath);
    assert.throws(
      () => readServerPasswordConfiguration(envPath),
      /private regular file/,
    );
    fs.unlinkSync(hardLinkedPath);

    for (const mode of [0o640, 0o644, 0o666]) {
      fs.chmodSync(envPath, mode);
      assert.throws(
        () => readServerPasswordConfiguration(envPath),
        /private regular file/,
      );
    }
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
