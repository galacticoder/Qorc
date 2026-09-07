import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'vite';

test('account credential encoding rejects delimiter collisions and lossy Unicode', async () => {
  const server = await createServer({
    configFile: false, server: { middlewareMode: true, watch: null },
    appType: 'custom', logLevel: 'silent', optimizeDeps: { noDiscovery: true },
  });
  try {
    const { encodeAccountAuthSecret, isValidAccountCredential } =
      await server.ssrLoadModule('/src/lib/auth/account-credentials.ts');
    assert.throws(() => encodeAccountAuthSecret('alice', 'password\0s:middle', 'tail'));
    assert.throws(() => encodeAccountAuthSecret('alice', 'password', 'middle\0s:tail'));
    for (const invalid of ['', '\0', 'x\0y', '\ud800', '\udfff', 'a\ud800b', '\udc00\ud800', 'x'.repeat(1025)]) {
      assert.equal(isValidAccountCredential(invalid), false);
      assert.throws(() => encodeAccountAuthSecret('alice', invalid, 'passphrase'));
      assert.throws(() => encodeAccountAuthSecret('alice', 'password', invalid));
    }
    for (const password of ['ordinary password', 'é密码🔒', '\ufffd', 'p:s:\n\t', 'x'.repeat(1024)]) {
      assert.equal(isValidAccountCredential(password), true);
      assert.notDeepEqual(
        encodeAccountAuthSecret('alice', password, '🔑different phrase'),
        new TextEncoder().encode(`u:alice\0p:${password}\0s:🔑different phrase`),
      );
    }
    for (let unit = 0; unit <= 0xffff; unit += 1) {
      const value = String.fromCharCode(unit);
      if (!isValidAccountCredential(value)) continue;
      assert.notDeepEqual(
        encodeAccountAuthSecret('alice', `password${value}`, 'passphrase'),
        encodeAccountAuthSecret('alice', 'password', `${value}passphrase`),
      );
    }
  } finally {
    await server.close();
  }
});
