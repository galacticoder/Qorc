import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'vite';

test('native browser menu is suppressed while application handlers still run', async () => {
  const server = await createServer({
    configFile: false,
    server: { middlewareMode: true, watch: null },
    appType: 'custom',
    logLevel: 'silent',
    optimizeDeps: { noDiscovery: true },
  });
  try {
    const { installNativeContextMenuGuard } =
      await server.ssrLoadModule('/src/lib/runtime/native-context-menu.ts');
    const target = new EventTarget();
    let applicationHandlerCalls = 0;

    installNativeContextMenuGuard(target);
    installNativeContextMenuGuard(target);
    target.addEventListener('contextmenu', () => {
      applicationHandlerCalls += 1;
    });

    const event = new Event('contextmenu', { bubbles: true, cancelable: true });
    assert.equal(target.dispatchEvent(event), false);
    assert.equal(event.defaultPrevented, true);
    assert.equal(applicationHandlerCalls, 1);
  } finally {
    await server.close();
  }
});

test('packaged desktop configuration cannot expose developer tools', async () => {
  const { readFile } = await import('node:fs/promises');
  const [configText, capabilityText, cargoText] = await Promise.all([
    readFile(new URL('../../src-tauri/tauri.conf.json', import.meta.url), 'utf8'),
    readFile(new URL('../../src-tauri/capabilities/default.json', import.meta.url), 'utf8'),
    readFile(new URL('../../src-tauri/Cargo.toml', import.meta.url), 'utf8'),
  ]);
  const config = JSON.parse(configText);
  const capability = JSON.parse(capabilityText);

  assert.equal(config.app.windows[0].devtools, false);
  assert.equal(capability.permissions.some((value) => value.includes('devtools')), false);
  assert.doesNotMatch(cargoText, /features\s*=\s*\[[^\]]*\"devtools\"/s);
});
