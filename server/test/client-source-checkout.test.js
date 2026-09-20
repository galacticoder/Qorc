import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('../../', import.meta.url));
const sourceFiles = new Set(execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], {
  cwd: root,
  encoding: 'utf8',
  maxBuffer: 16 * 1024 * 1024,
}).split('\0'));

test('fresh client checkouts include their package manifest and frontend build configuration', () => {
  for (const file of [
    'package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', 'postcss.config.js',
    'tailwind.config.ts', 'tsconfig.json', 'tsconfig.app.json', 'tsconfig.node.json',
    'vite.config.simple.ts', '.gitattributes',
  ]) {
    assert.ok(sourceFiles.has(file), `${file} must not be excluded from the source checkout`);
    assert.ok(fs.existsSync(path.join(root, file)), `${file} must exist`);
  }
  const config = JSON.parse(fs.readFileSync(path.join(root, 'tsconfig.node.json'), 'utf8'));
  for (const included of config.include) assert.ok(sourceFiles.has(included), `${included} must exist in the checkout`);
});

test('all vendored PIR checksum inputs are included and match their original bytes', () => {
  let checked = 0;
  const directory = 'workers/ypir/vendor';
  for (const crate of fs.readdirSync(path.join(root, directory))) {
    const manifest = `${directory}/${crate}/.cargo-checksum.json`;
    const { files } = JSON.parse(fs.readFileSync(path.join(root, manifest), 'utf8'));
    for (const [filename, expected] of Object.entries(files)) {
      const file = `${directory}/${crate}/${filename}`;
      assert.ok(sourceFiles.has(file), `${file} is required by Cargo but excluded from the source checkout`);
      const content = fs.readFileSync(path.join(root, file));
      assert.equal(createHash('sha256').update(content).digest('hex'), expected, `${file} has changed`);
      checked++;
    }
  }
  assert.ok(checked > 1000);
});

test('Windows-style Git checkout preserves Cargo vendor checksums', () => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-vendor-checkout-'));
  try {
    const git = args => execFileSync('git', ['-c', 'core.autocrlf=true', ...args], { cwd: fixture, stdio: 'pipe' });
    git(['init', '--quiet']);
    fs.copyFileSync(path.join(root, '.gitattributes'), path.join(fixture, '.gitattributes'));
    const files = [
      'workers/ypir/vendor/proc-macro2-1.0.78/build/probe.rs',
      'workers/ypir/vendor/typenum-1.17.0/build/main.rs',
      'workers/ypir/vendor/cc-1.0.83/src/bin/gcc-shim.rs',
    ];
    for (const file of files) {
      fs.mkdirSync(path.dirname(path.join(fixture, file)), { recursive: true });
      fs.copyFileSync(path.join(root, file), path.join(fixture, file));
    }
    git(['add', '--', '.gitattributes', ...files]);
    const checkout = path.join(fixture, 'checkout');
    fs.mkdirSync(checkout);
    git(['checkout-index', '--all', `--prefix=${checkout.replaceAll('\\', '/')}/`]);
    for (const file of files) {
      assert.deepEqual(fs.readFileSync(path.join(checkout, file)), fs.readFileSync(path.join(root, file)), file);
    }
  } finally {
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});
