#!/usr/bin/env node
'use strict';

/**
 * Builds two PIR sidecars and stages for bundling
 */

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '..');
const cargoDir = path.join(repoRoot, 'workers', 'ypir');
const outDir = path.join(repoRoot, 'src-tauri', 'binaries');
const BINARIES = ['qor-pir-worker', 'qor-pir-client'];

function hostTriple() {
  const output = execFileSync('rustc', ['-vV'], { encoding: 'utf8' });
  const match = /^host:\s*(\S+)$/m.exec(output);
  if (!match) throw new Error('Could not determine the host target triple');
  return match[1];
}

function main() {
  if (process.platform !== 'linux' && process.platform !== 'win32') {
    throw new Error('Qor PIR sidecars support only Linux and Windows');
  }

  if (!fs.existsSync(path.join(cargoDir, 'Cargo.toml'))) {
    throw new Error(`Vendored YPIR tree is missing at ${cargoDir}`);
  }

  console.log('[pir] building sidecars');
  execFileSync('cargo', ['build', '--release', '--offline', '--bins'], {
    cwd: cargoDir,
    stdio: 'inherit'
  });

  const triple = hostTriple();
  const executableSuffix = process.platform === 'win32' ? '.exe' : '';
  fs.mkdirSync(outDir, { recursive: true });

  for (const name of BINARIES) {
    const built = path.join(cargoDir, 'target', 'release', `${name}${executableSuffix}`);
    if (!fs.existsSync(built)) {
      throw new Error(`Expected ${name} at ${built}`);
    }
    const staged = path.join(outDir, `${name}-${triple}${executableSuffix}`);
    fs.copyFileSync(built, staged);
    fs.chmodSync(staged, 0o755);
    const { size } = fs.statSync(staged);
    console.log(`[pir] staged ${path.relative(repoRoot, staged)} (${size} bytes)`);
  }
}

try {
  main();
} catch (error) {
  console.error(`[pir] ${error.message}`);
  process.exit(1);
}
