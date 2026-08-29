#!/usr/bin/env node
'use strict';

/**
 * Builds PIR sidecars and stages them for bundling.
 */

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '..');
const cargoDir = path.join(repoRoot, 'workers', 'ypir');
const outDir = path.join(repoRoot, 'src-tauri', 'binaries');
const ALL_BINARIES = ['qor-pir-worker', 'qor-pir-client'];

function parseArgs() {
  const args = process.argv.slice(2);
  let target = null;
  let clientOnly = false;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--client-only') {
      clientOnly = true;
    } else if (arg === '--target') {
      target = args[index + 1] || null;
      index += 1;
      if (!target) throw new Error('--target requires a Rust target triple');
    } else if (arg === '-h' || arg === '--help') {
      console.log('Usage: node scripts/build-pir-sidecars.cjs [--client-only] [--target <triple>]');
      console.log('  --client-only      Build only the client binary embedded in the desktop app');
      console.log('  --target <triple>  Build and stage a specific Rust target, including aarch64');
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return { target, clientOnly };
}

function hostTriple() {
  const output = execFileSync('rustc', ['-vV'], { encoding: 'utf8' });
  const match = /^host:\s*(\S+)$/m.exec(output);
  if (!match) throw new Error('Could not determine the host target triple');
  return match[1];
}

function validateTarget(target) {
  const architecture = target.split('-', 1)[0];
  if (!['x86_64', 'aarch64'].includes(architecture)) {
    throw new Error(`Unsupported PIR target architecture '${architecture}'; use x86_64 or aarch64`);
  }
  if (!/(linux|windows|darwin)/.test(target)) {
    throw new Error(`Unsupported PIR target platform in '${target}'. use Linux, Windows, or macOS`);
  }
}

function main() {
  const { target: requestedTarget, clientOnly } = parseArgs();

  if (!fs.existsSync(path.join(cargoDir, 'Cargo.toml'))) {
    throw new Error(`Vendored YPIR tree is missing at ${cargoDir}`);
  }

  const target = requestedTarget || hostTriple();
  validateTarget(target);
  const binaries = clientOnly ? ['qor-pir-client'] : ALL_BINARIES;
  const cargoArgs = ['build', '--release', '--offline'];
  if (requestedTarget) cargoArgs.push('--target', target);
  for (const binary of binaries) cargoArgs.push('--bin', binary);

  console.log(`[pir] building ${binaries.join(', ')} for ${target}`);
  execFileSync('cargo', cargoArgs, {
    cwd: cargoDir,
    stdio: 'inherit'
  });

  const executableSuffix = target.includes('windows') ? '.exe' : '';
  const releaseDir = requestedTarget
    ? path.join(cargoDir, 'target', target, 'release')
    : path.join(cargoDir, 'target', 'release');
  fs.mkdirSync(outDir, { recursive: true });

  for (const name of binaries) {
    const built = path.join(releaseDir, `${name}${executableSuffix}`);
    if (!fs.existsSync(built)) {
      throw new Error(`Expected ${name} at ${built}`);
    }
    const staged = path.join(outDir, `${name}-${target}${executableSuffix}`);
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
