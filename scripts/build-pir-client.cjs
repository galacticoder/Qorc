#!/usr/bin/env node

// Builds pinned hintless PIR worker and client binaries from workers/hintless and extracts into src-tauri/binaries

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '..');
const hintlessDir = path.join(repoRoot, 'workers', 'hintless');
const image = process.env.QOR_PIR_BUILD_IMAGE || 'qor-pir-hintless:build';
const outDir = path.join(repoRoot, 'src-tauri', 'binaries');
const clientOutPath = path.join(outDir, process.platform === 'win32' ? 'qor-pir-client.exe' : 'qor-pir-client');
const workerOutPath = path.join(outDir, process.platform === 'win32' ? 'qor-pir-worker.exe' : 'qor-pir-worker');

function run(command, args, options = {}) {
  execFileSync(command, args, { cwd: repoRoot, stdio: options.stdio || 'inherit' });
}

fs.mkdirSync(outDir, { recursive: true });

run('docker', ['build', '--target', 'build', '-t', image, hintlessDir]);

const containerId = execFileSync('docker', ['create', image], {
  cwd: repoRoot,
  encoding: 'utf8'
}).trim();

try {
  run('docker', ['cp', `${containerId}:/out/qor-pir-client`, clientOutPath]);
  run('docker', ['cp', `${containerId}:/out/qor-pir-worker`, workerOutPath]);
  fs.chmodSync(clientOutPath, 0o755);
  fs.chmodSync(workerOutPath, 0o755);
  console.log(`[PIR-BINARIES] Wrote ${path.relative(repoRoot, clientOutPath)}`);
  console.log(`[PIR-BINARIES] Wrote ${path.relative(repoRoot, workerOutPath)}`);
} finally {
  run('docker', ['rm', '-f', containerId], { stdio: 'ignore' });
}
