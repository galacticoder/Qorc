#!/usr/bin/env node

// Build YPIR client daemon and place in src-tauri/binaries/ypir-client

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..');
const crateDir = path.join(repoRoot, 'workers', 'ypir');
const suffix = process.platform === 'win32' ? '.exe' : '';
const outDir = path.join(repoRoot, 'src-tauri', 'binaries');
const outPath = path.join(outDir, `ypir-client${suffix}`);

fs.mkdirSync(outDir, { recursive: true });

const home = process.env.HOME || '';
const env = {
  ...process.env,
  RUSTFLAGS: `-C target-cpu=native -L native=${path.join(home, '.local/lib')}`
};

console.log('[build-ypir-client] cargo build --release --bin ypir_client nightly AVX-512');
execFileSync('cargo', ['build', '--release', '--bin', 'ypir_client'], {
  cwd: crateDir,
  stdio: 'inherit',
  env
});

const built = path.join(crateDir, 'target', 'release', `ypir_client${suffix}`);
if (!fs.existsSync(built)) {
  console.error(`[build-ypir-client] expected binary not found: ${built}`);
  process.exit(1);
}

fs.copyFileSync(built, outPath);
console.log(`[build-ypir-client] -> ${outPath}`);
