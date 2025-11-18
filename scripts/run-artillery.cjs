#!/usr/bin/env node
/*
 * Artillery runner for testing server handling and stability
 * Usage: node scripts/run-artillery.cjs <100k|aggressive>
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

function findInPath(bin) {
  const parts = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  const exts = process.platform === 'win32' ? (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';') : [''];
  for (const dir of parts) {
    for (const ext of exts) {
      try { const p = path.join(dir, bin + ext); if (fs.existsSync(p)) return p; } catch {}
    }
  }
  return null;
}

function binOrNull(names) {
  for (const n of names) { const p = findInPath(n); if (p) return p; }
  return null;
}

(async () => {
  const mode = (process.argv[2] || '100k').toLowerCase();
  const envName = mode === 'aggressive' ? 'aggressive' : 'hundredk';
  const out = mode === 'aggressive' ? 'aggressive.json' : 'hundredk.json';
  const yaml = path.resolve('artillery.yml');
  if (!fs.existsSync(yaml)) {
    console.error('artillery.yml not found at repo root');
    process.exit(1);
  }

  const artillery = findInPath('artillery');
  const npx = binOrNull(['npx', 'npx.cmd']);
  const cmd = artillery ? artillery : (npx ? npx : null);
  if (!cmd) {
    console.error('Artillery not installed. Run: npm i -g artillery OR use npx artillery');
    process.exit(1);
  }

  const args = artillery ? ['run', '-e', envName, '-o', out, yaml] : ['artillery@latest', 'run', '-e', envName, '-o', out, yaml];
  const env = { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: '0' };
  console.log(`[ARTILLERY] Running mode=${envName}, output=${out}`);
  const child = spawn(cmd, args, { stdio: 'inherit', env });
  child.on('exit', (code) => process.exit(code || 0));
})();
