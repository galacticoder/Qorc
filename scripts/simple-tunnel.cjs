#!/usr/bin/env node
/*
 * Cloudflare Tunnel helper 
 * Commands: start | stop | status | restart
 */

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const { spawn } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
const cfgDir = path.join(__dirname, 'config', 'tunnel');
const pidFile = path.join(cfgDir, 'pid');
const logFile = path.join(cfgDir, 'cloudflared.log');

function findInPath(bin) {
  const parts = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  const exts = process.platform === 'win32' ? (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';') : [''];
  for (const dir of parts) {
    for (const ext of exts) {
      try {
        const cand = path.join(dir, bin + ext);
        if (fs.existsSync(cand)) return cand;
      } catch { }
    }
  }
  return null;
}

async function start() {
  const bin = findInPath('cloudflared');
  if (!bin) {
    console.error('[TUNNEL] cloudflared not found. Install via: node scripts/install-deps.cjs cloudflared');
    process.exit(1);
  }

  const port = Number(process.env.HAPROXY_HTTPS_PORT || 8443);
  await fsp.mkdir(path.dirname(logFile), { recursive: true });
  const out = fs.createWriteStream(logFile, { flags: 'w' });

  // If CLOUDFLARED_TOKEN is set then use it for persistent tunnel
  const args = process.env.CLOUDFLARED_TOKEN
    ? ['tunnel', 'run', '--token', process.env.CLOUDFLARED_TOKEN]
    : ['tunnel', '--url', `https://127.0.0.1:${port}`, '--no-tls-verify'];

  console.log(`[TUNNEL] Starting cloudflared on port ${port}...`);

  const child = spawn(bin, args, { cwd: repoRoot, stdio: ['ignore', 'pipe', 'pipe'] });

  child.stdout.pipe(out, { end: false });
  child.stderr.pipe(out, { end: false });

  await fsp.writeFile(pidFile, String(child.pid || ''), 'utf8').catch(() => { });

  let url = null;
  console.log('[TUNNEL] Waiting for public URL...');

  for (let i = 0; i < 30 && !url; i++) {
    await new Promise((r) => setTimeout(r, 1000));
    try {
      const content = await fsp.readFile(logFile, 'utf8');
      const match = content.match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/);
      if (match) {
        url = match[0];
      }
    } catch { }
  }

  if (url) {
    console.log('Public HTTPS URL:', url);
  } else {
    if (process.env.CLOUDFLARED_TOKEN) {
      console.log('Cloudflare Tunnel started. Check Cloudflare Dashboard for status.');
    } else {
      console.log('Cloudflare Tunnel started but URL not found yet. Check scripts/config/tunnel/cloudflared.log');
    }
  }
}

async function stop() {
  try {
    const pid = Number((await fsp.readFile(pidFile, 'utf8')).trim());
    if (pid) {
      try { process.kill(pid, 'SIGTERM'); } catch { }
      console.log('Stopped cloudflared tunnel (PID ' + pid + ')');
    }
  } catch { }

  try {
    if (process.platform !== 'win32') {
      const { execSync } = require('child_process');
      execSync('pkill cloudflared || true');
    }
  } catch { }

  await fsp.unlink(pidFile).catch(() => { });
}

async function status() {
  try {
    const pid = Number((await fsp.readFile(pidFile, 'utf8')).trim());
    if (pid) {
      try {
        process.kill(pid, 0);
        console.log('Cloudflared is running (PID ' + pid + ')');

        const content = await fsp.readFile(logFile, 'utf8');
        const match = content.match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/);
        if (match) {
          console.log('Public HTTPS URL:', match[0]);
        }
        process.exit(0);
      } catch {
        console.log('Stale PID file found. Tunnel not running.');
        process.exit(1);
      }
    }
  } catch { }

  console.log('No active tunnel');
  process.exit(1);
}

(async () => {
  const cmd = (process.argv[2] || '').toLowerCase();
  switch (cmd) {
    case 'start': await start(); break;
    case 'stop': await stop(); break;
    case 'status': await status(); break;
    case 'restart': await stop().catch(() => { }); await start(); break;
    default:
      console.log('Usage: node scripts/simple-tunnel.cjs <start|stop|status|restart>');
      process.exit(1);
  }
})();
