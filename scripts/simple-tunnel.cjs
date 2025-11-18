#!/usr/bin/env node
/*
 * Cross-platform ngrok tunnel helper 
 * Commands: start | stop | status | restart
 * Uses scripts/config/tunnel for config/logs/pid
 */

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const http = require('http');
const { spawn } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
const cfgDir = path.join(__dirname, 'config', 'tunnel');
const pidFile = path.join(cfgDir, 'pid');
const logFile = path.join(cfgDir, 'tunnel.log');
const ngrokLog = path.join(cfgDir, 'ngrok.log');
const ngrokConfig = path.join(cfgDir, 'ngrok.yml');

function findInPath(bin) {
  const parts = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  const exts = process.platform === 'win32' ? (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';') : [''];
  for (const dir of parts) {
    for (const ext of exts) {
      try {
        const cand = path.join(dir, bin + ext);
        if (fs.existsSync(cand)) return cand;
      } catch {}
    }
  }
  return null;
}

async function httpGetJson(url, timeoutMs = 1500) {
  return new Promise((resolve) => {
    try {
      const req = http.get(url, { timeout: timeoutMs }, (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          try { resolve(JSON.parse(data || '{}')); } catch { resolve(null); }
        });
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { try { req.destroy(); } catch {}; resolve(null); });
    } catch { resolve(null); }
  });
}

async function writeNgrokConfig() {
  await fsp.mkdir(cfgDir, { recursive: true });
  const token = process.env.NGROK_AUTHTOKEN || '';
  const yml = token ? `authtoken: ${token}\n` : '';
  await fsp.writeFile(ngrokConfig, yml, 'utf8');
}

async function getHttpsUrl() {
  const data = await httpGetJson('http://127.0.0.1:4040/api/tunnels', 1500);
  const tunnels = Array.isArray(data?.tunnels) ? data.tunnels : [];
  const https = tunnels.find((t) => t.proto === 'https' && typeof t.public_url === 'string');
  return https?.public_url || null;
}

async function start() {
  // Prefer repo-local ngrok binary if available
  const localNgrok = path.join(cfgDir, 'ngrok');
  let bin = null;
  if (fs.existsSync(localNgrok)) {
    bin = localNgrok;
  } else {
    bin = findInPath('ngrok');
  }
  if (!bin) {
    console.error('[TUNNEL] ngrok not found. Install via: node scripts/install-deps.cjs ngrok');
    process.exit(1);
  }

  await writeNgrokConfig();
  const port = Number(process.env.HAPROXY_HTTPS_PORT || 8443);
  await fsp.mkdir(path.dirname(logFile), { recursive: true });
  const out = fs.createWriteStream(ngrokLog, { flags: 'a' });

  const env = { ...process.env, NGROK_CONFIG: ngrokConfig };
  const target = `https://127.0.0.1:${port}`;

  const child = spawn(bin, ['http', target], { cwd: repoRoot, env, stdio: ['ignore', 'pipe', 'pipe'] });
  child.on('error', (e) => console.error('[TUNNEL] ngrok error:', e.message));
  if (child.stdout) child.stdout.pipe(out, { end: false });
  if (child.stderr) child.stderr.pipe(out, { end: false });

  await fsp.writeFile(pidFile, String(child.pid || ''), 'utf8').catch(() => {});

  // Wait for public URL
  let url = null;
  for (let i = 0; i < 20 && !url; i++) {
    await new Promise((r) => setTimeout(r, 300));
    url = await getHttpsUrl();
  }
  if (url) {
    console.log('Public HTTPS URL:', url);
    console.log('Dashboard: http://127.0.0.1:4040');
  } else {
    console.log('ngrok started; waiting for tunnel (dashboard at http://127.0.0.1:4040)');
  }
}

async function stop() {
  try {
    const pid = Number((await fsp.readFile(pidFile, 'utf8')).trim());
    if (pid) { try { process.kill(pid, 'SIGTERM'); } catch {} }
  } catch {}
  const data = await httpGetJson('http://127.0.0.1:4040/api/tunnels', 1000);
  const tunnels = Array.isArray(data?.tunnels) ? data.tunnels : [];
  for (const t of tunnels) {
    const name = t?.name;
    if (!name) continue;
    await new Promise((resolve) => {
      const req = http.request({ host: '127.0.0.1', port: 4040, path: `/api/tunnels/${encodeURIComponent(name)}`, method: 'DELETE', timeout: 1000 }, (res) => {
        res.resume(); res.on('end', resolve);
      });
      req.on('error', resolve);
      req.on('timeout', () => { try { req.destroy(); } catch {}; resolve(); });
      req.end();
    });
  }
  await fsp.unlink(pidFile).catch(() => {});
  console.log('Stopped ngrok tunnel (if running).');
}

async function status() {
  const url = await getHttpsUrl();
  if (url) {
    console.log('Public HTTPS URL:', url);
    process.exit(0);
  } else {
    console.log('No active tunnel');
    process.exit(1);
  }
}

(async () => {
  const cmd = (process.argv[2] || '').toLowerCase();
  switch (cmd) {
    case 'start': await start(); break;
    case 'stop': await stop(); break;
    case 'status': await status(); break;
    case 'restart': await stop().catch(()=>{}); await start(); break;
    default:
      console.log('Usage: node scripts/simple-tunnel.cjs <start|stop|status|restart>');
      process.exit(1);
  }
})();
