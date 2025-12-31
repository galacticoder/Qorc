#!/usr/bin/env node
/*
 * Tailscale TLS generator
 * - Writes cert/key to server/config/certs/<dns>.crt|.key
 */

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const { execFile, spawn } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

const repoRoot = path.resolve(__dirname, '..');
const CERT_DIR = path.join(repoRoot, 'server', 'config', 'certs');
const ENV_PATH = path.join(repoRoot, '.env');
const DB_TLS_LINES = [
  'DB_CA_CERT_PATH=/app/postgres-certs/root.crt',
  'DB_TLS_SERVERNAME=postgres'
];
const AUTH_WAIT_SECONDS = 120;

function findInPath(bin) {
  const exts = process.platform === 'win32' ? (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';') : [''];
  const parts = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  for (const dir of parts) {
    for (const ext of exts) {
      const p = path.join(dir, bin + ext);
      try { if (fs.existsSync(p)) return p; } catch { }
    }
  }
  return null;
}

async function mergeEnv(targetPath, newLines, ownership = null) {
  let existing = '';
  try { existing = await fs.promises.readFile(targetPath, 'utf8'); } catch { existing = ''; }

  const map = new Map();
  existing.split(/\r?\n/).forEach(line => {
    const m = line.match(/^([^#=\s]+)=?(.*)$/);
    if (m) map.set(m[1], line);
  });

  newLines.forEach((line) => {
    const m = line.match(/^([^#=\s]+)=?(.*)$/);
    if (m) map.set(m[1], line);
  });

  const merged = [...map.values()].join('\n') + '\n';
  const tmp = `${targetPath}.tmp`;
  await fs.promises.writeFile(tmp, merged, 'utf8');
  if (ownership) {
    const { uid, gid } = ownership;
    try { await fs.promises.chown(tmp, uid, gid); } catch { }
  }
  await fs.promises.rename(tmp, targetPath);
}

async function getTailscaleDNS() {
  try {
    const { stdout } = await execFileAsync('tailscale', ['status', '--json'], { windowsHide: true });
    const data = JSON.parse(stdout || '{}');
    const name = (data && data.Self && data.Self.DNSName) ? String(data.Self.DNSName) : '';
    return name.replace(/\.$/, '');
  } catch {
    return '';
  }
}

async function getStatus() {
  try {
    const { stdout } = await execFileAsync('tailscale', ['status', '--json'], { windowsHide: true });
    return JSON.parse(stdout || '{}');
  } catch {
    return null;
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let currentChild = null;
let aborted = false;
let printingDisabled = false;
const safeWrite = (s) => { if (!printingDisabled) try { process.stdout.write(s); } catch { } };

async function ensureLoggedIn() {
  const initialStatus = await getStatus();
  if (initialStatus && initialStatus.Self && initialStatus.Self.DNSName) {
    return String(initialStatus.Self.DNSName).replace(/\.$/, '');
  }

  const host = process.env.TAILSCALE_HOSTNAME || `Qor-${Math.random().toString(16).slice(2, 10)}`;
  const args = ['up', '--hostname', host, '--accept-dns=true'];

  const needsSudo = process.platform !== 'win32' && process.getuid && process.getuid() !== 0;
  const cmd = needsSudo ? 'sudo' : 'tailscale';
  const cmdArgs = needsSudo ? ['tailscale', ...args] : args;

  const waitForDns = async () => {
    safeWrite('[INFO] Waiting for Tailscale authentication');
    let dots = 0;
    let lastBackendState = '';
    for (let i = 0; i < AUTH_WAIT_SECONDS; i++) {
      if (aborted) { safeWrite('\n'); throw new Error('aborted'); }
      const status = await getStatus();
      const dns = status && status.Self && status.Self.DNSName ? String(status.Self.DNSName).replace(/\.$/, '') : '';
      if (dns) { safeWrite('\n'); return dns; }
      const backend = status && status.BackendState ? status.BackendState : '';
      if (backend && backend !== lastBackendState) {
        safeWrite(`\n[INFO] Backend state: ${backend}\n`);
        lastBackendState = backend;
        const loginUrl = status && status.LoginURL ? status.LoginURL : null;
        if (backend === 'NeedsLogin' && loginUrl) console.log(`[AUTH] Go to: ${loginUrl}`);
      }
      safeWrite('.');
      dots = (dots + 1) % 3;
      if (dots === 0) safeWrite('\r[INFO] Waiting for Tailscale authentication');
      await sleep(1000);
    }
    safeWrite('\n');
    throw new Error('Timed out waiting for Tailscale authentication');
  };

  const runAuth = async () => {
    if (process.env.TS_AUTHKEY) {
      const key = process.env.TS_AUTHKEY.trim();
      await execFileAsync(cmd, [...cmdArgs, '--authkey', key], { windowsHide: true });
      return;
    }

    if (!process.stdin.isTTY) {
      console.error('[FATAL] Tailscale authentication requires interactive mode or TS_AUTHKEY.');
      console.error('[FATAL] In Docker/non-interactive environments, set TS_AUTHKEY in your .env file.');
      console.error('[FATAL] Get an auth key from: https://login.tailscale.com/admin/settings/keys');
      throw new Error('TS_AUTHKEY required for non-interactive authentication');
    }

    console.log('[INFO] Starting Tailscale authentication...');
    if (needsSudo) console.log('[INFO] Running with sudo (Tailscale requires root access)');
    console.log('[INFO] Waiting for authentication to complete...');

    let urlShown = false;
    const child = spawn(cmd, cmdArgs, { stdio: ['inherit', 'pipe', 'pipe'] });
    currentChild = child;

    const showUrl = (s) => {
      const m = s.match(/https?:\/\/\S+/);
      if (m && !urlShown) {
        urlShown = true;
        console.log(`[AUTH] Go to: ${m[0]}`);
      }
    };

    child.stdout.on('data', (buf) => showUrl(buf.toString()));
    child.stderr.on('data', (buf) => showUrl(buf.toString()));
    const exitCode = await new Promise((resolve) => child.on('exit', (code, signal) => {
      if (signal === 'SIGINT' || signal === 'SIGTERM' || code === 130) aborted = true;
      resolve(code);
    }));
    currentChild = null;

    if (aborted) { printingDisabled = true; throw new Error('aborted'); }
    if (exitCode !== 0) throw new Error(`tailscale up exited with code ${exitCode}`);
  };

  await runAuth();
  if (aborted) throw new Error('aborted');
  return waitForDns();
}

async function getTailscaleVersion() {
  try {
    const { stdout, stderr } = await execFileAsync('tailscale', ['version']);
    const text = `${stdout || ''}\n${stderr || ''}`;
    const m = text.match(/\b(\d+)\.(\d+)\.(\d+)\b/);
    if (m) return { major: +m[1], minor: +m[2], patch: +m[3] };
  } catch { }
  return null;
}

async function tailscaleSupportsCertFiles() {
  try {
    const { stdout, stderr } = await execFileAsync('tailscale', ['cert', '--help']);
    const text = `${stdout || ''}\n${stderr || ''}`;
    if (/--cert-file/.test(text) && /--key-file/.test(text)) return true;
  } catch (e) {
    const text = `${(e && e.stdout) || ''}\n${(e && e.stderr) || ''}`;
    if (/--cert-file/.test(text) && /--key-file/.test(text)) return true;
  }
  const v = await getTailscaleVersion();
  if (v && (v.major > 1 || (v.major === 1 && v.minor >= 38))) return true;
  return false;
}

(async () => {
  let isExiting = false;
  process.on('SIGINT', () => {
    if (isExiting) {
      process.exit(130);
    }
    isExiting = true;
    aborted = true;
    printingDisabled = true;
    try { process.stdout.write('\n'); } catch { }
    console.log('[INFO] Interrupted. Exiting...');
    if (currentChild) {
      try { currentChild.kill('SIGINT'); } catch { }
      try { currentChild.kill('SIGTERM'); } catch { }
    }
    process.exit(130);
  });

  try {
    if (!findInPath('tailscale')) {
      console.error('[FATAL] tailscale CLI not found on PATH. Install it first (e.g., node scripts/install-deps.cjs tailscale).');
      process.exit(1);
    }

    const dns = await ensureLoggedIn();
    if (!/\.ts\.net$/.test(dns)) throw new Error(`Unexpected DNS name '${dns}' (expected *.ts.net)`);

    if (!(await tailscaleSupportsCertFiles())) {
      throw new Error("Your 'tailscale cert' lacks --cert-file/--key-file flags. Update Tailscale (>=1.38).");
    }

    const certPath = path.join(CERT_DIR, `${dns}.crt`);
    const keyPath = path.join(CERT_DIR, `${dns}.key`);
    await fsp.mkdir(CERT_DIR, { recursive: true });

    const certExists = fs.existsSync(certPath);
    const keyExists = fs.existsSync(keyPath);

    if (certExists || keyExists) {
      console.log('[WARN] Certificate files already exist:');
      if (certExists) console.log(`  - ${certPath}`);
      if (keyExists) console.log(`  - ${keyPath}`);

      const currentCert = process.env.TLS_CERT_PATH;
      const currentKey = process.env.TLS_KEY_PATH;
      
      const envCertMatch = currentCert && (currentCert === certPath || currentCert === `/app/server/config/certs/${dns}.crt`);
      const envKeyMatch = currentKey && (currentKey === keyPath || currentKey === `/app/server/config/certs/${dns}.key`);

      if (envCertMatch && envKeyMatch) {
          console.log('[INFO] .env already points to these certificates.');
          process.exit(0);
      }

      const readline = require('readline');
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
      });

      const answer = await new Promise((resolve) => {
        rl.question('Overwrite existing certificates? (y/N): ', (ans) => {
          rl.close();
          resolve(ans);
        });
      });

      if (!answer.trim().match(/^y(es)?$/i)) {
        console.log('[INFO] Keeping existing certificates');
        
        const tlsLines = [
          `TLS_CERT_PATH=/app/server/config/certs/${dns}.crt`,
          `TLS_KEY_PATH=/app/server/config/certs/${dns}.key`
        ];
        try {
          await mergeEnv(ENV_PATH, [...tlsLines, ...DB_TLS_LINES, 'SERVER_HOST=127.0.0.1']);
          console.log('[OK] Updated .env with existing TLS certificate paths');
        } catch (e) {
          console.log('[WARN] Could not update .env with existing paths');
        }
        process.exit(0);
      }

      console.log('[INFO] Overwriting certificates...');
    }

    try { await fsp.unlink(certPath); } catch { }
    try { await fsp.unlink(keyPath); } catch { }

    const needsSudo = process.platform !== 'win32' && process.getuid && process.getuid() !== 0;
    const certCmd = needsSudo ? 'sudo' : 'tailscale';
    const certArgs = needsSudo
      ? ['tailscale', 'cert', '--cert-file', certPath, '--key-file', keyPath, dns]
      : ['cert', '--cert-file', certPath, '--key-file', keyPath, dns];

    const { stderr } = await execFileAsync(certCmd, certArgs, { windowsHide: true });
    if (stderr && /does not support getting TLS certs/i.test(stderr)) {
      console.error('[FATAL] Your tailnet does not allow issuing TLS certs. Enable MagicDNS and HTTPS Certificates in the admin dashboard.');
      process.exit(1);
    }

    try { await fsp.chmod(keyPath, 0o600); } catch { }
    try { await fsp.chmod(certPath, 0o644); } catch { }

    if (process.platform !== 'win32' && process.env.SUDO_USER) {
      try {
        const uid = parseInt(process.env.SUDO_UID || '1000', 10);
        const gid = parseInt(process.env.SUDO_GID || '1000', 10);
        await fsp.chown(certPath, uid, gid);
        await fsp.chown(keyPath, uid, gid);
      } catch { }
    }

    console.log('[OK] Generated TLS materials for', dns);
    console.log('Cert:', certPath);
    console.log('Key :', keyPath, '(600)');

    const tlsLines = [
      `TLS_CERT_PATH=/app/server/config/certs/${dns}.crt`,
      `TLS_KEY_PATH=/app/server/config/certs/${dns}.key`
    ];

    try {
      const ownership = (process.platform !== 'win32' && process.env.SUDO_USER)
        ? { uid: parseInt(process.env.SUDO_UID || '1000', 10), gid: parseInt(process.env.SUDO_GID || '1000', 10) }
        : null;
      await mergeEnv(ENV_PATH, [...tlsLines, ...DB_TLS_LINES, 'SERVER_HOST=127.0.0.1'], ownership);
      console.log('[OK] Updated .env with TLS_CERT_PATH, TLS_KEY_PATH, SERVER_HOST');
    } catch (err) {
      if (err.code === 'EACCES' && process.platform !== 'win32' && findInPath('sudo')) {
        const chownSpec = (process.getuid && process.getgid)
          ? `${process.getuid()}:${process.getgid()}`
          : `${process.env.USER || '$(id -u)'}:${process.env.GROUP || '$(id -g)'}`;
        const tmp = `${ENV_PATH}.tmp.${Date.now()}`;
        try {
          await mergeEnv(tmp, [...tlsLines, ...DB_TLS_LINES, 'SERVER_HOST=127.0.0.1']);
          const cmd = `cp '${tmp}' '${ENV_PATH}' && chown ${chownSpec} '${ENV_PATH}' && chmod 644 '${ENV_PATH}'`;
          await execFileAsync('sudo', ['bash', '-lc', cmd]);
          try { await fsp.unlink(tmp); } catch { }
          console.log('[OK] Updated .env with TLS_CERT_PATH, TLS_KEY_PATH, SERVER_HOST');
          return;
        } catch (e2) {
          try { await fsp.unlink(tmp); } catch { }
          console.log('[WARN] Could not write .env even with sudo');
        }
      }
      console.log('[WARN] Could not write .env (permission denied)');
      console.log('[INFO] Manually add to .env:');
      console.log(`  TLS_CERT_PATH=${certPath}`);
      console.log(`  TLS_KEY_PATH=${keyPath}`);
      console.log('  SERVER_HOST=127.0.0.1');
    }
  } catch (e) {
    if (e && String(e.message || e) === 'aborted') {
      process.exit(130);
    }
    console.error('[FATAL]', e.message);
    process.exit(1);
  }
})();
