#!/usr/bin/env node

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const os = require('os');
const net = require('net');
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

const repoRoot = path.resolve(__dirname, '..');
const CERT_DIR = path.join(repoRoot, 'server', 'config', 'certs');
const ENV_PATH = path.join(repoRoot, '.env');
const DB_TLS_LINES = [
  'PGSSLROOTCERT=postgres-certs/root.crt',
  'DB_TLS_SERVERNAME=postgres'
];

function normalizeTlsCertCommonName(rawValue) {
  const value = typeof rawValue === 'string' ? rawValue.trim().toLowerCase() : '';
  if (!value || value.length > 253 || /[\u0000-\u001f\u007f-\u009f]/.test(value)) {
    throw new Error('TLS_CERT_CN must be a valid DNS hostname or IPv4 address');
  }
  if (net.isIP(value) === 4) return value;
  const labels = value.split('.');
  if (labels.some((label) => (
    label.length < 1 ||
    label.length > 63 ||
    !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  ))) {
    throw new Error('TLS_CERT_CN must be a valid DNS hostname or IPv4 address');
  }
  return value;
}

const CERT_CN = normalizeTlsCertCommonName(process.env.TLS_CERT_CN || 'localhost');

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
  await fs.promises.writeFile(targetPath, merged, { encoding: 'utf8', mode: 0o600 });
  await fs.promises.chmod(targetPath, 0o600);

  if (ownership) {
    const { uid, gid } = ownership;
    try { await fs.promises.chown(targetPath, uid, gid); } catch { }
  }
}

function buildSanList() {
  const sans = new Set(['DNS:localhost', 'IP:127.0.0.1', 'IP:::1']);
  if (CERT_CN !== 'localhost') {
    sans.add(`${net.isIP(CERT_CN) ? 'IP' : 'DNS'}:${CERT_CN}`);
  }
  try {
    const hostname = normalizeTlsCertCommonName(os.hostname());
    if (!net.isIP(hostname)) sans.add(`DNS:${hostname}`);
  } catch { }
  return [...sans].join(',');
}

async function writeEnv(relCert, relKey) {
  const tlsLines = [
    `TLS_CERT_PATH=${relCert}`,
    `TLS_KEY_PATH=${relKey}`
  ];
  try {
    const ownership = (process.platform !== 'win32' && process.env.SUDO_USER)
      ? { uid: parseInt(process.env.SUDO_UID || '1000', 10), gid: parseInt(process.env.SUDO_GID || '1000', 10) }
      : null;
    await mergeEnv(ENV_PATH, [...tlsLines, ...DB_TLS_LINES, 'SERVER_HOST=127.0.0.1'], ownership);
    console.log('[OK] Updated .env with TLS_CERT_PATH, TLS_KEY_PATH, SERVER_HOST');
  } catch (err) {
    if (err.code === 'EACCES' && process.platform !== 'win32' && findInPath('sudo')) {
      const uid = typeof process.getuid === 'function' ? process.getuid() : null;
      const gid = typeof process.getgid === 'function' ? process.getgid() : null;
      if (!Number.isSafeInteger(uid) || uid < 0 || !Number.isSafeInteger(gid) || gid < 0) {
        throw new Error('Unable to determine safe .env ownership');
      }
      const tmpDirectory = await fsp.mkdtemp(path.join(os.tmpdir(), 'qorc-env-'));
      const tmp = path.join(tmpDirectory, '.env');
      try {
        const existing = await fsp.readFile(ENV_PATH, 'utf8').catch(() => '');
        await fsp.writeFile(tmp, existing, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
        await mergeEnv(tmp, [...tlsLines, ...DB_TLS_LINES, 'SERVER_HOST=127.0.0.1']);
        await execFileAsync('sudo', [
          'install',
          '-o', String(uid),
          '-g', String(gid),
          '-m', '600',
          '--', tmp, ENV_PATH
        ]);
        console.log('[OK] Updated .env with TLS_CERT_PATH, TLS_KEY_PATH, SERVER_HOST');
        return;
      } catch (e2) {
      } finally {
        try { await fsp.rm(tmpDirectory, { recursive: true, force: true }); } catch { }
      }
    }
    console.log('[WARN] Could not write .env. Manually add to .env:');
    console.log(`  TLS_CERT_PATH=${relCert}`);
    console.log(`  TLS_KEY_PATH=${relKey}`);
    console.log('  SERVER_HOST=127.0.0.1');
  }
}

if (require.main === module) {
(async () => {
  try {
    if (!findInPath('openssl')) {
      console.error('[FATAL] openssl CLI not found on PATH. Install it first (e.g., node scripts/install-deps.cjs openssl).');
      process.exit(1);
    }

    await fsp.mkdir(CERT_DIR, { recursive: true });
    const certPath = path.join(CERT_DIR, `${CERT_CN}.crt`);
    const keyPath = path.join(CERT_DIR, `${CERT_CN}.key`);
    const relCert = path.relative(repoRoot, certPath);
    const relKey = path.relative(repoRoot, keyPath);

    const force = process.argv.includes('--force');
    if (fs.existsSync(certPath) && fs.existsSync(keyPath) && !force) {
      console.log('[INFO] TLS certificate already exists:');
      console.log(`  - ${certPath}`);
      console.log(`  - ${keyPath}`);
      await writeEnv(relCert, relKey);
      console.log(`[JSON_PATHS] ${JSON.stringify({ TLS_CERT_PATH: relCert, TLS_KEY_PATH: relKey })}`);
      process.exit(0);
    }

    try { await fsp.unlink(certPath); } catch { }
    try { await fsp.unlink(keyPath); } catch { }

    const args = [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath, '-out', certPath,
      '-days', '825', '-sha256',
      '-subj', `/CN=${CERT_CN}`,
      '-addext', `subjectAltName=${buildSanList()}`
    ];
    await execFileAsync('openssl', args, { windowsHide: true });

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

    console.log('[OK] Generated self-signed TLS materials for', CERT_CN);
    console.log('Cert:', certPath);
    console.log('Key :', keyPath, '(600)');

    await writeEnv(relCert, relKey);
    console.log(`[JSON_PATHS] ${JSON.stringify({ TLS_CERT_PATH: relCert, TLS_KEY_PATH: relKey })}`);
  } catch (e) {
    console.error('[FATAL]', e.message);
    process.exit(1);
  }
})();
}

module.exports = { normalizeTlsCertCommonName };
