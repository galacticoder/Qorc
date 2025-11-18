#!/usr/bin/env node
/*
 * Cross-platform Tailscale TLS generator
 * - Writes cert/key to server/config/certs/<dns>.crt|.key
 */

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const { execFile, spawn } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

const repoRoot = path.resolve(__dirname, '..');

function findInPath(bin) {
  const exts = process.platform === 'win32' ? (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';') : [''];
  const parts = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  for (const dir of parts) {
    for (const ext of exts) {
      const p = path.join(dir, bin + ext);
      try { if (fs.existsSync(p)) return p; } catch {}
    }
  }
  return null;
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

let currentChild = null;
let aborted = false;
let printingDisabled = false;
const safeWrite = (s) => { if (!printingDisabled) try { process.stdout.write(s); } catch {} };

async function ensureLoggedIn() {
  let dns = await getTailscaleDNS();
  if (dns) return dns;

  const host = process.env.TAILSCALE_HOSTNAME || `endtoend-${Math.random().toString(16).slice(2, 10)}`;
  const args = ['up', '--hostname', host, '--accept-dns=true'];
  
  const needsSudo = process.platform !== 'win32' && process.getuid && process.getuid() !== 0;
  const cmd = needsSudo ? 'sudo' : 'tailscale';
  const cmdArgs = needsSudo ? ['tailscale', ...args] : args;
  
  if (process.env.TS_AUTHKEY) {
    cmdArgs.push('--authkey', process.env.TS_AUTHKEY);
    await execFileAsync(cmd, cmdArgs, { windowsHide: true });
  } else {
    console.log('[INFO] Starting Tailscale authentication...');
    if (needsSudo) {
      console.log('[INFO] Running with sudo (Tailscale requires root access)');
    }
    console.log('[INFO] Waiting for authentication to complete...');
    let loginUrl = '';
    let urlShown = false;
    const child = spawn(cmd, cmdArgs, { stdio: ['inherit', 'pipe', 'pipe'] });
    currentChild = child;
    
    const showUrl = (s) => {
      const m = s.match(/https?:\/\/\S+/);
      if (m && !urlShown) {
        loginUrl = m[0];
        urlShown = true;
        console.log(`[AUTH] Go to: ${loginUrl}`);
      }
    };
    
    child.stdout.on('data', (buf) => {
      const s = buf.toString();
      showUrl(s);
    });
    child.stderr.on('data', (buf) => {
      const s = buf.toString();
      showUrl(s);
    });
    await new Promise((resolve) => child.on('exit', (code, signal) => {
      if (signal === 'SIGINT' || signal === 'SIGTERM' || code === 130) {
        aborted = true;
      }
      resolve();
    }));
    currentChild = null;
    
    if (aborted) {
      printingDisabled = true;
      throw new Error('aborted');
    }
    
    if (!urlShown) {
      console.log('[WARN] No auth URL found in tailscale output. May already be authenticated.');
    }
  }

  if (aborted) throw new Error('aborted');
  safeWrite('[INFO] Waiting for Tailscale authentication');
  let dotCount = 0;
  for (let i = 0; i < 90; i++) {
    if (typeof aborted !== 'undefined' && aborted) { process.stdout.write('\n'); throw new Error('aborted'); }
    dns = await getTailscaleDNS();
    if (dns) { 
      safeWrite('\n'); 
      return dns; 
    }
    safeWrite('.');
    dotCount++;
    if (dotCount >= 3) {
      safeWrite('\r[INFO] Waiting for Tailscale authentication   ');
      safeWrite('\r[INFO] Waiting for Tailscale authentication');
      dotCount = 0;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  process.stdout.write('\n');
  throw new Error('Timed out waiting for Tailscale authentication');
}

async function getTailscaleVersion() {
  try {
    const { stdout, stderr } = await execFileAsync('tailscale', ['version']);
    const text = `${stdout || ''}\n${stderr || ''}`;
    const m = text.match(/\b(\d+)\.(\d+)\.(\d+)\b/);
    if (m) return { major: +m[1], minor: +m[2], patch: +m[3] };
  } catch {}
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
    try { process.stdout.write('\n'); } catch {}
    console.log('[INFO] Interrupted. Exiting...');
    if (currentChild) {
      try { currentChild.kill('SIGINT'); } catch {}
      try { currentChild.kill('SIGTERM'); } catch {}
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

    const baseDir = path.join(repoRoot, 'server', 'config', 'certs');
    const certPath = path.join(baseDir, `${dns}.crt`);
    const keyPath = path.join(baseDir, `${dns}.key`);
    await fsp.mkdir(baseDir, { recursive: true });

    // Check if certs already exist and ask user
    const certExists = fs.existsSync(certPath);
    const keyExists = fs.existsSync(keyPath);
    
    if (certExists || keyExists) {
      console.log('[WARN] Certificate files already exist:');
      if (certExists) console.log(`  - ${certPath}`);
      if (keyExists) console.log(`  - ${keyPath}`);
      
      // Prompt user
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
        console.log('[INFO] Certificate paths already in .env');
        process.exit(0);
      }
      
      console.log('[INFO] Overwriting certificates...');
    }

    try { await fsp.unlink(certPath); } catch {}
    try { await fsp.unlink(keyPath); } catch {}

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

    // Permissions and ownership 
    try { await fsp.chmod(keyPath, 0o600); } catch {}
    try { await fsp.chmod(certPath, 0o644); } catch {}
    
    // If we ran tailscale with sudo, fix ownership back to current user
    if (process.platform !== 'win32' && process.env.SUDO_USER) {
      try {
        const { execFileAsync } = require('child_process');
        const { promisify } = require('util');
        const uid = parseInt(process.env.SUDO_UID || '1000');
        const gid = parseInt(process.env.SUDO_GID || '1000');
        await fsp.chown(certPath, uid, gid);
        await fsp.chown(keyPath, uid, gid);
      } catch {}
    }

    console.log('[OK] Generated TLS materials for', dns);
    console.log('Cert:', certPath);
    console.log('Key :', keyPath, '(600)');

    // Write/update .env at project root
    const envPath = path.join(repoRoot, '.env');
    const absCert = certPath;
    const absKey = keyPath;

    // Update or create .env with TLS paths and SERVER_HOST
    let envText = '';
    try { envText = await fsp.readFile(envPath, 'utf8'); } catch {}
    const lines = envText ? envText.split(/\r?\n/) : [];
    const setKV = (k, v) => {
      const idx = lines.findIndex(l => l.trim().startsWith(k + '='));
      const newLine = `${k}=${JSON.stringify(v).replace(/^"|"$/g, '')}`;
      if (idx >= 0) lines[idx] = newLine; else lines.push(newLine);
    };
    setKV('TLS_CERT_PATH', absCert);
    setKV('TLS_KEY_PATH', absKey);
    if (!/^[ \t]*SERVER_HOST=/.test(envText || '')) setKV('SERVER_HOST', '127.0.0.1');
    const newEnv = lines.filter(Boolean).join('\n') + '\n';
    
    try {
      // If running as sudo, write as the original user
      if (process.platform !== 'win32' && process.env.SUDO_USER && process.getuid() === 0) {
        const user = process.env.SUDO_USER;
        const tmpFile = envPath + '.tmp';
        await fsp.writeFile(tmpFile, newEnv, 'utf8');
        
        const uid = parseInt(process.env.SUDO_UID || '1000');
        const gid = parseInt(process.env.SUDO_GID || '1000');
        await fsp.chown(tmpFile, uid, gid);
        await fsp.rename(tmpFile, envPath);
      } else {
        await fsp.writeFile(envPath, newEnv, 'utf8');
      }
      
      console.log('[OK] Updated .env with TLS_CERT_PATH, TLS_KEY_PATH, SERVER_HOST');
    } catch (err) {
      if (err.code === 'EACCES') {
        // Try to elevate with sudo to replace .env as the original user
        if (process.platform !== 'win32' && findInPath('sudo')) {
          const tmpUserFile = envPath + '.tmp.' + Date.now();
          try {
            await fsp.writeFile(tmpUserFile, newEnv, 'utf8');
            const uid = process.getuid ? process.getuid() : null;
            const gid = process.getgid ? process.getgid() : null;
            const chownSpec = uid !== null && gid !== null ? `${uid}:${gid}` : `${process.env.USER || '$(id -u)'}:${process.env.GROUP || '$(id -g)'}`;
            const cmd = `cp '${tmpUserFile}' '${envPath}' && chown ${chownSpec} '${envPath}' && chmod 644 '${envPath}'`;
            await execFileAsync('sudo', ['bash', '-lc', cmd]);
            try { await fsp.unlink(tmpUserFile); } catch {}
            console.log('[OK] Updated .env with TLS_CERT_PATH, TLS_KEY_PATH, SERVER_HOST');
            return;
          } catch (e2) {
            try { await fsp.unlink(tmpUserFile); } catch {}
            console.log('[WARN] Could not write .env even with sudo');
          }
        }
        console.log('[WARN] Could not write .env (permission denied)');
        console.log('[INFO] Manually add to .env:');
        console.log(`  TLS_CERT_PATH=${absCert}`);
        console.log(`  TLS_KEY_PATH=${absKey}`);
        console.log(`  SERVER_HOST=127.0.0.1`);
      } else {
        throw err;
      }
    }
  } catch (e) {
    if (e && String(e.message || e) === 'aborted') {
      process.exit(130);
    }
    console.error('[FATAL]', e.message);
    process.exit(1);
  }
})();
