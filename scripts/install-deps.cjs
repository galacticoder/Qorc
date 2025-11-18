#!/usr/bin/env node
/*
 * Dependency installer for server
 * Usage:
 *   node scripts/install-deps.cjs <component...>
 * Components:
 *   haproxy, tailscale, jq, redis, postgres, ngrok
 *   all  -> installs a reasonable set: haproxy, tailscale, jq
 */

const os = require('os');
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

function findInPath(bin) {
  const pathEnv = process.env.PATH || '';
  const parts = pathEnv.split(path.delimiter).filter(Boolean);
  const exts = process.platform === 'win32' ? (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';') : [''];
  for (const dir of parts) {
    for (const ext of exts) {
      try {
        const full = path.join(dir, bin + ext);
        if (fs.existsSync(full)) return full;
      } catch {}
    }
  }
  return null;
}

async function tryExec(bin, args, opts = {}) {
  try {
    await execFileAsync(bin, args, { stdio: 'ignore', windowsHide: true, ...opts });
    return true;
  } catch {
    return false;
  }
}

async function trySudo(args, opts = {}) {
  if (process.platform === 'win32') return false;
  if (!findInPath('sudo')) return false;
  let nonInteractive = true;
  try { await execFileAsync('sudo', ['-n', 'true']); } catch { nonInteractive = false; }
  try {
    if (nonInteractive) {
      await execFileAsync('sudo', args, { windowsHide: true, ...opts });
    } else {
      // Fallback to interactive sudo so user can enter password
      await execFileAsync('sudo', args, { stdio: 'inherit', ...opts });
    }
    return true;
  } catch {
    return false;
  }
}

function pmHas(pm) { return !!findInPath(pm); }

async function installLinux(pkg) {
  if (pmHas('apk')) return await (await trySudo(['apk', 'add', '--no-cache', pkg]) || pmHas('apk') && await tryExec('apk', ['add', '--no-cache', pkg]));
  if (pmHas('apt-get')) {
    await trySudo(['apt-get', 'update']);
    return await (await trySudo(['apt-get', 'install', '-y', pkg]));
  }
  if (pmHas('dnf')) return await (await trySudo(['dnf', '-y', 'install', pkg]));
  if (pmHas('yum')) return await (await trySudo(['yum', '-y', 'install', pkg]));
  if (pmHas('zypper')) return await (await trySudo(['zypper', '--non-interactive', 'install', pkg]));
  if (pmHas('pacman')) return await (await trySudo(['pacman', '-S', '--noconfirm', pkg]));
  return false;
}

async function redisHasTlsSupport(bin) {
  try {
    const { stdout, stderr } = await execFileAsync(bin, ['--help']);
    const out = `${stdout || ''}${stderr || ''}`;
    return /--tls-port\b/.test(out);
  } catch (e) {
    const out = `${e.stdout || ''}${e.stderr || ''}`;
    if (!out) return false;
    return /--tls-port\b/.test(out);
  }
}

async function installRedisTlsLocal() {
  const plat = process.platform;
  if (plat !== 'linux' && plat !== 'darwin') {
    console.log('[INFO] TLS Redis auto-build is currently supported on Linux and macOS only.');
    return false;
  }

  const repoRoot = path.resolve(__dirname, '..');
  const binDir = path.join(repoRoot, 'server', 'bin');
  const redisBin = path.join(binDir, 'redis-server-tls');

  try {
    if (fs.existsSync(redisBin) && await redisHasTlsSupport(redisBin)) {
      return true;
    }
  } catch {}

  const buildOk = await installComponent('build-tools');
  if (!buildOk) {
    console.log('[INFO] Failed to install build-tools required for TLS Redis (gcc/make)');
    return false;
  }

  if (plat === 'linux') {
    await installLinux('libssl-dev') || await installLinux('openssl-devel') || await installLinux('openssl-dev');
  } else if (plat === 'darwin' && pmHas('brew')) {
    await tryExec('brew', ['install', 'openssl']);
  }

  let downloader = findInPath('curl') ? 'curl' : null;
  if (!downloader && findInPath('wget')) downloader = 'wget';
  if (!downloader) {
    await installComponent('curl');
    if (findInPath('curl')) {
      downloader = 'curl';
    } else if (findInPath('wget')) {
      downloader = 'wget';
    }
  }
  if (!downloader) {
    console.log('[INFO] Neither curl nor wget is available; cannot download Redis sources automatically.');
    return false;
  }

  const tmpRoot = await require('fs/promises').mkdtemp(path.join(os.tmpdir(), 'redis-tls-'));
  const tarPath = path.join(tmpRoot, 'redis.tar.gz');

  // Pin recent Redis release with TLS support.
  const redisUrl = process.env.REDIS_TLS_SOURCE_URL || 'https://download.redis.io/releases/redis-7.2.5.tar.gz';
  console.log('[INFO] Downloading Redis source for TLS build from', redisUrl);

  try {
    if (downloader === 'curl') {
      await execFileAsync('curl', ['-fsSL', redisUrl, '-o', tarPath], { stdio: 'inherit' });
    } else {
      await execFileAsync('wget', ['-O', tarPath, redisUrl], { stdio: 'inherit' });
    }
  } catch (e) {
    console.log('[INFO] Failed to download Redis sources:', e.message);
    return false;
  }

  try {
    await execFileAsync('tar', ['-xzf', tarPath, '-C', tmpRoot], { stdio: 'inherit' });
  } catch (e) {
    console.log('[INFO] Failed to extract Redis sources (tar xzf):', e.message);
    return false;
  }

  let extractedDir = null;
  try {
    const entries = fs.readdirSync(tmpRoot, { withFileTypes: true });
    for (const ent of entries) {
      if (ent.isDirectory() && ent.name.startsWith('redis-')) {
        extractedDir = path.join(tmpRoot, ent.name);
        break;
      }
    }
  } catch {}
  if (!extractedDir) {
    console.log('[INFO] Could not locate extracted Redis source directory.');
    return false;
  }

  console.log('[INFO] Building Redis with TLS support...');
  try {
    await execFileAsync('make', ['BUILD_TLS=yes'], { cwd: extractedDir, stdio: 'inherit' });
  } catch (e) {
    console.log('[INFO] Redis TLS build failed:', e.message);
    console.log('[INFO] Ensure OpenSSL dev libraries are installed (e.g., libssl-dev / openssl-devel).');
    return false;
  }

  const builtServer = path.join(extractedDir, 'src', 'redis-server');
  if (!fs.existsSync(builtServer)) {
    console.log('[INFO] Built redis-server binary not found at', builtServer);
    return false;
  }

  // Install into server/bin and mark executable
  try {
    await require('fs/promises').mkdir(binDir, { recursive: true, mode: 0o755 });
    fs.copyFileSync(builtServer, redisBin);
    fs.chmodSync(redisBin, 0o755);
  } catch (e) {
    console.log('[INFO] Failed to install TLS redis-server into project bin:', e.message);
    return false;
  }

  // Persist TLS_REDIS_SERVER into project .env so start-server.cjs can use it
  try {
    const envPath = path.join(repoRoot, '.env');
    let envText = '';
    try { envText = fs.readFileSync(envPath, 'utf8'); } catch {}
    const lines = envText ? envText.split(/\r?\n/) : [];
    const line = `TLS_REDIS_SERVER=${redisBin}`;
    const idx = lines.findIndex(l => l.trim().startsWith('TLS_REDIS_SERVER='));
    if (idx >= 0) lines[idx] = line; else lines.push(line);
    const newEnv = lines.filter(Boolean).join('\n') + '\n';
    fs.writeFileSync(envPath, newEnv, 'utf8');
    console.log('[INFO] TLS Redis binary installed at', redisBin, 'and recorded as TLS_REDIS_SERVER in .env');
  } catch (e) {
    console.log('[INFO] TLS Redis installed at', redisBin, 'but failed to persist TLS_REDIS_SERVER in .env:', e.message);
  }

  return true;
}

async function installComponent(name) {
  const plat = process.platform;
  switch (name) {
    case 'haproxy': {
      if (findInPath('haproxy')) return true;
      if (plat === 'linux') return await installLinux('haproxy');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'haproxy']);
      if (plat === 'win32' && pmHas('choco')) return await tryExec('choco', ['install', 'haproxy', '-y']);
      if (plat === 'win32' && pmHas('winget')) return await tryExec('winget', ['install', '--id', 'HAProxyTechnologies.HAProxy', '-e', '-h']) || await tryExec('winget', ['install', 'haproxy', '-e', '-h']);
      return false;
    }
    case 'tailscale': {
      if (findInPath('tailscale') || findInPath('tailscaled')) return true;
      if (plat === 'linux') {
        const installed = await installLinux('tailscale');
        if (installed) return true;
        console.log('[INFO] Tailscale not in default repos. Add tailscale repo: https://tailscale.com/kb/1031/install-linux');
        return false;
      }
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'tailscale']);
      if (plat === 'win32' && pmHas('winget')) return await tryExec('winget', ['install', '--id', 'Tailscale.Tailscale', '-e', '-h']);
      return false;
    }
    case 'jq': {
      if (findInPath('jq')) return true;
      if (plat === 'linux') return await installLinux('jq');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'jq']);
      if (plat === 'win32' && pmHas('choco')) return await tryExec('choco', ['install', 'jq', '-y']);
      if (plat === 'win32' && pmHas('winget')) return await tryExec('winget', ['install', '--id', 'jqlang.jq', '-e', '-h']);
      return false;
    }
    case 'redis': {
      const existing = findInPath('redis-server');
      if (existing) {
        const hasTls = await redisHasTlsSupport(existing);
        if (hasTls) return true;
      }

      let installed = false;
      if (plat === 'linux') {
        installed = await installLinux('redis-server') || await installLinux('redis');
      } else if (plat === 'darwin' && pmHas('brew')) {
        installed = await tryExec('brew', ['install', 'redis']);
      }

      if (installed) {
        const after = findInPath('redis-server');
        if (after) {
          const hasTlsAfter = await redisHasTlsSupport(after);
          if (hasTlsAfter) return true;
        }
      }

      const tlsInstalled = await installRedisTlsLocal();
      if (tlsInstalled) return true;

      if (plat === 'win32') {
        console.log('[INFO] For Windows, run a TLS-enabled Redis in WSL and point REDIS_URL at it.');
      } else {
        console.log('[INFO] Install a TLS-enabled Redis manually (Redis >= 6 built with BUILD_TLS=yes) and ensure redis-server supports --tls-port.');
      }
      return false;
    }
    case 'postgres': {
      if (findInPath('psql')) return true;
      if (plat === 'linux') {
        return await installLinux('postgresql') || await installLinux('postgresql-client');
      }
      if (plat === 'darwin' && pmHas('brew')) {
        return await tryExec('brew', ['install', 'postgresql']);
      }
      if (plat === 'win32') {
        console.log('[INFO] On Windows, install PostgreSQL via the official installer: https://www.postgresql.org/download/.');
        return false;
      }
      return false;
    }
    case 'ngrok': {
      if (findInPath('ngrok')) return true;
      if (plat === 'linux') {
        if (findInPath('snap')) {
          const installed = await trySudo(['snap', 'install', 'ngrok']);
          if (installed) return true;
        }
        console.log('[INFO] Install ngrok: curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc && echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list && sudo apt update && sudo apt install ngrok');
        return false;
      }
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'ngrok/ngrok/ngrok']);
      if (plat === 'win32' && pmHas('choco')) return await tryExec('choco', ['install', 'ngrok', '-y']);
      console.log('[INFO] Install ngrok from https://ngrok.com/download');
      return false;
    }
    case 'nodejs': {
      if (findInPath('node')) return true;
      if (plat === 'linux') return await installLinux('nodejs');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'node']);
      if (plat === 'win32' && pmHas('choco')) return await tryExec('choco', ['install', 'nodejs', '-y']);
      if (plat === 'win32' && pmHas('winget')) return await tryExec('winget', ['install', '--id', 'OpenJS.NodeJS.LTS', '-e', '-h']) || await tryExec('winget', ['install', '--id', 'OpenJS.NodeJS', '-e', '-h']);
      return false;
    }
    case 'git': {
      if (findInPath('git')) return true;
      if (plat === 'linux') return await installLinux('git');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'git']);
      if (plat === 'win32' && pmHas('choco')) return await tryExec('choco', ['install', 'git', '-y']);
      if (plat === 'win32' && pmHas('winget')) return await tryExec('winget', ['install', '--id', 'Git.Git', '-e', '-h']);
      return false;
    }
    case 'curl': {
      if (findInPath('curl')) return true;
      if (plat === 'linux') return await installLinux('curl');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'curl']);
      if (plat === 'win32' && pmHas('choco')) return await tryExec('choco', ['install', 'curl', '-y']);
      return false;
    }
    case 'wget': {
      if (findInPath('wget')) return true;
      if (plat === 'linux') return await installLinux('wget');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'wget']);
      if (plat === 'win32' && pmHas('choco')) return await tryExec('choco', ['install', 'wget', '-y']);
      return false;
    }
    case 'python3': {
      if (findInPath('python3')) return true;
      if (plat === 'linux') return await installLinux('python3');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'python@3']);
      if (plat === 'win32' && pmHas('choco')) return await tryExec('choco', ['install', 'python', '-y']);
      if (plat === 'win32' && pmHas('winget')) return await tryExec('winget', ['install', '--id', 'Python.Python.3', '-e', '-h']);
      return false;
    }
    case 'openssl': {
      if (findInPath('openssl')) return true;
      if (plat === 'linux') return await installLinux('openssl');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'openssl']);
      if (plat === 'win32') {
        console.log('[INFO] Install OpenSSL from https://slproweb.com/products/Win32OpenSSL.html or via chocolatey');
        return false;
      }
      return false;
    }
    case 'build-tools': {
      if (findInPath('gcc') && findInPath('make')) return true;
      
      if (plat === 'linux') {
        if (pmHas('apt-get')) return await trySudo(['apt-get', 'install', '-y', 'build-essential', 'python3-dev']);
        if (pmHas('dnf')) return await trySudo(['dnf', 'groupinstall', '-y', 'Development Tools']) && await trySudo(['dnf', 'install', '-y', 'python3-devel']);
        if (pmHas('yum')) return await trySudo(['yum', 'groupinstall', '-y', 'Development Tools']) && await trySudo(['yum', 'install', '-y', 'python3-devel']);
        if (pmHas('pacman')) return await trySudo(['pacman', '-S', '--noconfirm', 'base-devel']);
        if (pmHas('zypper')) return await trySudo(['zypper', 'install', '-y', 'gcc', 'make']);
        if (pmHas('apk')) return await trySudo(['apk', 'add', '--no-cache', 'build-base', 'python3-dev']);
        return false;
      }
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'gcc', 'make', 'python@3']);
      if (plat === 'win32') {
        console.log('[INFO] Install Microsoft C++ Build Tools (Visual Studio Build Tools) and Python3 for native modules.');
        return false;
      }
      return false;
    }
    case 'liboqs': {
      const forceRebuild = process.env.FORCE_REBUILD === '1';
      if (!forceRebuild) {
        const libPaths = plat === 'darwin' 
          ? ['/usr/local/lib/liboqs.dylib', '/opt/homebrew/lib/liboqs.dylib']
          : ['/usr/local/lib/liboqs.so', '/usr/lib/liboqs.so', '/usr/lib64/liboqs.so', '/usr/lib/x86_64-linux-gnu/liboqs.so'];
        
        for (const p of libPaths) {
          if (fs.existsSync(p)) return true;
        }
      }
      
      if (plat === 'linux') {
        if (!findInPath('git')) {
          console.log('[INFO] git required to build liboqs');
          return false;
        }
        if (!findInPath('cmake')) {
          console.log('[INFO] cmake required to build liboqs');
          return false;
        }
        if (!findInPath('ninja')) {
          console.log('[INFO] ninja required to build liboqs');
          return false;
        }
        
        console.log('[INFO] Building liboqs from latest source...');
        const tmpRoot = await require('fs/promises').mkdtemp(path.join(os.tmpdir(), 'liboqs-'));
        const srcDir = path.join(tmpRoot, 'src');
        try {
          // Clone latest main branch
          await execFileAsync('git', ['clone', '--depth', '1', 'https://github.com/open-quantum-safe/liboqs.git', srcDir], { stdio: 'inherit' });
          
          // Build
          const buildDir = path.join(srcDir, 'build');
          await require('fs/promises').mkdir(buildDir, { recursive: true });
          await execFileAsync('cmake', ['-GNinja', '-DCMAKE_INSTALL_PREFIX=/usr/local', '-DBUILD_SHARED_LIBS=ON', '-DOQS_DIST_BUILD=ON', '..'], { cwd: buildDir, stdio: 'inherit' });
          await execFileAsync('ninja', [], { cwd: buildDir, stdio: 'inherit' });
          
          // Install
          const installed = await trySudo(['ninja', 'install'], { cwd: buildDir });
          if (!installed) {
            console.log('[INFO] Run: cd', buildDir, '&& sudo ninja install');
            return false;
          }
          
          // Update library cache
          await trySudo(['ldconfig']);
          return true;
        } catch (e) {
          console.log('[INFO] Build failed:', e.message);
          return false;
        }
      }
      if (plat === 'darwin' && pmHas('brew')) {
        return await tryExec('brew', ['install', 'liboqs']);
      }
      console.log('[INFO] Install liboqs from: https://github.com/open-quantum-safe/liboqs');
      return false;
    }
    case 'oqs-provider': {
      const forceRebuild = process.env.FORCE_REBUILD === '1';
      if (!forceRebuild) {
        const modPaths = plat === 'darwin'
          ? ['/usr/local/lib/ossl-modules/oqsprovider.dylib', '/opt/homebrew/lib/ossl-modules/oqsprovider.dylib']
          : ['/usr/local/lib/ossl-modules/oqsprovider.so', '/usr/local/lib64/ossl-modules/oqsprovider.so', 
             '/usr/lib/ossl-modules/oqsprovider.so', '/usr/lib64/ossl-modules/oqsprovider.so'];
        
        for (const p of modPaths) {
          if (fs.existsSync(p)) {
            try {
              const { stdout } = await execFileAsync('openssl', ['list', '-providers']);
              if (/oqs/i.test(stdout || '')) return true;
            } catch {}
          }
        }
      }
      
      if (plat === 'linux') {
        if (!findInPath('git')) {
          console.log('[INFO] git required to build oqs-provider');
          return false;
        }
        if (!findInPath('cmake')) {
          console.log('[INFO] cmake required to build oqs-provider');
          return false;
        }
        
        console.log('[INFO] Building oqs-provider from latest source...');
        const tmpRoot = await require('fs/promises').mkdtemp(path.join(os.tmpdir(), 'oqs-provider-'));
        const srcDir = path.join(tmpRoot, 'src');
        try {
          // Clone latest main branch
          await execFileAsync('git', ['clone', '--depth', '1', 'https://github.com/open-quantum-safe/oqs-provider.git', srcDir], { stdio: 'inherit' });
          
          // Build
          const buildDir = path.join(srcDir, '_build');
          await require('fs/promises').mkdir(buildDir, { recursive: true });
          await execFileAsync('cmake', ['-S', '..', '-B', '.'], { cwd: buildDir, stdio: 'inherit' });
          await execFileAsync('cmake', ['--build', '.'], { cwd: buildDir, stdio: 'inherit' });
          
          // Install
          const installed = await trySudo(['cmake', '--install', '.'], { cwd: buildDir });
          if (!installed) {
            console.log('[INFO] Run: cd', buildDir, '&& sudo cmake --install .');
            return false;
          }
          
          return true;
        } catch (e) {
          console.log('[INFO] Build failed:', e.message);
          return false;
        }
      }
      if (plat === 'darwin' && pmHas('brew')) {
        return await tryExec('brew', ['install', 'oqs-provider']);
      }
      console.log('[INFO] Install oqs-provider from: https://github.com/open-quantum-safe/oqs-provider');
      return false;
    }
    case 'cmake': {
      if (findInPath('cmake')) return true;
      if (plat === 'linux') return await installLinux('cmake');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'cmake']);
      if (plat === 'win32' && pmHas('choco')) return await tryExec('choco', ['install', 'cmake', '-y']);
      if (plat === 'win32' && pmHas('winget')) return await tryExec('winget', ['install', '--id', 'Kitware.CMake', '-e', '-h']);
      return false;
    }
    case 'ninja': {
      if (findInPath('ninja')) return true;
      if (plat === 'linux') return await installLinux('ninja-build') || await installLinux('ninja');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'ninja']);
      if (plat === 'win32' && pmHas('choco')) return await tryExec('choco', ['install', 'ninja', '-y']);
      return false;
    }
    default:
      console.log(`[WARN] Unknown component: ${name}`);
      return false;
  }
}

(async () => {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.log('Usage: node scripts/install-deps.cjs <component...>');
    console.log('Components: haproxy, tailscale, jq, redis, postgres, ngrok, nodejs, curl, wget, python3, openssl, build-tools, cmake, ninja, liboqs, oqs-provider');
    console.log('Presets: all, server, edge, quantum');
    process.exit(1);
  }
  const presets = {
    all: ['git', 'nodejs', 'redis', 'postgres', 'python3', 'openssl', 'build-tools', 'cmake', 'ninja', 'liboqs', 'oqs-provider', 'haproxy', 'tailscale', 'jq', 'ngrok'],
    server: ['nodejs', 'redis', 'postgres', 'python3', 'openssl', 'build-tools'],
    edge: ['haproxy', 'ngrok'],
    quantum: ['git', 'openssl', 'build-tools', 'cmake', 'ninja', 'liboqs', 'oqs-provider']
  };
  const expanded = [];
  for (const a of args) {
    if (presets[a]) expanded.push(...presets[a]); else expanded.push(a);
  }
  const components = expanded;
  let ok = true;
  
  for (const c of components) {
    process.stdout.write(`[INSTALL] ${c} ... `);
    try {
      const res = await installComponent(c);
      console.log(res ? 'OK' : 'SKIPPED/FAILED');
      if (!res) ok = false;
      if (c === 'redis' && res) redisInstalled = true;
      if (c === 'postgres' && res) postgresInstalled = true;
    } catch (e) {
      console.log('ERROR');
      ok = false;
    }
  }
  
  process.exit(ok ? 0 : 1);
})();
