#!/usr/bin/env node
/*
 * Dependency installer for server and client
 * Usage:
 *   node scripts/install-deps.cjs <component...>
 *   node scripts/install-deps.cjs --client
 *   node scripts/install-deps.cjs --server
 * Components:
 *   haproxy, tailscale, jq, redis, postgres, cloudflared
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
  for (const dir of parts) {
    try {
      const full = path.join(dir, bin);
      if (fs.existsSync(full)) return full;
    } catch { }
  }
  return null;
}

async function tryExec(bin, args, opts = {}) {
  try {
    await execFileAsync(bin, args, { stdio: 'ignore', ...opts });
    return true;
  } catch {
    return false;
  }
}

async function trySudo(args, opts = {}) {
  if (process.getuid && process.getuid() === 0) {
    try {
      await execFileAsync(args[0], args.slice(1), { stdio: 'inherit', ...opts });
      return true;
    } catch {
      return false;
    }
  }

  if (!findInPath('sudo')) {
    try {
      await execFileAsync(args[0], args.slice(1), { stdio: 'inherit', ...opts });
      return true;
    } catch {
      return false;
    }
  }

  let nonInteractive = true;
  try { await execFileAsync('sudo', ['-n', 'true']); } catch { nonInteractive = false; }
  try {
    if (nonInteractive) {
      await execFileAsync('sudo', args, { stdio: 'ignore', ...opts });
    } else {
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
    try { await trySudo(['apt-get', 'update']); } catch { }
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
  } catch { }

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

  // Pin recent Redis release
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
  } catch { }
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
    try { envText = fs.readFileSync(envPath, 'utf8'); } catch { }
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
      return false;
    }
    case 'tailscale': {
      if (findInPath('tailscale') || findInPath('tailscaled')) return true;
      if (plat === 'linux') {
        const installed = await installLinux('tailscale');
        if (installed) return true;
        try {
          const { execSync } = require('child_process');
          execSync('curl -fsSL https://tailscale.com/install.sh | sh', { stdio: 'inherit', shell: true });
          if (findInPath('tailscale') || findInPath('tailscaled')) return true;
        } catch (e) {
          console.log('[INFO] Failed to install via script. See: https://tailscale.com/kb/1031/install-linux');
          return false;
        }
      }
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'tailscale']);
      return false;
    }
    case 'jq': {
      if (findInPath('jq')) return true;
      if (plat === 'linux') return await installLinux('jq');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'jq']);
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

      console.log('[INFO] Install a TLS-enabled Redis manually (Redis >= 6 built with BUILD_TLS=yes) and ensure redis-server supports --tls-port.');
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
      return false;
    }
    case 'cloudflared': {
      if (findInPath('cloudflared')) return true;
      if (plat === 'linux') {
        if (pmHas('apt-get')) {
          try {
            await execFileAsync('curl', ['-L', 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb', '-o', '/tmp/cloudflared.deb']);
            await trySudo(['dpkg', '-i', '/tmp/cloudflared.deb']);
            return true;
          } catch (e) { }
        }

        const arch = os.arch() === 'arm64' ? 'arm64' : 'amd64';
        const url = `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}`;
        const binPath = '/usr/local/bin/cloudflared';
        try {
          await trySudo(['curl', '-L', url, '-o', binPath]);
          await trySudo(['chmod', '+x', binPath]);
          return true;
        } catch (e) {
          return false;
        }
      }
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'cloudflared']);

      console.log('[INFO] Install cloudflared from https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation');
      return false;
    }
    case 'nodejs': {
      if (findInPath('node')) return true;
      if (plat === 'linux') return await installLinux('nodejs');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'node']);
      return false;
    }
    case 'git': {
      if (findInPath('git')) return true;
      if (plat === 'linux') return await installLinux('git');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'git']);
      return false;
    }
    case 'curl': {
      if (findInPath('curl')) return true;
      if (plat === 'linux') return await installLinux('curl');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'curl']);
      return false;
    }
    case 'wget': {
      if (findInPath('wget')) return true;
      if (plat === 'linux') return await installLinux('wget');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'wget']);
      return false;
    }
    case 'python3': {
      if (findInPath('python3')) return true;
      if (plat === 'linux') return await installLinux('python3');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'python@3']);
      return false;
    }
    case 'openssl': {
      if (findInPath('openssl')) return true;
      if (plat === 'linux') return await installLinux('openssl');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'openssl']);
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
          await execFileAsync('git', ['clone', '--depth', '1', 'https://github.com/open-quantum-safe/liboqs.git', srcDir], { stdio: 'inherit' });

          const buildDir = path.join(srcDir, 'build');
          await require('fs/promises').mkdir(buildDir, { recursive: true });
          await execFileAsync('cmake', ['-GNinja', '-DCMAKE_INSTALL_PREFIX=/usr/local', '-DBUILD_SHARED_LIBS=ON', '-DOQS_DIST_BUILD=ON', '..'], { cwd: buildDir, stdio: 'inherit' });
          await execFileAsync('ninja', [], { cwd: buildDir, stdio: 'inherit' });

          const installed = await trySudo(['ninja', 'install'], { cwd: buildDir });
          if (!installed) {
            console.log('[INFO] Run: cd', buildDir, '&& sudo ninja install');
            return false;
          }

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
            } catch { }
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
      return false;
    }
    case 'ninja': {
      if (findInPath('ninja')) return true;
      if (plat === 'linux') return await installLinux('ninja-build') || await installLinux('ninja');
      if (plat === 'darwin' && pmHas('brew')) return await tryExec('brew', ['install', 'ninja']);
      return false;
    }
    case 'pnpm': {
      if (findInPath('pnpm')) return true;

      try {
        await execFileAsync('corepack', ['enable', 'pnpm'], { stdio: 'ignore' });
        if (findInPath('pnpm')) return true;
      } catch { }

      try {
        await execFileAsync('npm', ['install', '-g', 'pnpm', '--no-audit', '--no-fund'], { stdio: 'inherit' });
        if (findInPath('pnpm')) return true;
      } catch { }

      console.log('[INFO] Failed to install pnpm via corepack or npm');
      return false;
    }
    case 'electron': {
      // Check if electron is installed
      const repoRoot = path.resolve(__dirname, '..');

      const findElectronPath = () => {
        try {
          const pnpmDir = path.join(repoRoot, 'node_modules', '.pnpm');
          if (!fs.existsSync(pnpmDir)) return null;

          const entries = fs.readdirSync(pnpmDir);
          for (const entry of entries) {
            if (entry.startsWith('electron@')) {
              const binPath = path.join(pnpmDir, entry, 'node_modules', 'electron', 'dist', 'electron');
              if (fs.existsSync(binPath)) return { version: entry, binPath };

              const installScript = path.join(pnpmDir, entry, 'node_modules', 'electron', 'install.js');
              if (fs.existsSync(installScript)) {
                return { version: entry, binPath, installScript };
              }
            }
          }
        } catch { }
        return null;
      };

      const existing = findElectronPath();
      if (existing && fs.existsSync(existing.binPath)) return true;

      // Install electron
      try {
        const pnpmBin = findInPath('pnpm');
        if (!pnpmBin) {
          console.log('[INFO] pnpm required to install electron');
          return false;
        }
        await execFileAsync(pnpmBin, ['add', '-D', 'electron@latest'], { cwd: repoRoot, stdio: 'inherit' });

        const installed = findElectronPath();
        if (installed && !fs.existsSync(installed.binPath) && installed.installScript) {
          console.log('[INFO] Running electron postinstall script...');
          try {
            await execFileAsync('node', [installed.installScript], { cwd: repoRoot, stdio: 'inherit' });
          } catch (e) {
            console.log('[INFO] Failed to run electron install script:', e.message);
            return false;
          }
        }

        const final = findElectronPath();
        return final && fs.existsSync(final.binPath);
      } catch (e) {
        console.log('[INFO] Electron installation failed:', e.message);
        return false;
      }
    }
    case 'libevent': {
      // Check if libevent is installed
      if (plat === 'linux') {
        if (pmHas('apt-get')) {
          try {
            await execFileAsync('dpkg', ['-l', 'libevent-2.1-7t64'], { stdio: 'ignore' });
            return true;
          } catch {
            try {
              await execFileAsync('dpkg', ['-l', 'libevent-2.1-7'], { stdio: 'ignore' });
              return true;
            } catch {
              return await installLinux('libevent-2.1-7t64') || await installLinux('libevent-2.1-7');
            }
          }
        }
        return await installLinux('libevent');
      }

      if (plat === 'darwin' && pmHas('brew')) {
        try {
          await execFileAsync('brew', ['list', 'libevent'], { stdio: 'ignore' });
          return true;
        } catch {
          return await tryExec('brew', ['install', 'libevent']);
        }
      }

      return false;
    }
    case 'rust': {
      if (findInPath('cargo')) return true;

      try {
        const rustupUrl = 'https://sh.rustup.rs';
        const tmpScript = path.join(os.tmpdir(), 'rustup.sh');

        if (findInPath('curl')) {
          await execFileAsync('curl', ['--proto', '=https', '--tlsv1.2', '-sSf', rustupUrl, '-o', tmpScript]);
        } else if (findInPath('wget')) {
          await execFileAsync('wget', ['-O', tmpScript, rustupUrl]);
        } else {
          console.log('[INFO] curl or wget required to install Rust');
          return false;
        }

        await execFileAsync('sh', [tmpScript, '-y'], { stdio: 'inherit' });
        return true;
      } catch {
        console.log('[INFO] Failed to install Rust via rustup');
        return false;
      }
    }
    default:
      console.log(`[WARN] Unknown component: ${name}`);
      return false;
  }
}

(async () => {
  const args = process.argv.slice(2);

  if (process.platform === 'win32') {
    console.log('[ERROR] This script does not support Windows.');
    console.log('[INFO] Please use the provided Docker setup for running the server on Windows.');
    console.log('[INFO] Run: node scripts/start-docker.cjs');
    process.exit(1);
  }

  // Check for help flag
  if (args.length === 0 || args.some(a => a === '-h' || a === '--help')) {
    console.log('Usage: node scripts/install-deps.cjs <component...>');
    console.log('       node scripts/install-deps.cjs --client');
    console.log('       node scripts/install-deps.cjs --server');
    console.log('Components: haproxy, tailscale, jq, redis, postgres, cloudflared, nodejs, curl, wget, python3, openssl, build-tools, cmake, ninja, liboqs, oqs-provider, pnpm, electron, libevent, rust');
    console.log('Presets:');
    console.log('  all      - All server and edge dependencies');
    console.log('  server   - Server runtime dependencies');
    console.log('  client   - Client runtime dependencies');
    console.log('  edge     - Edge/proxy dependencies');
    console.log('  quantum  - Quantum-safe crypto dependencies');
    process.exit(args.length === 0 ? 1 : 0);
  }

  const presets = {
    all: ['git', 'nodejs', 'redis', 'postgres', 'python3', 'openssl', 'build-tools', 'cmake', 'ninja', 'liboqs', 'oqs-provider', 'haproxy', 'tailscale', 'jq', 'cloudflared'],
    server: ['nodejs', 'redis', 'postgres', 'python3', 'openssl', 'build-tools', 'tailscale'],
    client: ['nodejs', 'git', 'curl', 'wget', 'pnpm', 'libevent', 'rust', 'build-tools', 'electron'],
    edge: ['haproxy', 'cloudflared'],
    quantum: ['git', 'openssl', 'build-tools', 'cmake', 'ninja', 'liboqs', 'oqs-provider']
  };

  const expanded = [];
  for (const a of args) {
    const cleanArg = a.replace(/^--/, '');
    if (presets[cleanArg]) {
      expanded.push(...presets[cleanArg]);
    } else {
      expanded.push(a);
    }
  }

  const components = expanded;
  let ok = true;

  for (const c of components) {
    process.stdout.write(`[INSTALL] ${c} ... `);
    try {
      const res = await installComponent(c);
      console.log(res ? 'OK' : 'SKIPPED/FAILED');
      if (!res) ok = false;
    } catch (e) {
      console.log('ERROR');
      ok = false;
    }
  }

  process.exit(ok ? 0 : 1);
})();
