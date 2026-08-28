#!/usr/bin/env node
/*
 * Dependency installer for server and client
 * Usage:
 *   node scripts/install-deps.cjs <component...>
 *   node scripts/install-deps.cjs --client
 *   node scripts/install-deps.cjs --server
 * Components:
 *   jq, redis, postgres, docker
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
  if (plat !== 'linux') {
    console.log('[INFO] TLS Redis auto-build is supported only on Linux.');
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

  await installLinux('libssl-dev') || await installLinux('openssl-devel') || await installLinux('openssl-dev');

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
    case 'jq': {
      if (findInPath('jq')) return true;
      if (plat === 'linux') return await installLinux('jq');
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
      return false;
    }
    case 'nodejs': {
      if (findInPath('node')) return true;
      if (plat === 'linux') return await installLinux('nodejs');
      return false;
    }
    case 'git': {
      if (findInPath('git')) return true;
      if (plat === 'linux') return await installLinux('git');
      return false;
    }
    case 'curl': {
      if (findInPath('curl')) return true;
      if (plat === 'linux') return await installLinux('curl');
      return false;
    }
    case 'wget': {
      if (findInPath('wget')) return true;
      if (plat === 'linux') return await installLinux('wget');
      return false;
    }
    case 'python3': {
      if (findInPath('python3')) return true;
      if (plat === 'linux') return await installLinux('python3');
      return false;
    }
    case 'openssl': {
      if (findInPath('openssl')) return true;
      if (plat === 'linux') return await installLinux('openssl');
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
      return false;
    }
    case 'cmake': {
      if (findInPath('cmake')) return true;
      if (plat === 'linux') return await installLinux('cmake');
      return false;
    }
    case 'ninja': {
      if (findInPath('ninja')) return true;
      if (plat === 'linux') return await installLinux('ninja-build') || await installLinux('ninja');
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
    case 'tauri': {
      if (findInPath('tauri')) return true;

      if (!findInPath('cargo')) {
        const rustInstalled = await installComponent('rust');
        if (!rustInstalled) {
          console.log('[INFO] Rust (cargo) is required for Tauri CLI.');
          return false;
        }
      }

      try {
        await execFileAsync('cargo', ['install', 'tauri-cli', '--locked'], { stdio: 'inherit' });
        return true;
      } catch (e) {
        console.log('[INFO] Failed to install tauri-cli via cargo:', e.message);
        return false;
      }
    }
    case 'libevent': {
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

      return false;
    }
    case 'docker': {
      let isDocker = fs.existsSync('/.dockerenv');
      if (!isDocker && fs.existsSync('/proc/self/cgroup')) {
        try {
          const cgroup = fs.readFileSync('/proc/self/cgroup', 'utf8');
          isDocker = cgroup.includes('docker') || cgroup.includes('buildkit');
        } catch { }
      }
      if (!isDocker && (process.env.container === 'docker' || process.env.CI_DOCKER_BUILD)) {
        isDocker = true;
      }

      if (isDocker) {
        console.log('[INFO] Running inside Docker (build or run). Skipping Docker installation.');
        return true;
      }
      if (findInPath('docker')) return true;
      if (plat === 'linux') {
        if (pmHas('apt-get')) {
          try {
            await trySudo(['apt-get', 'update']);
            await trySudo(['apt-get', 'install', '-y', 'ca-certificates', 'curl', 'gnupg']);
            await execFileAsync('curl', ['-fsSL', 'https://download.docker.com/linux/ubuntu/gpg'], { stdio: 'pipe' });
            await trySudo(['sh', '-c', 'curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg']);
            await trySudo(['sh', '-c', 'echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null']);
            await trySudo(['apt-get', 'update']);
            return await trySudo(['apt-get', 'install', '-y', 'docker-ce', 'docker-ce-cli', 'containerd.io']);
          } catch (e) {
            return await installLinux('docker.io') || await installLinux('docker-ce');
          }
        }
        if (pmHas('dnf')) {
          try {
            await trySudo(['dnf', 'install', '-y', 'dnf-plugins-core']);
            await trySudo(['dnf', 'config-manager', '--add-repo', 'https://download.docker.com/linux/fedora/docker-ce.repo']);
            return await trySudo(['dnf', 'install', '-y', 'docker-ce', 'docker-ce-cli', 'containerd.io']);
          } catch (e) {
            return await installLinux('docker');
          }
        }
        if (pmHas('yum')) {
          try {
            await trySudo(['yum', 'install', '-y', 'yum-utils']);
            await trySudo(['yum-config-manager', '--add-repo', 'https://download.docker.com/linux/centos/docker-ce.repo']);
            return await trySudo(['yum', 'install', '-y', 'docker-ce', 'docker-ce-cli', 'containerd.io']);
          } catch (e) {
            return await installLinux('docker');
          }
        }
        if (pmHas('pacman')) {
          return await trySudo(['pacman', '-S', '--noconfirm', 'docker']);
        }
        if (pmHas('zypper')) {
          return await trySudo(['zypper', '--non-interactive', 'install', 'docker']);
        }
        if (pmHas('apk')) {
          return await trySudo(['apk', 'add', '--no-cache', 'docker']);
        }
        // Generic fallback
        return await installLinux('docker.io') || await installLinux('docker-ce') || await installLinux('docker');
      }
      console.log('[INFO] Install Docker from https://docs.docker.com/get-docker/');
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

  if (process.platform !== 'linux') {
    console.log('[ERROR] Native dependency installation supports only Linux.');
    console.log('[INFO] Use the provided Docker setup for running the server on other platforms.');
    console.log('[INFO] Run: node scripts/start-docker.cjs');
    process.exit(1);
  }

  if (args.length === 0 || args.some(a => a === '-h' || a === '--help')) {
    console.log('Usage: node scripts/install-deps.cjs <component...>');
    console.log('       node scripts/install-deps.cjs --client');
    console.log('       node scripts/install-deps.cjs --server');
    console.log('Components: jq, redis, postgres, docker, nodejs, curl, wget, python3, openssl, build-tools, cmake, ninja, pnpm, tauri, libevent, rust');
    console.log('Presets:');
    console.log('  all      - Server build and runtime dependencies');
    console.log('  server   - Server runtime dependencies');
    console.log('  client   - Client runtime dependencies');
    process.exit(args.length === 0 ? 1 : 0);
  }

  const presets = {
    all: ['git', 'nodejs', 'redis', 'postgres', 'python3', 'openssl', 'build-tools', 'cmake', 'ninja', 'jq', 'docker'],
    server: ['nodejs', 'redis', 'postgres', 'python3', 'openssl', 'build-tools'],
    client: ['nodejs', 'git', 'curl', 'wget', 'pnpm', 'rust', 'build-tools', 'tauri']
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
