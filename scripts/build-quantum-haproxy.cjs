#!/usr/bin/env node
/*
 * Build HAProxy with OpenSSL (OQS provider)
 * - Downloads and builds HAProxy in a temporary directory
 * - Requires: make, gcc, tar, openssl, OQS provider installed and available
 */

const os = require('os');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const https = require('https');
const { spawn } = require('child_process');

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

function download(url, dest) {
  return new Promise((resolve, reject) => {
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    const file = fs.createWriteStream(dest);
    const req = https.get(url, { timeout: 300000 }, (res) => {
      if ([301,302].includes(res.statusCode || 0) && res.headers.location) {
        const redirect = res.headers.location.startsWith('http') ? res.headers.location : new URL(res.headers.location, url).toString();
        res.resume();
        return resolve(download(redirect, dest));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode}`)); }
      res.pipe(file);
      file.on('finish', () => file.close(() => resolve(dest)));
    });
    req.on('timeout', () => { try { req.destroy(); } catch {}; reject(new Error('Download timeout')); });
    req.on('error', (e) => { try { file.close(); } catch {}; reject(e); });
  });
}

(async () => {
  try {
    if (process.platform === 'win32') {
      console.error('[BUILD] HAProxy cannot be built from source on Windows.');
      console.error('[BUILD] Please use WSL or install HAProxy via package manager.');
      process.exit(1);
    }

    // Ensure quantum dependencies
    console.log('[BUILD] Ensuring quantum dependencies (this may prompt for sudo)...');
    await new Promise((resolve, reject) => {
      const p = spawn(process.execPath, ['scripts/install-deps.cjs', 'quantum'], { stdio: 'inherit', env: { ...process.env, FORCE_REBUILD: '1' } });
      p.on('exit', (code) => code === 0 ? resolve() : reject(new Error(`install-deps failed: ${code}`)));
    });

    const need = ['make', 'gcc', 'openssl', 'tar'];
    for (const b of need) {
      if (!findInPath(b)) { console.error(`[BUILD] missing tool: ${b}`); process.exit(1); }
    }

    const moduleCandidates = [
      // Linux
      '/usr/local/lib/ossl-modules/oqsprovider.so',
      '/usr/local/lib64/ossl-modules/oqsprovider.so',
      '/usr/lib/ossl-modules/oqsprovider.so',
      '/usr/lib64/ossl-modules/oqsprovider.so',
      '/usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so',
      // macOS Homebrew locations
      '/opt/homebrew/lib/ossl-modules/oqsprovider.dylib',
      '/usr/local/lib/ossl-modules/oqsprovider.dylib'
    ];
    let oqsModule = null;
    const envModule = process.env.OQS_PROVIDER_MODULE;
    if (envModule) {
      try {
        if (fs.existsSync(envModule)) oqsModule = envModule;
      } catch {}
    }
    if (!oqsModule) {
      oqsModule = moduleCandidates.find(p => { try { return require('fs').existsSync(p); } catch { return false; } }) || null;
    }
    const localConf = require('path').join('server', 'config', 'openssl-oqs.cnf');

    try {
      await fsp.mkdir(require('path').dirname(localConf), { recursive: true });
      if (!fs.existsSync(localConf)) {
        const confBody = [
          'openssl_conf = openssl_init',
          '',
          '[openssl_init]',
          'providers = provider_sect',
          '',
          '[provider_sect]',
          'default = default_sect',
          'oqsprovider = oqs_sect',
          '',
          '[default_sect]',
          'activate = 1',
          '',
          '[oqs_sect]',
          '# The OQS provider module path is provided via the environment.',
          'module = ${ENV::OQS_PROVIDER_MODULE}',
          'activate = 1',
          ''
        ].join('\n');
        await fsp.writeFile(localConf, confBody, 'utf8');
      }
    } catch {}

    if (oqsModule) {
      try {
        const moduleInfoPath = require('path').join('server', 'config', 'oqs-module-path.txt');
        await fsp.mkdir(require('path').dirname(moduleInfoPath), { recursive: true });
        await fsp.writeFile(moduleInfoPath, String(oqsModule).trim() + '\n', 'utf8');
      } catch {}
    }

    const localEnv = { ...process.env };
    if (oqsModule) {
      localEnv.OPENSSL_CONF = localConf;
      localEnv.OQS_PROVIDER_MODULE = oqsModule;
      try { localEnv.OPENSSL_MODULES = require('path').dirname(oqsModule); } catch {}
    }
    localEnv.LD_LIBRARY_PATH = [ '/usr/local/lib', process.env.LD_LIBRARY_PATH || '' ].filter(Boolean).join(':');

    const HAPROXY_VERSION = process.env.HAPROXY_VERSION || '3.2.0';
    const mm = HAPROXY_VERSION.split('.').slice(0,2).join('.');
    const url = `https://www.haproxy.org/download/${mm}/src/haproxy-${HAPROXY_VERSION}.tar.gz`;

    const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'haproxy-build-'));
    const tarPath = path.join(tmp, path.basename(url));
    console.log('[BUILD] Downloading', url);
    await download(url, tarPath);

    console.log('[BUILD] Extracting ...');
    const { extract } = require('tar');
    await extract({ file: tarPath, cwd: tmp });
    const srcDir = path.join(tmp, `haproxy-${HAPROXY_VERSION}`);

    console.log('[BUILD] Running make ...');
    const { execSync } = require('child_process');
    
    const target = process.platform === 'darwin' ? 'osx' : 'linux-glibc';
    
    let sslInc = null;
    let sslLib = null;

    const tryPkg = () => {
      try {
        const cflags = execSync('pkg-config --cflags openssl', { encoding: 'utf8' });
        const incs = (cflags.match(/-I\S+/g) || []).map(s => s.slice(2));
        for (const inc of incs) {
          if (fs.existsSync(path.join(inc, 'openssl', 'ssl.h'))) { sslInc = inc; break; }
        }
      } catch {}
      try {
        const libs = execSync('pkg-config --libs openssl', { encoding: 'utf8' });
        const libDirs = (libs.match(/-L\S+/g) || []).map(s => s.slice(2));
        for (const lib of libDirs) {
          if (fs.existsSync(path.join(lib))) { sslLib = lib; break; }
        }
      } catch {}
    };
    tryPkg();

    if (!sslInc || !sslLib) {
      const candidates = [
        { inc: '/usr/local/include', lib: '/usr/local/lib' },
        { inc: '/usr/include', lib: '/usr/lib/x86_64-linux-gnu' },
        { inc: '/usr/include', lib: '/usr/lib' },
      ];
      for (const p of candidates) {
        if (!sslInc && fs.existsSync(path.join(p.inc, 'openssl', 'ssl.h'))) sslInc = p.inc;
        if (!sslLib && fs.existsSync(p.lib)) sslLib = p.lib;
        if (sslInc && sslLib) break;
      }
    }

    let oqsOk = false;
    try {
      const providers = execSync('openssl list -providers 2>/dev/null || true', { encoding: 'utf8', env: localEnv });
      oqsOk = /oqs/i.test(providers);
    } catch {}
    const moduleExists = !!oqsModule;

    if (!sslInc || !sslLib || !(oqsOk || moduleExists)) {
      console.error('[BUILD] ERROR: OQS-enabled OpenSSL not detected.');
      console.error('[BUILD] Looked for oqsprovider at:');
      console.error('        ' + moduleCandidates.join('\n        '));
      console.error('[BUILD] You can try exporting OPENSSL_CONF to', localConf);
      process.exit(1);
    }
    console.log(`[BUILD] OpenSSL include: ${sslInc}`);
    console.log(`[BUILD] OpenSSL lib:     ${sslLib}`);
    if (oqsModule) console.log(`[BUILD] OQS provider:   ${oqsModule}`);

    const args = [
      `TARGET=${target}`,
      `USE_OPENSSL=1`,
      `SSL_INC=${sslInc}`,
      `SSL_LIB=${sslLib}`,
      `USE_THREAD=1`,
    ];
    
    try {
      execSync('pkg-config --exists zlib', { stdio: 'ignore' });
      args.push('USE_ZLIB=1');
      console.log('[BUILD] Detected zlib');
    } catch {
      console.log('[BUILD] zlib not detected, building without compression support');
    }
    
    try {
      execSync('pkg-config --exists libpcre2-8', { stdio: 'ignore' });
      args.push('USE_PCRE2=1');
      console.log('[BUILD] Detected pcre2');
    } catch {
      console.log('[BUILD] pcre2 not detected, building without regex support');
    }
    
    let luaLib = null;
    try {
      for (const name of ['lua5.4', 'lua54', 'lua5.3', 'lua53', 'lua']) {
        try {
          execSync(`pkg-config --exists ${name}`, { stdio: 'ignore' });
          luaLib = name;
          break;
        } catch {}
      }
    } catch {}
    
    if (luaLib) {
      console.log(`[BUILD] Detected Lua library: ${luaLib}`);
      args.push('USE_LUA=1');
      args.push(`LUA_LIB_NAME=${luaLib}`);
    } else {
      console.log('[BUILD] Lua not detected, building without Lua support');
    }
    await new Promise((resolve, reject) => {
      const mk = spawn('make', args, { cwd: srcDir, stdio: 'inherit', env: localEnv });
      mk.on('exit', (code) => code === 0 ? resolve() : reject(new Error(`make failed: ${code}`)));
    });

    console.log('[BUILD] Build complete. Binaries are in:', srcDir);

    // Run setup to generate PQC certs and HAProxy config
    console.log('[BUILD] Generating PQC certs and HAProxy config...');
    await new Promise((resolve, reject) => {
      const p = spawn(process.execPath, ['scripts/setup-quantum-haproxy.cjs'], { stdio: 'inherit', env: localEnv });
      p.on('exit', (code) => code === 0 ? resolve() : reject(new Error(`setup failed: ${code}`)));
    });

    // Persist build metadata for the start script
    const buildMeta = {
      haproxy_bin: path.join(srcDir, 'haproxy'),
      src_dir: srcDir,
      haproxy_version: HAPROXY_VERSION,
      built_at: new Date().toISOString(),
      openssl_conf: path.join('server', 'config', 'openssl-oqs.cnf'),
      haproxy_cfg: path.join('server', 'config', 'haproxy-quantum.cfg')
    };
    try {
      await fsp.mkdir(path.join('server', 'config'), { recursive: true });
      await fsp.writeFile(path.join('server', 'config', 'haproxy-build.json'), JSON.stringify(buildMeta, null, 2));
      console.log('[BUILD] Build metadata written to server/config/haproxy-build.json');
    } catch {}
  } catch (e) {
    console.error('[BUILD] Failed:', e.message);
    process.exit(1);
  }
})();
