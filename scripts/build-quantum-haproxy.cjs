#!/usr/bin/env node
/*
 * Build HAProxy with OpenSSL (OQS provider)
 */

const os = require('os');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const https = require('https');
const { spawn } = require('child_process');

const REQUIRED_TOOLS = ['make', 'gcc', 'openssl', 'tar'];
const DEFAULT_HAPROXY_VERSION = '3.2.0';
const MODULE_CANDIDATES = [
  '/usr/local/lib/ossl-modules/oqsprovider.so',
  '/usr/local/lib64/ossl-modules/oqsprovider.so',
  '/usr/lib/ossl-modules/oqsprovider.so',
  '/usr/lib64/ossl-modules/oqsprovider.so',
  '/usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so',
  '/opt/homebrew/lib/ossl-modules/oqsprovider.dylib',
  '/usr/local/lib/ossl-modules/oqsprovider.dylib'
];

const OPENSSL_CONF_PATH = path.join('server', 'config', 'openssl-oqs.cnf');
const OQS_MODULE_INFO_PATH = path.join('server', 'config', 'oqs-module-path.txt');
const HAPROXY_CFG_PATH = path.join('server', 'config', 'haproxy-quantum.cfg');
const BUILD_META_PATH = path.join('server', 'config', 'haproxy-build.json');

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

function download(url, dest) {
  return new Promise((resolve, reject) => {
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    const file = fs.createWriteStream(dest);
    const req = https.get(url, { timeout: 300000 }, (res) => {
      if ([301, 302].includes(res.statusCode || 0) && res.headers.location) {
        const redirect = res.headers.location.startsWith('http') ? res.headers.location : new URL(res.headers.location, url).toString();
        res.resume();
        return resolve(download(redirect, dest));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode}`)); }
      res.pipe(file);
      file.on('finish', () => file.close(() => resolve(dest)));
    });
    req.on('timeout', () => { try { req.destroy(); } catch { }; reject(new Error('Download timeout')); });
    req.on('error', (e) => { try { file.close(); } catch { }; reject(e); });
  });
}

function runSpawn(cmd, args, options = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, options);
    p.on('exit', (code) => code === 0 ? resolve() : reject(new Error(`${cmd} failed: ${code}`)));
  });
}

async function ensureQuantumDeps() {
  console.log('[BUILD] Ensuring quantum dependencies...');
  await runSpawn(process.execPath, ['scripts/install-deps.cjs', 'quantum'], {
    stdio: 'inherit',
    env: { ...process.env, FORCE_REBUILD: '1' }
  });
}

function ensureToolsAvailable() {
  for (const tool of REQUIRED_TOOLS) {
    if (!findInPath(tool)) {
      console.error(`[BUILD] missing tool: ${tool}`);
      process.exit(1);
    }
  }
}

function locateOqsModule() {
  const envModule = process.env.OQS_PROVIDER_MODULE;
  if (envModule) {
    try {
      if (fs.existsSync(envModule)) return envModule;
    } catch { }
  }
  return MODULE_CANDIDATES.find(p => {
    try { return fs.existsSync(p); } catch { return false; }
  }) || null;
}

async function ensureOpenSslConf() {
  await fsp.mkdir(path.dirname(OPENSSL_CONF_PATH), { recursive: true });
  if (fs.existsSync(OPENSSL_CONF_PATH)) return;

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

  await fsp.writeFile(OPENSSL_CONF_PATH, confBody, 'utf8');
}

async function writeOqsModuleInfo(oqsModule) {
  if (!oqsModule) return;
  await fsp.mkdir(path.dirname(OQS_MODULE_INFO_PATH), { recursive: true });
  await fsp.writeFile(OQS_MODULE_INFO_PATH, `${String(oqsModule).trim()}\n`, 'utf8');
}

function buildLocalEnv(oqsModule) {
  const localEnv = { ...process.env };
  if (oqsModule) {
    localEnv.OPENSSL_CONF = OPENSSL_CONF_PATH;
    localEnv.OQS_PROVIDER_MODULE = oqsModule;
    try { localEnv.OPENSSL_MODULES = path.dirname(oqsModule); } catch { }
  }

  if (process.platform === 'darwin') {
    localEnv.DYLD_LIBRARY_PATH = [
      '/usr/local/lib',
      '/opt/homebrew/lib',
      process.env.DYLD_LIBRARY_PATH || ''
    ].filter(Boolean).join(':');
  } else {
    localEnv.LD_LIBRARY_PATH = [
      '/usr/local/lib',
      process.env.LD_LIBRARY_PATH || ''
    ].filter(Boolean).join(':');
  }

  return localEnv;
}

function detectOpenSslPaths(execSync) {
  let sslInc = null;
  let sslLib = null;

  const probePkgConfig = () => {
    try {
      const cflags = execSync('pkg-config --cflags openssl', { encoding: 'utf8' });
      const incs = (cflags.match(/-I\S+/g) || []).map(s => s.slice(2));
      for (const inc of incs) {
        if (fs.existsSync(path.join(inc, 'openssl', 'ssl.h'))) { sslInc = inc; break; }
      }
    } catch { }

    try {
      const libs = execSync('pkg-config --libs openssl', { encoding: 'utf8' });
      const libDirs = (libs.match(/-L\S+/g) || []).map(s => s.slice(2));
      for (const lib of libDirs) {
        if (fs.existsSync(lib)) { sslLib = lib; break; }
      }
    } catch { }
  };

  probePkgConfig();

  if (sslInc && sslLib) return { sslInc, sslLib };

  const fallbackCandidates = process.platform === 'darwin' ? [
    { inc: '/opt/homebrew/opt/openssl@3/include', lib: '/opt/homebrew/opt/openssl@3/lib' },
    { inc: '/usr/local/opt/openssl@3/include', lib: '/usr/local/opt/openssl@3/lib' },
    { inc: '/opt/homebrew/opt/openssl/include', lib: '/opt/homebrew/opt/openssl/lib' },
    { inc: '/usr/local/opt/openssl/include', lib: '/usr/local/opt/openssl/lib' },
  ] : [
    { inc: '/usr/local/include', lib: '/usr/local/lib' },
    { inc: '/usr/include', lib: '/usr/lib/x86_64-linux-gnu' },
    { inc: '/usr/include', lib: '/usr/lib' },
  ];

  for (const candidate of fallbackCandidates) {
    if (!sslInc && fs.existsSync(path.join(candidate.inc, 'openssl', 'ssl.h'))) sslInc = candidate.inc;
    if (!sslLib && fs.existsSync(candidate.lib)) sslLib = candidate.lib;
    if (sslInc && sslLib) break;
  }

  return { sslInc, sslLib };
}

function verifyOqs(localEnv, execSync, oqsModule) {
  let oqsOk = false;
  try {
    const providers = execSync('openssl list -providers 2>/dev/null || true', { encoding: 'utf8', env: localEnv });
    oqsOk = /oqs/i.test(providers);
  } catch { }
  const moduleExists = !!oqsModule;
  return { oqsOk, moduleExists };
}

function detectOptionalFeatures(execSync) {
  const args = [];
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
      } catch { }
    }
  } catch { }

  if (luaLib) {
    console.log(`[BUILD] Detected Lua library: ${luaLib}`);
    args.push('USE_LUA=1', `LUA_LIB_NAME=${luaLib}`);
  } else {
    console.log('[BUILD] Lua not detected, building without Lua support');
  }

  return args;
}

async function runMake(srcDir, args, env) {
  await runSpawn('make', args, { cwd: srcDir, stdio: 'inherit', env });
}

async function runSetup(env) {
  console.log('[BUILD] Generating PQC certs and HAProxy config...');
  await runSpawn(process.execPath, ['scripts/setup-quantum-haproxy.cjs'], { stdio: 'inherit', env });
}

async function writeBuildMetadata(srcDir, haproxyVersion) {
  const buildMeta = {
    haproxy_bin: path.join(srcDir, 'haproxy'),
    src_dir: srcDir,
    haproxy_version: haproxyVersion,
    built_at: new Date().toISOString(),
    openssl_conf: OPENSSL_CONF_PATH,
    haproxy_cfg: HAPROXY_CFG_PATH
  };

  try {
    await fsp.mkdir(path.dirname(BUILD_META_PATH), { recursive: true });
    await fsp.writeFile(BUILD_META_PATH, JSON.stringify(buildMeta, null, 2));
    console.log('[BUILD] Build metadata written to server/config/haproxy-build.json');
  } catch { }
}

async function buildHaproxy() {
  if (process.platform === 'win32') {
    console.error('[BUILD] This script is not supported on Windows. You need to use this command to start the server on windows: ');
    console.error('  node scripts/start-docker.cjs server');
    process.exit(1);
  }

  await ensureQuantumDeps();
  ensureToolsAvailable();
  const oqsModule = locateOqsModule();
  await ensureOpenSslConf();
  await writeOqsModuleInfo(oqsModule);

  const localEnv = buildLocalEnv(oqsModule);
  const target = process.platform === 'darwin' ? 'osx' : 'linux-glibc';
  const haproxyVersion = process.env.HAPROXY_VERSION || DEFAULT_HAPROXY_VERSION;
  const mm = haproxyVersion.split('.').slice(0, 2).join('.');
  const url = `https://www.haproxy.org/download/${mm}/src/haproxy-${haproxyVersion}.tar.gz`;

  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'haproxy-build-'));
  const tarPath = path.join(tmp, path.basename(url));
  console.log('[BUILD] Downloading', url);
  await download(url, tarPath);

  console.log('[BUILD] Extracting ...');
  const { extract } = require('tar');
  await extract({ file: tarPath, cwd: tmp });
  const srcDir = path.join(tmp, `haproxy-${haproxyVersion}`);

  console.log('[BUILD] Running make ...');
  const { execSync } = require('child_process');

  const { sslInc, sslLib } = detectOpenSslPaths(execSync);
  const { oqsOk, moduleExists } = verifyOqs(localEnv, execSync, oqsModule);

  if (!sslInc || !sslLib || !(oqsOk || moduleExists)) {
    console.error('[BUILD] ERROR: OQS-enabled OpenSSL not detected.');
    console.error('[BUILD] Looked for oqsprovider at:');
    console.error('        ' + MODULE_CANDIDATES.join('\n        '));
    console.error('[BUILD] You can try exporting OPENSSL_CONF to', OPENSSL_CONF_PATH);
    process.exit(1);
  }

  console.log(`[BUILD] OpenSSL include: ${sslInc}`);
  console.log(`[BUILD] OpenSSL lib:     ${sslLib}`);
  if (oqsModule) console.log(`[BUILD] OQS provider:   ${oqsModule}`);

  const makeArgs = [
    `TARGET=${target}`,
    'USE_OPENSSL=1',
    `SSL_INC=${sslInc}`,
    `SSL_LIB=${sslLib}`,
    'USE_THREAD=1',
    ...detectOptionalFeatures(execSync)
  ];

  await runMake(srcDir, makeArgs, localEnv);
  console.log('[BUILD] Build complete. Binaries are in:', srcDir);

  await runSetup(localEnv);
  await writeBuildMetadata(srcDir, haproxyVersion);
}

(async () => {
  try {
    await buildHaproxy();
  } catch (e) {
    console.error('[BUILD] Failed:', e.message);
    process.exit(1);
  }
})();
