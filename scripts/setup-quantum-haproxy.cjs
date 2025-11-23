#!/usr/bin/env node
/*
 * Setup OpenSSL OQS configuration and certs for HAProxy
 */

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

function findInPath(bin) {
  const parts = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  const exts = process.platform === 'win32' ? (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';') : [''];
  for (const dir of parts) {
    for (const ext of exts) {
      try { const p = path.join(dir, bin + ext); if (fs.existsSync(p)) return p; } catch { }
    }
  }
  return null;
}

async function hasOqsProvider(env) {
  try {
    const { stdout } = await execFileAsync('openssl', ['list', '-providers'], { env });
    return /oqs/i.test(stdout || '');
  } catch {
    return false;
  }
}

(async () => {
  try {
    if (!findInPath('openssl')) {
      console.error('[SETUP] openssl not found. Install openssl and oqs provider first.');
      console.error('[SETUP] You can configure OPENSSL_CONF to point to a local config that loads oqsprovider.so');
      process.exit(1);
    }

    const baseDir = path.join('server', 'config', 'certs');
    await fsp.mkdir(baseDir, { recursive: true });
    const localConf = path.join('server', 'config', 'openssl-oqs.cnf');


    const modulePaths = [
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

    let modulePath = null;
    const envModule = process.env.OQS_PROVIDER_MODULE;
    if (envModule) {
      try {
        if (fs.existsSync(envModule)) modulePath = envModule;
      } catch { }
    }
    if (!modulePath) {
      modulePath = modulePaths.find(p => fs.existsSync(p)) || modulePaths[0];
    }

    try {
      await fsp.mkdir(path.dirname(localConf), { recursive: true });
      if (!fs.existsSync(localConf)) {
        const body = [
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
        await fsp.writeFile(localConf, body, 'utf8');
      }
    } catch { }

    try {
      const moduleInfoPath = path.join('server', 'config', 'oqs-module-path.txt');
      await fsp.mkdir(path.dirname(moduleInfoPath), { recursive: true });
      await fsp.writeFile(moduleInfoPath, String(modulePath).trim() + '\n', 'utf8');
    } catch { }

    const env = { ...process.env };
    env.OPENSSL_CONF = localConf;
    env.OQS_PROVIDER_MODULE = modulePath;
    try { env.OPENSSL_MODULES = path.dirname(modulePath); } catch { }

    if (process.platform === 'darwin') {
      env.DYLD_LIBRARY_PATH = [
        '/usr/local/lib',
        '/opt/homebrew/lib',
        process.env.DYLD_LIBRARY_PATH || ''
      ].filter(Boolean).join(':');
    } else {
      env.LD_LIBRARY_PATH = [
        '/usr/local/lib',
        '/usr/lib/x86_64-linux-gnu',
        process.env.LD_LIBRARY_PATH || ''
      ].filter(Boolean).join(':');
    }

    const ok = await hasOqsProvider(env);
    if (!ok) {
      console.error('[SETUP] ERROR: oqs provider not detected in openssl list.');
      console.error('[SETUP] Quantum-secure setup requires OQS provider to be installed.');
      console.error('[SETUP] Ensure oqsprovider module is installed in one of:');
      modulePaths.forEach(p => console.error(`  - ${p}`));
      process.exit(1);
    }

    console.log('[SETUP] Generating ECDSA P-384 certificate (HAProxy-compatible)...');
    const ecdsaKey = path.join(baseDir, 'ecdsa-p384-key.pem');
    const ecdsaCrt = path.join(baseDir, 'ecdsa-p384-cert.pem');
    await execFileAsync('openssl', ['ecparam', '-name', 'secp384r1', '-genkey', '-noout', '-out', ecdsaKey], { env });
    await execFileAsync('openssl', ['req', '-new', '-x509', '-days', '365', '-key', ecdsaKey, '-out', ecdsaCrt, '-subj', '/CN=localhost'], { env });

    // generate PQC cert for future use when HAProxy supports it ill add this to use when available
    const requested = (process.env.OQS_SIG || '').trim();
    const tryList = [];
    if (requested) tryList.push(requested);
    tryList.push('ml-dsa-65', 'ml-dsa-44', 'ml-dsa-87', 'dilithium3', 'dilithium2', 'dilithium5', 'falcon512', 'falcon1024');

    let usedAlg = null;
    for (const name of Array.from(new Set(tryList))) {
      const pqKey = path.join(baseDir, `${name}-key.pem`);
      try {
        await execFileAsync('openssl', ['genpkey', '-algorithm', name, '-out', pqKey], { env });
        usedAlg = name;
        break;
      } catch {
        continue;
      }
    }
    if (usedAlg) {
      const pqKey = path.join(baseDir, `${usedAlg}-key.pem`);
      const pqCrt = path.join(baseDir, `${usedAlg}-cert.pem`);
      try {
        await execFileAsync('openssl', ['req', '-new', '-x509', '-days', '365', '-key', pqKey, '-out', pqCrt, '-subj', '/CN=localhost-pqc'], { env });
        console.log(`[SETUP] PQC cert also generated: ${pqCrt} (for future use)`);
      } catch { }
    }

    // Combine ECDSA cert to cert.pem
    const combined = path.join(baseDir, 'cert.pem');
    await fsp.writeFile(combined, (await fsp.readFile(ecdsaCrt)).toString() + (await fsp.readFile(ecdsaKey)).toString());

    const pqcGroups = [
      'X25519MLKEM768',
      'SecP256r1MLKEM768',
      'SecP384r1MLKEM1024'
    ];
    const groupsOut = pqcGroups.join(':');
    console.log('[SETUP] Using PQC TLS groups:', groupsOut);

    const hapCfgPath = path.join('server', 'config', 'haproxy-quantum.cfg');
    const absCert = path.resolve(combined);
    const hapCfg = `global\n  daemon\n  maxconn 1000\n  tune.ssl.default-dh-param 2048\n  # deny non-TLS1.3\n  ssl-default-bind-options no-tlsv10 no-tlsv11 no-tlsv12 no-sslv3\n  ssl-default-server-options no-tlsv10 no-tlsv11 no-tlsv12 no-sslv3\n  # TLS1.3 AEADs only\n  ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256\n  ssl-default-server-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256\n\ndefaults\n  mode http\n  timeout connect 5s\n  timeout client 30s\n  timeout server 30s\n\nfrontend https_in\n  bind *:8443 ssl crt ${absCert} curves ${groupsOut}\n  http-request set-header X-Forwarded-Proto https\n  default_backend app\n\nbackend app\n  server s1 127.0.0.1:3000 check\n`;
    await fsp.mkdir(path.dirname(hapCfgPath), { recursive: true });
    await fsp.writeFile(hapCfgPath, hapCfg, 'utf8');

    console.log('[SETUP] OpenSSL local config:', localConf);
    console.log('[SETUP] PQC cert written:', combined);
    console.log('[SETUP] HAProxy config written:', hapCfgPath);
    console.log('[SETUP] Export OPENSSL_CONF to force loading oqsprovider:');
    console.log(`  export OPENSSL_CONF="${localConf}"`);
    console.log('[SETUP] Start HAProxy with:');
    console.log(`  OPENSSL_CONF="${localConf}" haproxy -f ${hapCfgPath}`);
  } catch (e) {
    console.error('[SETUP] Failed:', e.message);
    process.exit(1);
  }
})();
