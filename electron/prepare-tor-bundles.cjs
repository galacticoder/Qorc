#!/usr/bin/env node
/*
 * Tor expert bundles preparer for Electron packaging
 */

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const os = require('os');
const https = require('https');
const crypto = require('crypto');
const { extract } = require('tar');

const { resolveTorDownloadInfo, expertBundleFileName } = require('./tor-download-info.cjs');
const OUT_DIR = path.resolve(process.cwd(), 'tor-bundles');
function log(...args) { console.log('[prepare-tor]', ...args); }
function logErr(...args) { console.error('[prepare-tor]', ...args); }

// Get platform info
function hostPlatformToken() {
  const p = process.platform;
  const a = process.arch;
  if (p === 'linux') return a === 'arm64' ? 'linux-aarch64' : 'linux-x86_64';
  if (p === 'darwin') return a === 'arm64' ? 'macos-aarch64' : 'macos-x86_64';
  if (p === 'win32') return 'windows-x86_64';
  throw new Error(`Unsupported host platform: ${p}/${a}`);
}

// Convert platform to directory
function platformToDir(token) {
  if (token.startsWith('linux-')) return 'linux';
  if (token.startsWith('macos-')) return 'macos';
  if (token.startsWith('windows-')) return 'windows';
  return token.replace(/[^a-z0-9_-]+/gi, '_');
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    const file = fs.createWriteStream(dest);
    const req = https.get(url, { timeout: 300000 }, (res) => {
      if (res.statusCode && (res.statusCode === 301 || res.statusCode === 302) && res.headers.location) {
        const redirect = res.headers.location.startsWith('http') ? res.headers.location : new URL(res.headers.location, url).toString();
        res.resume();
        return resolve(download(redirect, dest));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      res.pipe(file);
      file.on('finish', () => file.close(() => resolve(dest)));
    });
    req.on('timeout', () => { try { req.destroy(); } catch { } reject(new Error('Download timeout')); });
    req.on('error', (err) => { try { file.close(); } catch { } reject(err); });
  });
}

async function readSha256List() {
  const { baseUrl } = await resolveTorDownloadInfo();
  const unsigned = `${baseUrl}/sha256sums-unsigned-build.txt`;
  const signed = `${baseUrl}/sha256sums-signed-build.txt`;
  const tmp = path.join(os.tmpdir(), `tor_sha256_${Date.now()}.txt`);
  try { await download(unsigned, tmp); return await fsp.readFile(tmp, 'utf8'); }
  catch (_) { }
  await download(signed, tmp);
  return await fsp.readFile(tmp, 'utf8');
}

function parseChecksumFor(filename, listText) {
  const escaped = filename.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const gnu = new RegExp(`^([a-fA-F0-9]{64})\\s+\\*?${escaped}$`, 'm');
  const bsd = new RegExp(`^SHA256 \\(${escaped}\\) = ([a-fA-F0-9]{64})$`, 'm');
  let m = listText.match(gnu);
  if (!m) m = listText.match(bsd);
  return m ? m[1].toLowerCase() : null;
}

async function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  const stream = fs.createReadStream(filePath);
  return new Promise((resolve, reject) => {
    stream.on('data', (d) => hash.update(d));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

async function ensureBundle(token) {
  const { version, baseUrl } = await resolveTorDownloadInfo();
  const archFile = expertBundleFileName(token, version);
  const url = `${baseUrl}/${archFile}`;
  const tmpArchive = path.join(os.tmpdir(), archFile);
  const targetDir = path.join(OUT_DIR, platformToDir(token));

  log(`Downloading ${archFile} for ${token} ...`);
  await download(url, tmpArchive);

  log('Fetching checksum list ...');
  const list = await readSha256List();
  const expected = parseChecksumFor(archFile, list);
  if (!expected) throw new Error(`Checksum for ${archFile} not found`);

  const actual = await sha256File(tmpArchive);
  if (actual !== expected) {
    throw new Error(`SHA256 mismatch for ${archFile}: expected ${expected}, got ${actual}`);
  }
  log('Checksum OK');

  await fsp.mkdir(targetDir, { recursive: true });
  log('Extracting ...');
  await extract({ file: tmpArchive, cwd: targetDir, strip: 1 });

  if (process.platform !== 'win32') {
    const bins = ['tor', 'obfs4proxy', 'snowflake-client', 'conjure-client', 'lyrebird'];
    for (const b of bins) {
      const p = path.join(targetDir, b);
      try {
        await fsp.chmod(p, 0o755);
      } catch (_) { }
      const pt = path.join(targetDir, 'pluggable_transports', b);
      try {
        await fsp.chmod(pt, 0o755);
      } catch (_) { }
    }
  }

  const isWinToken = token.startsWith('windows-');
  const ext = isWinToken ? '.exe' : '';
  const torPath = path.join(targetDir, `tor${ext}`);
  const lyrePath = path.join(targetDir, 'pluggable_transports', `lyrebird${ext}`);
  const torOk = fs.existsSync(torPath);
  const lyreOk = fs.existsSync(lyrePath);
  if (!torOk || !lyreOk) {
    throw new Error(`Bundle incomplete for ${token}: tor=${torOk}, lyrebird=${lyreOk}`);
  }

  log(`${platformToDir(token)} bundle ready`);
}

(async () => {
  try {
    const all = process.argv.includes('--all-platforms');
    const tokens = all
      ? ['linux-x86_64', 'macos-x86_64', 'windows-x86_64']
      : [hostPlatformToken()];

    await fsp.mkdir(OUT_DIR, { recursive: true });
    for (const t of tokens) {
      const dir = path.join(OUT_DIR, platformToDir(t));
      await fsp.mkdir(dir, { recursive: true });
    }

    for (const t of tokens) {
      await ensureBundle(t);
    }

    let ok = true;
    for (const t of tokens) {
      const d = platformToDir(t);
      const ext = d === 'windows' ? '.exe' : '';
      const torPath = path.join(OUT_DIR, d, `tor${ext}`);
      const lyrePath = path.join(OUT_DIR, d, 'pluggable_transports', `lyrebird${ext}`);
      if (fs.existsSync(torPath) && fs.existsSync(lyrePath)) {
        log(`${d}/tor${ext} - OK`);
        log(`${d}/pluggable_transports/lyrebird${ext} - OK`);
      } else {
        ok = false;
        logErr(`${d} - MISSING components`);
      }
    }

    if (!ok) {
      process.exitCode = 1;
      logErr('Some bundles incomplete');
      return;
    }

    const { execSync } = require('child_process');
    let size = 'unknown';
    try {
      if (process.platform !== 'win32') {
        size = execSync(`du -sh ${OUT_DIR} | cut -f1`, { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
      }
    } catch { }
    log(`All bundles prepared! Size: ${size}`);
  } catch (e) {
    logErr('Failed:', e.message);
    process.exit(1);
  }
})();