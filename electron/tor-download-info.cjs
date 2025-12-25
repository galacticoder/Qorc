const https = require('https');

const DEFAULT_UPDATE_URL = 'https://aus1.torproject.org/torbrowser/update_3/release/downloads.json';
const DEFAULT_DIST_BASE = 'https://dist.torproject.org/torbrowser';

const MAX_REDIRECTS = 5;
const JSON_TIMEOUT_MS = 15_000;

function httpGetJson(url, redirectsLeft = MAX_REDIRECTS) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: JSON_TIMEOUT_MS }, (res) => {
      const status = res.statusCode || 0;

      if ((status === 301 || status === 302 || status === 307 || status === 308) && res.headers.location) {
        if (redirectsLeft <= 0) {
          res.resume();
          return reject(new Error('Too many redirects'));
        }
        const redirectUrl = res.headers.location.startsWith('http')
          ? res.headers.location
          : new URL(res.headers.location, url).toString();
        res.resume();
        return resolve(httpGetJson(redirectUrl, redirectsLeft - 1));
      }

      if (status !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${status} for ${url}`));
      }

      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (err) {
          reject(err);
        }
      });
    });

    req.on('timeout', () => {
      try { req.destroy(); } catch { }
      reject(new Error('Request timeout'));
    });
    req.on('error', reject);
  });
}

async function resolveLatestTorBrowserVersion() {
  const json = await httpGetJson(DEFAULT_UPDATE_URL);
  const version = typeof json?.version === 'string' ? json.version.trim() : '';
  if (version) {
    return { version, sourceUrl: DEFAULT_UPDATE_URL };
  }

  const candidates = [];
  try {
    const downloads = json?.downloads && typeof json.downloads === 'object' ? json.downloads : null;
    if (downloads) {
      for (const platformKey of Object.keys(downloads)) {
        const all = downloads[platformKey]?.ALL;
        const binary = typeof all?.binary === 'string' ? all.binary : '';
        if (binary) candidates.push(binary);
      }
    }
  } catch { }

  for (const candidate of candidates) {
    const match = candidate.match(/\/torbrowser\/(\d+\.\d+(?:\.\d+)?[a-z0-9.]*)\//i);
    if (match?.[1]) {
      return { version: match[1], sourceUrl: DEFAULT_UPDATE_URL };
    }
  }

  throw new Error('Could not resolve latest Tor Browser version (set TOR_VERSION to override)');
}

let cachedInfoPromise = null;

async function resolveTorDownloadInfo() {
  if (cachedInfoPromise) return cachedInfoPromise;

  cachedInfoPromise = (async () => {
    const versionOverride = typeof process.env.TOR_VERSION === 'string' ? process.env.TOR_VERSION.trim() : '';
    const baseUrlOverride = typeof process.env.TOR_BASE_URL === 'string' ? process.env.TOR_BASE_URL.trim() : '';

    let resolved;
    if (versionOverride) {
      resolved = { version: versionOverride, sourceUrl: 'env:TOR_VERSION' };
    } else {
      resolved = await resolveLatestTorBrowserVersion();
    }

    const baseUrl = baseUrlOverride || `${DEFAULT_DIST_BASE}/${resolved.version}`;

    return {
      version: resolved.version,
      baseUrl,
      updateSource: resolved.sourceUrl,
    };
  })();

  return cachedInfoPromise;
}

function expertBundleFileName(platformToken, version) {
  if (!platformToken) throw new Error('Missing platform token');
  if (!version) throw new Error('Missing version');
  return `tor-expert-bundle-${platformToken}-${version}.tar.gz`;
}

module.exports = {
  resolveTorDownloadInfo,
  expertBundleFileName,
};
