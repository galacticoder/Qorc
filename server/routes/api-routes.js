import express from 'express';
import { logError } from '../security/logging.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';

const router = express.Router();

let cachedPublicIp = null;
let lastIpFetchTime = 0;

async function getPublicIp() {
  const now = Date.now();
  if (cachedPublicIp && (now - lastIpFetchTime < 3600000)) {
    return cachedPublicIp;
  }
  try {
    const resp = await fetch('https://api.ipify.org?format=json');
    if (resp.ok) {
      const data = await resp.json();
      if (data.ip) {
        cachedPublicIp = data.ip;
        lastIpFetchTime = now;
        return cachedPublicIp;
      }
    }
  } catch (err) {
    cryptoLogger.warn('[ICE-CONFIG] Failed to auto-detect public IP', { error: err.message });
  }
  return process.env.PUBLIC_IP || null;
}

router.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', timestamp: Date.now() });
});

router.get('/tunnel-url', async (req, res) => {
  try {
    const resp = await fetch('http://127.0.0.1:4040/api/tunnels');
    if (!resp.ok) {
      res.status(404).type('text/plain').send('Tunnel URL not found');
      return;
    }
    const data = await resp.json();
    const httpsTunnel = (data.tunnels || []).find(t => typeof t.public_url === 'string' && t.public_url.startsWith('https://'));
    if (httpsTunnel) {
      res.type('text/plain').send(httpsTunnel.public_url);
    } else {
      res.status(404).type('text/plain').send('Tunnel URL not found');
    }
  } catch (error) {
    logError(error, { endpoint: '/api/tunnel-url' });
    res.status(500).type('text/plain').send('Server error');
  }
});

router.get('/ice/config', async (req, res) => {
  try {
    const turnRaw = process.env.TURN_SERVERS || '';
    const stunRaw = process.env.STUN_SERVERS || '';
    let turnServers = null;
    let stunServers = null;
    if (turnRaw) {
      try {
        const parsed = JSON.parse(turnRaw);
        if (Array.isArray(parsed)) turnServers = parsed;
      } catch { }
    }
    if (stunRaw) {
      try {
        const parsed = JSON.parse(stunRaw);
        if (Array.isArray(parsed)) stunServers = parsed;
      } catch { }
    }
    const iceServers = [];

    if (stunServers && Array.isArray(stunServers)) {
      for (const url of stunServers) {
        if (typeof url === 'string' && url.startsWith('stun:')) {
          iceServers.push({ urls: url });
        }
      }
    }

    if (turnServers && Array.isArray(turnServers)) {
      for (const entry of turnServers) {
        if (!entry) continue;
        const urls = entry.urls;
        const hasUrls = Array.isArray(urls) ? urls.length > 0 : typeof urls === 'string';
        if (!hasUrls) continue;
        if (!entry.username || !entry.credential) continue;
        iceServers.push(entry);
      }
    }

    const turnUsername = process.env.TURN_USERNAME;
    const turnPassword = process.env.TURN_PASSWORD;

    if (turnUsername && turnPassword) {
      let turnExternalIp = process.env.TURN_EXTERNAL_IP;
      if (!turnExternalIp || turnExternalIp.trim() === '') {
        turnExternalIp = await getPublicIp();
      }

      if (turnExternalIp) {
        const turnPort = process.env.TURN_PORT || '3478';
        const turnsPort = process.env.TURNS_PORT || '5349';
        const turnUrl = `turn:${turnExternalIp}:${turnPort}`;

        const alreadyExists = iceServers.some(s => {
          const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
          return urls.some(u => typeof u === 'string' && u.startsWith(turnUrl));
        });

        if (!alreadyExists) {
          iceServers.push({
            urls: [
              `turn:${turnExternalIp}:${turnPort}`,
              `turns:${turnExternalIp}:${turnsPort}`
            ],
            username: turnUsername,
            credential: turnPassword
          });
          cryptoLogger.info('[ICE-CONFIG] Included Docker TURN server in ICE config', {
            ip: turnExternalIp,
            turnPort,
            turnsPort,
            autoDetected: !process.env.TURN_EXTERNAL_IP
          });
        }
      }
    }

    if (iceServers.length === 0) {
      iceServers.push(
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' }
      );
    }

    const iceTransportPolicy = process.env.ICE_TRANSPORT_POLICY === 'relay' ? 'relay' : 'all';
    res.json({ iceServers, iceTransportPolicy });
  } catch (error) {
    logError(error, { endpoint: '/api/ice/config' });
    res.status(500).json({ error: 'ICE configuration error' });
  }
});

export default router;
