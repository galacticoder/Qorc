import express from 'express';
import { logError } from '../security/logging.js';

const router = express.Router();

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

export default router;
