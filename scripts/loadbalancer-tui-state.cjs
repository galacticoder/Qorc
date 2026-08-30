'use strict';

function parseActiveServers(storedServers, now, timeoutMs) {
  const servers = [];

  for (const [id, data] of Object.entries(storedServers || {})) {
    try {
      const info = JSON.parse(data);
      const lastHeartbeat = Number(info?.lastHeartbeat || 0);
      const heartbeatAge = now - lastHeartbeat;
      if (
        !Number.isSafeInteger(lastHeartbeat) ||
        lastHeartbeat <= 0 ||
        heartbeatAge >= timeoutMs
      ) {
        continue;
      }
      servers.push({
        id,
        host: info.host || '127.0.0.1',
        port: info.port || '?',
        heartbeatAge: Math.max(0, heartbeatAge),
      });
    } catch { }
  }

  servers.sort((a, b) => a.id.localeCompare(b.id));
  return servers;
}

module.exports = { parseActiveServers };
