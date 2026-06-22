import { CryptoUtils } from '../crypto/unified-crypto.js';
import * as ServerConfig from '../config/config.js';
import { TTL_CONFIG } from '../config/config.js';
import { withRedisClient } from '../session/redis-client.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';

// Configuration for server capacity
const MAX_CONNECTIONS = parseInt(process.env.MAX_CONNECTIONS || '1000', 10);
const CONNECTION_COUNTER_KEY = 'server:active_connections';
const CONNECTION_COUNTER_TTL = TTL_CONFIG.CONNECTION_COUNTER_TTL;

export const isServerFull = async () => {
  try {
    const luaScript = `
      local key = KEYS[1]
      local max_conn = tonumber(ARGV[1])
      local ttl = tonumber(ARGV[2])
      
      local current = redis.call('GET', key)
      if current == false then
        current = 0
      else
        current = tonumber(current)
      end
      
      if current >= max_conn then
        return 1  -- Server is full
      end
      
      -- Increment counter and set TTL
      local new_count = redis.call('INCR', key)
      if new_count == 1 then
        redis.call('EXPIRE', key, ttl)
      end
      
      if new_count > max_conn then
        redis.call('DECR', key)  -- Rollback
        return 1  -- Server is full
      end
      
      return 0  -- Server has capacity
    `;

    const result = await withRedisClient(client =>
      client.eval(luaScript, 1, CONNECTION_COUNTER_KEY, MAX_CONNECTIONS, CONNECTION_COUNTER_TTL)
    );
    return result === 1;
  } catch (error) {
    cryptoLogger.error('[AUTH] Redis error in isServerFull. Treating server as full', { error: error?.message });
    return true;
  }
};

// Helper function to decrement connection count when a client disconnects
export const decrementConnectionCount = async () => {
  try {
    await withRedisClient(client => client.decr(CONNECTION_COUNTER_KEY));
  } catch (error) {
    cryptoLogger.error('[AUTH] Error decrementing connection count', { error: error?.message });
  }
};

export async function setServerPasswordOnInput() {
  try {
    const plaintextPassword = typeof process.env.SERVER_PASSWORD === 'string'
      ? process.env.SERVER_PASSWORD.trim()
      : '';

    if (plaintextPassword.length > 0) {
      const password = plaintextPassword;
      if (password.length > 512) {
        cryptoLogger.error('[SERVER] SERVER_PASSWORD too long');
        process.emit('SIGTERM');
        return;
      }

      const hash = await CryptoUtils.Password.hashPassword(password);
      ServerConfig.setServerPassword(hash);

      // Initialize Gatekeeper with plaintext before deleting it
      try {
        const { ServerGatekeeper } = await import('./gatekeeper.js');
        await ServerGatekeeper.initializeExplicit(password);
      } catch (gkErr) {
        cryptoLogger.warn('[SERVER] Failed to auto-initialize gatekeeper', { error: gkErr?.message });
      }

      process.env.SERVER_PASSWORD_HASH = hash;
      delete process.env.SERVER_PASSWORD;

      if (process.env.ENABLE_CLUSTERING === 'true') {
        try {
          const { withRedisClient } = await import('../session/redis-client.js');
          await withRedisClient(async (client) => {
            await client.hset('cluster:config', 'SERVER_PASSWORD_HASH', hash);
            cryptoLogger.info('[SERVER] Stored password hash in cluster shared config');
          });
        } catch (error) {
          cryptoLogger.warn('[SERVER] Could not store password in cluster', { error: error?.message });
        }
      }

      cryptoLogger.info('[SERVER] Server password set from environment');
      return;
    }

    if (process.env.ENABLE_CLUSTERING === 'true') {
      try {
        const { ClusterManager } = await import('../cluster/cluster-manager.js');
        const sharedPasswordHash = await ClusterManager.getSharedConfig('SERVER_PASSWORD_HASH');
        if (sharedPasswordHash && sharedPasswordHash.length > 0) {
          ServerConfig.setServerPassword(sharedPasswordHash);
          cryptoLogger.info('[SERVER] Server password hash loaded from cluster shared config');
          return;
        }
      } catch (error) {
        cryptoLogger.warn('[SERVER] Could not load password from cluster', { error: error?.message });
      }
    }

    console.error('\n' + '='.repeat(80));
    console.error('ERROR: Server password required but not provided');
    console.error('='.repeat(80));
    console.error('\nPlease provide server password using an environment variable:');
    console.error('   export SERVER_PASSWORD="your_password"');
    console.error('\nblind server entry requires the plaintext SERVER_PASSWORD at boot to initialize the gatekeeper.');
    console.error('\n' + '='.repeat(80) + '\n');
    process.exit(1);
  } catch (error) {
    if (error?.message?.includes('Password must be at least')) {
      cryptoLogger.error('[SERVER] Password too short');
    } else {
      cryptoLogger.error('[SERVER] Failed to set server password', {
        error: error?.message,
        type: error?.constructor?.name
      });
    }
    process.emit('SIGTERM');
  }
}
