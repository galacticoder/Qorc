import { CryptoUtils } from '../crypto/unified-crypto.js';
import * as ServerConfig from '../config/config.js';
import { TTL_CONFIG } from '../config/config.js';
import { UserDatabase } from '../database/database.js';
import { withRedisClient } from '../presence/presence.js';

export const validateUsernameFormat = (username) => {
  if (!username || typeof username !== 'string') return false;
  const isPseudonym = /^[a-f0-9]{32,}$/i.test(username);
  if (isPseudonym) return true;

  return /^[a-zA-Z0-9_-]+$/.test(username);
};

export const validateUsernameLength = (username) => {
  if (!username || typeof username !== 'string') return false;
  const isPseudonym = /^[a-f0-9]{32,}$/i.test(username);
  if (isPseudonym) {
    return username.length >= 32 && username.length <= 128;
  }

  return username.length >= 3 && username.length <= 32;
};
export const isUsernameAvailable = async (username) => {
  try {
    if (!username || typeof username !== 'string') {
      throw new Error('Invalid username parameter');
    }
    
    const existingUser = await UserDatabase.loadUser(username);
    return existingUser === null;
  } catch (error) {
    console.error(`[AUTH] Error checking username availability for ${username}:`, error);
    throw error; 
  }
};

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
    console.error('[AUTH] Redis error in isServerFull. Treating server as full:', error);
    return true;
  }
};

// Helper function to decrement connection count when a client disconnects
export const decrementConnectionCount = async () => {
  try {
    await withRedisClient(client => client.decr(CONNECTION_COUNTER_KEY));
  } catch (error) {
    console.error('[AUTH] Error decrementing connection count:', error);
  }
};

export async function setServerPasswordOnInput() {
  try {
    if (process.env.SERVER_PASSWORD_HASH && process.env.SERVER_PASSWORD_HASH.length > 0) {
      ServerConfig.setServerPassword(process.env.SERVER_PASSWORD_HASH);
      console.log('[SERVER] Server password hash set from environment');
      return;
    }

    if (process.env.SERVER_PASSWORD && process.env.SERVER_PASSWORD.length > 0) {
      const password = process.env.SERVER_PASSWORD;
      if (password.length > 512) {
        console.error('SERVER_PASSWORD too long (max 512 characters). Exiting...');
        process.emit('SIGTERM');
        return;
      }

      const hash = await CryptoUtils.Password.hashPassword(password);
      ServerConfig.setServerPassword(hash);

      process.env.SERVER_PASSWORD_HASH = hash;
      delete process.env.SERVER_PASSWORD;

      if (process.env.ENABLE_CLUSTERING === 'true') {
        try {
          const { withRedisClient } = await import('../presence/presence.js');
          await withRedisClient(async (client) => {
            await client.hset('cluster:config', 'SERVER_PASSWORD_HASH', hash);
            console.log('[SERVER] Stored password hash in cluster shared config');
          });
        } catch (error) {
          console.log('[SERVER] Could not store password in cluster:', error.message);
        }
      }

      console.log('[SERVER] Server password set from environment');
      return;
    }

    if (process.env.ENABLE_CLUSTERING === 'true') {
      try {
        const { ClusterManager } = await import('../cluster/cluster-manager.js');
        const sharedPasswordHash = await ClusterManager.getSharedConfig('SERVER_PASSWORD_HASH');
        if (sharedPasswordHash && sharedPasswordHash.length > 0) {
          ServerConfig.setServerPassword(sharedPasswordHash);
          console.log('[SERVER] Server password hash loaded from cluster shared config');
          return;
        }
      } catch (error) {
        console.log('[SERVER] Could not load password from cluster: ' + error.message);
      }
    }

    console.error('\n' + '='.repeat(80));
    console.error('ERROR: Server password required but not provided');
    console.error('='.repeat(80));
    console.error('\nPlease provide server password using one of these methods:');
    console.error('\n1. Environment variable');
    console.error('   export SERVER_PASSWORD_HASH="your_argon2_hash"');
    console.error('   export SERVER_PASSWORD="your_password"');
    console.error('\n' + '='.repeat(80) + '\n');
    process.exit(1);
  } catch (error) {
    if (error?.message?.includes('Password must be at least')) {
      console.error(`[SERVER] Password too short: ${error.message}`);
      console.error('Please set a server password with at least 12 characters via SERVER_PASSWORD or SERVER_PASSWORD_HASH.');
      console.error('Exiting...');
    } else {
      console.error('[SERVER] Failed to set server password:', {
        message: error?.message || error,
        stack: error?.stack,
        type: error?.constructor?.name
      });
      console.error('Password setting failed. Exiting...');
    }
    process.emit('SIGTERM');
  }
}
