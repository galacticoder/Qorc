import promptSync from 'prompt-sync';
import * as db from '../database/database.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import * as ServerConfig from '../config/config.js';
import { UserDatabase } from '../database/database.js';
import { redis } from '../presence/presence.js';

const prompt = promptSync({ sigint: true });

export const validateUsernameFormat = (username) => {
  if (!username || typeof username !== 'string') return false;
  return /^[a-zA-Z0-9_-]+$/.test(username);
};

export const validateUsernameLength = (username) => {
  if (!username || typeof username !== 'string') return false;
  return username.length >= 3 && username.length <= 32; // Increased to match database validation
};
export const isUsernameAvailable = (username) => {
  try {
    if (!username || typeof username !== 'string') {
      throw new Error('Invalid username parameter');
    }
    
    const existingUser = UserDatabase.loadUser(username);
    return existingUser === null; // Available if no user found
  } catch (error) {
    console.error(`[AUTH] Error checking username availability for ${username}:`, error);
    throw error; // Re-throw to surface DB errors
  }
};

// Configuration for server capacity
const MAX_CONNECTIONS = parseInt(process.env.MAX_CONNECTIONS || '1000', 10);
const CONNECTION_COUNTER_KEY = 'server:active_connections';
const CONNECTION_COUNTER_TTL = 3600; // 1 hour TTL to avoid stale keys

export const isServerFull = async () => {
  try {
    // Atomic check and increment using Lua script
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
    
    const result = await redis.eval(luaScript, 1, CONNECTION_COUNTER_KEY, MAX_CONNECTIONS, CONNECTION_COUNTER_TTL);
    return result === 1;
  } catch (error) {
    console.error('[AUTH] Redis error in isServerFull, failing safe (treating as full):', error);
    return true; // Fail-safe: treat server as full on Redis errors
  }
};

// Helper function to decrement connection count when a client disconnects
export const decrementConnectionCount = async () => {
  try {
    await redis.decr(CONNECTION_COUNTER_KEY);
  } catch (error) {
    console.error('[AUTH] Error decrementing connection count:', error);
    // Don't throw here - this is cleanup, shouldn't block disconnect
  }
};

export async function setServerPasswordOnInput() {
  const password = prompt.hide('Set server password (Input will not be visible): ').trim();
  const confirm = prompt.hide('Confirm password: ').trim();

  // SECURITY: Validate password (minimum length requirement removed)
  
  if (password.length > 512) {
    console.error('Password too long (max 512 characters). Exiting.');
    process.exit(1);
  }

  if (password !== confirm) {
    console.error('Passwords do not match. Exiting.');
    process.exit(1);
  }
  
  // SECURITY: Clear password variables from memory
  try {
    const serverPasswordHash = await CryptoUtils.Password.hashPassword(password);
    ServerConfig.setServerPassword(serverPasswordHash);
    console.log('Password set successfully.');
  } catch (error) {
    console.error('Failed to hash password:', error.message);
    process.exit(1);
  }
}
