import Redis from 'ioredis';
import { createPool } from 'generic-pool';
import { TTL_CONFIG } from '../config/config.js';

const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
const REDIS_CLUSTER_NODES = (process.env.REDIS_CLUSTER_NODES || '').trim();
const USING_CLUSTER = REDIS_CLUSTER_NODES.length > 0;

// Redis connection pool configuration
const POOL_CONFIG = {
  min: 4,
  max: Math.max(20, Number.parseInt(process.env.REDIS_POOL_MAX || '50', 10)),
  acquireTimeoutMillis: 15000,
  idleTimeoutMillis: 30000,
  evictionRunIntervalMillis: 60000,
};

// Redis client options with robust error handling
const REDIS_OPTIONS = {
  host: process.env.REDIS_HOST || '127.0.0.1',
  port: parseInt(process.env.REDIS_PORT || '6379', 10),
  maxRetriesPerRequest: 3,
  retryDelayOnFailover: 100,
  enableAutoPipelining: true,
  reconnectOnError: (err) => {
    const targetError = /READONLY|ECONNRESET|ENOTFOUND|ECONNREFUSED/;
    return targetError.test(err.message);
  },
  connectTimeout: 10000,
  commandTimeout: 5000,
};

let clusterClient = null;
if (USING_CLUSTER) {
  try {
    const nodes = REDIS_CLUSTER_NODES.split(',').map(s => {
      const [host, portStr] = s.trim().split(':');
      return { host, port: Number.parseInt(portStr || '6379', 10) };
    }).filter(n => n.host);
    clusterClient = new Redis.Cluster(nodes, {
      redisOptions: REDIS_OPTIONS
    });
    clusterClient.on('connect', () => console.log('[PRESENCE] Redis Cluster client connected'));
    clusterClient.on('ready', () => console.log('[PRESENCE] Redis Cluster client ready'));
    clusterClient.on('error', (e) => console.error('[PRESENCE] Redis Cluster error:', e));
  } catch (e) {
    console.error('[PRESENCE] Failed to initialize Redis Cluster client:', e);
  }
}

// Factory for creating Redis clients (standalone mode)
const factory = {
  create: async () => {
    const client = new Redis(REDIS_URL, REDIS_OPTIONS);
    
    // Add event listeners for monitoring
    client.on('error', (error) => {
      console.error('[PRESENCE] Redis client error:', error);
    });
    
    client.on('connect', () => {
      console.log('[PRESENCE] Redis pool client connected');
    });
    
    client.on('ready', () => {
      console.log('[PRESENCE] Redis pool client ready');
    });
    
    client.on('close', () => {
      console.log('[PRESENCE] Redis client closed');
    });
    
    client.on('reconnecting', () => {
      console.log('[PRESENCE] Redis client reconnecting');
    });
    
    // Wait for connection to be ready with timeout
    await new Promise((resolve, reject) => {
      if (client.status === 'ready') {
        resolve();
        return;
      }
      
      let timeout;
      let readyHandler;
      let errorHandler;
      
      const cleanup = () => {
        if (timeout) clearTimeout(timeout);
        if (readyHandler) client.off('ready', readyHandler);
        if (errorHandler) client.off('error', errorHandler);
      };
      
      readyHandler = () => {
        cleanup();
        resolve();
      };
      
      errorHandler = (error) => {
        cleanup();
        reject(error);
      };
      
      // Set up timeout (10 seconds)
      timeout = setTimeout(() => {
        cleanup();
        reject(new Error('Redis client connection timeout - neither ready nor error event received within 10 seconds'));
      }, 10000);
      
      client.once('ready', readyHandler);
      client.once('error', errorHandler);
    });
    
    return client;
  },
  destroy: async (client) => {
    try {
      await client.quit();
    } catch (error) {
      console.error('[PRESENCE] Error destroying Redis client:', error);
      try {
        client.disconnect();
      } catch (disconnectError) {
        console.error('[PRESENCE] Error disconnecting Redis client:', disconnectError);
      }
    }
  }
};

// Create the connection pool (standalone only)
export const redisPool = USING_CLUSTER ? null : createPool(factory, POOL_CONFIG);

// Helper function to execute Redis commands with automatic pool management
export async function withRedisClient(operation) {
  if (USING_CLUSTER && clusterClient) {
    return operation(clusterClient);
  }
  const client = await redisPool.acquire();
  try {
    return await operation(client);
  } finally {
    await redisPool.release(client);
  }
}

// Legacy export for backward compatibility (deprecated)
export const redis = {
  set: (...args) => withRedisClient(client => client.set(...args)),
  get: (...args) => withRedisClient(client => client.get(...args)),
  del: (...args) => withRedisClient(client => client.del(...args)),
  exists: (...args) => withRedisClient(client => client.exists(...args)),
  expire: (...args) => withRedisClient(client => client.expire(...args)),
  incr: (...args) => withRedisClient(client => client.incr(...args)),
  decr: (...args) => withRedisClient(client => client.decr(...args)),
  publish: (...args) => withRedisClient(client => client.publish(...args)),
  eval: (...args) => withRedisClient(client => client.eval(...args)),
  duplicate: () => {
    // For subscribers, create a new dedicated connection
    if (USING_CLUSTER && clusterClient) {
      const nodes = REDIS_CLUSTER_NODES.split(',').map(s => {
        const [host, portStr] = s.trim().split(':');
        return { host, port: Number.parseInt(portStr || '6379', 10) };
      }).filter(n => n.host);
      return new Redis.Cluster(nodes, { redisOptions: REDIS_OPTIONS });
    }
    return new Redis(REDIS_URL, REDIS_OPTIONS);
  }
};

// NOTE: Removed global activeSubscribers Set to avoid storing millions of connections in memory
// Subscribers are now cleaned up per-connection when WebSocket closes

export async function createSubscriber() {
  // Dedicated subscriber connection (not pooled)
  const sub = new Redis(REDIS_URL, REDIS_OPTIONS);
  
  // Add basic error logging
  sub.on('error', (error) => {
    console.error('[PRESENCE] Redis subscriber error:', error);
  });
  
  sub.on('ready', () => {
    console.log('[PRESENCE] Redis subscriber ready for user notifications');
  });
  
  sub.on('close', () => {
    console.log('[PRESENCE] Redis subscriber closed');
  });
  
  // Wait for the subscriber to be ready
  await new Promise((resolve, reject) => {
    if (sub.status === 'ready') {
      resolve();
      return;
    }
    
    let timeout;
    let readyHandler;
    let errorHandler;
    
    const cleanup = () => {
      if (timeout) clearTimeout(timeout);
      if (readyHandler) sub.off('ready', readyHandler);
      if (errorHandler) sub.off('error', errorHandler);
    };
    
    readyHandler = () => {
      cleanup();
      resolve();
    };
    
    errorHandler = (error) => {
      cleanup();
      reject(error);
    };
    
    // Set up timeout (10 seconds)
    timeout = setTimeout(() => {
      cleanup();
      reject(new Error('Redis subscriber connection timeout - neither ready nor error event received within 10 seconds'));
    }, 10000);
    
    sub.once('ready', readyHandler);
    sub.once('error', errorHandler);
  });
  
  // NOTE: No longer tracking subscribers globally to avoid memory issues with millions of users
  // Subscribers are cleaned up per-connection when WebSocket closes
  
  return sub;
}

// Cleanup function for shutting down subscribers
export async function closeSubscriber(subscriber) {
  if (subscriber) {
    try {
      // Only try to quit if connection is still active
      if (subscriber.status !== 'end' && subscriber.status !== 'close') {
        await subscriber.quit();
      }
    } catch (error) {
      console.error('[PRESENCE] Error closing subscriber:', error);
    }
  }
}

// Global cleanup on process termination
const cleanup = async () => {
  console.log('[PRESENCE] Cleaning up Redis connection pool...');
  
  // Drain the connection pool (standalone)
  if (redisPool) {
    try {
      await redisPool.drain();
      await redisPool.clear();
      console.log('[PRESENCE] Redis connection pool cleaned up');
    } catch (error) {
      console.error('[PRESENCE] Error cleaning up Redis pool:', error);
    }
  }
  // Quit cluster client
  if (clusterClient) {
    try { await clusterClient.quit(); } catch {}
  }
};

// Graceful shutdown with timeout fallback
const gracefulShutdown = async (signal) => {
  console.log(`[PRESENCE] Received ${signal}, shutting down gracefully...`);
  
  try {
    // Set a timeout to force exit if cleanup takes too long
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Cleanup timeout')), 5000);
    });
    
    // Race between cleanup and timeout
    await Promise.race([cleanup(), timeoutPromise]);
    console.log('[PRESENCE] Graceful shutdown completed');
    process.exit(0);
  } catch (error) {
    console.error('[PRESENCE] Error during graceful shutdown:', error);
    process.exit(1);
  }
};

// Use process.once to avoid multiple handlers
process.once('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.once('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle process exit - but don't await here as it's synchronous
process.once('exit', () => {
  console.log('[PRESENCE] Process exiting, attempting final cleanup...');
  // Note: exit event is synchronous, so we can't await here
  // Just attempt cleanup without waiting
  cleanup().catch(err => console.error('[PRESENCE] Final cleanup error:', err));
});

const ONLINE_KEY = (u) => `online:${u}`;
const DELIVER_CH = (u) => `deliver:${u}`;

export async function setOnline(username, ttlSeconds = TTL_CONFIG.PRESENCE_TTL) {
  try {
    // Set online with TTL to auto-expire after crashes
    const safeTtl = Math.max(10, ttlSeconds);
    await redis.set(ONLINE_KEY(username), '1', 'EX', safeTtl);
    console.log(`[PRESENCE] User ${username} set online with ${safeTtl}s TTL`);
  } catch (error) {
    console.error(`[PRESENCE] Error setting user ${username} online:`, error);
    throw error; // Re-throw to let caller handle appropriately
  }
}

export async function bumpOnline(username, ttlSeconds = TTL_CONFIG.PRESENCE_TTL) {
  try {
    // Lightweight TTL refresh - silently ignore errors
    const safeTtl = Math.max(10, ttlSeconds);
    await redis.expire(ONLINE_KEY(username), safeTtl);
  } catch (error) {
    // Silently ignore errors as this is opportunistic
  }
}

export async function setOffline(username) {
  try {
    await redis.del(ONLINE_KEY(username));
    console.log(`[PRESENCE] User ${username} set offline`);
  } catch (error) {
    console.error(`[PRESENCE] Error setting user ${username} offline:`, error);
    throw error; // Re-throw to let caller handle appropriately
  }
}

export async function isOnline(username) {
  try {
    const ex = await redis.exists(ONLINE_KEY(username));
    return ex === 1;
  } catch (error) {
    console.error(`[PRESENCE] Error checking online status for user ${username}:`, error);
    return false; // Safe fallback: assume offline on error
  }
}

export async function publishToUser(username, payloadObj) {
  try {
    const msg = typeof payloadObj === 'string' ? payloadObj : JSON.stringify(payloadObj);
    await redis.publish(DELIVER_CH(username), msg);
    return true; // Delivery will be handled by pattern subscribers on instances
  } catch (error) {
    console.error(`[PRESENCE] Error publishing message to user ${username}:`, error);
    return false;
  }
}

export async function subscribeUserChannel(subscriber, username, onMessage) {
  await subscriber.subscribe(DELIVER_CH(username));
  const handler = (channel, message) => {
    if (channel === DELIVER_CH(username)) {
      onMessage(message);
    }
  };
  subscriber.on('message', handler);
  return async () => {
    try {
      subscriber.off('message', handler);
    } catch (error) {
      console.error(`[PRESENCE] Error removing message handler for user ${username}:`, error);
    }
    try {
      await subscriber.unsubscribe(DELIVER_CH(username));
    } catch (error) {
      console.error(`[PRESENCE] Error unsubscribing from channel for user ${username}:`, error);
    }
  };
}


