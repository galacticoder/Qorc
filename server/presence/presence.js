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

// Helper function to parse Redis cluster nodes from environment variable
function parseRedisClusterNodes(redisClusterNodes) {
  if (!redisClusterNodes) return [];
  return redisClusterNodes.split(',').map(s => {
    const [host, portStr] = s.trim().split(':');
    return { host, port: Number.parseInt(portStr || '6379', 10) };
  }).filter(n => n.host);
}

let clusterClient = null;
// Connection pool for duplicate() calls to avoid exhausting connections
let duplicateConnectionPool = [];
const MAX_DUPLICATE_CONNECTIONS = 5;

if (USING_CLUSTER) {
  try {
    const nodes = parseRedisClusterNodes(REDIS_CLUSTER_NODES);
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
  duplicate: async () => {
    // For subscribers, reuse cached connections to avoid exhausting connections
    if (USING_CLUSTER && clusterClient) {
      // Try to reuse an existing connection from the pool with health check
      while (duplicateConnectionPool.length > 0) {
        const cachedClient = duplicateConnectionPool.pop();

        // Perform lightweight health check
        if (cachedClient && cachedClient.status === 'ready') {
          try {
            // Quick ping to verify connection is alive
            await cachedClient.ping();
            return cachedClient;
          } catch (error) {
            // Client failed health check, properly dispose of it
            try {
              if (cachedClient._originalQuit) {
                await cachedClient._originalQuit();
              } else {
                await cachedClient.quit();
              }
            } catch (quitError) {
              console.debug('[PRESENCE] Error disposing unhealthy cached client:', quitError.message);
            }
            // Continue to next client in pool or create new one
          }
        } else {
          // Client is not ready, dispose of it
          try {
            if (cachedClient && cachedClient._originalQuit) {
              await cachedClient._originalQuit();
            } else if (cachedClient) {
              await cachedClient.quit();
            }
          } catch (quitError) {
            console.debug('[PRESENCE] Error disposing invalid cached client:', quitError.message);
          }
        }
      }

      // Create new connection if pool is empty or all connections are invalid
      const nodes = parseRedisClusterNodes(REDIS_CLUSTER_NODES);
      const newClient = new Redis.Cluster(nodes, { redisOptions: REDIS_OPTIONS });

      // Store original quit method
      const originalQuit = newClient.quit.bind(newClient);
      newClient._originalQuit = originalQuit;

      // Add error handlers to remove client from pool on failure
      const removeFromPool = () => {
        const index = duplicateConnectionPool.indexOf(newClient);
        if (index > -1) {
          duplicateConnectionPool.splice(index, 1);
        }
      };

      newClient.on('error', removeFromPool);
      newClient.on('close', removeFromPool);
      newClient.on('end', removeFromPool);

      // Override quit to return connection to pool when done
      newClient.quit = async () => {
        // Remove event listeners before returning to pool
        newClient.removeListener('error', removeFromPool);
        newClient.removeListener('close', removeFromPool);
        newClient.removeListener('end', removeFromPool);

        // Validate client is still connected before pooling
        if (newClient.status === 'ready' && duplicateConnectionPool.length < MAX_DUPLICATE_CONNECTIONS) {
          try {
            await newClient.ping();
            duplicateConnectionPool.push(newClient);
            return Promise.resolve();
          } catch (error) {
            // Client failed validation, properly close it
            return originalQuit();
          }
        } else {
          // Pool is full or client is not ready, properly close it
          return originalQuit();
        }
      };

      return newClient;
    }

    // For standalone Redis, create new connection (lightweight)
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

  // Clean up duplicate connection pool
  if (duplicateConnectionPool.length > 0) {
    console.log(`[PRESENCE] Cleaning up ${duplicateConnectionPool.length} duplicate connections...`);
    const cleanupPromises = duplicateConnectionPool.map(async (client) => {
      try {
        if (client && client._originalQuit && typeof client._originalQuit === 'function') {
          await client._originalQuit();
        } else if (client && typeof client.quit === 'function') {
          await client.quit();
        }
      } catch (err) {
        console.error('[PRESENCE] Error quitting duplicate connection:', err);
      }
    });
    await Promise.all(cleanupPromises);
    duplicateConnectionPool = [];
  }

  // Quit cluster client
  if (clusterClient) {
    try {
      await clusterClient.quit();
    } catch (err) {
      console.error('[PRESENCE] Error quitting clusterClient in presence cleanup:', err);
    }
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
    // Log in debug mode but don't throw as this is opportunistic
    if (process.env.DEBUG_SERVER_LOGS === 'true') {
      console.debug(`[PRESENCE] Failed to bump online status for ${username}:`, error.message);
    }
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


