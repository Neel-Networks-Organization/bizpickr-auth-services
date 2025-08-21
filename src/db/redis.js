import Redis from 'ioredis';
import {
  redisConfig,
  getRedisConnectionOptions,
  getRedisRetryStrategy,
  validateRedisConfig,
} from '../config/redis.js';
import { safeLogger } from '../config/logger.js';
import { ApiError } from '../utils/index.js';

/**
 * Simple Redis Client for authService
 *
 * Purpose: Basic Redis caching and session storage
 * Features:
 * - Simple connection management
 * - Basic error handling
 * - Connection retry
 * - Graceful shutdown
 */

// Redis client instance
let redis = null;

/**
 * Initialize Redis connection
 * @returns {Promise<Redis>} Redis client instance
 */
export async function initRedis() {
  return new Promise((resolve, reject) => {
    let timeout = setTimeout(() => {
      safeLogger.error(
        'Redis connection timeout (10s): Unable to connect to Redis server',
      );
      reject(
        new ApiError(504, 'Redis connection timeout', [
          'Redis did not become ready within 10 seconds',
          'Please check Redis server status and network connectivity',
        ]),
      );
    }, 10000); // 10 seconds

    if (redis && redis.status === 'ready') {
      clearTimeout(timeout);
      safeLogger.info('Redis client already initialized and ready');
      return resolve(redis);
    }

    try {
      validateRedisConfig();

      const connectionOptions = getRedisConnectionOptions();
      const retryStrategy = getRedisRetryStrategy();

      safeLogger.info('Initializing Redis connection', {
        host: redisConfig.host,
        port: redisConfig.port,
        db: redisConfig.db,
      });

      redis = new Redis({
        ...connectionOptions,
        retryStrategy,
      });

      setupRedisEventListeners(
        client => {
          clearTimeout(timeout);
          resolve(client);
        },
        err => {
          safeLogger.error('Redis connection failed', { error: err.message });
          reject(err);
        },
      );
    } catch (error) {
      clearTimeout(timeout);
      safeLogger.error('Redis initialization failed', { error: error.message });
      reject(error);
    }
  });
}

/**
 * Setup Redis event listeners
 */
function setupRedisEventListeners(onConnect, onError) {
  redis.on('connect', () => {
    safeLogger.info('Redis connected');
  });

  redis.on('ready', () => {
    safeLogger.info('Redis ready');
    onConnect(redis);
  });

  redis.on('error', error => {
    safeLogger.error('Redis error', { error: error.message });
    onError(error);
  });

  redis.on('close', () => {
    safeLogger.warn('Redis connection closed');
  });

  redis.on('reconnecting', () => {
    safeLogger.info('Redis reconnecting');
  });

  redis.on('end', () => {
    safeLogger.warn('Redis connection ended');
  });
}

/**
 * Get Redis client instance
 * @returns {Redis|null} Redis client
 */
export function getRedisClient() {
  return redis;
}

/**
 * Check if Redis is connected
 * @returns {boolean} Connection status
 */
export function isRedisConnected() {
  return redis && redis.status === 'ready';
}

/**
 * Close Redis connection
 * @returns {Promise<void>}
 */
export async function closeRedis() {
  if (redis) {
    try {
      await redis.quit();
      safeLogger.info('Redis connection closed');
    } catch (error) {
      safeLogger.error('Error closing Redis connection', {
        error: error.message,
      });
    }
  }
}

/**
 * Basic Redis operations
 */
export const redisOperations = {
  // Set key-value with TTL
  set: async(key, value, ttl = null) => {
    if (!isRedisConnected()) {
      throw new Error('Redis not connected');
    }

    if (ttl) {
      return await redis.setex(key, ttl, value);
    }
    return await redis.set(key, value);
  },

  // Get value by key
  get: async key => {
    if (!isRedisConnected()) {
      throw new Error('Redis not connected');
    }
    return await redis.get(key);
  },

  // Delete key
  del: async key => {
    if (!isRedisConnected()) {
      throw new Error('Redis not connected');
    }
    return await redis.del(key);
  },

  // Check if key exists
  exists: async key => {
    if (!isRedisConnected()) {
      throw new Error('Redis not connected');
    }
    return await redis.exists(key);
  },

  // Set TTL for key
  expire: async(key, ttl) => {
    if (!isRedisConnected()) {
      throw new Error('Redis not connected');
    }
    return await redis.expire(key, ttl);
  },

  // Get TTL for key
  ttl: async key => {
    if (!isRedisConnected()) {
      throw new Error('Redis not connected');
    }
    return await redis.ttl(key);
  },
};

export default redis;
