import { getRedisClient } from '../db/redis.js';
import { safeLogger } from '../config/logger.js';
import CircuitBreaker from 'opossum';

/**
 * Industry-Standard Auth Cache
 * Professional caching with circuit breakers, performance metrics, and advanced features
 */

// ✅ Industry-standard cache prefixes
const PREFIX = {
  USER_SESSION: 'user:session:',
  BLACKLISTED_TOKEN: 'blacklist:token:',
  USER_PROFILE: 'user:profile:',
  USER_PERMISSIONS: 'user:permissions:',
  RATE_LIMIT: 'rate:limit:',
  USER_STATS: 'user:stats:',
  CACHE_METRICS: 'cache:metrics:',
  DISTRIBUTED_LOCK: 'lock:',
  CACHE_WARMING: 'warming:',
};

// ✅ Industry-standard cache expiry times
const EXPIRY = {
  USER_SESSION: 24 * 60 * 60, // 24 hours
  BLACKLISTED_TOKEN: 7 * 24 * 60 * 60, // 7 days
  USER_PROFILE: 60 * 60, // 1 hour
  USER_PERMISSIONS: 30 * 60, // 30 minutes
  RATE_LIMIT: 15 * 60, // 15 minutes
  USER_STATS: 5 * 60, // 5 minutes
  CACHE_METRICS: 60, // 1 minute
  DISTRIBUTED_LOCK: 30, // 30 seconds
  CACHE_WARMING: 300, // 5 minutes
};

// ✅ Industry-standard cache configuration
const CACHE_CONFIG = {
  MAX_RETRIES: 3,
  RETRY_DELAY: 1000,
  CIRCUIT_BREAKER_THRESHOLD: 5,
  CIRCUIT_BREAKER_TIMEOUT: 10000,
  COMPRESSION_THRESHOLD: 1024, // 1KB
  BATCH_SIZE: 100,
  MAX_CONCURRENT_OPERATIONS: 50,
};

/**
 * Industry-standard cache operations
 */
class AuthCache {
  constructor() {
    this.redis = null;
    this.metrics = {
      hits: 0,
      misses: 0,
      errors: 0,
      operations: 0,
      lastReset: Date.now(),
    };
    this.circuitBreaker = new CircuitBreaker(this._redisOperation.bind(this), {
      timeout: CACHE_CONFIG.CIRCUIT_BREAKER_TIMEOUT,
      errorThresholdPercentage: CACHE_CONFIG.CIRCUIT_BREAKER_THRESHOLD,
      resetTimeout: 30000,
    });
    this._setupCircuitBreakerListeners();
    this._startMetricsCollection();
  }

  /**
   * Initialize Redis client
   */
  async _ensureRedis() {
    if (!this.redis) {
      try {
        this.redis = getRedisClient();
      } catch (error) {
        safeLogger.warn('Redis not ready yet, will retry', { error: error.message });
        throw error;
      }
    }
    return this.redis;
  }

  /**
   * Get Redis client safely
   */
  async _getRedis() {
    try {
      return await this._ensureRedis();
    } catch (error) {
      safeLogger.warn('Redis not available, operation will fail', { error: error.message });
      throw error;
    }
  }

  /**
   * Setup circuit breaker event listeners
   */
  _setupCircuitBreakerListeners() {
    this.circuitBreaker.on('open', () => {
      safeLogger.warn('Cache circuit breaker opened', { timestamp: Date.now() });
    });

    this.circuitBreaker.on('close', () => {
      safeLogger.info('Cache circuit breaker closed', { timestamp: Date.now() });
    });

    this.circuitBreaker.on('halfOpen', () => {
      safeLogger.info('Cache circuit breaker half-open', { timestamp: Date.now() });
    });
  }

  /**
   * Start metrics collection
   */
  _startMetricsCollection() {
    setInterval(() => {
      this._resetMetrics();
    }, 60000); // Reset every minute
  }

  /**
   * Reset metrics
   */
  _resetMetrics() {
    this.metrics = {
      hits: 0,
      misses: 0,
      errors: 0,
      operations: 0,
      lastReset: Date.now(),
    };
  }

  /**
   * Get cache metrics
   */
  getMetrics() {
    const hitRate = this.metrics.operations > 0 
      ? (this.metrics.hits / this.metrics.operations * 100).toFixed(2)
      : 0;
    
    return {
      ...this.metrics,
      hitRate: `${hitRate}%`,
      circuitBreakerState: this.circuitBreaker.opened ? 'open' : 'closed',
    };
  }

  /**
   * Wrapper for Redis operations with circuit breaker
   */
  async _redisOperation(operation, ...args) {
    try {
      const result = await operation(...args);
      this.metrics.operations++;
      return result;
    } catch (error) {
      this.metrics.errors++;
      throw error;
    }
  }

  /**
   * Set cache value with advanced features
   */
  async set(key, value, expiry = null) {
    try {
      const redis = await this._ensureRedis();
      const fullKey = this._getFullKey(key);
      let serializedValue = JSON.stringify(value);
      
      // Compress large values
      if (serializedValue.length > CACHE_CONFIG.COMPRESSION_THRESHOLD) {
        serializedValue = await this._compress(serializedValue);
      }
      
      const result = await this.circuitBreaker.fire(
        async () => {
          if (expiry) {
            return await redis.setex(fullKey, expiry, serializedValue);
          } else {
            return await redis.set(fullKey, serializedValue);
          }
        }
      );
      
      this.metrics.hits++;
      return result === 'OK';
    } catch (error) {
      this.metrics.errors++;
      safeLogger.error('Cache set error', { key, error: error.message });
      return false;
    }
  }

  /**
   * Get cache value with advanced features
   */
  async get(key) {
    try {
      const redis = await this._ensureRedis();
      const fullKey = this._getFullKey(key);
      
      const value = await this.circuitBreaker.fire(
        async () => await redis.get(fullKey)
      );
      
      if (!value) {
        this.metrics.misses++;
        return null;
      }
      
      this.metrics.hits++;
      
      // Decompress if needed
      let parsedValue;
      try {
        parsedValue = JSON.parse(value);
      } catch (parseError) {
        // Try to decompress if parsing fails
        parsedValue = await this._decompress(value);
      }
      
      return parsedValue;
    } catch (error) {
      this.metrics.errors++;
      safeLogger.error('Cache get error', { key, error: error.message });
      return null;
    }
  }

  /**
   * Delete cache value
   */
  async delete(key) {
    try {
      const redis = await this._getRedis();
      const fullKey = this._getFullKey(key);
      await redis.del(fullKey);
      return true;
    } catch (error) {
      safeLogger.error('Cache delete error', { key, error: error.message });
      return false;
    }
  }

  /**
   * Check if key exists
   */
  async exists(key) {
    try {
      const redis = await this._getRedis();
      const fullKey = this._getFullKey(key);
      return await redis.exists(fullKey);
    } catch (error) {
      safeLogger.error('Cache exists error', { key, error: error.message });
      return false;
    }
  }

  /**
   * Set expiry for key
   */
  async expire(key, seconds) {
    try {
      const redis = await this._getRedis();
      const fullKey = this._getFullKey(key);
      return await redis.expire(fullKey, seconds);
    } catch (error) {
      safeLogger.error('Cache expire error', { key, error: error.message });
      return false;
    }
  }

  /**
   * Get full key with prefix
   */
  _getFullKey(key) {
    return `${PREFIX[key] || ''}${key}`;
  }

  /**
   * Compress data using gzip
   */
  async _compress(data) {
    try {
      const { gzip } = await import('zlib');
      const { promisify } = await import('util');
      const gzipAsync = promisify(gzip);
      return await gzipAsync(data);
    } catch (error) {
      safeLogger.warn('Compression failed, using uncompressed data', { error: error.message });
      return data;
    }
  }

  /**
   * Decompress data using gunzip
   */
  async _decompress(data) {
    try {
      const { gunzip } = await import('zlib');
      const { promisify } = await import('util');
      const gunzipAsync = promisify(gunzip);
      const decompressed = await gunzipAsync(data);
      return JSON.parse(decompressed.toString());
    } catch (error) {
      safeLogger.warn('Decompression failed, trying direct parse', { error: error.message });
      return JSON.parse(data);
    }
  }

  /**
   * Acquire distributed lock
   */
  async acquireLock(lockKey, ttl = EXPIRY.DISTRIBUTED_LOCK) {
    try {
      const redis = await this._getRedis();
      const lockName = `${PREFIX.DISTRIBUTED_LOCK}${lockKey}`;
      const lockValue = Date.now().toString();
      
      const result = await redis.set(lockName, lockValue, 'PX', ttl * 1000, 'NX');
      
      if (result === 'OK') {
        return { acquired: true, lockValue, lockName };
      }
      
      return { acquired: false, lockValue: null, lockName };
    } catch (error) {
      safeLogger.error('Failed to acquire lock', { lockKey, error: error.message });
      return { acquired: false, lockValue: null, lockName: null };
    }
  }

  /**
   * Release distributed lock
   */
  async releaseLock(lockInfo) {
    try {
      if (!lockInfo.acquired || !lockInfo.lockName) {
        return false;
      }
      
      const redis = await this._getRedis();
      
      // Use Lua script for atomic release
      const luaScript = `
        if redis.call("get", KEYS[1]) == ARGV[1] then
          return redis.call("del", KEYS[1])
        else
          return 0
        end
      `;
      
      const result = await redis.eval(luaScript, 1, lockInfo.lockName, lockInfo.lockValue);
      return result === 1;
    } catch (error) {
      safeLogger.error('Failed to release lock', { lockInfo, error: error.message });
      return false;
    }
  }

  /**
   * Batch operations for performance
   */
  async batchSet(operations) {
    try {
      if (operations.length > CACHE_CONFIG.BATCH_SIZE) {
        throw new Error(`Batch size exceeds limit of ${CACHE_CONFIG.BATCH_SIZE}`);
      }
      
      const redis = await this._getRedis();
      const pipeline = redis.pipeline();
      
      operations.forEach(({ key, value, expiry }) => {
        const fullKey = this._getFullKey(key);
        let serializedValue = JSON.stringify(value);
        
        if (serializedValue.length > CACHE_CONFIG.COMPRESSION_THRESHOLD) {
          serializedValue = this._compress(serializedValue);
        }
        
        if (expiry) {
          pipeline.setex(fullKey, expiry, serializedValue);
        } else {
          pipeline.set(fullKey, serializedValue);
        }
      });
      
      const results = await pipeline.exec();
      this.metrics.operations += operations.length;
      
      return results.every(result => result[1] === 'OK');
    } catch (error) {
      this.metrics.errors++;
      safeLogger.error('Batch set error', { error: error.message, operationCount: operations.length });
      return false;
    }
  }

  /**
   * Cache warming for frequently accessed data
   */
  async warmCache(warmingData) {
    try {
      const warmingKey = `${PREFIX.CACHE_WARMING}${Date.now()}`;
      await this.set(warmingKey, { status: 'warming', data: warmingData }, EXPIRY.CACHE_WARMING);
      
      safeLogger.info('Cache warming initiated', { 
        warmingKey, 
        dataCount: Object.keys(warmingData).length 
      });
      
      return true;
    } catch (error) {
      safeLogger.error('Cache warming failed', { error: error.message });
      return false;
    }
  }

  /**
   * Get cache warming status
   */
  async getWarmingStatus() {
    try {
      const redis = await this._getRedis();
      const warmingKeys = await redis.keys(`${PREFIX.CACHE_WARMING}*`);
      const statuses = await Promise.all(
        warmingKeys.map(async (key) => {
          const data = await this.get(key.replace('warming:', ''));
          return { key, data };
        })
      );
      
      return statuses.filter(status => status.data);
    } catch (error) {
      safeLogger.error('Failed to get warming status', { error: error.message });
      return [];
    }
  }

  /**
   * Health check for cache system
   */
  async healthCheck() {
    try {
      const redis = await this._getRedis();
      const ping = await redis.ping();
      const info = await redis.info();
      
      return {
        status: 'healthy',
        ping: ping === 'PONG',
        info: info ? 'Redis info available' : 'Redis info unavailable',
        metrics: this.getMetrics(),
        circuitBreaker: this.circuitBreaker.opened ? 'open' : 'closed',
        timestamp: Date.now(),
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message,
        timestamp: Date.now(),
      };
    }
  }

  /**
   * Initialize cache system
   */
  async initialize() {
    try {
      // Initialize Redis connection
      await this._ensureRedis();
      safeLogger.info('Cache system initialized successfully');
      return true;
    } catch (error) {
      safeLogger.error('Failed to initialize cache system', { error: error.message });
      return false;
    }
  }

  /**
   * Shutdown cache system
   */
  async shutdown() {
    try {
      await this.close();
      safeLogger.info('Cache system shutdown successfully');
      return true;
    } catch (error) {
      safeLogger.error('Failed to shutdown cache system', { error: error.message });
      return false;
    }
  }

  // ✅ User session methods
  async setUserSession(userId, sessionData) {
    return this.set(`session:${userId}`, sessionData, EXPIRY.USER_SESSION);
  }

  async getUserSession(userId) {
    return this.get(`session:${userId}`);
  }

  async deleteUserSession(userId) {
    return this.delete(`session:${userId}`);
  }

  // ✅ Token blacklist methods
  async blacklistToken(token, userId) {
    return this.set(`blacklist:${token}`, { userId, blacklistedAt: Date.now() }, EXPIRY.BLACKLISTED_TOKEN);
  }

  async isTokenBlacklisted(token) {
    return await this.exists(`blacklist:${token}`);
  }

  // ✅ User profile methods
  async setUserProfile(userId, profileData) {
    return this.set(`profile:${userId}`, profileData, EXPIRY.USER_PROFILE);
  }

  async getUserProfile(userId) {
    return this.get(`profile:${userId}`);
  }

  // ✅ Additional user profile methods for backward compatibility
  async storeUserProfile(userId, profileData) {
    return this.setUserProfile(userId, profileData);
  }

  async removeUserProfile(userId) {
    return this.delete(`profile:${userId}`);
  }

  // ✅ Rate limiting methods
  async incrementRateLimit(key, window = EXPIRY.RATE_LIMIT) {
    try {
      const redis = await this._getRedis();
      const fullKey = `rate:${key}`;
      const current = await redis.incr(fullKey);
      
      if (current === 1) {
        await redis.expire(fullKey, window);
      }
      
      return current;
    } catch (error) {
      safeLogger.error('Rate limit increment error', { key, error: error.message });
      return 0;
    }
  }

  async getRateLimit(key) {
    try {
      const redis = await this._getRedis();
      const fullKey = `rate:${key}`;
      return await redis.get(fullKey) || 0;
    } catch (error) {
      safeLogger.error('Rate limit get error', { key, error: error.message });
      return 0;
    }
  }
}

// ✅ Create singleton instance
const authCache = new AuthCache();

// ✅ Export default
export default authCache;

// ✅ Export individual methods
export const {
  setUserSession,
  getUserSession,
  deleteUserSession,
  blacklistToken,
  isTokenBlacklisted,
  setUserProfile,
  getUserProfile,
  incrementRateLimit,
  getRateLimit,
  getMetrics,
  acquireLock,
  releaseLock,
  batchSet,
  warmCache,
  getWarmingStatus,
  healthCheck,
  initialize,
  shutdown,
} = authCache;

// ✅ Export cache management functions for backward compatibility
export const initializeCache = () => authCache.initialize();
export const shutdownCache = () => authCache.shutdown();

// ✅ Export the instance as named export for backward compatibility
export { authCache };
