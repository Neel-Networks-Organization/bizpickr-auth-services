import { getRedisClient } from '../db/redis.js';
import { safeLogger } from '../config/logger.js';

/**
 * Clean General Cache - Essential caching for other services
 * Focused on what's actually needed
 */

// ✅ Essential cache prefixes
const PREFIX = {
  GENERAL: 'cache:general:',
  JWK: 'cache:jwk:',
};

// ✅ Essential cache expiry times
const EXPIRY = {
  SHORT: 5 * 60, // 5 minutes
  MEDIUM: 30 * 60, // 30 minutes
  LONG: 2 * 60 * 60, // 2 hours
  EXTENDED: 24 * 60 * 60, // 24 hours
};

/**
 * Clean cache operations
 */
class GeneralCache {
  constructor() {
    this.redis = null;
  }

  /**
   * Initialize Redis client
   */
  async _ensureRedis() {
    if (!this.redis) {
      try {
        this.redis = getRedisClient();
      } catch (error) {
        safeLogger.warn('Redis not ready yet, will retry', {
          error: error.message,
        });
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
      safeLogger.warn('Redis not available, operation will fail', {
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Set cache value
   * @param {string} namespace - Cache namespace
   * @param {string} key - Cache key
   * @param {any} value - Value to cache
   * @param {Object} options - Cache options
   * @returns {Promise<boolean>} Success status
   */
  async set(namespace, key, value, options = {}) {
    try {
      const redis = await this._getRedis();
      const cacheKey = `${PREFIX[namespace] || PREFIX.GENERAL}${key}`;
      const serializedValue = JSON.stringify(value);
      const ttl = options.ttl || EXPIRY.MEDIUM;

      if (ttl > 0) {
        await redis.set(cacheKey, serializedValue, 'EX', ttl);
      } else {
        await redis.set(cacheKey, serializedValue);
      }

      safeLogger.debug('Cache value set', { namespace, key, ttl });
      return true;
    } catch (error) {
      safeLogger.error('Failed to set cache value', {
        error: error.message,
        namespace,
        key,
      });
      return false;
    }
  }

  /**
   * Get cache value
   * @param {string} namespace - Cache namespace
   * @param {string} key - Cache key
   * @returns {Promise<any|null>} Cached value or null
   */
  async get(namespace, key) {
    try {
      const redis = await this._getRedis();
      const cacheKey = `${PREFIX[namespace] || PREFIX.GENERAL}${key}`;

      const data = await redis.get(cacheKey);
      if (!data) {
        return null;
      }

      return JSON.parse(data);
    } catch (error) {
      safeLogger.error('Failed to get cache value', {
        error: error.message,
        namespace,
        key,
      });
      return null;
    }
  }

  /**
   * Delete cache value
   * @param {string} namespace - Cache namespace
   * @param {string} key - Cache key
   * @returns {Promise<boolean>} Success status
   */
  async delete(namespace, key) {
    try {
      const redis = await this._getRedis();
      const cacheKey = `${PREFIX[namespace] || PREFIX.GENERAL}${key}`;

      await redis.del(cacheKey);

      safeLogger.debug('Cache value deleted', { namespace, key });
      return true;
    } catch (error) {
      safeLogger.error('Failed to delete cache value', {
        error: error.message,
        namespace,
        key,
      });
      return false;
    }
  }

  /**
   * Check if key exists
   * @param {string} namespace - Cache namespace
   * @param {string} key - Cache key
   * @returns {Promise<boolean>} True if exists
   */
  async exists(namespace, key) {
    try {
      const redis = await this._getRedis();
      const cacheKey = `${PREFIX[namespace] || PREFIX.GENERAL}${key}`;

      const exists = await redis.exists(cacheKey);
      return exists === 1;
    } catch (error) {
      safeLogger.error('Failed to check cache key existence', {
        error: error.message,
        namespace,
        key,
      });
      return false;
    }
  }

  /**
   * Set expiry for key
   * @param {string} namespace - Cache namespace
   * @param {string} key - Cache key
   * @param {number} seconds - Expiry time in seconds
   * @returns {Promise<boolean>} Success status
   */
  async expire(namespace, key, seconds) {
    try {
      const redis = await this._getRedis();
      const cacheKey = `${PREFIX[namespace] || PREFIX.GENERAL}${key}`;

      const result = await redis.expire(cacheKey, seconds);
      return result === 1;
    } catch (error) {
      safeLogger.error('Failed to set cache expiry', {
        error: error.message,
        namespace,
        key,
        seconds,
      });
      return false;
    }
  }

  /**
   * Get TTL for key
   * @param {string} namespace - Cache namespace
   * @param {string} key - Cache key
   * @returns {Promise<number>} TTL in seconds (-1 if no expiry, -2 if key doesn't exist)
   */
  async ttl(namespace, key) {
    try {
      const redis = await this._getRedis();
      const cacheKey = `${PREFIX[namespace] || PREFIX.GENERAL}${key}`;

      return await redis.ttl(cacheKey);
    } catch (error) {
      safeLogger.error('Failed to get cache TTL', {
        error: error.message,
        namespace,
        key,
      });
      return -2;
    }
  }

  /**
   * Clear all keys in namespace
   * @param {string} namespace - Cache namespace
   * @returns {Promise<boolean>} Success status
   */
  async clearNamespace(namespace) {
    try {
      const redis = await this._getRedis();
      const pattern = `${PREFIX[namespace] || PREFIX.GENERAL}*`;

      const keys = await redis.keys(pattern);
      if (keys.length > 0) {
        await redis.del(keys);
      }

      safeLogger.debug('Cache namespace cleared', {
        namespace,
        keyCount: keys.length,
      });
      return true;
    } catch (error) {
      safeLogger.error('Failed to clear cache namespace', {
        error: error.message,
        namespace,
      });
      return false;
    }
  }

  /**
   * Initialize cache
   */
  async initialize() {
    try {
      await this._ensureRedis();
      safeLogger.info('General cache initialized successfully');
    } catch (error) {
      safeLogger.error('Failed to initialize general cache', {
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Shutdown cache
   */
  async shutdown() {
    try {
      if (this.redis) {
        await this.redis.quit();
        this.redis = null;
        safeLogger.info('General cache shutdown successfully');
      }
    } catch (error) {
      safeLogger.error('Failed to shutdown general cache', {
        error: error.message,
      });
    }
  }
}

// ✅ Export cache instance
const generalCache = new GeneralCache();

export default generalCache;
export { generalCache };
export const initializeGeneralCache = () => generalCache.initialize();
export const shutdownGeneralCache = () => generalCache.shutdown();
