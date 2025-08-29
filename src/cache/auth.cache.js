import { getRedisClient } from '../db/redis.js';
import { safeLogger } from '../config/logger.js';

/**
 * Clean Auth Cache - Essential caching for auth service
 * Focused on what's actually needed
 */

// ✅ Essential cache prefixes
const PREFIX = {
  USER_SESSION: 'user:session:',
  BLACKLISTED_TOKEN: 'blacklist:token:',
  USER_SESSION: 'user:session:',
  LOCKOUT: 'lockout:',
  RATE_LIMIT: 'rate_limit:',
};

// ✅ Essential cache expiry times
const EXPIRY = {
  USER_SESSION: 24 * 60 * 60, // 24 hours
  BLACKLISTED_TOKEN: 7 * 24 * 60 * 60, // 7 days
  USER_SESSION: 60 * 60, // 1 hour
  LOCKOUT: 30 * 60, // 30 minutes
  RATE_LIMIT: 60 * 60, // 1 hour
};

/**
 * Clean cache operations
 */
class AuthCache {
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
   * Store user session data
   * @param {string} userId - User ID
   * @param {Object} sessionData - Session data
   * @returns {Promise<boolean>} Success status
   */
  async storeUserSession(userId, sessionData) {
    try {
      const redis = await this._getRedis();
      const key = `${PREFIX.USER_SESSION}${userId}`;
      const serializedData = JSON.stringify(sessionData);

      await redis.set(key, serializedData, 'EX', EXPIRY.USER_SESSION);

      safeLogger.debug('User session stored in cache', { userId });
      return true;
    } catch (error) {
      safeLogger.error('Failed to store user session in cache', {
        error: error.message,
        userId,
      });
      return false;
    }
  }

  /**
   * Get user session data
   * @param {string} userId - User ID
   * @returns {Promise<Object|null>} Session data or null
   */
  async getUserSession(userId) {
    try {
      const redis = await this._getRedis();
      const key = `${PREFIX.USER_SESSION}${userId}`;

      const data = await redis.get(key);
      if (!data) {
        return null;
      }

      return JSON.parse(data);
    } catch (error) {
      safeLogger.error('Failed to get user session from cache', {
        error: error.message,
        userId,
      });
      return null;
    }
  }

  /**
   * Remove user session data
   * @param {string} userId - User ID
   * @returns {Promise<boolean>} Success status
   */
  async removeUserSession(userId) {
    try {
      const redis = await this._getRedis();
      const key = `${PREFIX.USER_SESSION}${userId}`;

      await redis.del(key);

      safeLogger.debug('User session removed from cache', { userId });
      return true;
    } catch (error) {
      safeLogger.error('Failed to remove user session from cache', {
        error: error.message,
        userId,
      });
      return false;
    }
  }

  /**
   * Blacklist a token
   * @param {string} token - Token to blacklist
   * @param {Object} metadata - Token metadata
   * @returns {Promise<boolean>} Success status
   */
  async blacklistToken(token, metadata = {}) {
    try {
      const redis = await this._getRedis();
      const key = `${PREFIX.BLACKLISTED_TOKEN}${token}`;
      const data = JSON.stringify({
        ...metadata,
        blacklistedAt: new Date().toISOString(),
      });

      await redis.set(key, data, 'EX', EXPIRY.BLACKLISTED_TOKEN);

      safeLogger.debug('Token blacklisted', { token });
      return true;
    } catch (error) {
      safeLogger.error('Failed to blacklist token', {
        error: error.message,
        token,
      });
      return false;
    }
  }

  /**
   * Check if token is blacklisted
   * @param {string} token - Token to check
   * @returns {Promise<boolean>} True if blacklisted
   */
  async isTokenBlacklisted(token) {
    try {
      const redis = await this._getRedis();
      const key = `${PREFIX.BLACKLISTED_TOKEN}${token}`;

      const exists = await redis.exists(key);
      return exists === 1;
    } catch (error) {
      safeLogger.error('Failed to check token blacklist status', {
        error: error.message,
        token,
      });
      return false;
    }
  }

  /**
   * Store user profile data
   * @param {string} userId - User ID
   * @param {Object} profileData - Profile data
   * @returns {Promise<boolean>} Success status
   */
  async storeUserProfile(userId, profileData) {
    try {
      const redis = await this._getRedis();
      const key = `${PREFIX.USER_SESSION}${userId}`;
      const serializedData = JSON.stringify(profileData);

      await redis.set(key, serializedData, 'EX', EXPIRY.USER_SESSION);

      safeLogger.debug('User profile stored in cache', { userId });
      return true;
    } catch (error) {
      safeLogger.error('Failed to store user profile in cache', {
        error: error.message,
        userId,
      });
      return false;
    }
  }

  /**
   * Get user profile data
   * @param {string} userId - User ID
   * @returns {Promise<Object|null>} Profile data or null
   */
  async getUserProfile(userId) {
    try {
      const redis = await this._getRedis();
      const key = `${PREFIX.USER_SESSION}${userId}`;

      const data = await redis.get(key);
      if (!data) {
        return null;
      }

      return JSON.parse(data);
    } catch (error) {
      safeLogger.error('Failed to get user profile from cache', {
        error: error.message,
        userId,
      });
      return null;
    }
  }

  /**
   * Remove user profile data
   * @param {string} userId - User ID
   * @returns {Promise<boolean>} Success status
   */
  async removeUserProfile(userId) {
    try {
      const redis = await this._getRedis();
      const key = `${PREFIX.USER_SESSION}${userId}`;

      await redis.del(key);

      safeLogger.debug('User profile removed from cache', { userId });
      return true;
    } catch (error) {
      safeLogger.error('Failed to remove user profile from cache', {
        error: error.message,
        userId,
      });
      return false;
    }
  }

  /**
   * Generic get method for any key
   * @param {string} key - Cache key
   * @returns {Promise<any>} Cached data or null
   */
  async get(key) {
    try {
      const redis = await this._getRedis();
      const data = await redis.get(key);

      if (!data) {
        return null;
      }

      return JSON.parse(data);
    } catch (error) {
      safeLogger.error('Failed to get data from cache', {
        error: error.message,
        key,
      });
      return null;
    }
  }

  /**
   * Generic set method for any key with expiry
   * @param {string} key - Cache key
   * @param {any} value - Data to cache
   * @param {number} expiry - Expiry time in seconds
   * @returns {Promise<boolean>} Success status
   */
  async set(key, value, expiry = null) {
    try {
      const redis = await this._getRedis();
      const serializedData = JSON.stringify(value);

      if (expiry) {
        await redis.set(key, serializedData, 'EX', expiry);
      } else {
        await redis.set(key, serializedData);
      }

      safeLogger.debug('Data stored in cache', { key, expiry });
      return true;
    } catch (error) {
      safeLogger.error('Failed to store data in cache', {
        error: error.message,
        key,
        expiry,
      });
      return false;
    }
  }

  /**
   * Generic delete method for any key
   * @param {string} key - Cache key
   * @returns {Promise<boolean>} Success status
   */
  async delete(key) {
    try {
      const redis = await this._getRedis();
      await redis.del(key);

      safeLogger.debug('Data deleted from cache', { key });
      return true;
    } catch (error) {
      safeLogger.error('Failed to delete data from cache', {
        error: error.message,
        key,
      });
      return false;
    }
  }

  /**
   * Store lockout data for failed login attempts
   * @param {string} email - User email
   * @param {Object} lockoutData - Lockout data
   * @returns {Promise<boolean>} Success status
   */
  async storeLockout(email, lockoutData) {
    try {
      const redis = await this._getRedis();
      const key = `${PREFIX.LOCKOUT}${email}`;
      const serializedData = JSON.stringify(lockoutData);

      await redis.set(key, serializedData, 'EX', EXPIRY.LOCKOUT);

      safeLogger.debug('Lockout data stored in cache', { email });
      return true;
    } catch (error) {
      safeLogger.error('Failed to store lockout data in cache', {
        error: error.message,
        email,
      });
      return false;
    }
  }

  /**
   * Get lockout data for user
   * @param {string} email - User email
   * @returns {Promise<Object|null>} Lockout data or null
   */
  async getLockout(email) {
    try {
      const redis = await this._getRedis();
      const key = `${PREFIX.LOCKOUT}${email}`;

      const data = await redis.get(key);
      if (!data) {
        return null;
      }

      return JSON.parse(data);
    } catch (error) {
      safeLogger.error('Failed to get lockout data from cache', {
        error: error.message,
        email,
      });
      return null;
    }
  }

  /**
   * Remove lockout data for user
   * @param {string} email - User email
   * @returns {Promise<boolean>} Success status
   */
  async removeLockout(email) {
    try {
      const redis = await this._getRedis();
      const key = `${PREFIX.LOCKOUT}${email}`;

      await redis.del(key);

      safeLogger.debug('Lockout data removed from cache', { email });
      return true;
    } catch (error) {
      safeLogger.error('Failed to remove lockout data from cache', {
        error: error.message,
        email,
      });
      return false;
    }
  }

  /**
   * Store rate limit data
   * @param {string} key - Rate limit key (IP, email, etc.)
   * @param {Object} rateLimitData - Rate limit data
   * @returns {Promise<boolean>} Success status
   */
  async storeRateLimit(key, rateLimitData) {
    try {
      const redis = await this._getRedis();
      const cacheKey = `${PREFIX.RATE_LIMIT}${key}`;
      const serializedData = JSON.stringify(rateLimitData);

      await redis.set(cacheKey, serializedData, 'EX', EXPIRY.RATE_LIMIT);

      safeLogger.debug('Rate limit data stored in cache', { key });
      return true;
    } catch (error) {
      safeLogger.error('Failed to store rate limit data in cache', {
        error: error.message,
        key,
      });
      return false;
    }
  }

  /**
   * Get rate limit data
   * @param {string} key - Rate limit key
   * @returns {Promise<Object|null>} Rate limit data or null
   */
  async getRateLimit(key) {
    try {
      const redis = await this._getRedis();
      const cacheKey = `${PREFIX.RATE_LIMIT}${key}`;

      const data = await redis.get(cacheKey);
      if (!data) {
        return null;
      }

      return JSON.parse(data);
    } catch (error) {
      safeLogger.error('Failed to get rate limit data from cache', {
        error: error.message,
        key,
      });
      return null;
    }
  }

  /**
   * Clear all cache data for a user
   * @param {string} userId - User ID
   * @param {string} email - User email
   * @returns {Promise<boolean>} Success status
   */
  async clearUserCache(userId, email) {
    try {
      const redis = await this._getRedis();
      const keys = [
        `${PREFIX.USER_SESSION}${userId}`,
        `${PREFIX.USER_SESSION}${userId}`,
        `${PREFIX.LOCKOUT}${email}`,
      ];

      // Delete all keys in parallel
      await Promise.all(keys.map(key => redis.del(key)));

      safeLogger.debug('User cache cleared', { userId, email });
      return true;
    } catch (error) {
      safeLogger.error('Failed to clear user cache', {
        error: error.message,
        userId,
        email,
      });
      return false;
    }
  }

  /**
   * Get cache statistics
   * @returns {Promise<Object>} Cache statistics
   */
  async getStats() {
    try {
      const redis = await this._getRedis();
      const info = await redis.info('memory');

      // Parse Redis info for basic stats
      const stats = {
        connected: true,
        memory: info,
        timestamp: new Date().toISOString(),
      };

      return stats;
    } catch (error) {
      safeLogger.error('Failed to get cache stats', {
        error: error.message,
      });
      return {
        connected: false,
        error: error.message,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Initialize cache
   */
  async initialize() {
    try {
      await this._ensureRedis();
      safeLogger.info('Auth cache initialized successfully');
    } catch (error) {
      safeLogger.error('Failed to initialize auth cache', {
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
        safeLogger.info('Auth cache shutdown successfully');
      }
    } catch (error) {
      safeLogger.error('Failed to shutdown auth cache', {
        error: error.message,
      });
    }
  }
}

// ✅ Export cache instance
const authCache = new AuthCache();

export default authCache;
export { authCache };
export const initializeCache = () => authCache.initialize();
export const shutdownCache = () => authCache.shutdown();
