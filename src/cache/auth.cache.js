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
  USER_PROFILE: 'user:profile:',
};

// ✅ Essential cache expiry times
const EXPIRY = {
  USER_SESSION: 24 * 60 * 60, // 24 hours
  BLACKLISTED_TOKEN: 7 * 24 * 60 * 60, // 7 days
  USER_PROFILE: 60 * 60, // 1 hour
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
      const key = `${PREFIX.USER_PROFILE}${userId}`;
      const serializedData = JSON.stringify(profileData);

      await redis.set(key, serializedData, 'EX', EXPIRY.USER_PROFILE);

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
      const key = `${PREFIX.USER_PROFILE}${userId}`;

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
      const key = `${PREFIX.USER_PROFILE}${userId}`;

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
