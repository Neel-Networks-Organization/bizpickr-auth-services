/**
 * Cache Warming Service - Intelligent Cache Preloading
 *
 * Features:
 * - Predictive cache warming based on usage patterns
 * - User profile preloading
 * - JWK set caching
 * - Permission and role caching
 * - Session data preloading
 * - Rate limit data warming
 */
import { safeLogger } from '../config/logger.js';
import { authCache } from '../cache/auth.cache.js';
import { generalCache } from '../cache/general.cache.js';
import jwkService from './jwk.service.js';
import { metricsService } from './metrics.service.js';

class CacheWarmingService {
  constructor() {
    this.warmingStrategies = {
      userProfiles: this.warmUserProfiles.bind(this),
      jwkSets: this.warmJWKSets.bind(this),
      permissions: this.warmPermissions.bind(this),
      sessionData: this.warmSessionData.bind(this),
      rateLimitData: this.warmRateLimitData.bind(this),
    };

    this.warmingSchedule = {
      userProfiles: 300000, // 5 minutes
      jwkSets: 3600000, // 1 hour
      permissions: 1800000, // 30 minutes
      sessionData: 60000, // 1 minute
      rateLimitData: 30000, // 30 seconds
    };

    this.isWarming = new Map();
    this.lastWarmTime = new Map();
  }

  async warmUserProfiles() {
    if (this.isWarming.get('userProfiles')) {
      return;
    }

    this.isWarming.set('userProfiles', true);

    try {
      const startTime = Date.now();

      // Get frequently accessed users (this would come from analytics)
      const frequentUsers = await this.getFrequentUsers();

      let warmedCount = 0;
      for (const user of frequentUsers) {
        try {
          await authCache.storeUserProfile(user.id, {
            id: user.id,
            email: user.email,
            fullName: user.fullName,
            role: user.role,
            status: user.status,
            lastLogin: user.lastLogin,
            permissions: user.permissions,
          });
          warmedCount++;
        } catch (error) {
          safeLogger.error('Failed to warm user profile', {
            userId: user.id,
            error: error.message,
          });
        }
      }

      const duration = Date.now() - startTime;
      this.lastWarmTime.set('userProfiles', Date.now());

      safeLogger.info('User profiles cache warmed', {
        count: warmedCount,
        duration,
        totalUsers: frequentUsers.length,
      });

      metricsService.incrementMetric('cacheWarming', 1, {
        type: 'userProfiles',
      });
    } catch (error) {
      safeLogger.error('Failed to warm user profiles cache', {
        error: error.message,
      });
    } finally {
      this.isWarming.set('userProfiles', false);
    }
  }

  async warmJWKSets() {
    if (this.isWarming.get('jwkSets')) {
      return;
    }

    this.isWarming.set('jwkSets', true);

    try {
      const startTime = Date.now();

      // Use the imported jwkService instance
      const jwkSet = await jwkService.getJWKSet();

      await generalCache.set('jwk', 'set', jwkSet, {
        ttl: 3600,
        compress: true,
      });

      const duration = Date.now() - startTime;
      this.lastWarmTime.set('jwkSets', Date.now());

      safeLogger.info('JWK sets cache warmed', {
        duration,
        keyCount: jwkSet.keys?.length || 0,
      });

      metricsService.incrementMetric('cacheWarming', 1, { type: 'jwkSets' });
    } catch (error) {
      safeLogger.error('Failed to warm JWK sets cache', {
        error: error.message,
      });
    } finally {
      this.isWarming.set('jwkSets', false);
    }
  }

  async warmPermissions() {
    if (this.isWarming.get('permissions')) {
      return;
    }

    this.isWarming.set('permissions', true);

    try {
      const startTime = Date.now();

      // Import permission service for role-based permissions
      const { ROLE_PERMISSIONS } = await import('./permission.service.js');

      // Preload role-based permissions
      const rolePermissions = ROLE_PERMISSIONS;

      for (const [role, permissions] of Object.entries(rolePermissions)) {
        await generalCache.set('permissions', role, permissions, { ttl: 1800 });
      }

      const duration = Date.now() - startTime;
      this.lastWarmTime.set('permissions', Date.now());

      safeLogger.info('Permissions cache warmed', {
        duration,
        roles: Object.keys(rolePermissions),
      });

      metricsService.incrementMetric('cacheWarming', 1, {
        type: 'permissions',
      });
    } catch (error) {
      safeLogger.error('Failed to warm permissions cache', {
        error: error.message,
      });
    } finally {
      this.isWarming.set('permissions', false);
    }
  }

  async warmSessionData() {
    if (this.isWarming.get('sessionData')) {
      return;
    }

    this.isWarming.set('sessionData', true);

    try {
      const startTime = Date.now();

      // Preload active session metadata
      const activeSessions = await this.getActiveSessions();

      for (const session of activeSessions) {
        await authCache.setSessionMetadata(session.id, {
          userId: session.userId,
          lastActivity: session.lastActivity,
          deviceInfo: session.deviceInfo,
          ipAddress: session.ipAddress,
        });
      }

      const duration = Date.now() - startTime;
      this.lastWarmTime.set('sessionData', Date.now());

      safeLogger.info('Session data cache warmed', {
        duration,
        sessionCount: activeSessions.length,
      });

      metricsService.incrementMetric('cacheWarming', 1, {
        type: 'sessionData',
      });
    } catch (error) {
      safeLogger.error('Failed to warm session data cache', {
        error: error.message,
      });
    } finally {
      this.isWarming.set('sessionData', false);
    }
  }

  async warmRateLimitData() {
    if (this.isWarming.get('rateLimitData')) {
      return;
    }

    this.isWarming.set('rateLimitData', true);

    try {
      const startTime = Date.now();

      // Preload rate limit configurations
      const rateLimitConfigs = {
        login: { window: 900000, max: 5 }, // 5 attempts per 15 minutes
        register: { window: 3600000, max: 3 }, // 3 attempts per hour
        passwordReset: { window: 3600000, max: 3 }, // 3 attempts per hour
        api: { window: 60000, max: 100 }, // 100 requests per minute
      };

      for (const [endpoint, config] of Object.entries(rateLimitConfigs)) {
        await generalCache.set('rateLimit', endpoint, config, { ttl: 3600 });
      }

      const duration = Date.now() - startTime;
      this.lastWarmTime.set('rateLimitData', Date.now());

      safeLogger.info('Rate limit data cache warmed', {
        duration,
        endpoints: Object.keys(rateLimitConfigs),
      });

      metricsService.incrementMetric('cacheWarming', 1, {
        type: 'rateLimitData',
      });
    } catch (error) {
      safeLogger.error('Failed to warm rate limit data cache', {
        error: error.message,
      });
    } finally {
      this.isWarming.set('rateLimitData', false);
    }
  }

  async warmAllCaches() {
    safeLogger.info('Starting comprehensive cache warming');

    const promises = Object.entries(this.warmingStrategies).map(
      ([name, strategy]) =>
        strategy().catch(error => {
          safeLogger.error(`Failed to warm ${name} cache`, {
            error: error.message,
          });
          return null;
        })
    );

    const results = await Promise.allSettled(promises);

    const successCount = results.filter(
      result => result.status === 'fulfilled'
    ).length;
    const totalCount = results.length;

    safeLogger.info('Cache warming completed', {
      successCount,
      totalCount,
      successRate: (successCount / totalCount) * 100,
    });

    return {
      successCount,
      totalCount,
      successRate: (successCount / totalCount) * 100,
    };
  }

  async scheduleWarming() {
    // Schedule periodic warming
    setInterval(() => {
      this.checkAndWarmCaches();
    }, 60000); // Check every minute

    // Initial warming
    await this.warmAllCaches();
  }

  async checkAndWarmCaches() {
    const now = Date.now();

    for (const [cacheType, interval] of Object.entries(this.warmingSchedule)) {
      const lastWarm = this.lastWarmTime.get(cacheType) || 0;

      if (now - lastWarm >= interval) {
        const strategy = this.warmingStrategies[cacheType];
        if (strategy) {
          strategy().catch(error => {
            safeLogger.error(`Scheduled warming failed for ${cacheType}`, {
              error: error.message,
            });
          });
        }
      }
    }
  }

  async getFrequentUsers() {
    // This would integrate with analytics to get frequently accessed users
    // For now, return a mock list
    return [
      {
        id: '1',
        email: 'admin@example.com',
        fullName: 'Admin User',
        role: 'admin',
        status: 'active',
      },
      {
        id: '2',
        email: 'user@example.com',
        fullName: 'Regular User',
        role: 'user',
        status: 'active',
      },
    ];
  }

  async getActiveSessions() {
    // This would get active sessions from database
    // For now, return empty array
    return [];
  }

  getWarmingStatus() {
    const status = {};

    for (const [cacheType, isWarming] of this.isWarming.entries()) {
      status[cacheType] = {
        isWarming,
        lastWarmTime: this.lastWarmTime.get(cacheType),
        nextWarmTime:
          this.lastWarmTime.get(cacheType) + this.warmingSchedule[cacheType],
      };
    }

    return status;
  }

  async preloadUserData(userId) {
    try {
      // Preload specific user data on demand
      const userData = await this.getUserData(userId);

      if (userData) {
        await authCache.storeUserProfile(userId, userData);
        safeLogger.info('User data preloaded', { userId });
      }
    } catch (error) {
      safeLogger.error('Failed to preload user data', {
        userId,
        error: error.message,
      });
    }
  }

  async getUserData(userId) {
    // This would fetch user data from database
    // For now, return null
    return null;
  }
}

export const cacheWarmingService = new CacheWarmingService();
