/**
 * Session Service - Session Management Layer
 *
 * Handles all session-related business logic:
 * - Session creation and management
 * - Session validation
 * - Session revocation
 * - Session analytics
 */
import { safeLogger } from '../config/logger.js';
import { publishEvent } from '../events/index.js';
import { authCache } from '../cache/auth.cache.js';
import { Session, AuditLog } from '../models/index.model.js';
import { Op } from 'sequelize';
import { getRedisClient } from '../db/redis.js';

class SessionService {
  constructor() {
    this.sessionTTL = 24 * 60 * 60; // 24 hours
    this.refreshTokenTTL = 7 * 24 * 60 * 60; // 7 days
  }

  /**
   * Get user sessions
   * @param {number} userId - User ID
   * @returns {Promise<Array>} User sessions
   */
  async getUserSessions(userId) {
    try {
      const sessions = await Session.findAll({
        where: { userId },
        order: [['createdAt', 'DESC']],
      });

      // Check which sessions are still active in cache
      const sessionsWithStatus = await Promise.all(
        sessions.map(async session => {
          const sessionData = await authCache.getUserSession(session.userId);
          const isActiveInCache =
            sessionData && sessionData.sessionId === session.sessionToken;
          return {
            id: session.id,
            sessionToken: session.sessionToken,
            deviceInfo: session.deviceInfo,
            ipAddress: session.ipAddress,
            createdAt: session.createdAt,
            expiresAt: session.expiresAt,
            isActive: new Date() < session.expiresAt && isActiveInCache,
          };
        })
      );

      safeLogger.info('User sessions retrieved', {
        userId,
        totalSessions: sessions.length,
        activeSessions: sessionsWithStatus.filter(s => s.isActive).length,
      });

      return sessionsWithStatus;
    } catch (error) {
      safeLogger.error('Failed to get user sessions', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Revoke user session
   * @param {string} sessionId - Session ID
   * @param {number} userId - User ID
   * @returns {Promise<boolean>} Revoke success
   */
  async revokeSession(sessionId, userId) {
    try {
      safeLogger.info('Attempting to revoke session', {
        sessionId,
        userId,
      });

      // Check if session exists before trying to delete
      const existingSession = await Session.findOne({
        where: { sessionToken: sessionId, userId },
      });

      safeLogger.info('Session lookup result', {
        sessionId,
        userId,
        sessionExists: !!existingSession,
        sessionDetails: existingSession
          ? {
              id: existingSession.id,
              sessionToken: existingSession.sessionToken,
              userId: existingSession.userId,
              isActive: existingSession.isActive,
              expiresAt: existingSession.expiresAt,
            }
          : null,
      });

      // Remove from cache using userId (not sessionId)
      await authCache.removeUserSession(userId);

      // Remove from database
      const deletedCount = await Session.destroy({
        where: { sessionToken: sessionId, userId },
      });

      safeLogger.info('Session deletion result', {
        sessionId,
        userId,
        deletedCount,
      });

      if (deletedCount === 0) {
        throw new Error('Session not found or already revoked');
      }

      // Publish session revoked event
      await publishEvent('session.revoked', {
        userId,
        sessionId,
        timestamp: new Date(),
      });

      // Create audit log
      await AuditLog.create({
        userId,
        action: 'SESSION_REVOKED',
        resourceType: 'SESSION',
        resourceId: sessionId,
        details: { sessionId },
      });

      safeLogger.info('Session revoked successfully', {
        userId,
        sessionId,
      });

      return true;
    } catch (error) {
      safeLogger.error('Failed to revoke session', {
        error: error.message,
        userId,
        sessionId,
      });
      throw error;
    }
  }

  /**
   * Revoke all user sessions
   * @param {number} userId - User ID
   * @returns {Promise<boolean>} Revoke success
   */
  async revokeAllSessions(userId) {
    try {
      // Get all sessions
      const sessions = await Session.findAll({
        where: { userId },
      });

      // Remove from cache
      await authCache.removeUserSession(userId);

      // Remove from database
      const deletedCount = await Session.destroy({
        where: { userId },
      });

      // Publish all sessions revoked event
      await publishEvent('session.all_revoked', {
        userId,
        sessionsRevoked: deletedCount,
        timestamp: new Date(),
      });

      // Create audit log
      await AuditLog.create({
        userId,
        action: 'ALL_SESSIONS_REVOKED',
        resourceType: 'USER',
        resourceId: userId,
        details: { sessionsRevoked: deletedCount },
      });

      safeLogger.info('All sessions revoked', {
        userId,
        sessionsRevoked: deletedCount,
      });

      return true;
    } catch (error) {
      safeLogger.error('Failed to revoke all sessions', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Validate session
   * @param {string} sessionId - Session ID
   * @returns {Promise<Object|null>} Session data or null
   */
  async validateSession(sessionId) {
    try {
      // Check cache first
      const sessionData = await authCache.getUserSession(sessionId);
      if (!sessionData) {
        return null;
      }

      // Check if session is expired
      if (new Date() > new Date(sessionData.expiresAt)) {
        // Remove expired session
        await authCache.removeUserSession(sessionId);
        return null;
      }

      return sessionData;
    } catch (error) {
      safeLogger.error('Failed to validate session', {
        error: error.message,
        sessionId,
      });
      return null;
    }
  }

  /**
   * Create session
   * @param {Object} sessionData - Session data
   * @returns {Promise<Object>} Created session
   */
  async createSession(sessionData) {
    try {
      const { userId, sessionId, deviceInfo, ipAddress, userAgent } =
        sessionData;

      safeLogger.info('Creating session', {
        userId,
        sessionId,
        deviceInfo: !!deviceInfo,
        ipAddress,
        userAgent: !!userAgent,
      });

      const expiresAt = new Date(Date.now() + this.sessionTTL * 1000);

      // Store in cache
      await authCache.storeUserSession(sessionId, {
        userId,
        sessionId,
        deviceInfo,
        ipAddress,
        userAgent,
        createdAt: new Date(),
        expiresAt,
      });

      safeLogger.info('Session stored in cache', {
        userId,
        sessionId,
      });

      // Store in database
      const session = await Session.create({
        userId,
        sessionToken: sessionId,
        deviceInfo,
        ipAddress,
        expiresAt,
      });

      safeLogger.info('Session created in database', {
        userId,
        sessionId,
        databaseSessionId: session.id,
        sessionToken: session.sessionToken,
      });

      return {
        sessionId,
        expiresAt,
        session,
      };
    } catch (error) {
      safeLogger.error('Failed to create session', {
        error: error.message,
        stack: error.stack,
        sessionData,
      });
      throw error;
    }
  }

  /**
   * Store refresh token
   * @param {string} refreshToken - Refresh token
   * @param {Object} tokenData - Token data
   * @returns {Promise<boolean>} Storage success
   */
  async storeRefreshToken(refreshToken, tokenData) {
    try {
      await getRedisClient().setex(
        `refresh:${refreshToken}`,
        this.refreshTokenTTL,
        JSON.stringify(tokenData)
      );

      safeLogger.debug('Refresh token stored', {
        userId: tokenData.userId,
        sessionId: tokenData.sessionId,
      });

      return true;
    } catch (error) {
      safeLogger.error('Failed to store refresh token', {
        error: error.message,
        userId: tokenData.userId,
      });
      throw error;
    }
  }

  /**
   * Get refresh token data
   * @param {string} refreshToken - Refresh token
   * @returns {Promise<Object|null>} Token data or null
   */
  async getRefreshTokenData(refreshToken) {
    try {
      const tokenData = await getRedisClient().get(`refresh:${refreshToken}`);
      if (!tokenData) {
        return null;
      }

      return JSON.parse(tokenData);
    } catch (error) {
      safeLogger.error('Failed to get refresh token data', {
        error: error.message,
      });
      return null;
    }
  }

  /**
   * Remove refresh token
   * @param {string} refreshToken - Refresh token
   * @returns {Promise<boolean>} Removal success
   */
  async removeRefreshToken(refreshToken) {
    try {
      await getRedisClient().del(`refresh:${refreshToken}`);
      return true;
    } catch (error) {
      safeLogger.error('Failed to remove refresh token', {
        error: error.message,
      });
      return false;
    }
  }

  /**
   * Get session statistics
   * @param {number} userId - User ID
   * @returns {Promise<Object>} Session statistics
   */
  async getSessionStats(userId) {
    try {
      const totalSessions = await Session.count({
        where: { userId },
      });

      const activeSessions = await Session.count({
        where: {
          userId,
          expiresAt: {
            [Op.gt]: new Date(),
          },
        },
      });

      const recentSessions = await Session.findAll({
        where: { userId },
        order: [['createdAt', 'DESC']],
        limit: 5,
      });

      safeLogger.info('Session statistics retrieved', {
        userId,
        totalSessions,
        activeSessions,
      });

      return {
        totalSessions,
        activeSessions,
        recentSessions,
      };
    } catch (error) {
      safeLogger.error('Failed to get session statistics', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Clean expired sessions
   * @returns {Promise<number>} Number of cleaned sessions
   */
  async cleanExpiredSessions() {
    try {
      const expiredSessions = await Session.findAll({
        where: {
          expiresAt: {
            [Op.lt]: new Date(),
          },
        },
      });

      let cleanedCount = 0;
      for (const session of expiredSessions) {
        try {
          // Remove from cache
          await authCache.removeUserSession(session.sessionToken);

          // Remove from database
          await session.destroy();
          cleanedCount++;
        } catch (error) {
          safeLogger.warn('Failed to clean expired session', {
            sessionId: session.sessionToken,
            error: error.message,
          });
        }
      }

      safeLogger.info('Expired sessions cleaned', {
        cleanedCount,
        totalExpired: expiredSessions.length,
      });

      return cleanedCount;
    } catch (error) {
      safeLogger.error('Failed to clean expired sessions', {
        error: error.message,
      });
      throw error;
    }
  }
}

export default new SessionService();
