import { DataTypes, Model } from 'sequelize';
import sequelize from '../db/index.js';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
/**
 * Industry-level Session Model
 *
 * Features:
 * - Comprehensive session tracking
 * - Security features and validation
 * - Performance optimizations
 * - Audit logging and monitoring
 * - Session lifecycle management
 * - Device and location tracking
 * - Security event logging
 */
/**
 * Enhanced Session model with industry-level features
 */
class Session extends Model {
  /**
   * Find active sessions for user
   * @param {number} userId - User ID
   * @returns {Promise<Array>} Active sessions
   */
  static async findActiveSessions(userId) {
    try {
      return await this.findAll({
        where: {
          userId,
          isActive: true,
          expiresAt: {
            [sequelize.Op.gt]: new Date(),
          },
        },
        order: [['createdAt', 'DESC']],
      });
    } catch (error) {
      safeLogger.error('Failed to find active sessions', {
        userId,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }
  /**
   * Create session with validation
   * @param {Object} sessionData - Session data
   * @param {Object} options - Creation options
   * @returns {Promise<Session>} Created session
   */
  static async createSession(sessionData, options = {}) {
    const correlationId = getCorrelationId();
    try {
      // Set default expiration if not provided
      if (!sessionData.expiresAt) {
        sessionData.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
      }
      const session = await this.create(sessionData, options);
      safeLogger.info('Session created successfully', {
        sessionId: session.id,
        userId: session.userId,
        expiresAt: session.expiresAt,
        correlationId,
      });
      return session;
    } catch (error) {
      safeLogger.error('Failed to create session', {
        userId: sessionData.userId,
        error: error.message,
        correlationId,
      });
      throw error;
    }
  }
  /**
   * Invalidate session
   * @param {string} sessionId - Session ID
   * @param {Object} options - Invalidation options
   * @returns {Promise<boolean>} Success status
   */
  static async invalidateSession(sessionId, options = {}) {
    const correlationId = getCorrelationId();
    try {
      const session = await this.findByPk(sessionId);
      if (!session) {
        throw new Error('Session not found');
      }
      await session.update({
        isActive: false,
        invalidatedAt: new Date(),
        invalidationReason: options.reason || 'manual_invalidation',
      });
      safeLogger.info('Session invalidated successfully', {
        sessionId: session.id,
        userId: session.userId,
        reason: options.reason,
        correlationId,
      });
      return true;
    } catch (error) {
      safeLogger.error('Failed to invalidate session', {
        sessionId,
        error: error.message,
        correlationId,
      });
      throw error;
    }
  }
  /**
   * Clean up expired sessions
   * @returns {Promise<number>} Number of cleaned sessions
   */
  static async cleanupExpiredSessions() {
    const correlationId = getCorrelationId();
    try {
      const result = await this.update(
        {
          isActive: false,
          invalidatedAt: new Date(),
          invalidationReason: 'expired',
        },
        {
          where: {
            isActive: true,
            expiresAt: {
              [sequelize.Op.lt]: new Date(),
            },
          },
        }
      );
      const cleanedCount = result[0];
      safeLogger.info('Expired sessions cleaned up', {
        cleanedCount,
        correlationId,
      });
      return cleanedCount;
    } catch (error) {
      safeLogger.error('Failed to cleanup expired sessions', {
        error: error.message,
        correlationId,
      });
      throw error;
    }
  }
  /**
   * Get session statistics
   * @returns {Promise<Object>} Session statistics
   */
  static async getSessionStats() {
    try {
      const stats = await this.findAll({
        attributes: [
          [sequelize.fn('COUNT', sequelize.col('id')), 'totalSessions'],
          [
            sequelize.fn(
              'COUNT',
              sequelize.literal('CASE WHEN isActive = true THEN 1 END')
            ),
            'activeSessions',
          ],
          [
            sequelize.fn(
              'COUNT',
              sequelize.literal('CASE WHEN isActive = false THEN 1 END')
            ),
            'inactiveSessions',
          ],
          [
            sequelize.fn(
              'COUNT',
              sequelize.literal('CASE WHEN expiresAt < NOW() THEN 1 END')
            ),
            'expiredSessions',
          ],
        ],
        raw: true,
      });
      return stats[0] || {};
    } catch (error) {
      safeLogger.error('Failed to get session statistics', {
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }
}
// Model definition
Session.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
      comment: 'Unique session identifier',
    },
    userId: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: 'auth_users',
        key: 'id',
      },
      comment: 'Associated user ID',
    },
    sessionToken: {
      type: DataTypes.STRING(512),
      allowNull: false,
      unique: true,
      field: 'session_token',
      comment: 'Session token for authentication',
    },
    refreshToken: {
      type: DataTypes.STRING(512),
      allowNull: true,
      unique: true,
      field: 'refresh_token',
      comment: 'Refresh token for session renewal',
    },
    isActive: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
      comment: 'Session active status',
    },
    expiresAt: {
      type: DataTypes.DATE,
      allowNull: false,
      comment: 'Session expiration timestamp',
    },
    invalidatedAt: {
      type: DataTypes.DATE,
      allowNull: true,
      comment: 'Session invalidation timestamp',
    },
    invalidationReason: {
      type: DataTypes.STRING(100),
      allowNull: true,
      comment: 'Reason for session invalidation',
    },
    userAgent: {
      type: DataTypes.TEXT,
      allowNull: true,
      comment: 'User agent string',
    },
    ipAddress: {
      type: DataTypes.STRING(45), // IPv6 support
      allowNull: true,
      validate: {
        isIP: {
          msg: 'Please provide a valid IP address',
        },
      },
      comment: 'IP address of session',
    },
    deviceInfo: {
      type: DataTypes.JSON,
      allowNull: true,
      comment: 'Device information',
    },
    locationInfo: {
      type: DataTypes.JSON,
      allowNull: true,
      comment: 'Geographic location information',
    },
    lastActivityAt: {
      type: DataTypes.DATE,
      allowNull: true,
      comment: 'Last activity timestamp',
    },
    loginAt: {
      type: DataTypes.DATE,
      allowNull: true,
      comment: 'Login timestamp',
    },
    logoutAt: {
      type: DataTypes.DATE,
      allowNull: true,
      comment: 'Logout timestamp',
    },
    securityEvents: {
      type: DataTypes.JSON,
      allowNull: true,
      defaultValue: [],
      comment: 'Security events for this session',
    },
    metadata: {
      type: DataTypes.JSON,
      allowNull: true,
      defaultValue: {},
      comment: 'Additional session metadata',
    },
  },
  {
    sequelize,
    modelName: 'Session',
    tableName: 'sessions',
    timestamps: true,
    paranoid: true, // Soft deletes
    indexes: [
      {
        fields: ['session_token'],
        unique: true,
        name: 'sessions_sessionToken_unique',
      },
      {
        fields: ['refresh_token'],
        unique: true,
        name: 'sessions_refreshToken_unique',
      },
      {
        fields: ['user_id'],
        name: 'sessions_userId_idx',
      },
      {
        fields: ['is_active'],
        name: 'sessions_isActive_idx',
      },
      {
        fields: ['expires_at'],
        name: 'sessions_expiresAt_idx',
      },
      {
        fields: ['last_activity_at'],
        name: 'sessions_lastActivityAt_idx',
      },
      {
        fields: ['created_at'],
        name: 'sessions_createdAt_idx',
      },
    ],
    hooks: {
      beforeCreate: async (session, options) => {
        const correlationId = getCorrelationId();
        try {
          // Set default values
          if (!session.loginAt) {
            session.loginAt = new Date();
          }
          if (!session.lastActivityAt) {
            session.lastActivityAt = new Date();
          }
          safeLogger.info('Session creation hook executed', {
            sessionId: session.id,
            userId: session.userId,
            correlationId,
          });
        } catch (error) {
          safeLogger.error('Session creation hook failed', {
            userId: session.userId,
            error: error.message,
            correlationId,
          });
          throw error;
        }
      },
      beforeUpdate: async (session, options) => {
        const correlationId = getCorrelationId();
        try {
          // Update last activity if session is being updated
          if (session.changed() && session.isActive) {
            session.lastActivityAt = new Date();
          }
          safeLogger.debug('Session update hook executed', {
            sessionId: session.id,
            changedFields: session.changed(),
            correlationId,
          });
        } catch (error) {
          safeLogger.error('Session update hook failed', {
            sessionId: session.id,
            error: error.message,
            correlationId,
          });
          throw error;
        }
      },
      afterCreate: async (session, options) => {
        const correlationId = getCorrelationId();
        safeLogger.info('Session created successfully', {
          sessionId: session.id,
          userId: session.userId,
          expiresAt: session.expiresAt,
          correlationId,
        });
      },
      afterUpdate: async (session, options) => {
        const correlationId = getCorrelationId();
        safeLogger.info('Session updated successfully', {
          sessionId: session.id,
          userId: session.userId,
          changedFields: session.changed(),
          correlationId,
        });
      },
      afterDestroy: async (session, options) => {
        const correlationId = getCorrelationId();
        safeLogger.info('Session deleted successfully', {
          sessionId: session.id,
          userId: session.userId,
          correlationId,
        });
      },
    },
  }
);
// Instance methods
Session.prototype.updateActivity = async function () {
  try {
    this.lastActivityAt = new Date();
    await this.save();
    safeLogger.debug('Session activity updated', {
      sessionId: this.id,
      lastActivityAt: this.lastActivityAt,
      correlationId: getCorrelationId(),
    });
  } catch (error) {
    safeLogger.error('Failed to update session activity', {
      sessionId: this.id,
      error: error.message,
      correlationId: getCorrelationId(),
    });
  }
};
Session.prototype.logout = async function (reason = 'user_logout') {
  try {
    this.isActive = false;
    this.logoutAt = new Date();
    this.invalidatedAt = new Date();
    this.invalidationReason = reason;
    await this.save();
    safeLogger.info('Session logged out', {
      sessionId: this.id,
      userId: this.userId,
      reason,
      correlationId: getCorrelationId(),
    });
  } catch (error) {
    safeLogger.error('Failed to logout session', {
      sessionId: this.id,
      error: error.message,
      correlationId: getCorrelationId(),
    });
    throw error;
  }
};
Session.prototype.addSecurityEvent = async function (event) {
  try {
    const events = this.securityEvents || [];
    events.push({
      ...event,
      timestamp: new Date().toISOString(),
    });
    this.securityEvents = events;
    await this.save();
    safeLogger.warn('Security event added to session', {
      sessionId: this.id,
      userId: this.userId,
      event: event.type,
      correlationId: getCorrelationId(),
    });
  } catch (error) {
    safeLogger.error('Failed to add security event', {
      sessionId: this.id,
      error: error.message,
      correlationId: getCorrelationId(),
    });
  }
};
Session.prototype.isExpired = function () {
  return new Date() > this.expiresAt;
};
Session.prototype.toSafeJSON = function () {
  const safeData = this.toJSON();
  // Remove sensitive fields
  delete safeData.sessionToken;
  delete safeData.refreshToken;
  return safeData;
};
export default Session;
