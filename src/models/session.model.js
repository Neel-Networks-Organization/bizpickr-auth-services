import { DataTypes, Model } from 'sequelize';
import { getDatabase } from '../db/index.js';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';

class Session extends Model {
  static async findActiveSessions(userId) {
    try {
      return await this.findAll({
        where: {
          userId,
          isActive: true,
          expiresAt: {
            [getDatabase().Op.gt]: new Date(),
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

  async updateActivity() {
    try {
      this.lastActivityAt = new Date();
      await this.save();
    } catch (error) {
      safeLogger.error('Failed to update activity', {
        sessionId: this.id,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

  async logout() {
    try {
      this.isActive = false;
      this.logoutAt = new Date();
      await this.save();
    } catch (error) {
      safeLogger.error('Failed to logout', {
        sessionId: this.id,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

  isExpired() {
    return new Date() > this.expiresAt;
  }

  toSafeJSON() {
    const safeData = this.toJSON();
    delete safeData.sessionToken;
    delete safeData.refreshToken;
    return safeData;
  }
}
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
  },
  {
    sequelize: getDatabase(),
    modelName: 'Session',
    tableName: 'sessions',
    timestamps: true,
    paranoid: true,
    indexes: [
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
        fields: ['created_at'],
        name: 'sessions_createdAt_idx',
      },
    ],
  }
);

export default Session;
