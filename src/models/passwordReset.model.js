import { DataTypes, Model, Op } from 'sequelize';
import sequelize from '../db/index.js';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import { ApiError } from '../utils/ApiError.js';

/**
 * Industry-level Password Reset Model
 *
 * Features:
 * - Comprehensive token management
 * - Security features and validation
 * - Performance optimizations
 * - Audit logging and tracking
 * - Token lifecycle management
 * - Rate limiting and attempt tracking
 * - IP tracking and security monitoring
 */

/**
 * Enhanced PasswordReset model with industry-level features
 */
class PasswordReset extends Model {
  /**
   * Find reset by token
   * @param {string} token - Reset token
   * @returns {Promise<PasswordReset|null>} Reset instance
   */
  static async findByToken(token) {
    try {
      return await this.findOne({
        where: { token },
        include: [
          {
            model: sequelize.models.AuthUser,
            as: 'user',
            attributes: ['id', 'email', 'type', 'role'],
          },
        ],
      });
    } catch (error) {
      safeLogger.error('Failed to find password reset by token', {
        token: token ? `${token.substring(0, 8)}...` : null,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

  /**
   * Find reset by token hash
   * @param {string} tokenHash - Hashed token
   * @returns {Promise<PasswordReset|null>} Reset instance
   */
  static async findByTokenHash(tokenHash) {
    try {
      return await this.findOne({
        where: { tokenHash },
        include: [
          {
            model: sequelize.models.AuthUser,
            as: 'user',
            attributes: ['id', 'email', 'type', 'role'],
          },
        ],
      });
    } catch (error) {
      safeLogger.error('Failed to find password reset by token hash', {
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

  /**
   * Find active resets for user
   * @param {string} userId - User ID
   * @returns {Promise<Array>} Active resets
   */
  static async findActiveResets(userId) {
    try {
      return await this.findAll({
        where: {
          userId,
          status: 'pending',
          expiresAt: {
            [Op.gt]: new Date(),
          },
        },
        order: [['createdAt', 'DESC']],
      });
    } catch (error) {
      safeLogger.error('Failed to find active password resets', {
        userId,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

  /**
   * Create password reset with validation
   * @param {Object} resetData - Reset data
   * @param {Object} options - Creation options
   * @returns {Promise<PasswordReset>} Created reset
   */
  static async createPasswordReset(resetData, options = {}) {
    const correlationId = getCorrelationId();
    try {
      // Validate required fields
      if (!resetData.userId) {
        throw new ApiError(400, 'User ID is required');
      }
      if (!resetData.token) {
        throw new ApiError(400, 'Token is required');
      }
      if (!resetData.tokenHash) {
        throw new ApiError(400, 'Token hash is required');
      }

      // Set default expiration if not provided
      if (!resetData.expiresAt) {
        resetData.expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
      }

      // Check for existing active reset
      const existingReset = await this.findOne({
        where: {
          userId: resetData.userId,
          status: 'pending',
          expiresAt: {
            [Op.gt]: new Date(),
          },
        },
      });

      if (existingReset) {
        safeLogger.warn('Active password reset already exists', {
          userId: resetData.userId,
          correlationId,
        });
        throw new ApiError(409, 'Active password reset already exists');
      }

      const reset = await this.create(resetData, options);

      safeLogger.info('Password reset created successfully', {
        resetId: reset.id,
        userId: reset.userId,
        expiresAt: reset.expiresAt,
        correlationId,
      });

      return reset;
    } catch (error) {
      safeLogger.error('Failed to create password reset', {
        userId: resetData.userId,
        error: error.message,
        correlationId,
      });
      throw error;
    }
  }

  /**
   * Mark reset as used
   * @param {string} resetId - Reset ID
   * @param {Object} options - Update options
   * @returns {Promise<PasswordReset>} Updated reset
   */
  static async markAsUsed(resetId, options = {}) {
    const correlationId = getCorrelationId();
    try {
      const reset = await this.findByPk(resetId);
      if (!reset) {
        throw new ApiError(404, 'Password reset not found');
      }

      if (reset.status !== 'pending') {
        throw new ApiError(400, 'Password reset is not in pending status');
      }

      if (reset.expiresAt < new Date()) {
        throw new ApiError(400, 'Password reset has expired');
      }

      await reset.update(
        {
          status: 'used',
          usedAt: new Date(),
        },
        options
      );

      safeLogger.info('Password reset marked as used', {
        resetId: reset.id,
        userId: reset.userId,
        correlationId,
      });

      return reset;
    } catch (error) {
      safeLogger.error('Failed to mark password reset as used', {
        resetId,
        error: error.message,
        correlationId,
      });
      throw error;
    }
  }

  /**
   * Revoke password reset
   * @param {string} resetId - Reset ID
   * @param {string} reason - Revocation reason
   * @param {Object} options - Update options
   * @returns {Promise<PasswordReset>} Updated reset
   */
  static async revokePasswordReset(
    resetId,
    reason = 'manual_revocation',
    options = {}
  ) {
    const correlationId = getCorrelationId();
    try {
      const reset = await this.findByPk(resetId);
      if (!reset) {
        throw new ApiError(404, 'Password reset not found');
      }

      await reset.update(
        {
          status: 'revoked',
        },
        options
      );

      safeLogger.info('Password reset revoked', {
        resetId: reset.id,
        userId: reset.userId,
        reason,
        correlationId,
      });

      return reset;
    } catch (error) {
      safeLogger.error('Failed to revoke password reset', {
        resetId,
        reason,
        error: error.message,
        correlationId,
      });
      throw error;
    }
  }

  /**
   * Clean up expired resets
   * @returns {Promise<number>} Number of cleaned resets
   */
  static async cleanupExpiredResets() {
    const correlationId = getCorrelationId();
    try {
      const result = await this.update(
        {
          status: 'expired',
        },
        {
          where: {
            status: 'pending',
            expiresAt: {
              [Op.lt]: new Date(),
            },
          },
        }
      );
      const cleanedCount = result[0];

      safeLogger.info('Expired password resets cleaned up', {
        cleanedCount,
        correlationId,
      });

      return cleanedCount;
    } catch (error) {
      safeLogger.error('Failed to cleanup expired password resets', {
        error: error.message,
        correlationId,
      });
      throw error;
    }
  }

  /**
   * Get reset statistics
   * @returns {Promise<Object>} Reset statistics
   */
  static async getResetStats() {
    try {
      const stats = await this.findAll({
        attributes: [
          'status',
          [sequelize.fn('COUNT', sequelize.col('id')), 'count'],
        ],
        group: ['status'],
        raw: true,
      });

      return stats.reduce((acc, stat) => {
        acc[stat.status] = parseInt(stat.count);
        return acc;
      }, {});
    } catch (error) {
      safeLogger.error('Failed to get password reset statistics', {
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

  /**
   * Validate reset token using centralized validators
   * @param {string} token - Token to validate
   * @returns {Object} Validation result
   */
  static async validateToken(token) {
    try {
      const { validatePasswordReset } = await import(
        '../validators/authValidators.js'
      );
      return await validatePasswordReset({ token });
    } catch (error) {
      safeLogger.error('Token validation error', {
        error: error.message,
        correlationId: getCorrelationId(),
      });
      return { isValid: false, errors: [error.message] };
    }
  }

  /**
   * Validate IP address format using centralized validators
   * @param {string} ipAddress - IP address to validate
   * @returns {Object} Validation result
   */
  static async validateIpAddress(ipAddress) {
    try {
      return await validateIpAddress(ipAddress);
    } catch (error) {
      safeLogger.error('IP address validation error', {
        error: error.message,
        correlationId: getCorrelationId(),
      });
      return { isValid: false, errors: [error.message] };
    }
  }
}

// Model definition
PasswordReset.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
      comment: 'Unique reset identifier',
    },
    userId: {
      type: DataTypes.UUID,
      allowNull: false,
      field: 'user_id',
      references: {
        model: 'auth_users',
        key: 'id',
      },
      comment: 'Associated user ID',
    },
    token: {
      type: DataTypes.STRING(255),
      allowNull: false,
      unique: true,
      validate: {
        len: {
          args: [32, 255],
          msg: 'Token must be between 32 and 255 characters',
        },
      },
      comment: 'Secure reset token',
    },
    tokenHash: {
      type: DataTypes.STRING(255),
      allowNull: false,
      field: 'token_hash',
      validate: {
        len: {
          args: [32, 255],
          msg: 'Token hash must be between 32 and 255 characters',
        },
      },
      comment: 'Hashed version of the token for security',
    },
    expiresAt: {
      type: DataTypes.DATE,
      allowNull: false,
      field: 'expires_at',
      validate: {
        isDate: {
          msg: 'Expiration date must be a valid date',
        },
        isAfterNow(value) {
          if (value <= new Date()) {
            throw new Error('Expiration date must be in the future');
          }
        },
      },
      comment: 'Token expiration time',
    },
    usedAt: {
      type: DataTypes.DATE,
      allowNull: true,
      field: 'used_at',
      comment: 'When the token was used',
    },
    ipAddress: {
      type: DataTypes.STRING(45),
      allowNull: true,
      field: 'ip_address',
      validate: {
        isIP: {
          msg: 'Please provide a valid IP address',
        },
      },
      comment: 'IP address where reset was requested',
    },
    userAgent: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'user_agent',
      comment: 'User agent of the request',
    },
    status: {
      type: DataTypes.ENUM('pending', 'used', 'expired', 'revoked'),
      defaultValue: 'pending',
      validate: {
        isIn: {
          args: [['pending', 'used', 'expired', 'revoked']],
          msg: 'Status must be one of: pending, used, expired, revoked',
        },
      },
      comment: 'Status of the reset token',
    },
    attempts: {
      type: DataTypes.INTEGER,
      defaultValue: 0,
      validate: {
        min: 0,
        max: 10,
      },
      comment: 'Number of attempts to use this token',
    },
    maxAttempts: {
      type: DataTypes.INTEGER,
      defaultValue: 3,
      field: 'max_attempts',
      validate: {
        min: 1,
        max: 10,
      },
      comment: 'Maximum allowed attempts',
    },
  },
  {
    sequelize,
    modelName: 'PasswordReset',
    tableName: 'password_resets',
    timestamps: true,
    paranoid: true, // Soft deletes
    indexes: [
      {
        name: 'idx_password_reset_user_id',
        fields: ['user_id'],
      },
      {
        name: 'idx_password_reset_token',
        fields: ['token'],
        unique: true,
      },
      {
        name: 'idx_password_reset_token_hash',
        fields: ['token_hash'],
      },
      {
        name: 'idx_password_reset_expires_at',
        fields: ['expires_at'],
      },
      {
        name: 'idx_password_reset_status',
        fields: ['status'],
      },
      {
        name: 'idx_password_reset_created_at',
        fields: ['created_at'],
      },
    ],
    hooks: {
      beforeCreate: async reset => {
        const correlationId = getCorrelationId();
        try {
          // Validate token format
          const tokenValidation = await PasswordReset.validateToken(
            reset.token
          );
          if (!tokenValidation.isValid) {
            throw new Error(
              `Token validation failed: ${tokenValidation.errors.join(', ')}`
            );
          }

          // Validate IP address if provided
          if (reset.ipAddress) {
            const ipValidation = await PasswordReset.validateIpAddress(
              reset.ipAddress
            );
            if (!ipValidation.isValid) {
              throw new Error(
                `IP address validation failed: ${ipValidation.errors.join(', ')}`
              );
            }
          }

          safeLogger.debug('Password reset creation hook executed', {
            userId: reset.userId,
            correlationId,
          });
        } catch (error) {
          safeLogger.error('Password reset creation hook failed', {
            userId: reset.userId,
            error: error.message,
            correlationId,
          });
          throw error;
        }
      },
      beforeUpdate: async reset => {
        const correlationId = getCorrelationId();
        try {
          // Validate IP address if being updated
          if (reset.changed('ipAddress') && reset.ipAddress) {
            const ipValidation = await PasswordReset.validateIpAddress(
              reset.ipAddress
            );
            if (!ipValidation.isValid) {
              throw new Error(
                `IP address validation failed: ${ipValidation.errors.join(', ')}`
              );
            }
          }

          safeLogger.debug('Password reset update hook executed', {
            resetId: reset.id,
            changedFields: reset.changed(),
            correlationId,
          });
        } catch (error) {
          safeLogger.error('Password reset update hook failed', {
            resetId: reset.id,
            error: error.message,
            correlationId,
          });
          throw error;
        }
      },
      afterCreate: async reset => {
        const correlationId = getCorrelationId();
        safeLogger.info('Password reset created', {
          resetId: reset.id,
          userId: reset.userId,
          expiresAt: reset.expiresAt,
          correlationId,
        });
      },
      afterUpdate: async reset => {
        const correlationId = getCorrelationId();
        safeLogger.info('Password reset updated', {
          resetId: reset.id,
          userId: reset.userId,
          changedFields: reset.changed(),
          correlationId,
        });
      },
      afterDestroy: async reset => {
        const correlationId = getCorrelationId();
        safeLogger.info('Password reset deleted', {
          resetId: reset.id,
          userId: reset.userId,
          correlationId,
        });
      },
    },
  }
);

// Instance methods
PasswordReset.prototype.isExpired = function () {
  return new Date() > this.expiresAt;
};

PasswordReset.prototype.isMaxAttemptsReached = function () {
  return this.attempts >= this.maxAttempts;
};

PasswordReset.prototype.incrementAttempts = async function () {
  try {
    this.attempts += 1;
    await this.save();

    safeLogger.debug('Password reset attempts incremented', {
      resetId: this.id,
      attempts: this.attempts,
      maxAttempts: this.maxAttempts,
      correlationId: getCorrelationId(),
    });
  } catch (error) {
    safeLogger.error('Failed to increment password reset attempts', {
      resetId: this.id,
      error: error.message,
      correlationId: getCorrelationId(),
    });
    throw error;
  }
};

PasswordReset.prototype.markAsUsed = async function () {
  try {
    this.status = 'used';
    this.usedAt = new Date();
    await this.save();

    safeLogger.info('Password reset marked as used', {
      resetId: this.id,
      userId: this.userId,
      correlationId: getCorrelationId(),
    });
  } catch (error) {
    safeLogger.error('Failed to mark password reset as used', {
      resetId: this.id,
      error: error.message,
      correlationId: getCorrelationId(),
    });
    throw error;
  }
};

PasswordReset.prototype.toSafeJSON = function () {
  const safeData = this.toJSON();
  // Remove sensitive fields
  delete safeData.token;
  delete safeData.tokenHash;
  return safeData;
};

export default PasswordReset;
