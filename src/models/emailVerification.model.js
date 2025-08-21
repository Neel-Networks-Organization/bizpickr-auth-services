import { DataTypes, Model, Op } from 'sequelize';
import sequelize from '../db/index.js';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import { ApiError } from '../utils/ApiError.js';

/**
 * Industry-level Email Verification Model
 *
 * Features:
 * - Comprehensive token management
 * - Security features and validation
 * - Performance optimizations
 * - Audit logging and tracking
 * - Token lifecycle management
 * - Rate limiting and attempt tracking
 * - Email provider integration
 */

/**
 * Enhanced EmailVerification model with industry-level features
 */
class EmailVerification extends Model {
  /**
   * Find verification by token
   * @param {string} token - Verification token
   * @returns {Promise<EmailVerification|null>} Verification instance
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
      safeLogger.error('Failed to find verification by token', {
        token: token ? `${token.substring(0, 8)}...` : null,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

  /**
   * Find verification by token hash
   * @param {string} tokenHash - Hashed token
   * @returns {Promise<EmailVerification|null>} Verification instance
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
      safeLogger.error('Failed to find verification by token hash', {
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

  /**
   * Find active verifications for user
   * @param {string} userId - User ID
   * @returns {Promise<Array>} Active verifications
   */
  static async findActiveVerifications(userId) {
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
      safeLogger.error('Failed to find active verifications', {
        userId,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

  /**
   * Create verification with validation
   * @param {Object} verificationData - Verification data
   * @param {Object} options - Creation options
   * @returns {Promise<EmailVerification>} Created verification
   */
  static async createVerification(verificationData, options = {}) {
    const correlationId = getCorrelationId();
    try {
      // Validate required fields
      if (!verificationData.userId) {
        throw new ApiError(400, 'User ID is required');
      }
      if (!verificationData.email) {
        throw new ApiError(400, 'Email is required');
      }
      if (!verificationData.token) {
        throw new ApiError(400, 'Token is required');
      }
      if (!verificationData.tokenHash) {
        throw new ApiError(400, 'Token hash is required');
      }

      // Set default expiration if not provided
      if (!verificationData.expiresAt) {
        verificationData.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
      }

      // Check for existing active verification
      const existingVerification = await this.findOne({
        where: {
          userId: verificationData.userId,
          email: verificationData.email,
          status: 'pending',
          expiresAt: {
            [Op.gt]: new Date(),
          },
        },
      });

      if (existingVerification) {
        safeLogger.warn('Active verification already exists', {
          userId: verificationData.userId,
          email: verificationData.email,
          correlationId,
        });
        throw new ApiError(409, 'Active verification already exists');
      }

      const verification = await this.create(verificationData, options);

      safeLogger.info('Email verification created successfully', {
        verificationId: verification.id,
        userId: verification.userId,
        email: verification.email,
        expiresAt: verification.expiresAt,
        correlationId,
      });

      return verification;
    } catch (error) {
      safeLogger.error('Failed to create email verification', {
        userId: verificationData.userId,
        email: verificationData.email,
        error: error.message,
        correlationId,
      });
      throw error;
    }
  }

  /**
   * Mark verification as verified
   * @param {string} verificationId - Verification ID
   * @param {Object} options - Update options
   * @returns {Promise<EmailVerification>} Updated verification
   */
  static async markAsVerified(verificationId, options = {}) {
    const correlationId = getCorrelationId();
    try {
      const verification = await this.findByPk(verificationId);
      if (!verification) {
        throw new ApiError(404, 'Verification not found');
      }

      if (verification.status !== 'pending') {
        throw new ApiError(400, 'Verification is not in pending status');
      }

      if (verification.expiresAt < new Date()) {
        throw new ApiError(400, 'Verification has expired');
      }

      await verification.update(
        {
          status: 'verified',
          verifiedAt: new Date(),
        },
        options,
      );

      safeLogger.info('Email verification marked as verified', {
        verificationId: verification.id,
        userId: verification.userId,
        email: verification.email,
        correlationId,
      });

      return verification;
    } catch (error) {
      safeLogger.error('Failed to mark verification as verified', {
        verificationId,
        error: error.message,
        correlationId,
      });
      throw error;
    }
  }

  /**
   * Revoke verification
   * @param {string} verificationId - Verification ID
   * @param {string} reason - Revocation reason
   * @param {Object} options - Update options
   * @returns {Promise<EmailVerification>} Updated verification
   */
  static async revokeVerification(
    verificationId,
    reason = 'manual_revocation',
    options = {},
  ) {
    const correlationId = getCorrelationId();
    try {
      const verification = await this.findByPk(verificationId);
      if (!verification) {
        throw new ApiError(404, 'Verification not found');
      }

      await verification.update(
        {
          status: 'revoked',
        },
        options,
      );

      safeLogger.info('Email verification revoked', {
        verificationId: verification.id,
        userId: verification.userId,
        email: verification.email,
        reason,
        correlationId,
      });

      return verification;
    } catch (error) {
      safeLogger.error('Failed to revoke verification', {
        verificationId,
        reason,
        error: error.message,
        correlationId,
      });
      throw error;
    }
  }

  /**
   * Clean up expired verifications
   * @returns {Promise<number>} Number of cleaned verifications
   */
  static async cleanupExpiredVerifications() {
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
        },
      );
      const cleanedCount = result[0];

      safeLogger.info('Expired verifications cleaned up', {
        cleanedCount,
        correlationId,
      });

      return cleanedCount;
    } catch (error) {
      safeLogger.error('Failed to cleanup expired verifications', {
        error: error.message,
        correlationId,
      });
      throw error;
    }
  }

  /**
   * Get verification statistics
   * @returns {Promise<Object>} Verification statistics
   */
  static async getVerificationStats() {
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
      safeLogger.error('Failed to get verification statistics', {
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

  /**
   * Validate verification token using centralized validators
   * @param {string} token - Token to validate
   * @returns {Object} Validation result
   */
  static async validateToken(token) {
    try {
      const { validateEmailVerification } = await import(
        '../validators/authValidators.js'
      );
      return await validateEmailVerification({ token });
    } catch (error) {
      safeLogger.error('Token validation error', {
        error: error.message,
        correlationId: getCorrelationId(),
      });
      return { isValid: false, errors: [error.message] };
    }
  }

  /**
   * Validate email format using centralized validators
   * @param {string} email - Email to validate
   * @returns {Object} Validation result
   */
  static async validateEmail(email) {
    try {
      // Basic email validation
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return { isValid: false, errors: ['Invalid email format'] };
      }
      return { isValid: true, errors: [] };
    } catch (error) {
      safeLogger.error('Email validation error', {
        error: error.message,
        correlationId: getCorrelationId(),
      });
      return { isValid: false, errors: [error.message] };
    }
  }
}

// Model definition
EmailVerification.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
      comment: 'Unique verification identifier',
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
    email: {
      type: DataTypes.STRING(255),
      allowNull: false,
      validate: {
        isEmail: {
          msg: 'Please provide a valid email address',
        },
        notEmpty: {
          msg: 'Email cannot be empty',
        },
      },
      comment: 'Email address to verify',
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
      comment: 'Secure verification token',
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
    verifiedAt: {
      type: DataTypes.DATE,
      allowNull: true,
      field: 'verified_at',
      comment: 'When the email was verified',
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
      comment: 'IP address where verification was requested',
    },
    userAgent: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'user_agent',
      comment: 'User agent of the request',
    },
    status: {
      type: DataTypes.ENUM('pending', 'verified', 'expired', 'revoked'),
      defaultValue: 'pending',
      validate: {
        isIn: {
          args: [['pending', 'verified', 'expired', 'revoked']],
          msg: 'Status must be one of: pending, verified, expired, revoked',
        },
      },
      comment: 'Status of the verification token',
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
      defaultValue: 5,
      field: 'max_attempts',
      validate: {
        min: 1,
        max: 10,
      },
      comment: 'Maximum allowed attempts',
    },
    sentAt: {
      type: DataTypes.DATE,
      allowNull: true,
      field: 'sent_at',
      comment: 'When the verification email was sent',
    },
    emailProvider: {
      type: DataTypes.STRING(50),
      allowNull: true,
      field: 'email_provider',
      comment: 'Email service provider used',
    },
    emailId: {
      type: DataTypes.STRING(255),
      allowNull: true,
      field: 'email_id',
      comment: 'Email provider\'s message ID',
    },
  },
  {
    sequelize,
    modelName: 'EmailVerification',
    tableName: 'email_verifications',
    timestamps: true,
    paranoid: true, // Soft deletes
    indexes: [
      {
        name: 'idx_email_verification_user_id',
        fields: ['user_id'],
      },
      {
        name: 'idx_email_verification_email',
        fields: ['email'],
      },
      {
        name: 'idx_email_verification_token',
        fields: ['token'],
        unique: true,
      },
      {
        name: 'idx_email_verification_token_hash',
        fields: ['token_hash'],
      },
      {
        name: 'idx_email_verification_expires_at',
        fields: ['expires_at'],
      },
      {
        name: 'idx_email_verification_status',
        fields: ['status'],
      },
      {
        name: 'idx_email_verification_created_at',
        fields: ['created_at'],
      },
    ],
    hooks: {
      beforeCreate: async verification => {
        const correlationId = getCorrelationId();
        try {
          // Validate token format
          const tokenValidation = await EmailVerification.validateToken(
            verification.token,
          );
          if (!tokenValidation.isValid) {
            throw new Error(
              `Token validation failed: ${tokenValidation.errors.join(', ')}`,
            );
          }

          // Validate email format
          const emailValidation = await EmailVerification.validateEmail(
            verification.email,
          );
          if (!emailValidation.isValid) {
            throw new Error(
              `Email validation failed: ${emailValidation.errors.join(', ')}`,
            );
          }

          safeLogger.debug('Email verification creation hook executed', {
            userId: verification.userId,
            email: verification.email,
            correlationId,
          });
        } catch (error) {
          safeLogger.error('Email verification creation hook failed', {
            userId: verification.userId,
            email: verification.email,
            error: error.message,
            correlationId,
          });
          throw error;
        }
      },
      beforeUpdate: async verification => {
        const correlationId = getCorrelationId();
        try {
          // Validate email if being updated
          if (verification.changed('email')) {
            const emailValidation = EmailVerification.validateEmail(
              verification.email,
            );
            if (!emailValidation.isValid) {
              throw new Error(
                `Email validation failed: ${emailValidation.errors.join(', ')}`,
              );
            }
          }

          safeLogger.debug('Email verification update hook executed', {
            verificationId: verification.id,
            changedFields: verification.changed(),
            correlationId,
          });
        } catch (error) {
          safeLogger.error('Email verification update hook failed', {
            verificationId: verification.id,
            error: error.message,
            correlationId,
          });
          throw error;
        }
      },
      afterCreate: async verification => {
        const correlationId = getCorrelationId();
        safeLogger.info('Email verification created', {
          verificationId: verification.id,
          userId: verification.userId,
          email: verification.email,
          expiresAt: verification.expiresAt,
          correlationId,
        });
      },
      afterUpdate: async verification => {
        const correlationId = getCorrelationId();
        safeLogger.info('Email verification updated', {
          verificationId: verification.id,
          userId: verification.userId,
          changedFields: verification.changed(),
          correlationId,
        });
      },
      afterDestroy: async verification => {
        const correlationId = getCorrelationId();
        safeLogger.info('Email verification deleted', {
          verificationId: verification.id,
          userId: verification.userId,
          email: verification.email,
          correlationId,
        });
      },
    },
  },
);

// Instance methods
EmailVerification.prototype.isExpired = function() {
  return new Date() > this.expiresAt;
};

EmailVerification.prototype.isMaxAttemptsReached = function() {
  return this.attempts >= this.maxAttempts;
};

EmailVerification.prototype.incrementAttempts = async function() {
  try {
    this.attempts += 1;
    await this.save();

    safeLogger.debug('Verification attempts incremented', {
      verificationId: this.id,
      attempts: this.attempts,
      maxAttempts: this.maxAttempts,
      correlationId: getCorrelationId(),
    });
  } catch (error) {
    safeLogger.error('Failed to increment verification attempts', {
      verificationId: this.id,
      error: error.message,
      correlationId: getCorrelationId(),
    });
    throw error;
  }
};

EmailVerification.prototype.markAsSent = async function(
  emailProvider,
  emailId,
) {
  try {
    this.sentAt = new Date();
    this.emailProvider = emailProvider;
    this.emailId = emailId;
    await this.save();

    safeLogger.info('Email verification marked as sent', {
      verificationId: this.id,
      emailProvider,
      emailId,
      correlationId: getCorrelationId(),
    });
  } catch (error) {
    safeLogger.error('Failed to mark verification as sent', {
      verificationId: this.id,
      error: error.message,
      correlationId: getCorrelationId(),
    });
    throw error;
  }
};

EmailVerification.prototype.toSafeJSON = function() {
  const safeData = this.toJSON();
  // Remove sensitive fields
  delete safeData.token;
  delete safeData.tokenHash;
  return safeData;
};

export default EmailVerification;
