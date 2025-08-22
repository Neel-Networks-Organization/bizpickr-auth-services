import { DataTypes, Model, Op } from 'sequelize';
import sequelize from '../db/index.js';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';

class EmailVerification extends Model {
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

  isExpired() {
    return new Date() > this.expiresAt;
  }

  isMaxAttemptsReached() {
    return this.attempts >= this.maxAttempts;
  }

  async incrementAttempts() {
    try {
      this.attempts += 1;
      await this.save();
    } catch (error) {
      safeLogger.error('Failed to increment attempts', {
        verificationId: this.id,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

  toSafeJSON() {
    const safeData = this.toJSON();
    delete safeData.token;
    delete safeData.tokenHash;
    return safeData;
  }
}

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
  },
  {
    sequelize,
    modelName: 'EmailVerification',
    tableName: 'email_verifications',
    timestamps: true,
    paranoid: true,
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
  }
);

export default EmailVerification;
