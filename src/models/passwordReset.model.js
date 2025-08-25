import { DataTypes, Model, Op } from 'sequelize';
import sequelize from '../db/index.js';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';

class PasswordReset extends Model {
  static async findByOtp(otp) {
    try {
      return await this.findOne({
        where: { otp, status: 'pending' },
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
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

  static async findByOtpHash(otpHash) {
    try {
      return await this.findOne({
        where: { otpHash, status: 'pending' },
        include: [
          {
            model: sequelize.models.AuthUser,
            as: 'user',
            attributes: ['id', 'email', 'type', 'role'],
          },
        ],
      });
    } catch (error) {
      safeLogger.error('Failed to find password reset by otp hash', {
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

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

  isExpired() {
    return new Date() > this.expiresAt;
  }

  isMaxAttemptsReached() {
    return this.attempts >= this.maxAttempts;
  }

  isUsed() {
    return this.status === 'used';
  }

  async incrementAttempts() {
    this.attempts += 1;
    await this.save();
  }

  async markAsUsed() {
    try {
      this.status = 'used';
      this.usedAt = new Date();
      await this.save();
    } catch (error) {
      safeLogger.error('Failed to mark as used', {
        resetId: this.id,
        error: error.message,
      });
      throw error;
    }
  }

  toSafeJSON() {
    const safeData = this.toJSON();
    delete safeData.otp;
    delete safeData.otpHash;
    return safeData;
  }
}

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
    otpHash: {
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
    paranoid: true,
    indexes: [
      {
        name: 'idx_password_reset_user_id',
        fields: ['user_id'],
      },
      {
        name: 'idx_password_reset_otp_hash',
        fields: ['otp_hash'],
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
  }
);

export default PasswordReset;
