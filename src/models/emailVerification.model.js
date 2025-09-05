import { DataTypes, Model, Op } from 'sequelize';
import { getDatabase } from '../db/index.js';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';

const sequelize = getDatabase();

class EmailVerification extends Model {
  static async findByEmail(email) {
    try {
      return await this.findOne({
        where: { email },
        include: [
          {
            model: sequelize.models.AuthUser,
            as: 'user',
            attributes: ['id', 'email', 'type', 'role', 'emailVerified'],
          },
        ],
      });
    } catch (error) {
      safeLogger.error('Failed to find verification by email', {
        email,
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

  toSafeJSON() {
    const safeData = this.toJSON();
    delete safeData.otp;
    delete safeData.otpHash;
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
      allowNull: true,
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
      field: 'email',
      unique: true,
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
    otpHash: {
      type: DataTypes.STRING(255),
      allowNull: false,
      field: 'otp_hash',
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
    revokedUntil: {
      type: DataTypes.DATE,
      allowNull: true,
      field: 'revoked_until',
      comment: 'When the email was revoked',
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
      comment: 'Status of the verification',
    },
    attempts: {
      type: DataTypes.INTEGER,
      defaultValue: 0,
      validate: {
        min: 0,
        max: 10,
      },
      comment: 'Number of attempts to use this verification',
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
        name: 'idx_email_verification_email',
        fields: ['email'],
      },
      {
        name: 'idx_email_verification_otp_hash',
        fields: ['otp_hash'],
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
