import { DataTypes, Op, Model } from 'sequelize';
import { getDatabase } from '../db/index.js';
import bcrypt from 'bcryptjs';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';

class AuthUser extends Model {
  static async findByEmail(email) {
    try {
      return await this.findOne({
        where: {
          email: {
            [Op.iLike]: email.toLowerCase(),
          },
        },
      });
    } catch (error) {
      safeLogger.error('Failed to find user by email', {
        email,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

  static async findByProvider(provider, providerId) {
    try {
      return await this.findOne({
        where: {
          provider,
          providerId,
        },
      });
    } catch (error) {
      safeLogger.error('Failed to find user by provider', {
        provider,
        providerId,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

  static async findByRole(role) {
    try {
      return await this.findAll({
        where: { role },
        attributes: { exclude: ['password', 'refreshToken'] },
      });
    } catch (error) {
      safeLogger.error('Failed to find users by role', {
        role,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

  static async findByType(type) {
    try {
      return await this.findAll({
        where: { type },
        attributes: { exclude: ['password', 'refreshToken'] },
      });
    } catch (error) {
      safeLogger.error('Failed to find users by type', {
        type,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

  async isPasswordCorrect(password) {
    try {
      return await bcrypt.compare(password, this.password);
    } catch (error) {
      safeLogger.error('Password validation failed', {
        userId: this.id,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      return false;
    }
  }

  isLocked() {
    if (!this.lockedUntil) return false;
    return new Date() < this.lockedUntil;
  }

  isActive() {
    return this.status === 'active' && !this.isLocked();
  }
}

AuthUser.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
      allowNull: false,
      comment: 'Unique user identifier',
    },

    email: {
      type: DataTypes.STRING(255),
      allowNull: false,
      unique: true,
      validate: {
        isEmail: {
          msg: 'Please provide a valid email address',
        },
        notEmpty: {
          msg: 'Email cannot be empty',
        },
      },
      comment: "User's email address (unique)",
    },
    password: {
      type: DataTypes.STRING(255),
      allowNull: true,
      validate: {
        len: {
          args: [8, 255],
          msg: 'Password must be between 8 and 255 characters',
        },
      },
      comment: 'Hashed password (null for OAuth users)',
    },
    type: {
      type: DataTypes.ENUM('customer', 'vendor', 'staff', 'admin'),
      allowNull: false,
      validate: {
        isIn: {
          args: [['customer', 'vendor', 'staff', 'admin']],
          msg: 'Type must be one of: customer, vendor, staff, admin',
        },
      },
      comment: 'User type in the system',
    },
    role: {
      type: DataTypes.ENUM(
        'customer',
        'vendor',
        'manager',
        'hr_admin',
        'admin',
        'super_admin'
      ),
      allowNull: false,
      defaultValue: 'customer',
      validate: {
        isIn: {
          args: [
            [
              'customer',
              'vendor',
              'manager',
              'hr_admin',
              'admin',
              'super_admin',
            ],
          ],
          msg: 'Role must be one of: customer, vendor, manager, hr_admin, admin, super_admin',
        },
      },
      comment: 'User role in the system',
    },
    provider: {
      type: DataTypes.ENUM('manual', 'google', 'facebook', 'linkedin'),
      allowNull: true,
      defaultValue: 'manual',
      validate: {
        isIn: {
          args: [['manual', 'google', 'facebook', 'linkedin']],
          msg: 'Provider must be one of: manual, google, facebook, linkedin',
        },
      },
      comment: 'Authentication provider',
    },
    providerId: {
      type: DataTypes.STRING(255),
      allowNull: true,
      comment: 'Provider-specific user ID',
    },
    emailVerified: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
      comment: 'Email verification status',
    },
    emailVerifiedAt: {
      type: DataTypes.DATE,
      allowNull: true,
      comment: 'Email verification timestamp',
    },
    status: {
      type: DataTypes.ENUM('active', 'inactive', 'suspended', 'pending'),
      defaultValue: 'pending',
      validate: {
        isIn: {
          args: [['active', 'inactive', 'suspended', 'pending']],
          msg: 'Status must be one of: active, inactive, suspended, pending',
        },
      },
      comment: 'User account status',
    },
    failedLoginAttempts: {
      type: DataTypes.INTEGER,
      defaultValue: 0,
      validate: {
        min: 0,
        max: 10,
      },
      comment: 'Number of failed login attempts',
    },
    lockedUntil: {
      type: DataTypes.DATE,
      allowNull: true,
      comment: 'Account lock timestamp',
    },
    twoFactorEnabled: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
      comment: 'Two-factor authentication status',
    },
    twoFactorSecret: {
      type: DataTypes.STRING(255),
      allowNull: true,
      comment: 'Two-factor authentication secret',
    },
    suspendedAt: {
      type: DataTypes.DATE,
      allowNull: true,
      comment: 'Account suspension timestamp',
    },
    suspendedBy: {
      type: DataTypes.UUID,
      allowNull: true,
      comment: 'User ID who suspended the account',
    },
    suspensionReason: {
      type: DataTypes.TEXT,
      allowNull: true,
      comment: 'Reason for account suspension',
    },
    lastLoginAt: {
      type: DataTypes.DATE,
      allowNull: true,
      comment: 'Last login timestamp',
    },
    passwordChangedAt: {
      type: DataTypes.DATE,
      allowNull: true,
      comment: 'Password last changed timestamp',
    },
  },
  {
    sequelize: getDatabase(),
    modelName: 'AuthUser',
    tableName: 'auth_users',
    timestamps: true,
    paranoid: true,
    underscored: false,
    indexes: [
      {
        fields: ['email'],
        unique: true,
        name: 'auth_users_email_unique',
      },
      {
        fields: ['provider', 'providerId'],
        unique: true,
        where: {
          providerId: { [Op.ne]: null },
        },
        name: 'auth_users_provider_providerId_unique',
      },
      {
        fields: ['type'],
        name: 'auth_users_type_idx',
      },
      {
        fields: ['role'],
        name: 'auth_users_role_idx',
      },
      {
        fields: ['status'],
        name: 'auth_users_status_idx',
      },
      {
        fields: ['createdAt'],
        name: 'auth_users_created_at_idx',
      },
      {
        fields: ['suspendedAt'],
        name: 'auth_users_suspended_at_idx',
      },
      {
        fields: ['lastLoginAt'],
        name: 'auth_users_last_login_idx',
      },
    ],
    hooks: {
      beforeCreate: async user => {
        if (user.password) {
          const saltRounds = 12;
          user.password = await bcrypt.hash(user.password, saltRounds);
          user.passwordChangedAt = new Date();
        }
      },
      beforeUpdate: async user => {
        if (user.changed('password')) {
          const saltRounds = 12;
          user.password = await bcrypt.hash(user.password, saltRounds);
          user.passwordChangedAt = new Date();
        }
      },
    },
  }
);
export default AuthUser;
export { AuthUser };
