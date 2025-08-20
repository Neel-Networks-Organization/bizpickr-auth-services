import { DataTypes, Op, Model } from 'sequelize';
import sequelize from '../db/index.js';
import bcrypt from 'bcryptjs';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
/**
 * Industry-level Authentication User Model
 *
 * Features:
 * - Advanced validation and constraints
 * - Security features and password management
 * - Performance optimizations and indexing
 * - Audit logging and tracking
 * - Comprehensive model methods
 * - Data sanitization and encryption
 * - Business logic encapsulation
 * - Error handling and logging
 * - Multi-role system for BizPickr platform
 */

/**
 * Enhanced AuthUser model with industry-level features
 */
class AuthUser extends Model {
  /**
   * Validate password strength using centralized validators
   * @param {string} password - Password to validate
   * @returns {Object} Validation result
   */
  static async validatePasswordStrength(password) {
    try {
      const { validatePassword } = await import('../utils/index.js');
      return await validatePassword(password);
    } catch (error) {
      safeLogger.error('Password validation error', {
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
      const { validateEmail } = await import('../utils/index.js');
      return await validateEmail(email);
    } catch (error) {
      safeLogger.error('Email validation error', {
        error: error.message,
        correlationId: getCorrelationId(),
      });
      return { isValid: false, errors: [error.message] };
    }
  }

  /**
   * Find user by email with case-insensitive search
   * @param {string} email - Email to search for
   * @returns {Promise<AuthUser|null>} User instance
   */
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
  /**
   * Find user by provider and provider ID
   * @param {string} provider - Authentication provider
   * @param {string} providerId - Provider ID
   * @returns {Promise<AuthUser|null>} User instance
   */
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
  /**
   * Find users by role
   * @param {string} role - Role to search for
   * @returns {Promise<Array>} Array of users
   */
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
  /**
   * Find users by type
   * @param {string} type - Type to search for
   * @returns {Promise<Array>} Array of users
   */
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
  /**
   * Create user with validation and security
   * @param {Object} userData - User data
   * @param {Object} options - Creation options
   * @returns {Promise<AuthUser>} Created user instance
   */
  static async createUser(userData, options = {}) {
    const correlationId = getCorrelationId();
    try {
      // Validate email
      const emailValidation = await this.validateEmail(userData.email);
      if (!emailValidation.isValid) {
        throw new Error(
          `Email validation failed: ${emailValidation.errors.join(', ')}`
        );
      }
      // Validate password if provided
      if (userData.password) {
        const passwordValidation = await this.validatePasswordStrength(
          userData.password
        );
        if (!passwordValidation.isValid) {
          throw new Error(
            `Password validation failed: ${passwordValidation.errors.join(', ')}`
          );
        }
      }

      // Check for existing user
      const existingUser = await this.findByEmail(userData.email);
      if (existingUser) {
        throw new Error('User with this email already exists');
      }
      // Create user
      const user = await this.create(userData, options);
      safeLogger.info('User created successfully', {
        userId: user.id,
        email: user.email,
        type: user.type,
        role: user.role,
        correlationId,
      });
      return user;
    } catch (error) {
      safeLogger.error('Failed to create user', {
        email: userData.email,
        error: error.message,
        correlationId,
      });
      throw error;
    }
  }

  /**
   * Update user with validation
   * @param {string} userId - User ID
   * @param {Object} updateData - Update data
   * @param {Object} options - Update options
   * @returns {Promise<AuthUser>} Updated user instance
   */
  static async updateUser(userId, updateData, options = {}) {
    const correlationId = getCorrelationId();
    try {
      // Validate email if being updated
      if (updateData.email) {
        const emailValidation = await this.validateEmail(updateData.email);
        if (!emailValidation.isValid) {
          throw new Error(
            `Email validation failed: ${emailValidation.errors.join(', ')}`
          );
        }
      }
      // Validate password if being updated
      if (updateData.password) {
        const passwordValidation = await this.validatePasswordStrength(
          updateData.password
        );
        if (!passwordValidation.isValid) {
          throw new Error(
            `Password validation failed: ${passwordValidation.errors.join(', ')}`
          );
        }
      }
      const user = await this.findByPk(userId);
      if (!user) {
        throw new Error('User not found');
      }
      await user.update(updateData, options);
      safeLogger.info('User updated successfully', {
        userId: user.id,
        email: user.email,
        updatedFields: Object.keys(updateData),
        correlationId,
      });
      return user;
    } catch (error) {
      safeLogger.error('Failed to update user', {
        userId,
        error: error.message,
        correlationId,
      });
      throw error;
    }
  }
  /**
   * Soft delete user
   * @param {string} userId - User ID
   * @param {Object} options - Delete options
   * @returns {Promise<boolean>} Success status
   */
  static async softDeleteUser(userId, options = {}) {
    const correlationId = getCorrelationId();
    try {
      const user = await this.findByPk(userId);
      if (!user) {
        throw new Error('User not found');
      }
      await user.destroy(options);
      safeLogger.info('User soft deleted successfully', {
        userId: user.id,
        email: user.email,
        correlationId,
      });
      return true;
    } catch (error) {
      safeLogger.error('Failed to soft delete user', {
        userId,
        error: error.message,
        correlationId,
      });
      throw error;
    }
  }
  /**
   * Get user statistics
   * @returns {Promise<Object>} User statistics
   */
  static async getUserStats() {
    try {
      const stats = await this.findAll({
        attributes: [
          'type',
          'role',
          'status',
          [sequelize.fn('COUNT', sequelize.col('id')), 'count'],
        ],
        group: ['type', 'role', 'status'],
        raw: true,
      });
      return stats.reduce((acc, stat) => {
        const key = `${stat.type}_${stat.role}_${stat.status}`;
        acc[key] = parseInt(stat.count);
        return acc;
      }, {});
    } catch (error) {
      safeLogger.error('Failed to get user stats', {
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }
  /**
   * Validate password against stored hash
   * @param {string} password - Plain text password
   * @returns {Promise<boolean>} Password validity
   */
  async isValidPassword(password) {
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
  /**
   * Hash password and update
   * @param {string} password - Plain text password
   * @returns {Promise<void>}
   */
  async hashPassword(password) {
    try {
      const saltRounds = 12;
      this.password = await bcrypt.hash(password, saltRounds);
      this.passwordChangedAt = new Date();
      await this.save();
    } catch (error) {
      safeLogger.error('Password hashing failed', {
        userId: this.id,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      throw error;
    }
  }

  /**
   * Update last activity
   * @returns {Promise<void>}
   */
  async updateLastActivity() {
    try {
      this.lastActiveAt = new Date();
      await this.save();
    } catch (error) {
      safeLogger.error('Failed to update last activity', {
        userId: this.id,
        error: error.message,
        correlationId: getCorrelationId(),
      });
    }
  }
  /**
   * Update last login
   * @returns {Promise<void>}
   */
  async updateLastLogin() {
    try {
      this.lastLoginAt = new Date();
      this.lastActiveAt = new Date();
      this.failedLoginAttempts = 0;
      this.lockedUntil = null;
      await this.save();
    } catch (error) {
      safeLogger.error('Failed to update last login', {
        userId: this.id,
        error: error.message,
        correlationId: getCorrelationId(),
      });
    }
  }
  /**
   * Increment failed login attempts
   * @returns {Promise<void>}
   */
  async incrementFailedLoginAttempts() {
    try {
      this.failedLoginAttempts += 1;
      // Lock account after 5 failed attempts
      if (this.failedLoginAttempts >= 5) {
        this.lockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
        this.status = 'suspended';
      }
      await this.save();
    } catch (error) {
      safeLogger.error('Failed to increment login attempts', {
        userId: this.id,
        error: error.message,
        correlationId: getCorrelationId(),
      });
    }
  }
  /**
   * Check if account is locked
   * @returns {boolean} Whether account is locked
   */
  isLocked() {
    if (!this.lockedUntil) return false;
    return new Date() < this.lockedUntil;
  }
  /**
   * Unlock account
   * @returns {Promise<void>}
   */
  async unlockAccount() {
    try {
      this.failedLoginAttempts = 0;
      this.lockedUntil = null;
      this.status = 'active';
      await this.save();
    } catch (error) {
      safeLogger.error('Failed to unlock account', {
        userId: this.id,
        error: error.message,
        correlationId: getCorrelationId(),
      });
    }
  }
}
// ✅ Model definition with updated role system - AUTHENTICATION ONLY
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
      comment: `User "type" defines broad category/classification of the user in the system,
 * such as 'customer', 'vendor', 'staff', or 'admin'.
 * 
 * User "role" defines the specific responsibilities or permission level within that type,
 * for example, within 'admin' type, roles like 'admin' (normal admin) and 'super_admin' (full system owner)
 * exist to differentiate access levels.
 * 
 * This separation allows scalable, flexible access control (RBAC),
 * where "type" groups users broadly,
 * and "role" provides fine-grained authorization inside each group.
 * 
 * Example:
 * - type: 'admin', role: 'super_admin'   // Ultimate system owner with full privileges
 * - type: 'admin', role: 'admin'         // Admin with limited privileges
 * - type: 'staff', role: 'requirement_coordinator' // Internal staff with specific duties
 * - type: 'customer', role: 'customer'  // End user of the system`,
    },
    role: {
      type: DataTypes.ENUM(
        'customer',
        'vendor',
        'requirement_coordinator',
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
              'requirement_coordinator',
              'hr_admin',
              'admin',
              'super_admin',
            ],
          ],
          msg: 'Role must be one of: customer, vendor, requirement_coordinator, hr_admin, admin, super_admin',
        },
      },
      comment: 'User role in the system',
    },
    permissions: {
      type: DataTypes.JSON,
      allowNull: true,
      defaultValue: [],
      comment: 'User permissions array',
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
    deviceInfo: {
      type: DataTypes.JSON,
      allowNull: true,
      comment: 'Device information for security tracking',
    },
    ipAddress: {
      type: DataTypes.STRING(45), // IPv6 support
      allowNull: true,
      validate: {
        isIP: {
          msg: 'Please provide a valid IP address',
        },
      },
      comment: 'Last known IP address',
    },
    lastActiveAt: {
      type: DataTypes.DATE,
      allowNull: true,
      comment: 'Last activity timestamp',
    },
    lastLoginAt: {
      type: DataTypes.DATE,
      allowNull: true,
      comment: 'Last login timestamp',
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
    refreshToken: {
      type: DataTypes.STRING(512),
      allowNull: true,
      unique: true,
      comment: 'Refresh token for authentication',
    },
    refreshTokenExpiresAt: {
      type: DataTypes.DATE,
      allowNull: true,
      comment: 'Refresh token expiration timestamp',
    },
    isActive: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
      comment: 'User account active status',
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
    passwordChangedAt: {
      type: DataTypes.DATE,
      allowNull: true,
      comment: 'Password last changed timestamp',
    },
    passwordResetToken: {
      type: DataTypes.STRING(255),
      allowNull: true,
      comment: 'Password reset token',
    },
    passwordResetExpiresAt: {
      type: DataTypes.DATE,
      allowNull: true,
      comment: 'Password reset token expiration',
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
    preferences: {
      type: DataTypes.JSON,
      allowNull: true,
      defaultValue: {},
      comment: 'User preferences and settings',
    },
    metadata: {
      type: DataTypes.JSON,
      allowNull: true,
      defaultValue: {},
      comment: 'Additional user metadata',
    },
  },
  {
    sequelize,
    modelName: 'AuthUser',
    tableName: 'auth_users',
    timestamps: true,
    paranoid: true, // Soft deletes
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
        fields: ['lastActiveAt'],
        name: 'auth_users_last_active_idx',
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
      afterCreate: async user => {
        safeLogger.info('User created', {
          userId: user.id,
          email: user.email,
          type: user.type,
          role: user.role,
          correlationId: getCorrelationId(),
        });
      },
      afterUpdate: async user => {
        safeLogger.info('User updated', {
          userId: user.id,
          email: user.email,
          changedFields: user.changed(),
          correlationId: getCorrelationId(),
        });
      },
      afterDestroy: async user => {
        safeLogger.info('User deleted', {
          userId: user.id,
          email: user.email,
          correlationId: getCorrelationId(),
        });
      },
    },
  }
);
export default AuthUser;
