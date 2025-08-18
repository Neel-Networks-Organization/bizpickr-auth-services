'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('auth_users', {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
      },
      email: {
        type: Sequelize.STRING(255),
        allowNull: false,
        unique: true,
        comment: 'User email address',
      },
      password: {
        type: Sequelize.STRING(255),
        allowNull: true,
        comment: 'Hashed password (null for OAuth users)',
      },
      type: {
        type: Sequelize.ENUM('customer', 'vendor', 'staff', 'admin'),
        allowNull: false,
        defaultValue: 'customer',
        comment: 'User type classification (customer, vendor, staff, admin)',
      },
      role: {
        type: Sequelize.ENUM(
          'customer',
          'vendor',
          'requirement_coordinator',
          'hr_admin',
          'admin',
          'super_admin'
        ),
        allowNull: false,
        defaultValue: 'customer',
        comment: 'User role in the system',
      },
      permissions: {
        type: Sequelize.JSON,
        allowNull: true,
        comment: 'User permissions',
      },
      provider: {
        type: Sequelize.ENUM('manual', 'google', 'facebook', 'linkedin'),
        allowNull: true,
        defaultValue: 'manual',
        comment: 'OAuth or SSO provider',
      },
      providerId: {
        type: Sequelize.STRING(255),
        allowNull: true,
        comment: 'Provider user ID',
      },
      deviceInfo: {
        type: Sequelize.JSON,
        allowNull: true,
        comment: 'Device information',
      },
      ipAddress: {
        type: Sequelize.STRING(45),
        allowNull: true,
        comment: 'Last known IP address',
      },
      lastActiveAt: {
        type: Sequelize.DATE,
        allowNull: true,
        comment: 'Last activity timestamp',
      },
      lastLoginAt: {
        type: Sequelize.DATE,
        allowNull: true,
        comment: 'Last login timestamp',
      },
      emailVerified: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: false,
        comment: 'Is email verified?',
      },
      emailVerifiedAt: {
        type: Sequelize.DATE,
        allowNull: true,
        comment: 'When email was verified',
      },
      refreshToken: {
        type: Sequelize.STRING(512),
        allowNull: true,
        unique: true,
        comment: 'Refresh token for authentication',
      },
      refreshTokenExpiresAt: {
        type: Sequelize.DATE,
        allowNull: true,
        comment: 'Refresh token expiration timestamp',
      },
      isActive: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: true,
        comment: 'User account active status',
      },
      status: {
        type: Sequelize.ENUM('active', 'inactive', 'suspended', 'pending'),
        allowNull: false,
        defaultValue: 'pending',
        comment: 'User account status',
      },
      failedLoginAttempts: {
        type: Sequelize.INTEGER,
        allowNull: false,
        defaultValue: 0,
        comment: 'Number of failed login attempts',
      },
      lockedUntil: {
        type: Sequelize.DATE,
        allowNull: true,
        comment: 'Account lock timestamp',
      },
      passwordChangedAt: {
        type: Sequelize.DATE,
        allowNull: true,
        comment: 'Password last changed timestamp',
      },
      passwordResetToken: {
        type: Sequelize.STRING(255),
        allowNull: true,
        comment: 'Password reset token',
      },
      passwordResetExpiresAt: {
        type: Sequelize.DATE,
        allowNull: true,
        comment: 'Password reset token expiration',
      },
      twoFactorEnabled: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: false,
        comment: 'Two-factor authentication status',
      },
      twoFactorSecret: {
        type: Sequelize.STRING(255),
        allowNull: true,
        comment: 'Two-factor authentication secret',
      },
      preferences: {
        type: Sequelize.JSON,
        allowNull: true,
        defaultValue: {},
        comment: 'User preferences and settings',
      },
      metadata: {
        type: Sequelize.JSON,
        allowNull: true,
        defaultValue: {},
        comment: 'Additional user metadata',
      },
      createdAt: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.NOW,
      },
      updatedAt: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.NOW,
      },
      deletedAt: {
        type: Sequelize.DATE,
        allowNull: true,
      },
    });
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('auth_users');
  },
};
