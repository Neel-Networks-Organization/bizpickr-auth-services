/**
 * Password Service - Password Management Layer
 *
 * Handles all password-related business logic:
 * - Password reset
 * - Password change
 * - Password validation
 * - Password reset tokens
 */
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { safeLogger } from '../config/logger.js';
import { publishEvent } from '../events/index.js';
import {
  AuthUser as User,
  PasswordReset,
  AuditLog,
} from '../models/index.model.js';
import { Op } from 'sequelize';

class PasswordService {
  constructor() {
    this.saltRounds = 12;
    this.resetTokenExpiry = 60 * 60 * 1000; // 1 hour
  }

  /**
   * Change user password
   * @param {number} userId - User ID
   * @param {string} currentPassword - Current password
   * @param {string} newPassword - New password
   * @returns {Promise<boolean>} Password change success
   */
  async changePassword(userId, currentPassword, newPassword) {
    try {
      const user = await User.findByPk(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Verify current password
      const isCurrentPasswordValid = await bcrypt.compare(
        currentPassword,
        user.password,
      );
      if (!isCurrentPasswordValid) {
        throw new Error('Current password is incorrect');
      }

      // Validate new password
      this.validatePassword(newPassword);

      // Hash new password
      const hashedNewPassword = await bcrypt.hash(newPassword, this.saltRounds);

      // Update password
      await user.update({ password: hashedNewPassword });

      // Publish password changed event
      await publishEvent('user.password_changed', {
        userId,
        email: user.email,
        timestamp: new Date(),
      });

      // Create audit log
      await AuditLog.create({
        userId,
        action: 'PASSWORD_CHANGED',
        resourceType: 'USER',
        resourceId: userId,
        details: { passwordChanged: true },
      });

      safeLogger.info('Password changed successfully', {
        userId,
      });

      return true;
    } catch (error) {
      safeLogger.error('Password change failed', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Initiate password reset
   * @param {string} email - User email
   * @returns {Promise<boolean>} Reset initiation success
   */
  async initiatePasswordReset(email) {
    try {
      const user = await User.findOne({ where: { email } });
      if (!user) {
        // Don't reveal if user exists or not
        safeLogger.info('Password reset requested for non-existent email', {
          email,
        });
        return true;
      }

      // Generate reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetTokenHash = await bcrypt.hash(resetToken, 10);
      const expiresAt = new Date(Date.now() + this.resetTokenExpiry);

      // Store reset token
      await PasswordReset.create({
        userId: user.id,
        token: resetTokenHash,
        expiresAt,
        used: false,
      });

      // Publish password reset initiated event
      await publishEvent('user.password_reset_initiated', {
        userId: user.id,
        email: user.email,
        resetToken,
        expiresAt,
        timestamp: new Date(),
      });

      // Create audit log
      await AuditLog.create({
        userId: user.id,
        action: 'PASSWORD_RESET_INITIATED',
        resourceType: 'USER',
        resourceId: user.id,
        details: { email },
      });

      safeLogger.info('Password reset initiated', {
        userId: user.id,
        email,
      });

      return true;
    } catch (error) {
      safeLogger.error('Password reset initiation failed', {
        error: error.message,
        email,
      });
      throw error;
    }
  }

  /**
   * Reset password with token
   * @param {string} token - Reset token
   * @param {string} newPassword - New password
   * @returns {Promise<boolean>} Reset success
   */
  async resetPassword(token, newPassword) {
    try {
      // Find reset token
      const resetRecord = await PasswordReset.findOne({
        where: {
          token: await bcrypt.hash(token, 10),
          used: false,
          expiresAt: {
            [Op.gt]: new Date(),
          },
        },
        include: [{ model: User, as: 'user' }],
      });

      if (!resetRecord) {
        throw new Error('Invalid or expired reset token');
      }

      // Validate new password
      this.validatePassword(newPassword);

      // Hash new password
      const hashedNewPassword = await bcrypt.hash(newPassword, this.saltRounds);

      // Update user password
      await resetRecord.user.update({ password: hashedNewPassword });

      // Mark token as used
      await resetRecord.update({ used: true, usedAt: new Date() });

      // Publish password reset completed event
      await publishEvent('user.password_reset_completed', {
        userId: resetRecord.userId,
        email: resetRecord.user.email,
        timestamp: new Date(),
      });

      // Create audit log
      await AuditLog.create({
        userId: resetRecord.userId,
        action: 'PASSWORD_RESET_COMPLETED',
        resourceType: 'USER',
        resourceId: resetRecord.userId,
        details: { email: resetRecord.user.email },
      });

      safeLogger.info('Password reset completed', {
        userId: resetRecord.userId,
        email: resetRecord.user.email,
      });

      return true;
    } catch (error) {
      safeLogger.error('Password reset failed', {
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Validate password strength
   * @param {string} password - Password to validate
   * @throws {Error} If password is invalid
   */
  validatePassword(password) {
    if (!password || typeof password !== 'string') {
      throw new Error('Password is required');
    }

    if (password.length < 8) {
      throw new Error('Password must be at least 8 characters long');
    }

    if (password.length > 128) {
      throw new Error('Password must be less than 128 characters');
    }

    // Check for at least one uppercase letter
    if (!/[A-Z]/.test(password)) {
      throw new Error('Password must contain at least one uppercase letter');
    }

    // Check for at least one lowercase letter
    if (!/[a-z]/.test(password)) {
      throw new Error('Password must contain at least one lowercase letter');
    }

    // Check for at least one number
    if (!/\d/.test(password)) {
      throw new Error('Password must contain at least one number');
    }

    // Check for at least one special character
    if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
      throw new Error('Password must contain at least one special character');
    }

    // Check for common passwords (basic check)
    const commonPasswords = [
      'password',
      '123456',
      '123456789',
      'qwerty',
      'abc123',
      'password123',
      'admin',
      'letmein',
      'welcome',
      'monkey',
    ];

    if (commonPasswords.includes(password.toLowerCase())) {
      throw new Error(
        'Password is too common, please choose a stronger password',
      );
    }
  }

  /**
   * Hash password
   * @param {string} password - Plain text password
   * @returns {Promise<string>} Hashed password
   */
  async hashPassword(password) {
    return await bcrypt.hash(password, this.saltRounds);
  }

  /**
   * Verify password
   * @param {string} password - Plain text password
   * @param {string} hashedPassword - Hashed password
   * @returns {Promise<boolean>} Password validity
   */
  async verifyPassword(password, hashedPassword) {
    return await bcrypt.compare(password, hashedPassword);
  }

  /**
   * Clean expired reset tokens
   * @returns {Promise<number>} Number of cleaned tokens
   */
  async cleanExpiredResetTokens() {
    try {
      const expiredTokens = await PasswordReset.findAll({
        where: {
          expiresAt: {
            [Op.lt]: new Date(),
          },
        },
      });

      const deletedCount = await PasswordReset.destroy({
        where: {
          expiresAt: {
            [Op.lt]: new Date(),
          },
        },
      });

      safeLogger.info('Expired password reset tokens cleaned', {
        cleanedCount: deletedCount,
        totalExpired: expiredTokens.length,
      });

      return deletedCount;
    } catch (error) {
      safeLogger.error('Failed to clean expired reset tokens', {
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Get password reset statistics
   * @param {number} userId - User ID
   * @returns {Promise<Object>} Reset statistics
   */
  async getPasswordResetStats(userId) {
    try {
      const totalResets = await PasswordReset.count({
        where: { userId },
      });

      const usedResets = await PasswordReset.count({
        where: { userId, status: 'used' },
      });

      const pendingResets = await PasswordReset.count({
        where: {
          userId,
          status: 'pending',
          expiresAt: {
            [Op.gt]: new Date(),
          },
        },
      });

      const recentResets = await PasswordReset.findAll({
        where: { userId },
        order: [['createdAt', 'DESC']],
        limit: 5,
      });

      return {
        totalResets,
        usedResets,
        pendingResets,
        recentResets,
      };
    } catch (error) {
      safeLogger.error('Failed to get password reset statistics', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }
}

export default new PasswordService();
