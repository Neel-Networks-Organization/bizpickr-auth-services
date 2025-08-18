/**
 * Email Verification Service
 *
 * Handles email verification functionality:
 * - Generate verification tokens
 * - Send verification emails
 * - Verify email tokens
 * - Resend verification emails
 */
import crypto from 'crypto';
import { safeLogger } from '../config/logger.js';
import { env } from '../config/env.js';
import { AuthUser as User, EmailVerification } from '../models/index.model.js';
import { logAuditEvent } from '../middlewares/audit.middleware.js';
import emailService from './email.service.js';

class EmailVerificationService {
  constructor() {
    this.tokenExpiry = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
  }

  /**
   * Generate email verification token
   * @param {string} userId - User ID
   * @returns {string} Verification token
   */
  generateVerificationToken(userId) {
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    return { token, tokenHash };
  }

  /**
   * Create email verification record
   * @param {string} userId - User ID
   * @param {string} email - User email
   * @param {Object} deviceInfo - Device information
   * @returns {Promise<Object>} Verification record
   */
  async createVerificationRecord(userId, email, deviceInfo) {
    try {
      const { token, tokenHash } = this.generateVerificationToken(userId);

      const verification = await EmailVerification.create({
        userId,
        email,
        token: tokenHash,
        expiresAt: new Date(Date.now() + this.tokenExpiry),
        status: 'pending',
        attempts: 0,
        maxAttempts: 3,
        ipAddress: deviceInfo.ipAddress,
        userAgent: deviceInfo.userAgent,
        sentAt: new Date(),
      });

      return { verification, token };
    } catch (error) {
      safeLogger.error('Failed to create verification record', {
        error: error.message,
        userId,
        email,
      });
      throw new Error('Failed to create email verification record');
    }
  }

  /**
   * Send verification email
   * @param {string} userId - User ID
   * @param {string} email - User email
   * @param {string} token - Verification token
   * @param {Object} deviceInfo - Device information
   * @returns {Promise<boolean>} Send success
   */
  async sendVerificationEmail(userId, email, token, deviceInfo) {
    try {
      const verificationUrl = `${env.FRONTEND_URL}/verify-email?token=${token}`;

      const emailData = {
        to: email,
        subject: 'Verify Your Email Address',
        template: 'email-verification',
        data: {
          verificationUrl,
          token,
          expiresIn: '24 hours',
          supportEmail: env.SUPPORT_EMAIL,
        },
      };

      // Send email via email service
      await emailService.sendEmail(emailData);

      safeLogger.info('Verification email sent successfully', {
        userId,
        email,
        verificationUrl: verificationUrl.replace(token, '[REDACTED]'),
      });

      return true;
    } catch (error) {
      safeLogger.error('Failed to send verification email', {
        error: error.message,
        userId,
        email,
      });
      throw new Error('Failed to send verification email');
    }
  }

  /**
   * Verify email token
   * @param {string} token - Verification token
   * @returns {Promise<Object>} Verification result
   */
  async verifyEmailToken(token) {
    try {
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

      // Find verification record
      const verification = await EmailVerification.findOne({
        where: {
          token: tokenHash,
          status: 'pending',
          expiresAt: { [require('sequelize').Op.gt]: new Date() },
        },
      });

      if (!verification) {
        throw new Error('Invalid or expired verification token');
      }

      // Check if max attempts exceeded
      if (verification.attempts >= verification.maxAttempts) {
        await verification.update({
          status: 'expired',
          attempts: verification.attempts + 1,
        });
        throw new Error('Verification token expired due to too many attempts');
      }

      // Update verification record
      await verification.update({
        status: 'verified',
        verifiedAt: new Date(),
        attempts: verification.attempts + 1,
      });

      // Update user email verification status
      const user = await User.findByPk(verification.userId);
      if (user) {
        await user.update({
          emailVerified: true,
          emailVerifiedAt: new Date(),
        });
      }

      // Log audit event
      await logAuditEvent({
        type: 'EMAIL_VERIFICATION',
        user: {
          userId: verification.userId,
          username: verification.email,
          roles: [user?.role || 'unknown'],
          permissions: [],
          ip: verification.ipAddress,
          userAgent: verification.userAgent,
        },
        resourceType: 'USER',
        resourceId: verification.userId,
        details: {
          email: verification.email,
          verificationId: verification.id,
        },
        ipAddress: verification.ipAddress,
        userAgent: verification.userAgent,
        status: 'success',
        severity: 'low',
        category: 'authentication',
        description: 'Email verification completed successfully',
        timestamp: new Date(),
      });

      safeLogger.info('Email verification successful', {
        userId: verification.userId,
        email: verification.email,
        verificationId: verification.id,
      });

      return {
        userId: verification.userId,
        email: verification.email,
        verifiedAt: verification.verifiedAt,
      };
    } catch (error) {
      safeLogger.error('Email verification failed', {
        error: error.message,
        token: token.substring(0, 8) + '...',
      });
      throw error;
    }
  }

  /**
   * Resend verification email
   * @param {string} userId - User ID
   * @param {Object} deviceInfo - Device information
   * @returns {Promise<boolean>} Resend success
   */
  async resendVerificationEmail(userId, deviceInfo) {
    try {
      // Get user information
      const user = await User.findByPk(userId);
      if (!user) {
        throw new Error('User not found');
      }

      if (user.emailVerified) {
        throw new Error('Email is already verified');
      }

      // Check for existing pending verification
      const existingVerification = await EmailVerification.findOne({
        where: {
          userId,
          email: user.email,
          status: 'pending',
          expiresAt: { [require('sequelize').Op.gt]: new Date() },
        },
      });

      if (existingVerification) {
        // Check if we can resend (rate limiting)
        const timeSinceLastSent =
          Date.now() - existingVerification.sentAt.getTime();
        const minResendInterval = 5 * 60 * 1000; // 5 minutes

        if (timeSinceLastSent < minResendInterval) {
          const remainingTime = Math.ceil(
            (minResendInterval - timeSinceLastSent) / 1000 / 60,
          );
          throw new Error(
            `Please wait ${remainingTime} minutes before requesting another verification email`,
          );
        }

        // Delete existing verification
        await existingVerification.destroy();
      }

      // Create new verification record
      const { verification, token } = await this.createVerificationRecord(
        userId,
        user.email,
        deviceInfo,
      );

      // Send verification email
      await this.sendVerificationEmail(userId, user.email, token, deviceInfo);

      // Log audit event
      await logAuditEvent({
        type: 'EMAIL_VERIFICATION_RESENT',
        user: {
          userId: user.id,
          username: user.email,
          roles: [user.role],
          permissions: [],
          ip: deviceInfo.ipAddress,
          userAgent: deviceInfo.userAgent,
        },
        resourceType: 'USER',
        resourceId: user.id,
        details: {
          email: user.email,
          verificationId: verification.id,
        },
        ipAddress: deviceInfo.ipAddress,
        userAgent: deviceInfo.userAgent,
        status: 'success',
        severity: 'low',
        category: 'authentication',
        description: 'Email verification email resent',
        timestamp: new Date(),
      });

      safeLogger.info('Verification email resent successfully', {
        userId: user.id,
        email: user.email,
        verificationId: verification.id,
      });

      return true;
    } catch (error) {
      safeLogger.error('Failed to resend verification email', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Clean up expired verification records
   * @returns {Promise<number>} Number of records cleaned
   */
  async cleanupExpiredVerifications() {
    try {
      const result = await EmailVerification.destroy({
        where: {
          expiresAt: { [require('sequelize').Op.lt]: new Date() },
          status: 'pending',
        },
      });

      safeLogger.info('Cleaned up expired verification records', {
        count: result,
      });
      return result;
    } catch (error) {
      safeLogger.error('Failed to cleanup expired verifications', {
        error: error.message,
      });
      return 0;
    }
  }
}

export default new EmailVerificationService();
