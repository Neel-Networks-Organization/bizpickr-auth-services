/**
 * Two-Factor Authentication Service
 *
 * Handles 2FA functionality:
 * - TOTP secret generation
 * - QR code generation
 * - Backup codes generation
 * - 2FA verification
 * - 2FA enable/disable
 */
import crypto from 'crypto';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import bcrypt from 'bcryptjs';
import { safeLogger } from '../config/logger.js';
import { env } from '../config/env.js';
import { AuthUser as User } from '../models/index.model.js';
import { logAuditEvent } from '../middlewares/audit.middleware.js';
import sessionService from './session.service.js';

class TwoFactorService {
  constructor() {
    this.backupCodesCount = 10;
    this.backupCodeLength = 8;
    this.issuer = 'BizPickr';
    this.algorithm = 'sha1';
    this.digits = 6;
    this.period = 30; // 30 seconds
  }

  /**
   * Generate TOTP secret
   * @returns {string} Base32 encoded secret
   */
  generateSecret() {
    return speakeasy.generateSecret({
      name: this.issuer,
      issuer: this.issuer,
      length: 32,
    });
  }

  /**
   * Generate backup codes
   * @returns {Array<string>} Array of backup codes
   */
  generateBackupCodes() {
    const codes = [];
    for (let i = 0; i < this.backupCodesCount; i++) {
      const code = crypto
        .randomBytes(this.backupCodeLength)
        .toString('hex')
        .toUpperCase()
        .slice(0, this.backupCodeLength);
      codes.push(code);
    }
    return codes;
  }

  /**
   * Generate QR code for TOTP
   * @param {string} secret - TOTP secret
   * @param {string} email - User email
   * @returns {Promise<string>} QR code data URL
   */
  async generateQRCode(secret, email) {
    try {
      const otpauthUrl = speakeasy.otpauthURL({
        secret: secret.base32,
        label: email,
        issuer: this.issuer,
        algorithm: this.algorithm,
        digits: this.digits,
        period: this.period,
      });

      const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl, {
        errorCorrectionLevel: 'M',
        type: 'image/png',
        quality: 0.92,
        margin: 1,
        color: {
          dark: '#000000',
          light: '#FFFFFF',
        },
      });

      return qrCodeDataUrl;
    } catch (error) {
      safeLogger.error('Failed to generate QR code', { error: error.message });
      throw new Error('Failed to generate QR code');
    }
  }

  /**
   * Enable 2FA for user
   * @param {string} userId - User ID
   * @returns {Promise<Object>} 2FA setup data
   */
  async enableTwoFactor(userId) {
    try {
      const user = await User.findByPk(userId);
      if (!user) {
        throw new Error('User not found');
      }

      if (user.twoFactorEnabled) {
        throw new Error('2FA is already enabled');
      }

      // Generate TOTP secret
      const secret = this.generateSecret();

      // Generate backup codes
      const backupCodes = this.generateBackupCodes();
      const hashedBackupCodes = await Promise.all(
        backupCodes.map(code => bcrypt.hash(code, 12)),
      );

      // Generate QR code
      const qrCode = await this.generateQRCode(secret, user.email);

      // Update user with 2FA data
      await user.update({
        twoFactorEnabled: true,
        twoFactorSecret: secret.base32,
        twoFactorBackupCodes: hashedBackupCodes,
        twoFactorEnabledAt: new Date(),
      });

      // Log audit event
      await logAuditEvent({
        type: '2FA_ENABLED',
        user: {
          userId: user.id,
          username: user.email,
          roles: [user.role],
          permissions: [],
          ip: null, // Will be set by controller
          userAgent: null, // Will be set by controller
        },
        resourceType: 'USER',
        resourceId: user.id,
        details: {
          email: user.email,
          twoFactorMethod: 'TOTP',
        },
        status: 'success',
        severity: 'medium',
        category: 'authentication',
        description: 'Two-factor authentication enabled',
        timestamp: new Date(),
      });

      safeLogger.info('2FA enabled successfully', {
        userId: user.id,
        email: user.email,
      });

      return {
        qrCode,
        secret: secret.base32,
        backupCodes,
        message:
          'Please scan the QR code with your authenticator app and save the backup codes',
      };
    } catch (error) {
      safeLogger.error('Failed to enable 2FA', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Verify TOTP code
   * @param {string} secret - TOTP secret
   * @param {string} token - TOTP token
   * @returns {boolean} Verification result
   */
  verifyTOTP(secret, token) {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 2, // Allow 2 time steps (60 seconds) for clock skew
      algorithm: this.algorithm,
      digits: this.digits,
      period: this.period,
    });
  }

  /**
   * Verify backup code
   * @param {Array<string>} hashedBackupCodes - Array of hashed backup codes
   * @param {string} code - Backup code to verify
   * @returns {Promise<boolean>} Verification result
   */
  async verifyBackupCode(hashedBackupCodes, code) {
    for (let i = 0; i < hashedBackupCodes.length; i++) {
      const isValid = await bcrypt.compare(code, hashedBackupCodes[i]);
      if (isValid) {
        return { isValid: true, index: i };
      }
    }
    return { isValid: false, index: -1 };
  }

  /**
   * Verify 2FA code
   * @param {string} userId - User ID
   * @param {string} code - 2FA code (TOTP or backup)
   * @returns {Promise<boolean>} Verification result
   */
  async verifyTwoFactorCode(userId, code) {
    try {
      const user = await User.findByPk(userId);
      if (!user) {
        throw new Error('User not found');
      }

      if (!user.twoFactorEnabled) {
        throw new Error('2FA is not enabled');
      }

      // First try TOTP verification
      const totpValid = this.verifyTOTP(user.twoFactorSecret, code);
      if (totpValid) {
        return { valid: true, method: 'totp' };
      }

      // If TOTP fails, try backup code
      if (user.twoFactorBackupCodes && user.twoFactorBackupCodes.length > 0) {
        const backupResult = await this.verifyBackupCode(
          user.twoFactorBackupCodes,
          code,
        );
        if (backupResult.isValid) {
          // Remove used backup code
          const updatedBackupCodes = user.twoFactorBackupCodes.filter(
            (_, index) => index !== backupResult.index,
          );
          await user.update({ twoFactorBackupCodes: updatedBackupCodes });

          return {
            valid: true,
            method: 'backup',
            remainingBackupCodes: updatedBackupCodes.length,
          };
        }
      }

      return { valid: false, method: null };
    } catch (error) {
      safeLogger.error('2FA verification failed', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Disable 2FA for user
   * @param {string} userId - User ID
   * @param {string} code - 2FA verification code
   * @returns {Promise<boolean>} Disable success
   */
  async disableTwoFactor(userId, code) {
    try {
      const user = await User.findByPk(userId);
      if (!user) {
        throw new Error('User not found');
      }

      if (!user.twoFactorEnabled) {
        throw new Error('2FA is not enabled');
      }

      // Verify 2FA code
      const verification = await this.verifyTwoFactorCode(userId, code);
      if (!verification.valid) {
        throw new Error('Invalid 2FA code');
      }

      // Disable 2FA
      await user.update({
        twoFactorEnabled: false,
        twoFactorSecret: null,
        twoFactorBackupCodes: null,
        twoFactorEnabledAt: null,
        twoFactorDisabledAt: new Date(),
      });

      // Log audit event
      await logAuditEvent({
        type: '2FA_DISABLED',
        user: {
          userId: user.id,
          username: user.email,
          roles: [user.role],
          permissions: [],
          ip: null, // Will be set by controller
          userAgent: null, // Will be set by controller
        },
        resourceType: 'USER',
        resourceId: user.id,
        details: {
          email: user.email,
          verificationMethod: verification.method,
        },
        status: 'success',
        severity: 'medium',
        category: 'authentication',
        description: 'Two-factor authentication disabled',
        timestamp: new Date(),
      });

      safeLogger.info('2FA disabled successfully', {
        userId: user.id,
        email: user.email,
      });

      return true;
    } catch (error) {
      safeLogger.error('Failed to disable 2FA', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Complete 2FA verification for login
   * @param {string} code - 2FA code
   * @param {string} sessionId - Session ID
   * @returns {Promise<Object>} Login completion result
   */
  async completeTwoFactorLogin(code, sessionId) {
    try {
      // Get session
      const session = await sessionService.getSession(sessionId);
      if (!session) {
        throw new Error('Invalid session');
      }

      if (session.status !== 'pending_2fa') {
        throw new Error('Session is not in 2FA pending state');
      }

      // Verify 2FA code
      const verification = await this.verifyTwoFactorCode(session.userId, code);
      if (!verification.valid) {
        throw new Error('Invalid 2FA code');
      }

      // Get user
      const user = await User.findByPk(session.userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Update session
      await sessionService.updateSession(sessionId, {
        status: 'active',
        twoFactorVerifiedAt: new Date(),
        lastActivityAt: new Date(),
      });

      // Generate access token
      const jwt = require('jsonwebtoken');
      const accessToken = jwt.sign(
        {
          userId: user.id,
          email: user.email,
          role: user.role,
          twoFactorVerified: true,
        },
        env.JWT_SECRET,
        {
          expiresIn: env.JWT_EXPIRES_IN,
          issuer: 'auth-service',
          audience: 'api-gateway',
        },
      );

      // Log audit event
      await logAuditEvent({
        type: '2FA_LOGIN_COMPLETED',
        user: {
          userId: user.id,
          username: user.email,
          roles: [user.role],
          permissions: [],
          ip: session.ipAddress,
          userAgent: session.userAgent,
        },
        resourceType: 'USER',
        resourceId: user.id,
        details: {
          email: user.email,
          sessionId,
          verificationMethod: verification.method,
        },
        ipAddress: session.ipAddress,
        userAgent: session.userAgent,
        status: 'success',
        severity: 'low',
        category: 'authentication',
        description: '2FA login completed successfully',
        timestamp: new Date(),
      });

      safeLogger.info('2FA login completed successfully', {
        userId: user.id,
        email: user.email,
        sessionId,
        verificationMethod: verification.method,
      });

      return {
        accessToken,
        expiresIn: env.JWT_EXPIRES_IN,
        user: {
          id: user.id,
          email: user.email,
          fullName: user.fullName,
          role: user.role,
          status: user.status,
          emailVerified: user.emailVerified,
          twoFactorEnabled: user.twoFactorEnabled,
        },
      };
    } catch (error) {
      safeLogger.error('2FA login completion failed', {
        error: error.message,
        sessionId,
      });
      throw error;
    }
  }
}

export default new TwoFactorService();
