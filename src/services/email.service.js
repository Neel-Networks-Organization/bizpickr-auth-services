import { EmailVerification } from '../models/index.model.js';
import { ApiError } from '../utils/ApiError.js';
import { logAuditEvent } from './audit.service.js';
import { safeLogger } from '../config/logger.js';

class EmailService {
  constructor() {
    this.otpExpiry = 60 * 60 * 1000; // 1 hour
    this.saltRounds = 10;
  }

  async sendVerificationEmail(email) {
    if (!email) {
      throw new ApiError(400, 'Email is required');
    }

    const existing = await EmailVerification.findByEmail(email);
    if (existing) {
      if (existing.isVerified()) {
        throw new ApiError(400, 'Email already verified');
      }
      if (existing.isMaxAttemptsReached()) {
        await existing.markAsExpired();
        throw new ApiError(400, 'Too many attempts');
      }
      if (existing.isExpired()) {
        await existing.markAsExpired();
      }
    }

    try {
      const otp = crypto.randomInt(100000, 999999).toString();
      const otpHash = await bcrypt.hash(otp, this.saltRounds);
      const expiresAt = new Date(Date.now() + this.otpExpiry);

      await EmailVerification.create({
        email,
        otpHash,
        expiresAt,
        status: 'pending',
        attempts: 0,
      });

      // Send `otp` via email (not stored anywhere else)

      await logAuditEvent('EMAIL_VERIFICATION_SENT', {
        email,
      });

      safeLogger.info('Verification email sent', { email, expiresAt });

      return {
        expiresAt,
        expiresIn: this.otpExpiry,
      };
    } catch (error) {
      safeLogger.error('Failed to send verification email', {
        error: error.message,
        email,
      });
      throw error;
    }
  }

  async verifyEmail(email, otp) {
    try {
      const verification = await EmailVerification.findByEmail(email);
      if (!verification) {
        throw new ApiError(400, 'No verification request found');
      }

      if (verification.isExpired()) {
        await verification.markAsExpired();
        throw new ApiError(400, 'Verification code has expired');
      }

      if (verification.isMaxAttemptsReached()) {
        await verification.markAsExpired();
        throw new ApiError(400, 'Too many attempts');
      }

      if (verification.isVerified()) {
        throw new ApiError(400, 'Email already verified');
      }

      await verification.incrementAttempts();

      const isValid = await bcrypt.compare(otp, verification.otpHash);
      if (!isValid) {
        throw new ApiError(400, 'Invalid verification code');
      }

      await verification.user.update({ emailVerified: true });
      await verification.markAsVerified();

      await logAuditEvent('EMAIL_VERIFICATION_VERIFIED', {
        userId: verification.userId,
        email: verification.user.email,
      });

      safeLogger.info('Email verified', {
        userId: verification.userId,
        email: verification.user.email,
      });

      return true;
    } catch (error) {
      safeLogger.error('Failed to verify email', {
        error: error.message,
        email,
      });
      throw error;
    }
  }

  async getVerificationStats(email) {
    const verification = await EmailVerification.findByEmail(email);
    if (!verification) {
      throw new ApiError(400, 'Email not found');
    }
  }

  async getVerificationStats(email) {
    const verification = await EmailVerification.findByEmail(email);
    const totalVerifications = await EmailVerification.count({
      where: { email },
    });
    const usedVerifications = await EmailVerification.count({
      where: { email, status: 'used' },
    });
    if (!verification) {
      throw new ApiError(400, 'Email not found');
    }

    return {
      totalVerifications,
      usedVerifications,
    };
  }
}

export default new EmailService();
