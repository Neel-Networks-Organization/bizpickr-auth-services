import { EmailVerification } from '../models/index.model.js';
import { ApiError } from '../utils/ApiError.js';
import { logAuditEvent } from './audit.service.js';
import { safeLogger } from '../config/logger.js';
import { env } from '../config/env.js';

class EmailService {
  constructor() {
    const config = env.services.email;
    this.otpExpiry = config.otpExpiry;
    this.saltRounds = config.saltRounds;
    this.revokedUntil = config.revokedUntil;
    this.resendCooldown = config.resendCooldown;

    safeLogger.info('EmailService initialized with config', { config });
  }

  async sendVerificationEmail(email) {
    if (!email) {
      throw new ApiError(400, 'Email is required');
    }

    try {
      const existing = await EmailVerification.findByEmail(email);
      if (existing) {
        await existing.destroy();
      }

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
      console.log(`OTP for ${email}: ${otp}`);

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

  async resendVerificationEmail(email) {
    if (!email) {
      throw new ApiError(400, 'Email is required');
    }

    const existing = await EmailVerification.findByEmail(email);

    if (!existing) {
      throw new ApiError(404, 'No verification request found');
    }

    // ✅ Simple cooldown check
    const timeSinceLastSent = Date.now() - existing.updatedAt.getTime();
    if (timeSinceLastSent < this.resendCooldown) {
      throw new ApiError(429, 'Please wait before resending');
    }

    if (this.isMaxAttemptsReached(existing)) {
      await this.markAsRevoked(existing);
      throw new ApiError(429, 'Maximum attempts reached');
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    const otpHash = await bcrypt.hash(otp, this.saltRounds);
    const expiresAt = new Date(Date.now() + this.otpExpiry);

    await existing.update({
      otpHash,
      expiresAt,
      attempts: existing.attempts + 1,
    });

    console.log(`Resent OTP for ${email}: ${otp}`);

    return {
      expiresAt,
      attemptsRemaining: existing.maxAttempts - existing.attempts,
    };
  }

  async verifyEmail(email, otp) {
    try {
      const verification = await EmailVerification.findByEmail(email);

      if (!verification) {
        throw new ApiError(400, 'No verification request found');
      }

      if (this.isExpired(verification)) {
        await this.markAsExpired(verification);
        throw new ApiError(400, 'Verification code has expired');
      }

      const isValid = await bcrypt.compare(otp, verification.otpHash);
      if (!isValid) {
        throw new ApiError(400, 'Invalid verification code');
      }

      // ✅ Your simple solution
      if (verification.user) {
        const user = verification.user;
        const isExistingCustomer =
          user.role === 'customer' && user.emailVerified;

        if (!isExistingCustomer) {
          await user.update({
            emailVerified: true,
            emailVerifiedAt: new Date(),
          });
        }
      }

      await this.markAsVerified(verification);
      await this.resetAttempts(verification);

      await logAuditEvent('EMAIL_VERIFICATION_VERIFIED', {
        userId: verification.userId,
        email,
      });

      return verification;
    } catch (error) {
      safeLogger.error('Failed to verify email', {
        error: error.message,
        email,
      });
      throw error;
    }
  }

  // -------------------------------------Helper functions-----------------------------------------------------------
  isExpired(verification) {
    return new Date() > verification.expiresAt;
  }

  isMaxAttemptsReached(verification) {
    return verification.attempts >= verification.maxAttempts;
  }

  isVerified(verification) {
    return verification.status === 'verified';
  }

  async markAsVerified(verification) {
    try {
      verification.status = 'verified';
      verification.verifiedAt = new Date();
      await verification.save();
    } catch (error) {
      safeLogger.error('Failed to mark as verified', {
        verificationId: verification.id,
        error: error.message,
      });
      throw error;
    }
  }

  async markAsExpired(verification) {
    try {
      verification.status = 'expired';
      verification.expiredAt = new Date();
      await verification.save();
    } catch (error) {
      safeLogger.error('Failed to mark as expired', {
        verificationId: verification.id,
        error: error.message,
      });
      throw error;
    }
  }

  async markAsRevoked(verification) {
    try {
      verification.status = 'revoked';
      verification.revokedUntil = new Date(Date.now() + this.otpExpiry);
      await verification.save();
    } catch (error) {
      safeLogger.error('Failed to mark as revoked', {
        verificationId: verification.id,
        error: error.message,
      });
      throw error;
    }
  }

  async resetAttempts(verification) {
    try {
      verification.attempts = 0;
      await verification.save();
    } catch (error) {
      safeLogger.error('Failed to reset attempts', {
        verificationId: verification.id,
        error: error.message,
      });
      throw error;
    }
  }

  // -------------------------------------Admin level functions-----------------------------------------------------------
  async getVerificationStats() {
    const totalVerifications = await EmailVerification.count();
    const usedVerifications = await EmailVerification.count({
      where: { status: 'used' },
    });
    const pendingVerifications = await EmailVerification.count({
      where: { status: 'pending' },
    });
    const expiredVerifications = await EmailVerification.count({
      where: { status: 'expired' },
    });

    return {
      totalVerifications,
      usedVerifications,
      pendingVerifications,
      expiredVerifications,
    };
  }

  async getVerificationStatsByEmail(email) {
    const totalVerifications = await EmailVerification.count({
      where: { email },
    });
    const usedVerifications = await EmailVerification.count({
      where: { email, status: 'used' },
    });

    return {
      totalVerifications,
      usedVerifications,
    };
  }
}

export default new EmailService();
