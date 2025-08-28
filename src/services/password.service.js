import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { Op } from 'sequelize';
import { ApiError } from '../utils/ApiError.js';
import { safeLogger } from '../config/logger.js';
import { logAuditEvent } from './audit.service.js';
import { User, PasswordReset } from '../models/index.model.js';

class PasswordService {
  constructor() {
    this.otpExpiry = 60 * 60 * 1000; // 1 hour
    this.saltRounds = 10;
    this.maxAttempts = 5;
    this.resendCooldown = 60 * 1000; // optional: 1 min cooldown for resend
  }

  async changePassword(userId, currentPassword, newPassword) {
    if (!userId || !currentPassword || !newPassword)
      throw new ApiError(400, 'Invalid request');

    try {
      const user = await User.findByPk(userId);
      if (!user) throw new ApiError(404, 'User not found');

      const isPasswordCorrect = await user.isPasswordCorrect(currentPassword);
      if (!isPasswordCorrect)
        throw new ApiError(400, 'Invalid current password');

      await user.update({ password: newPassword });

      await logAuditEvent('PASSWORD_CHANGED', { userId });
      safeLogger.info('Password changed successfully', { userId });
    } catch (error) {
      safeLogger.error('Error changing password', { error });
      throw new ApiError(500, 'Failed to change password');
    }
  }

  async initiatePasswordReset(email) {
    const user = await User.findOne({ where: { email } });
    if (!user) {
      safeLogger.info('Password reset requested for non-existing email', {
        email,
      });
      return {};
    }

    let existing = await PasswordReset.findOne({
      where: { userId: user.id, status: 'pending' },
      order: [['createdAt', 'DESC']],
    });

    const now = Date.now();
    if (existing && !existing.isExpired()) {
      const elapsed = now - existing.updatedAt.getTime();
      if (elapsed < this.resendCooldown) {
        throw new ApiError(
          429,
          `Please wait ${Math.ceil((this.resendCooldown - elapsed) / 1000)}s before requesting a new OTP`
        );
      }
      await existing.markAsExpired();
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    const otpHash = await bcrypt.hash(otp, this.saltRounds);
    const expiresAt = new Date(now + this.otpExpiry);

    await PasswordReset.create({
      userId: user.id,
      otpHash,
      status: 'pending',
      attempts: 0,
      expiresAt,
    });

    // TODO: Send OTP via email

    await logAuditEvent('PASSWORD_RESET_INITIATED', { userId: user.id, email });
    safeLogger.info('Password reset OTP generated', { userId: user.id, email });

    return {
      expiresAt,
      expiresIn: this.otpExpiry,
    };
  }

  async resetPassword(email, otp, newPassword) {
    const user = await User.findOne({ where: { email } });
    if (!user) throw new ApiError(400, 'Invalid request');

    const resetRecord = await PasswordReset.findOne({
      where: { userId: user.id, status: 'pending' },
      order: [['createdAt', 'DESC']],
    });

    if (!resetRecord) throw new ApiError(400, 'No pending reset found');
    if (resetRecord.isUsed()) throw new ApiError(400, 'OTP already used');
    if (resetRecord.isExpired()) throw new ApiError(400, 'OTP expired');
    if (resetRecord.attempts >= this.maxAttempts)
      throw new ApiError(400, 'Max attempts reached');

    const valid = await bcrypt.compare(otp, resetRecord.otpHash);
    if (!valid) {
      await resetRecord.incrementAttempts();
      throw new ApiError(400, 'Invalid OTP');
    }

    await user.update({ password: newPassword });
    await resetRecord.markAsUsed();

    await logAuditEvent('PASSWORD_RESET_COMPLETED', { userId: user.id, email });
    safeLogger.info('Password reset completed', { userId: user.id, email });

    return true;
  }

  async cleanExpiredResetOtp() {
    const deletedCount = await PasswordReset.destroy({
      where: { expiresAt: { [Op.lt]: new Date() } },
    });
    safeLogger.info('Expired password reset otp cleaned', {
      cleanedCount: deletedCount,
    });
    return deletedCount;
  }

  async getPasswordResetStats() {
    const total = await PasswordReset.count();
    const used = await PasswordReset.count({
      where: { status: 'used' },
    });
    const pending = await PasswordReset.count({
      where: { status: 'pending', expiresAt: { [Op.gt]: new Date() } },
    });
    const recent = await PasswordReset.findAll({
      order: [['createdAt', 'DESC']],
      limit: 5,
    });

    return { total, used, pending, recent };
  }

  async getPasswordResetStatsByEmail(email) {
    const total = await PasswordReset.count({ where: { email } });
    const used = await PasswordReset.count({
      where: { email, status: 'used' },
    });
    const pending = await PasswordReset.count({
      where: { email, status: 'pending', expiresAt: { [Op.gt]: new Date() } },
    });

    return { total, used, pending };
  }
}

export default new PasswordService();
