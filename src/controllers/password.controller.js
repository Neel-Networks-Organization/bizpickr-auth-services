import { ApiError, ApiResponse } from '../utils/index.js';
import { safeLogger } from '../config/logger.js';
import { passwordService } from '../services/index.js';

/**
 * Change user password
 * POST /api/v1/password/change
 */
export const changePassword = async (req, res) => {
  const userId = req.user?.id;
  const { currentPassword, newPassword } = req.body;

  if (!userId) {
    throw new ApiError(401, 'User not authenticated', [
      'Please login to change your password',
    ]);
  }

  await passwordService.changePassword(userId, currentPassword, newPassword);

  safeLogger.info('Password changed successfully', {
    userId,
  });

  return res
    .status(200)
    .json(
      ApiResponse.success(
        {},
        'Password changed successfully. Please login again.'
      )
    );
};

/**
 * Forgot password
 * POST /api/v1/password/forgot
 */
export const forgotPassword = async (req, res) => {
  const { email } = req.body;

  await passwordService.initiatePasswordReset(email);

  safeLogger.info('Password reset initiated', {
    email,
  });

  return res.status(200).json(
    ApiResponse.success({}, 'Password reset email sent', {
      email,
      message:
        'If an account exists with this email, you will receive a password reset link',
    })
  );
};

/**
 * Reset password
 * POST /api/v1/password/reset
 */
export const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;

  await passwordService.resetPassword(email, otp, newPassword);

  safeLogger.info('Password reset completed', {
    otp: otp.substring(0, 8) + '...',
    email,
  });

  return res
    .status(200)
    .json(
      ApiResponse.success(
        {},
        'Password reset successful. You can now login with your new password.'
      )
    );
};

/**
 * Get password reset statistics
 * GET /api/v1/password/stats
 */
export const getPasswordStats = async (req, res) => {
  const stats = await passwordService.getPasswordResetStats();

  safeLogger.info('Password reset statistics retrieved', {
    totalResets: stats.total,
    usedResets: stats.used,
    pendingResets: stats.pending,
    recentResets: stats.recent,
  });

  return res
    .status(200)
    .json(
      ApiResponse.success(
        stats,
        'Password reset statistics retrieved successfully'
      )
    );
};

/**
 * Clean expired reset otp (Admin only)
 * POST /api/v1/password/cleanup
 */
export const cleanExpiredTokens = async (req, res) => {
  const userId = req.user?.id;
  const userRole = req.user?.role;

  if (!userId) {
    throw new ApiError(401, 'User not authenticated', [
      'Please login to perform otp cleanup',
    ]);
  }

  if (userRole !== 'admin') {
    throw new ApiError(403, 'Access denied', [
      'Only administrators can perform otp cleanup',
    ]);
  }

  const cleanedCount = await passwordService.cleanExpiredResetOtp();

  safeLogger.info('Expired password reset otp cleaned', {
    userId,
    cleanedCount,
  });

  return res
    .status(200)
    .json(
      ApiResponse.success(
        { cleanedCount },
        'Expired password reset otp cleaned successfully'
      )
    );
};

export const getPasswordResetStatsByEmail = async (req, res) => {
  const { email } = req.params;
  const stats = await passwordService.getPasswordResetStatsByEmail(email);

  return res
    .status(200)
    .json(
      ApiResponse.success(
        stats,
        'Password reset statistics by email retrieved successfully'
      )
    );
};
