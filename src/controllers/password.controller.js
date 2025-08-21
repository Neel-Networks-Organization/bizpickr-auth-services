/**
 * Password Controller - Password Management Layer
 *
 * Handles all password-related HTTP requests:
 * - Password reset
 * - Password change
 * - Password validation
 * - Password statistics
 */
import { asyncHandler, ApiError, ApiResponse } from '../utils/index.js';
import { safeLogger } from '../config/logger.js';
import passwordService from '../services/password.service.js';

/**
 * Change user password
 * POST /api/v1/password/change
 */
export const changePassword = asyncHandler(
  async(req, res) => {
    const userId = req.user?.id;
    const { currentPassword, newPassword } = req.body;

    if (!userId) {
      throw new ApiError(401, 'User not authenticated', [
        'Please login to change your password',
      ]);
    }

    if (!currentPassword || !newPassword) {
      throw new ApiError(400, 'Current and new password are required', [
        'Please provide both current and new passwords',
      ]);
    }

    await passwordService.changePassword(userId, currentPassword, newPassword);

    safeLogger.info('Password changed successfully', {
      userId,
    });

    return res.status(200).json(
      ApiResponse.success(
        {},
        'Password changed successfully. Please login again.',
        {
          requiresReLogin: true,
        },
      ),
    );
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 15000,
    retryAttempts: 1,
  },
);

/**
 * Forgot password
 * POST /api/v1/password/forgot
 */
export const forgotPassword = asyncHandler(
  async(req, res) => {
    const { email } = req.body;

    if (!email) {
      throw new ApiError(400, 'Email is required', [
        'Please provide a valid email address',
      ]);
    }

    await passwordService.initiatePasswordReset(email);

    safeLogger.info('Password reset initiated', {
      email,
    });

    return res.status(200).json(
      ApiResponse.success({}, 'Password reset email sent', {
        email,
        message:
          'If an account exists with this email, you will receive a password reset link',
      }),
    );
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 15000,
    retryAttempts: 1,
  },
);

/**
 * Reset password
 * POST /api/v1/password/reset
 */
export const resetPassword = asyncHandler(
  async(req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      throw new ApiError(400, 'Token and new password are required', [
        'Please provide both reset token and new password',
      ]);
    }

    await passwordService.resetPassword(token, newPassword);

    safeLogger.info('Password reset completed', {
      token: token.substring(0, 8) + '...',
    });

    return res
      .status(200)
      .json(
        ApiResponse.success(
          {},
          'Password reset successful. You can now login with your new password.',
        ),
      );
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 15000,
    retryAttempts: 1,
  },
);

/**
 * Validate password strength
 * POST /api/v1/password/validate
 */
export const validatePassword = asyncHandler(
  async(req, res) => {
    const { password } = req.body;

    if (!password) {
      throw new ApiError(400, 'Password is required', [
        'Please provide a password to validate',
      ]);
    }

    try {
      passwordService.validatePassword(password);

      safeLogger.info('Password validation successful');

      return res
        .status(200)
        .json(
          ApiResponse.success(
            { isValid: true },
            'Password meets all requirements',
          ),
        );
    } catch (error) {
      safeLogger.info('Password validation failed', {
        error: error.message,
      });

      return res
        .status(400)
        .json(
          ApiResponse.badRequest(
            { isValid: false, error: error.message },
            'Password validation failed',
          ),
        );
    }
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 5000,
    retryAttempts: 1,
  },
);

/**
 * Get password reset statistics
 * GET /api/v1/password/stats
 */
export const getPasswordStats = asyncHandler(
  async(req, res) => {
    const userId = req.user?.id;

    if (!userId) {
      throw new ApiError(401, 'User not authenticated', [
        'Please login to view password statistics',
      ]);
    }

    const stats = await passwordService.getPasswordResetStats(userId);

    safeLogger.info('Password reset statistics retrieved', {
      userId,
      totalResets: stats.totalResets,
      usedResets: stats.usedResets,
    });

    return res
      .status(200)
      .json(
        ApiResponse.success(
          stats,
          'Password reset statistics retrieved successfully',
        ),
      );
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 10000,
    retryAttempts: 1,
  },
);

/**
 * Clean expired reset tokens (Admin only)
 * POST /api/v1/password/cleanup
 */
export const cleanExpiredTokens = asyncHandler(
  async(req, res) => {
    const userId = req.user?.id;
    const userRole = req.user?.role;

    if (!userId) {
      throw new ApiError(401, 'User not authenticated', [
        'Please login to perform cleanup',
      ]);
    }

    if (userRole !== 'admin') {
      throw new ApiError(403, 'Access denied', [
        'Only administrators can perform token cleanup',
      ]);
    }

    const cleanedCount = await passwordService.cleanExpiredResetTokens();

    safeLogger.info('Expired password reset tokens cleaned', {
      userId,
      cleanedCount,
    });

    return res
      .status(200)
      .json(
        ApiResponse.success(
          { cleanedCount },
          'Expired password reset tokens cleaned successfully',
        ),
      );
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 30000,
    retryAttempts: 1,
  },
);
