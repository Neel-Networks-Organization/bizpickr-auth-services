/**
 * User Controller - User Management Layer
 *
 * Handles all user-related HTTP requests:
 * - User profile management
 * - Account operations
 * - Activity tracking
 * - User statistics
 */
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/ApiError.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import { safeLogger } from '../config/logger.js';
import userService from '../services/user.service.js';
import { verifyJWT } from '../middlewares/auth.middleware.js';

/**
 * Get user profile
 * GET /api/v1/user/profile
 */
export const getUserProfile = asyncHandler(
  async (req, res, next) => {
    const userId = req.user?.id;
    if (!userId) {
      throw new ApiError(401, 'User not authenticated', [
        'Please login to access your profile',
      ]);
    }

    const user = await userService.getUserById(userId);

    safeLogger.info('User profile retrieved', {
      userId,
      email: user.email,
    });

    return res
      .status(200)
      .json(
        ApiResponse.success({ user }, 'User profile retrieved successfully')
      );
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 10000,
    retryAttempts: 1,
  }
);

/**
 * Update user profile
 * PUT /api/v1/user/profile
 */
export const updateUserProfile = asyncHandler(
  async (req, res, next) => {
    const userId = req.user?.id;
    const { fullName, phone } = req.body;

    if (!userId) {
      throw new ApiError(401, 'User not authenticated', [
        'Please login to update your profile',
      ]);
    }

    // Validate input
    if (!fullName && !phone) {
      throw new ApiError(400, 'At least one field is required', [
        'Please provide fullName or phone to update',
      ]);
    }

    const user = await userService.updateUserProfile(userId, {
      fullName,
      phone,
    });

    safeLogger.info('User profile updated', {
      userId,
      updatedFields: Object.keys({ fullName, phone }).filter(
        key => req.body[key]
      ),
    });

    return res
      .status(200)
      .json(ApiResponse.success({ user }, 'Profile updated successfully'));
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 15000,
    retryAttempts: 1,
  }
);

/**
 * Get user activity log
 * GET /api/v1/user/activity
 */
export const getUserActivity = asyncHandler(
  async (req, res, next) => {
    const userId = req.user?.id;
    const { page = 1, limit = 20 } = req.query;

    if (!userId) {
      throw new ApiError(401, 'User not authenticated', [
        'Please login to view activity log',
      ]);
    }

    const activityData = await userService.getActivityLog(userId, {
      page: parseInt(page),
      limit: parseInt(limit),
    });

    safeLogger.info('User activity log retrieved', {
      userId,
      page: parseInt(page),
      limit: parseInt(limit),
      totalActivities: activityData.pagination.total,
    });

    return res
      .status(200)
      .json(
        ApiResponse.success(activityData, 'Activity log retrieved successfully')
      );
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 10000,
    retryAttempts: 1,
  }
);

/**
 * Get user statistics
 * GET /api/v1/user/stats
 */
export const getUserStats = asyncHandler(
  async (req, res, next) => {
    const userId = req.user?.id;

    if (!userId) {
      throw new ApiError(401, 'User not authenticated', [
        'Please login to view statistics',
      ]);
    }

    const stats = await userService.getUserStats(userId);

    safeLogger.info('User statistics retrieved', {
      userId,
      totalActivities: stats.stats.totalActivities,
    });

    return res
      .status(200)
      .json(
        ApiResponse.success(stats, 'User statistics retrieved successfully')
      );
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 10000,
    retryAttempts: 1,
  }
);

/**
 * Delete user account
 * DELETE /api/v1/user/account
 */
export const deleteUserAccount = asyncHandler(
  async (req, res, next) => {
    const userId = req.user?.id;
    const { password, confirmation } = req.body;

    if (!userId) {
      throw new ApiError(401, 'User not authenticated', [
        'Please login to delete your account',
      ]);
    }

    if (!password) {
      throw new ApiError(400, 'Password is required', [
        'Please provide your password to confirm deletion',
      ]);
    }

    if (!confirmation || confirmation !== 'DELETE') {
      throw new ApiError(400, 'Invalid confirmation', [
        "Please type 'DELETE' to confirm account deletion",
      ]);
    }

    await userService.deleteAccount(userId, password);

    safeLogger.info('User account deleted', {
      userId,
    });

    return res.status(200).json(
      ApiResponse.success({}, 'Account deleted successfully', {
        requiresLogout: true,
      })
    );
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 15000,
    retryAttempts: 1,
  }
);

/**
 * Create user activity
 * POST /api/v1/user/activity
 */
export const createUserActivity = asyncHandler(
  async (req, res, next) => {
    const userId = req.user?.id;
    const { activityType, details } = req.body;

    if (!userId) {
      throw new ApiError(401, 'User not authenticated', [
        'Please login to create activity',
      ]);
    }

    if (!activityType) {
      throw new ApiError(400, 'Activity type is required', [
        'Please provide activity type',
      ]);
    }

    const activity = await userService.createActivity(userId, activityType, {
      ...details,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    safeLogger.info('User activity created', {
      userId,
      activityType,
      activityId: activity.id,
    });

    return res
      .status(201)
      .json(ApiResponse.created({ activity }, 'Activity created successfully'));
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 10000,
    retryAttempts: 1,
  }
);
