/**
 * User Service - User Management Layer
 *
 * Handles all user-related business logic:
 * - User profile management
 * - Account operations
 * - Activity tracking
 * - User statistics
 */
import { safeLogger } from '../config/logger.js';
import { publishEvent } from '../events/index.js';
import { authCache } from '../cache/auth.cache.js';
import { AuthUser as User } from '../models/index.model.js';
import { AuditLog, UserActivity } from '../models/index.model.js';

class UserService {
  constructor() {
    this.defaultPageSize = 20;
    this.maxPageSize = 100;
  }

  /**
   * Get user by ID
   * @param {number} userId - User ID
   * @returns {Promise<Object>} User object
   */
  async getUserById(userId) {
    try {
      // Try to get from cache first
      const cachedUser = await authCache.getUserProfile(userId);
      if (cachedUser) {
        return cachedUser;
      }

      const user = await User.findByPk(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Cache user profile
      await authCache.storeUserProfile(userId, {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        status: user.status,
        emailVerified: user.emailVerified,
        createdAt: user.createdAt,
      });

      return user;
    } catch (error) {
      safeLogger.error('Failed to get user by ID', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Update user profile
   * @param {number} userId - User ID
   * @param {Object} updateData - Update data
   * @returns {Promise<Object>} Updated user object
   */
  async updateUserProfile(userId, updateData) {
    try {
      const user = await User.findByPk(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Update user
      await user.update(updateData);

      // Invalidate cache
      await authCache.removeUserProfile(userId);

      // Publish profile updated event
      await publishEvent('user.profile_updated', {
        userId,
        updatedFields: Object.keys(updateData),
        timestamp: new Date(),
      });

      return user;
    } catch (error) {
      safeLogger.error('Failed to update user profile', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Delete user account
   * @param {number} userId - User ID
   * @param {string} password - User password for verification
   * @returns {Promise<boolean>} Deletion success
   */
  async deleteAccount(userId, password) {
    try {
      const user = await User.findByPk(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Verify password before deletion
      const bcrypt = await import('bcryptjs');
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        throw new Error('Invalid password');
      }

      // Soft delete - mark as deleted
      await user.update({
        status: 'deleted',
        deletedAt: new Date(),
      });

      // Publish account deleted event
      await publishEvent('user.account_deleted', {
        userId,
        email: user.email,
        timestamp: new Date(),
      });

      // Create audit log
      await AuditLog.create({
        userId,
        action: 'ACCOUNT_DELETED',
        resourceType: 'USER',
        resourceId: userId,
        details: { email: user.email },
      });

      safeLogger.info('User account deleted', {
        userId,
        email: user.email,
      });

      return true;
    } catch (error) {
      safeLogger.error('Failed to delete user account', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Get user activity log
   * @param {string} userId - User ID (MongoDB ObjectId as string)
   * @param {Object} options - Pagination options
   * @returns {Promise<Object>} Activity log with pagination
   */
  async getActivityLog(userId, options = {}) {
    try {
      const { page = 1, limit = this.defaultPageSize } = options;
      const actualLimit = Math.min(limit, this.maxPageSize);
      const skip = (page - 1) * actualLimit;

      // Get activities from AuditLog (Mongoose)
      const [auditActivities, auditCount] = await Promise.all([
        AuditLog.find({ userId })
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(actualLimit)
          .lean(),
        AuditLog.countDocuments({ userId }),
      ]);

      // Get user activities from UserActivity (Mongoose)
      const [userActivities, userActivityCount] = await Promise.all([
        UserActivity.find({ userId })
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(actualLimit)
          .lean(),
        UserActivity.countDocuments({ userId }),
      ]);

      // Combine and sort activities
      const allActivities = [...auditActivities, ...userActivities].sort(
        (a, b) => new Date(b.createdAt) - new Date(a.createdAt),
      );

      const totalActivities = auditCount + userActivityCount;
      const totalPages = Math.ceil(totalActivities / actualLimit);

      safeLogger.info('User activity log retrieved', {
        userId,
        totalActivities,
        page,
        limit: actualLimit,
      });

      return {
        activities: allActivities.slice(0, actualLimit),
        pagination: {
          page: parseInt(page),
          limit: actualLimit,
          total: totalActivities,
          pages: totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1,
        },
      };
    } catch (error) {
      safeLogger.error('Failed to get user activity log', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Create user activity record
   * @param {string} userId - User ID (MongoDB ObjectId as string)
   * @param {string} activityType - Activity type
   * @param {Object} details - Activity details
   * @returns {Promise<Object>} Created activity
   */
  async createActivity(userId, activityType, details = {}) {
    try {
      const activity = await UserActivity.create({
        userId,
        action: activityType,
        ...details,
      });

      safeLogger.debug('User activity created', {
        userId,
        activityType,
        activityId: activity._id,
      });

      return activity;
    } catch (error) {
      safeLogger.error('Failed to create user activity', {
        error: error.message,
        userId,
        activityType,
      });
      throw error;
    }
  }

  /**
   * Get user statistics
   * @param {string} userId - User ID (MongoDB ObjectId as string)
   * @returns {Promise<Object>} User statistics
   */
  async getUserStats(userId) {
    try {
      const user = await User.findByPk(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Get activity counts
      const [activityCount, auditCount, recentActivities] = await Promise.all([
        UserActivity.countDocuments({ userId }),
        AuditLog.countDocuments({ userId }),
        UserActivity.find({ userId }).sort({ createdAt: -1 }).limit(5).lean(),
      ]);

      safeLogger.info('User statistics retrieved', {
        userId,
        activityCount,
        auditCount,
      });

      return {
        user: {
          id: user.id,
          email: user.email,
          fullName: user.fullName,
          role: user.role,
          status: user.status,
          emailVerified: user.emailVerified,
          createdAt: user.createdAt,
        },
        stats: {
          totalActivities: activityCount + auditCount,
          recentActivities: recentActivities.length,
          accountAge: Math.floor(
            (Date.now() - new Date(user.createdAt)) / (1000 * 60 * 60 * 24),
          ),
        },
        recentActivities,
      };
    } catch (error) {
      safeLogger.error('Failed to get user statistics', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }
}

export default new UserService();
