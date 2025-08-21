/**
 * Session Controller - Session Management Layer
 *
 * Handles all session-related HTTP requests:
 * - Session management
 * - Session validation
 * - Session analytics
 * - Session cleanup
 */
import { asyncHandler, ApiError, ApiResponse } from '../utils/index.js';
import { safeLogger } from '../config/logger.js';
import sessionService from '../services/session.service.js';

/**
 * Get user sessions
 * GET /api/v1/sessions
 */
export const getUserSessions = asyncHandler(
  async(req, res) => {
    const userId = req.user?.id;

    if (!userId) {
      throw new ApiError(401, 'User not authenticated', [
        'Please login to view your sessions',
      ]);
    }

    const sessions = await sessionService.getUserSessions(userId);

    safeLogger.info('User sessions retrieved', {
      userId,
      totalSessions: sessions.length,
      activeSessions: sessions.filter(s => s.isActive).length,
    });

    return res
      .status(200)
      .json(
        ApiResponse.success(
          { sessions },
          'User sessions retrieved successfully',
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
 * Revoke specific session
 * DELETE /api/v1/sessions/:sessionId
 */
export const revokeSession = asyncHandler(
  async(req, res) => {
    const userId = req.user?.id;
    const { sessionId } = req.params;

    if (!userId) {
      throw new ApiError(401, 'User not authenticated', [
        'Please login to manage your sessions',
      ]);
    }

    if (!sessionId) {
      throw new ApiError(400, 'Session ID is required', [
        'Please provide a valid session ID',
      ]);
    }

    await sessionService.revokeSession(sessionId, userId);

    safeLogger.info('Session revoked', {
      userId,
      sessionId,
    });

    return res
      .status(200)
      .json(
        ApiResponse.success({}, 'Session revoked successfully', { sessionId }),
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
 * Revoke all user sessions
 * DELETE /api/v1/sessions
 */
export const revokeAllSessions = asyncHandler(
  async(req, res) => {
    const userId = req.user?.id;

    if (!userId) {
      throw new ApiError(401, 'User not authenticated', [
        'Please login to manage your sessions',
      ]);
    }

    await sessionService.revokeAllSessions(userId);

    safeLogger.info('All sessions revoked', {
      userId,
    });

    return res.status(200).json(
      ApiResponse.success(
        {},
        'All sessions revoked successfully. Please login again.',
        {
          requiresReLogin: true,
        },
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
 * Get session statistics
 * GET /api/v1/sessions/stats
 */
export const getSessionStats = asyncHandler(
  async(req, res) => {
    const userId = req.user?.id;

    if (!userId) {
      throw new ApiError(401, 'User not authenticated', [
        'Please login to view session statistics',
      ]);
    }

    const stats = await sessionService.getSessionStats(userId);

    safeLogger.info('Session statistics retrieved', {
      userId,
      totalSessions: stats.totalSessions,
      activeSessions: stats.activeSessions,
    });

    return res
      .status(200)
      .json(
        ApiResponse.success(stats, 'Session statistics retrieved successfully'),
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
 * Validate session
 * POST /api/v1/sessions/validate
 */
export const validateSession = asyncHandler(
  async(req, res) => {
    const { sessionId } = req.body;

    if (!sessionId) {
      throw new ApiError(400, 'Session ID is required', [
        'Please provide a valid session ID',
      ]);
    }

    const sessionData = await sessionService.validateSession(sessionId);

    if (!sessionData) {
      throw new ApiError(401, 'Invalid or expired session', [
        'Session is not valid or has expired',
      ]);
    }

    safeLogger.info('Session validated', {
      sessionId,
      userId: sessionData.userId,
    });

    return res
      .status(200)
      .json(ApiResponse.success({ session: sessionData }, 'Session is valid'));
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 5000,
    retryAttempts: 1,
  },
);

/**
 * Clean expired sessions (Admin only)
 * POST /api/v1/sessions/cleanup
 */
export const cleanExpiredSessions = asyncHandler(
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
        'Only administrators can perform session cleanup',
      ]);
    }

    const cleanedCount = await sessionService.cleanExpiredSessions();

    safeLogger.info('Expired sessions cleaned', {
      userId,
      cleanedCount,
    });

    return res
      .status(200)
      .json(
        ApiResponse.success(
          { cleanedCount },
          'Expired sessions cleaned successfully',
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
