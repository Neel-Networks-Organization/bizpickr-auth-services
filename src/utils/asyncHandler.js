import { ApiError } from './ApiError.js';
import { safeLogger } from '../config/logger.js';

/**
 * Simple Async Handler for Express.js Routes
 *
 * Purpose: Handle async/await errors in route handlers
 * Features:
 * - Automatic async/await error handling
 * - Basic request logging
 * - Error response formatting
 * - Correlation ID tracking
 */

/**
 * Wrapper for async route handlers
 * @param {Function} requestHandler - Async route handler function
 * @returns {Function} Express middleware function
 */
const asyncHandler = requestHandler => {
  return async(req, res, next) => {
    const requestId =
      req.correlationId ||
      `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const startTime = Date.now();

    // Set correlation ID if not present
    if (!req.correlationId) {
      req.correlationId = requestId;
    }

    try {
      // Execute the route handler
      const result = await requestHandler(req, res, next);

      // Log successful request
      const duration = Date.now() - startTime;
      safeLogger.info('Request completed successfully', {
        requestId,
        method: req.method,
        url: req.originalUrl || req.url,
        duration: `${duration}ms`,
        statusCode: res.statusCode || 200,
      });

      return result;
    } catch (error) {
      // Log error
      const duration = Date.now() - startTime;
      safeLogger.error('Request failed', {
        requestId,
        method: req.method,
        url: req.originalUrl || req.url,
        duration: `${duration}ms`,
        error: {
          message: error.message,
          name: error.name,
          stack:
            process.env.NODE_ENV === 'development' ? error.stack : undefined,
        },
      });

      // Handle different error types
      if (error instanceof ApiError) {
        // API Error - pass to error handler
        next(error);
      } else {
        // Unknown error - convert to API Error
        const apiError = new ApiError(
          500,
          'Internal Server Error',
          [error.message],
          process.env.NODE_ENV === 'development' ? error.stack : '',
        );
        next(apiError);
      }
    }
  };
};

export { asyncHandler };
export default asyncHandler;
