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
  return async (req, res, next) => {
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
          process.env.NODE_ENV === 'development' ? error.stack : ''
        );
        next(apiError);
      }
    }
  };
};

/**
 * Wrapper for async middleware functions
 * @param {Function} middleware - Async middleware function
 * @returns {Function} Express middleware function
 */
const asyncMiddleware = middleware => {
  return async (req, res, next) => {
    try {
      await middleware(req, res, next);
    } catch (error) {
      safeLogger.error('Middleware error', {
        error: error.message,
        stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
        url: req.originalUrl || req.url,
      });
      next(error);
    }
  };
};

/**
 * Wrapper for async error handlers
 * @param {Function} errorHandler - Async error handler function
 * @returns {Function} Express error handler function
 */
const asyncErrorHandler = errorHandler => {
  return async (error, req, res, next) => {
    try {
      await errorHandler(error, req, res, next);
    } catch (handlerError) {
      safeLogger.error('Error handler failed', {
        originalError: error.message,
        handlerError: handlerError.message,
        stack:
          process.env.NODE_ENV === 'development'
            ? handlerError.stack
            : undefined,
      });

      // Fallback to default error response
      res.status(500).json({
        success: false,
        message: 'Internal Server Error',
        error: 'Error handler failed',
      });
    }
  };
};

export { asyncHandler, asyncMiddleware, asyncErrorHandler };
export default asyncHandler;
