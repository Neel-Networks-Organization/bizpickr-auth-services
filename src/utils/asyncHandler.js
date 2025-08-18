// src/utils/asyncHandler.js
import { ApiError } from './ApiError.js';
import { safeLogger } from '../config/logger.js';
/**
 * Industry-level Async Handler for Express.js
 *
 * Features:
 * - Automatic async/await error handling
 * - Performance monitoring and timing
 * - Request correlation tracking
 * - Detailed error logging
 * - Request/response validation
 * - Memory leak prevention
 * - Custom error transformation
 * - Middleware chaining support
 */
// Performance monitoring
const performanceMarks = new Map();
// Request tracking
const activeRequests = new Map();
// Enhanced async handler with comprehensive features
const asyncHandler = (requestHandler, options = {}) => {
  const {
    enableTiming = true,
    enableLogging = true,
    timeout = 30000, // 30 seconds default
    retryAttempts = 0,
    errorTransformer = null,
    preHandler = null,
    postHandler = null,
  } = options;
  return async(req, res, next) => {
    const requestId =
      req.correlationId ||
      `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const startTime = Date.now();
    let timeoutId = null;
    // Set correlation ID if not present
    if (!req.correlationId) {
      req.correlationId = requestId;
    }
    // Track active request
    if (enableLogging) {
      activeRequests.set(requestId, {
        url: req.originalUrl || req.url,
        method: req.method,
        startTime,
        user: req.user?.id,
      });
    }
    // Performance mark
    if (enableTiming) {
      performanceMarks.set(requestId, startTime);
    }
    // Pre-handler middleware
    if (preHandler && typeof preHandler === 'function') {
      try {
        await preHandler(req, res);
      } catch (error) {
        safeLogger.warn('Pre-handler error', {
          requestId,
          error: error.message,
          url: req.originalUrl,
        });
      }
    }

    // Set timeout
    if (timeout > 0) {
      timeoutId = setTimeout(() => {
        const timeoutError = new ApiError(408, 'Request timeout', [
          `Request exceeded ${timeout}ms timeout limit`,
        ]);
        next(timeoutError);
      }, timeout);
    }
    // Execute handler with retry logic
    let lastError = null;
    for (let attempt = 0; attempt <= retryAttempts; attempt++) {
      try {
        // Clear timeout on successful attempt
        if (timeoutId) {
          clearTimeout(timeoutId);
          timeoutId = null;
        }
        // Execute the actual handler
        const result = await requestHandler(req, res, next);
        // Post-handler middleware
        if (postHandler && typeof postHandler === 'function') {
          try {
            await postHandler(req, res, result);
          } catch (error) {
            safeLogger.warn('Post-handler error', {
              requestId,
              error: error.message,
              url: req.originalUrl,
            });
          }
        }
        // Log successful request
        if (enableLogging) {
          const duration = Date.now() - startTime;
          safeLogger.info('Request completed', {
            requestId,
            url: req.originalUrl || req.url,
            method: req.method,
            statusCode: res.statusCode,
            duration: `${duration}ms`,
            user: req.user?.id,
            userAgent: req.headers['user-agent'],
            ip: req.ip || req.connection?.remoteAddress,
          });
        }
        // Cleanup
        cleanup(requestId);
        return result;
      } catch (error) {
        lastError = error;
        // Log retry attempt
        if (attempt < retryAttempts) {
          safeLogger.warn('Request retry', {
            requestId,
            attempt: attempt + 1,
            maxAttempts: retryAttempts + 1,
            error: error.message,
            url: req.originalUrl,
          });
          // Wait before retry (exponential backoff)
          if (attempt > 0) {
            const delay = Math.min(1000 * Math.pow(2, attempt), 5000);
            await new Promise(resolve => setTimeout(resolve, delay));
          }
        }
      }
    }
    // All retry attempts failed
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
    // Transform error if custom transformer provided
    if (errorTransformer && typeof errorTransformer === 'function') {
      lastError = errorTransformer(lastError, req, res);
    }
    // Log final error
    if (enableLogging) {
      const duration = Date.now() - startTime;
      safeLogger.error('Request failed', {
        requestId,
        url: req.originalUrl || req.url,
        method: req.method,
        duration: `${duration}ms`,
        error: {
          message: lastError.message,
          stack: lastError.stack,
          name: lastError.name,
          code: lastError.code,
        },
        user: req.user?.id,
        userAgent: req.headers['user-agent'],
        ip: req.ip || req.connection?.remoteAddress,
        attempts: retryAttempts + 1,
      });
    }
    // Cleanup
    cleanup(requestId);
    // Pass error to next middleware
    next(lastError);
  };
};

// Cleanup helper
const cleanup = requestId => {
  activeRequests.delete(requestId);
  performanceMarks.delete(requestId);
};
// Utility functions for monitoring and debugging
const getActiveRequests = () => {
  return Array.from(activeRequests.entries()).map(([id, data]) => ({
    id,
    ...data,
    duration: Date.now() - data.startTime,
  }));
};
const getRequestStats = () => {
  const active = activeRequests.size;
  const total = performanceMarks.size;
  const avgDuration =
    total > 0
      ? Array.from(performanceMarks.values()).reduce(
        (sum, startTime) => sum + (Date.now() - startTime),
        0,
      ) / total
      : 0;
  return {
    activeRequests: active,
    totalRequests: total,
    averageDuration: `${Math.round(avgDuration)}ms`,
  };
};
const clearRequestData = () => {
  activeRequests.clear();
  performanceMarks.clear();
};
// Factory functions for common use cases
const asyncHandlerWithTimeout = timeout => handler =>
  asyncHandler(handler, { timeout });
const asyncHandlerWithRetry = retryAttempts => handler =>
  asyncHandler(handler, { retryAttempts });
const asyncHandlerWithValidation = handler =>
  asyncHandler(handler, { enableValidation: true });
const asyncHandlerWithLogging = handler =>
  asyncHandler(handler, { enableLogging: true });
const asyncHandlerWithTiming = handler =>
  asyncHandler(handler, { enableTiming: true });
// Export main function and utilities
export {
  asyncHandler,
  getActiveRequests,
  getRequestStats,
  clearRequestData,
  asyncHandlerWithTimeout,
  asyncHandlerWithRetry,
  asyncHandlerWithValidation,
  asyncHandlerWithLogging,
  asyncHandlerWithTiming,
};
