import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';

/**
 * Smart Logging Middleware
 * Simple request/response logging with essential information
 */

/**
 * Basic request logging middleware
 */
export const requestLogger = (options = {}) => {
  const {
    logRequests = true,
    logResponses = true,
    logErrors = true,
    logPerformance = true,
    excludePaths = ['/health', '/metrics', '/favicon.ico'],
  } = options;

  return (req, res, next) => {
    const correlationId = getCorrelationId();
    const startTime = Date.now();

    // Skip logging for excluded paths
    if (excludePaths.some(path => req.path.startsWith(path))) {
      return next();
    }

    // Log incoming request
    if (logRequests) {
      safeLogger.info('Request started', {
        correlationId,
        method: req.method,
        url: req.url,
        path: req.path,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.user?.id || 'anonymous',
        timestamp: new Date().toISOString(),
      });
    }

    // Override response end to log response
    const originalEnd = res.end;
    res.end = function (...args) {
      const duration = Date.now() - startTime;

      // Log response
      if (logResponses) {
        safeLogger.info('Request completed', {
          correlationId,
          method: req.method,
          url: req.url,
          path: req.path,
          statusCode: res.statusCode,
          duration: `${duration}ms`,
          userId: req.user?.id || 'anonymous',
          timestamp: new Date().toISOString(),
        });
      }

      // Log performance for slow requests
      if (logPerformance && duration > 1000) {
        safeLogger.warn('Slow request detected', {
          correlationId,
          method: req.method,
          path: req.path,
          duration: `${duration}ms`,
          userId: req.user?.id || 'anonymous',
        });
      }

      // Log errors
      if (logErrors && res.statusCode >= 400) {
        safeLogger.error('Request error', {
          correlationId,
          method: req.method,
          path: req.path,
          statusCode: res.statusCode,
          duration: `${duration}ms`,
          userId: req.user?.id || 'anonymous',
          ip: req.ip,
          userAgent: req.get('User-Agent'),
        });
      }

      originalEnd.apply(this, args);
    };

    next();
  };
};

/**
 * Error logging middleware
 */
export const errorLogger = (req, res, next) => {
  const correlationId = getCorrelationId();

  // Log unhandled errors
  process.on('uncaughtException', error => {
    safeLogger.error('Uncaught Exception', {
      error: error.message,
      stack: error.stack,
      correlationId,
      timestamp: new Date().toISOString(),
    });
  });

  process.on('unhandledRejection', (reason, promise) => {
    safeLogger.error('Unhandled Rejection', {
      reason: reason?.message || reason,
      stack: reason?.stack,
      correlationId,
      timestamp: new Date().toISOString(),
    });
  });

  next();
};

/**
 * Security event logging middleware
 */
export const securityLogger = (req, res, next) => {
  const correlationId = getCorrelationId();

  // Log suspicious patterns
  const suspiciousPatterns = [
    /<script/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /union\s+select/i,
    /drop\s+table/i,
    /exec\s*\(/i,
  ];

  const userInput = [
    req.url,
    JSON.stringify(req.query),
    JSON.stringify(req.body),
    req.headers['user-agent'] || '',
  ].join(' ');

  const hasSuspiciousPattern = suspiciousPatterns.some(pattern =>
    pattern.test(userInput)
  );

  if (hasSuspiciousPattern) {
    safeLogger.warn('Suspicious request detected', {
      correlationId,
      path: req.path,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      suspiciousInput: userInput.substring(0, 200),
      timestamp: new Date().toISOString(),
    });
  }

  next();
};

/**
 * User activity logging middleware
 */
export const userActivityLogger = (req, res, next) => {
  const correlationId = getCorrelationId();

  // Only log for authenticated users
  if (!req.user) {
    return next();
  }

  // Log sensitive operations
  const sensitiveOperations = [
    '/auth/login',
    '/auth/logout',
    '/auth/password',
    '/user/profile',
    '/admin',
  ];

  const isSensitiveOperation = sensitiveOperations.some(path =>
    req.path.startsWith(path)
  );

  if (isSensitiveOperation) {
    safeLogger.info('User activity', {
      correlationId,
      userId: req.user.id,
      email: req.user.email,
      operation: req.path,
      method: req.method,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString(),
    });
  }

  next();
};

/**
 * Simple logging middleware (combines all features)
 */
export const loggingMiddleware = (options = {}) => {
  return [
    requestLogger(options),
    errorLogger,
    securityLogger,
    userActivityLogger,
  ];
};

export default {
  requestLogger,
  errorLogger,
  securityLogger,
  userActivityLogger,
  loggingMiddleware,
};
