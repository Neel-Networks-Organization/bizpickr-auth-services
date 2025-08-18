/**
 * Enhanced Error Handler Middleware
 *
 * Features:
 * - Advanced error classification and severity determination
 * - Integration with metrics and monitoring
 * - Intelligent retry logic
 * - Comprehensive error logging and alerting
 * - Request correlation and tracing
 * - Performance impact tracking
 */
import { errorClassificationService } from '../services/errorClassification.service.js';
import { metricsService } from '../services/metrics.service.js';
import { safeLogger } from '../config/logger.js';

export const enhancedErrorHandler = (error, req, res, next) => {
  // Skip if response already sent
  if (res.headersSent) {
    return next(error);
  }

  try {
    // Generate correlation ID if not present
    if (!req.correlationId) {
      req.correlationId = errorClassificationService.generateCorrelationId();
    }

    // Create error response using classification service
    const errorResponse = errorClassificationService.createErrorResponse(
      error,
      req,
    );

    // Set response headers
    res.set('X-Correlation-ID', req.correlationId);
    res.set('X-Error-Type', errorResponse.error.type);
    res.set('X-Error-Code', errorResponse.error.code);

    // Add retry headers for retryable errors
    if (errorResponse.error.retryable) {
      res.set('Retry-After', errorResponse.error.retryAfter.toString());
      res.set('X-Retryable', 'true');
    }

    // Send error response
    res.status(errorResponse.error.statusCode).json(errorResponse);

    // Record metrics
    metricsService.incrementMetric('totalErrors', 1);
    metricsService.recordResponseTime(Date.now() - req.startTime);

    // Log error with full context
    const logContext = {
      correlationId: req.correlationId,
      error: error.message,
      stack: error.stack,
      type: errorResponse.error.type,
      code: errorResponse.error.code,
      statusCode: errorResponse.error.statusCode,
      endpoint: req.originalUrl,
      method: req.method,
      userId: req.user?.id,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      requestBody: req.body,
      requestQuery: req.query,
      requestParams: req.params,
      headers: {
        'user-agent': req.get('User-Agent'),
        'x-forwarded-for': req.get('X-Forwarded-For'),
        'x-real-ip': req.get('X-Real-IP'),
        'cf-connecting-ip': req.get('CF-Connecting-IP'),
      },
      timestamp: new Date().toISOString(),
    };

    // Use appropriate log level based on error severity
    const severity = errorClassificationService.getErrorSeverity(error);

    switch (severity) {
    case 'critical':
      safeLogger.error('Critical error occurred', logContext);
      break;
    case 'high':
      safeLogger.error('High severity error', logContext);
      break;
    case 'medium':
      safeLogger.warn('Medium severity error', logContext);
      break;
    case 'low':
      safeLogger.info('Low severity error', logContext);
      break;
    default:
      safeLogger.error('Unknown severity error', logContext);
    }

    // Send alerts for critical and high severity errors
    if (errorClassificationService.shouldAlert(error)) {
      sendAlert(error, logContext);
    }
  } catch (handlerError) {
    // Fallback error handling if our error handler fails
    safeLogger.error('Error handler failed', {
      originalError: error.message,
      handlerError: handlerError.message,
      correlationId: req.correlationId,
    });

    // Send generic error response
    res.status(500).json({
      error: {
        message: 'Internal server error',
        type: 'system_error',
        code: 'ERROR_HANDLER_FAILED',
        statusCode: 500,
        correlationId: req.correlationId || 'unknown',
        timestamp: new Date().toISOString(),
      },
    });
  }
};

// Async error handler for async routes
export const asyncErrorHandler = fn => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// Error handler for specific error types
export const handleValidationError = (error, req, res, next) => {
  error.type = 'VALIDATION_ERROR';
  next(error);
};

export const handleAuthenticationError = (error, req, res, next) => {
  error.type = 'AUTHENTICATION_ERROR';
  next(error);
};

export const handleAuthorizationError = (error, req, res, next) => {
  error.type = 'AUTHORIZATION_ERROR';
  next(error);
};

export const handleDatabaseError = (error, req, res, next) => {
  error.type = 'DATABASE_ERROR';
  next(error);
};

export const handleNetworkError = (error, req, res, next) => {
  error.type = 'NETWORK_ERROR';
  next(error);
};

// Rate limit error handler
export const handleRateLimitError = (error, req, res, next) => {
  error.type = 'RATE_LIMIT_ERROR';
  next(error);
};

// Not found error handler
export const handleNotFoundError = (req, res, next) => {
  const error = new Error('Resource not found');
  error.type = 'NOT_FOUND_ERROR';
  error.statusCode = 404;
  next(error);
};

// Method not allowed error handler
export const handleMethodNotAllowedError = (req, res, next) => {
  const error = new Error(`Method ${req.method} not allowed`);
  error.type = 'METHOD_NOT_ALLOWED_ERROR';
  error.statusCode = 405;
  next(error);
};

// Request timeout error handler
export const handleTimeoutError = (error, req, res, next) => {
  error.type = 'TIMEOUT_ERROR';
  next(error);
};

// Cache error handler
export const handleCacheError = (error, req, res, next) => {
  error.type = 'CACHE_ERROR';
  next(error);
};

// Security error handler
export const handleSecurityError = (error, req, res, next) => {
  error.type = 'SECURITY_ERROR';
  next(error);
};

// Function to send alerts (would integrate with alerting system)
function sendAlert(error, context) {
  // This would integrate with your alerting system (PagerDuty, Slack, etc.)
  const alert = {
    severity: errorClassificationService.getErrorSeverity(error),
    title: `Error Alert: ${error.message}`,
    message: 'An error occurred in the authentication service',
    context: {
      correlationId: context.correlationId,
      endpoint: context.endpoint,
      method: context.method,
      userId: context.userId,
      ipAddress: context.ipAddress,
    },
    timestamp: new Date().toISOString(),
  };

  // Log alert (replace with actual alerting system)
  safeLogger.error('ALERT: Critical error detected', alert);

  // Example: Send to external alerting service
  // await alertingService.sendAlert(alert);
}

// Error monitoring and reporting
export const errorMonitoring = {
  // Track error patterns
  trackErrorPattern: (error, req) => {
    const pattern = {
      type: error.type || 'UNKNOWN',
      endpoint: req.originalUrl,
      method: req.method,
      userId: req.user?.id,
      ipAddress: req.ip,
      timestamp: new Date().toISOString(),
    };

    // Store error pattern for analysis
    // This would integrate with your monitoring system
    safeLogger.info('Error pattern tracked', pattern);
  },

  // Get error statistics
  getErrorStats: () => {
    // This would return error statistics from your monitoring system
    return {
      totalErrors: 0,
      errorsByType: {},
      errorsByEndpoint: {},
      errorsBySeverity: {},
      timestamp: new Date().toISOString(),
    };
  },

  // Check if error rate is abnormal
  isErrorRateAbnormal: () => {
    // This would check error rates against thresholds
    return false;
  },
};

// Export all error handlers
export const errorHandlers = {
  enhancedErrorHandler,
  asyncErrorHandler,
  handleValidationError,
  handleAuthenticationError,
  handleAuthorizationError,
  handleDatabaseError,
  handleNetworkError,
  handleRateLimitError,
  handleNotFoundError,
  handleMethodNotAllowedError,
  handleTimeoutError,
  handleCacheError,
  handleSecurityError,
  errorMonitoring,
};
