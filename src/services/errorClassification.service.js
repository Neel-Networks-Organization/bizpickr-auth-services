/**
 * Error Classification Service
 * Provides intelligent error classification and handling strategies
 */

import { safeLogger } from '../config/logger.js';
import { metricsService } from './metrics.service.js';

class ErrorClassificationService {
  constructor() {
    this.errorTypes = {
      // Client Errors (4xx)
      VALIDATION_ERROR: {
        category: 'client_error',
        severity: 'low',
        retryable: false,
        statusCode: 400,
        userMessage: 'Invalid request data provided',
      },
      AUTHENTICATION_ERROR: {
        category: 'security_error',
        severity: 'medium',
        retryable: false,
        statusCode: 401,
        userMessage: 'Authentication failed',
      },
      AUTHORIZATION_ERROR: {
        category: 'security_error',
        severity: 'medium',
        retryable: false,
        statusCode: 403,
        userMessage: 'Access denied',
      },
      RATE_LIMIT_ERROR: {
        category: 'client_error',
        severity: 'low',
        retryable: true,
        statusCode: 429,
        userMessage: 'Too many requests. Please try again later',
        retryAfter: 60,
      },
      NOT_FOUND_ERROR: {
        category: 'client_error',
        severity: 'low',
        retryable: false,
        statusCode: 404,
        userMessage: 'Resource not found',
      },

      // Server Errors (5xx)
      DATABASE_ERROR: {
        category: 'infrastructure_error',
        severity: 'high',
        retryable: true,
        statusCode: 503,
        userMessage: 'Service temporarily unavailable',
        maxRetries: 3,
      },
      NETWORK_ERROR: {
        category: 'infrastructure_error',
        severity: 'medium',
        retryable: true,
        statusCode: 503,
        userMessage: 'Network connection error',
        maxRetries: 5,
      },
      TIMEOUT_ERROR: {
        category: 'infrastructure_error',
        severity: 'medium',
        retryable: true,
        statusCode: 504,
        userMessage: 'Request timeout',
        maxRetries: 2,
      },
      CACHE_ERROR: {
        category: 'infrastructure_error',
        severity: 'low',
        retryable: true,
        statusCode: 503,
        userMessage: 'Service temporarily unavailable',
        maxRetries: 3,
      },
      UNKNOWN_ERROR: {
        category: 'system_error',
        severity: 'critical',
        retryable: false,
        statusCode: 500,
        userMessage: 'Internal server error',
      },
    };

    this.severityLevels = {
      low: 1,
      medium: 2,
      high: 3,
      critical: 4,
    };
  }

  classifyError(error) {
    // Check if error has a predefined type
    if (error.type && this.errorTypes[error.type]) {
      return this.errorTypes[error.type];
    }

    // Classify based on error message patterns
    const message = error.message?.toLowerCase() || '';
    const stack = error.stack?.toLowerCase() || '';

    // Database errors
    if (
      message.includes('database') ||
      message.includes('sequelize') ||
      message.includes('connection') ||
      message.includes('timeout')
    ) {
      return this.errorTypes.DATABASE_ERROR;
    }

    // Network errors
    if (
      message.includes('network') ||
      message.includes('connection') ||
      message.includes('econnrefused') ||
      message.includes('enotfound')
    ) {
      return this.errorTypes.NETWORK_ERROR;
    }

    // Validation errors
    if (
      message.includes('validation') ||
      message.includes('invalid') ||
      message.includes('required') ||
      message.includes('format')
    ) {
      return this.errorTypes.VALIDATION_ERROR;
    }

    // Authentication errors
    if (
      message.includes('authentication') ||
      message.includes('unauthorized') ||
      message.includes('invalid token') ||
      message.includes('expired')
    ) {
      return this.errorTypes.AUTHENTICATION_ERROR;
    }

    // Authorization errors
    if (
      message.includes('authorization') ||
      message.includes('forbidden') ||
      message.includes('permission') ||
      message.includes('access denied')
    ) {
      return this.errorTypes.AUTHORIZATION_ERROR;
    }

    // Rate limit errors
    if (
      message.includes('rate limit') ||
      message.includes('too many requests') ||
      message.includes('throttle')
    ) {
      return this.errorTypes.RATE_LIMIT_ERROR;
    }

    // Cache errors
    if (
      message.includes('cache') ||
      message.includes('redis') ||
      message.includes('memory')
    ) {
      return this.errorTypes.CACHE_ERROR;
    }

    // Default to unknown error
    return this.errorTypes.UNKNOWN_ERROR;
  }

  getErrorSeverity(error) {
    const classification = this.classifyError(error);
    return classification.severity;
  }

  shouldRetry(error, attemptCount = 0) {
    const classification = this.classifyError(error);

    if (!classification.retryable) {
      return false;
    }

    const maxRetries = classification.maxRetries || 3;
    return attemptCount < maxRetries;
  }

  getRetryDelay(error, attemptCount = 0) {
    const classification = this.classifyError(error);

    if (!classification.retryable) {
      return 0;
    }

    // Exponential backoff with jitter
    const baseDelay = 1000; // 1 second
    const maxDelay = 30000; // 30 seconds
    const exponentialDelay = baseDelay * Math.pow(2, attemptCount);
    const jitter = Math.random() * 1000; // Random jitter up to 1 second

    return Math.min(exponentialDelay + jitter, maxDelay);
  }

  createErrorResponse(error, req) {
    const classification = this.classifyError(error);
    const correlationId = req.correlationId || this.generateCorrelationId();

    // Record error metrics
    this.recordErrorMetrics(classification);

    // Log error with context
    this.logError(error, classification, req);

    const response = {
      error: {
        message: classification.userMessage,
        type: classification.category,
        code: error.code || 'UNKNOWN_ERROR',
        statusCode: classification.statusCode,
        correlationId,
        timestamp: new Date().toISOString(),
      },
    };

    // Add retry information for retryable errors
    if (classification.retryable) {
      response.error.retryable = true;
      response.error.retryAfter = classification.retryAfter || 30;
      response.error.maxRetries = classification.maxRetries || 3;
    }

    // Add additional context in development
    if (process.env.NODE_ENV === 'development') {
      response.error.details = {
        originalMessage: error.message,
        stack: error.stack,
        endpoint: req.originalUrl,
        method: req.method,
        userId: req.user?.id,
      };
    }

    return response;
  }

  recordErrorMetrics(classification) {
    const metricMap = {
      client_error: 'validationErrors',
      security_error: 'authenticationErrors',
      infrastructure_error: 'databaseErrors',
      system_error: 'networkErrors',
    };

    const metricName = metricMap[classification.category];
    if (metricName) {
      metricsService.incrementMetric(metricName);
    }
  }

  logError(error, classification, req) {
    const logContext = {
      error: error.message,
      stack: error.stack,
      type: classification.category,
      severity: classification.severity,
      statusCode: classification.statusCode,
      correlationId: req.correlationId,
      userId: req.user?.id,
      endpoint: req.originalUrl,
      method: req.method,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString(),
    };

    // Use appropriate log level based on severity
    switch (classification.severity) {
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
  }

  generateCorrelationId() {
    return `corr_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  isSecurityError(error) {
    const classification = this.classifyError(error);
    return classification.category === 'security_error';
  }

  isInfrastructureError(error) {
    const classification = this.classifyError(error);
    return classification.category === 'infrastructure_error';
  }

  getErrorPriority(error) {
    const classification = this.classifyError(error);
    return this.severityLevels[classification.severity] || 1;
  }

  shouldAlert(error) {
    const classification = this.classifyError(error);
    return (
      classification.severity === 'critical' ||
      classification.severity === 'high'
    );
  }

  getErrorSummary() {
    return {
      totalErrors: 0, // Would be calculated from metrics
      criticalErrors: 0,
      highSeverityErrors: 0,
      retryableErrors: 0,
      securityErrors: 0,
      infrastructureErrors: 0,
      timestamp: new Date().toISOString(),
    };
  }
}

export const errorClassificationService = new ErrorClassificationService();
