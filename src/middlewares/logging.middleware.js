import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';

/**
 * Industry-Standard Logging Middleware
 * Professional logging with performance metrics, analytics, and advanced features
 */
class SimpleLoggingMiddleware {
  constructor() {
    this.config = {
      enabled: true,
      logLevel: 'info',
      logRequests: true,
      logErrors: true,
      logPerformance: true,
      logAnalytics: true,
      logSecurity: true,
      logUserBehavior: true,
      compressionThreshold: 1024, // 1KB
      maxLogSize: 10000, // 10KB
      enableMetrics: true,
    };
    
    this.metrics = {
      totalRequests: 0,
      totalErrors: 0,
      averageResponseTime: 0,
      slowRequests: 0,
      statusCodes: {},
      userAgents: {},
      ipAddresses: {},
      endpoints: {},
      lastReset: Date.now(),
    };
    
    this._startMetricsCollection();
  }

  /**
   * Main logging middleware function with advanced features
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Next middleware function
   */
  log(req, res, next) {
    if (!this.config.enabled) {
      return next();
    }

    const correlationId = getCorrelationId();
    const startTime = Date.now();
    const requestId = this._generateRequestId();

    // Add request context
    req.requestId = requestId;
    req.startTime = startTime;

    try {
      // Update metrics
      this._updateRequestMetrics(req);

      // Log incoming request with enhanced details
      if (this.config.logRequests) {
        const requestLog = this._createRequestLog(req, correlationId, requestId);
        safeLogger.info('Request received', requestLog);
      }

      // Security logging
      if (this.config.logSecurity) {
        this._logSecurityEvents(req, correlationId);
      }

      // User behavior logging
      if (this.config.logUserBehavior) {
        this._logUserBehavior(req, correlationId);
      }

      // Override response end for comprehensive logging
      const originalEnd = res.end;
      res.end = function(chunk, encoding) {
        const responseTime = Date.now() - startTime;
        const responseSize = chunk ? chunk.length : 0;
        
        // Update response metrics
        this._updateResponseMetrics(req, res, responseTime, responseSize);
        
        if (this.config.logRequests) {
          const responseLog = this._createResponseLog(req, res, responseTime, responseSize, correlationId, requestId);
          safeLogger.info('Request completed', responseLog);
        }

        // Performance logging
        if (this.config.logPerformance) {
          this._logPerformanceMetrics(req, res, responseTime, responseSize, correlationId);
        }

        // Analytics logging
        if (this.config.logAnalytics) {
          this._logAnalytics(req, res, responseTime, correlationId);
        }
        
        originalEnd.call(this, chunk, encoding);
      }.bind(this);

      next();
    } catch (error) {
      safeLogger.error('Logging middleware error', {
        error: error.message,
        correlationId,
        requestId,
      });
      next();
    }
  }

  /**
   * Log error with advanced details
   * @param {Object} req - Request object
   * @param {Object} res - Response object
   * @param {Error} error - Error object
   */
  logError(req, res, error) {
    if (!this.config.logErrors) return;

    const correlationId = getCorrelationId();
    const requestId = req.requestId || 'unknown';
    
    // Update error metrics
    this._updateErrorMetrics(req, error);
    
    safeLogger.error('Request error', {
      method: req.method,
      url: req.originalUrl || req.url,
      error: error.message,
      stack: error.stack,
      correlationId,
      requestId,
      userId: req.user?._id,
      userAgent: req.headers['user-agent'],
      ip: req.ip || req.connection?.remoteAddress,
      requestBody: this._sanitizeRequestBody(req.body),
      queryParams: req.query,
      headers: this._sanitizeHeaders(req.headers),
    });
  }

  /**
   * Generate unique request ID
   */
  _generateRequestId() {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Create comprehensive request log
   */
  _createRequestLog(req, correlationId, requestId) {
    return {
      method: req.method,
      url: req.originalUrl || req.url,
      ip: req.ip || req.connection?.remoteAddress,
      userAgent: req.headers['user-agent'],
      correlationId,
      requestId,
      userId: req.user?._id,
      contentType: req.headers['content-type'],
      contentLength: req.headers['content-length'],
      referer: req.headers.referer,
      origin: req.headers.origin,
      timestamp: new Date().toISOString(),
      queryParams: Object.keys(req.query).length > 0 ? req.query : undefined,
      requestBody: this._sanitizeRequestBody(req.body),
    };
  }

  /**
   * Create comprehensive response log
   */
  _createResponseLog(req, res, responseTime, responseSize, correlationId, requestId) {
    return {
      method: req.method,
      url: req.originalUrl || req.url,
      statusCode: res.statusCode,
      responseTime: `${responseTime}ms`,
      responseSize: `${responseSize} bytes`,
      correlationId,
      requestId,
      userId: req.user?._id,
      contentType: res.get('content-type'),
      cacheControl: res.get('cache-control'),
      timestamp: new Date().toISOString(),
      isSlow: responseTime > 1000, // Flag slow requests
    };
  }

  /**
   * Update request metrics
   */
  _updateRequestMetrics(req) {
    this.metrics.totalRequests++;
    
    const endpoint = req.originalUrl || req.url;
    this.metrics.endpoints[endpoint] = (this.metrics.endpoints[endpoint] || 0) + 1;
    
    const ip = req.ip || req.connection?.remoteAddress;
    if (ip) {
      this.metrics.ipAddresses[ip] = (this.metrics.ipAddresses[ip] || 0) + 1;
    }
    
    const userAgent = req.headers['user-agent'];
    if (userAgent) {
      this.metrics.userAgents[userAgent] = (this.metrics.userAgents[userAgent] || 0) + 1;
    }
  }

  /**
   * Update response metrics
   */
  _updateResponseMetrics(req, res, responseTime, responseSize) {
    const statusCode = res.statusCode;
    this.metrics.statusCodes[statusCode] = (this.metrics.statusCodes[statusCode] || 0) + 1;
    
    // Update average response time
    const totalRequests = this.metrics.totalRequests;
    this.metrics.averageResponseTime = 
      ((this.metrics.averageResponseTime * (totalRequests - 1)) + responseTime) / totalRequests;
    
    // Track slow requests
    if (responseTime > 1000) {
      this.metrics.slowRequests++;
    }
  }

  /**
   * Update error metrics
   */
  _updateErrorMetrics(req, error) {
    this.metrics.totalErrors++;
    
    const errorType = error.constructor.name;
    if (!this.metrics.errorTypes) {
      this.metrics.errorTypes = {};
    }
    this.metrics.errorTypes[errorType] = (this.metrics.errorTypes[errorType] || 0) + 1;
  }

  /**
   * Log security events
   */
  _logSecurityEvents(req, correlationId) {
    const securityEvents = [];
    
    // Check for suspicious patterns
    if (req.headers['user-agent']?.includes('bot') || req.headers['user-agent']?.includes('crawler')) {
      securityEvents.push('bot_detected');
    }
    
    if (req.ip && this._isPrivateIP(req.ip)) {
      securityEvents.push('private_ip_access');
    }
    
    if (req.headers['x-forwarded-for']) {
      securityEvents.push('proxied_request');
    }
    
    if (securityEvents.length > 0) {
      safeLogger.info('Security events detected', {
        events: securityEvents,
        correlationId,
        ip: req.ip || req.connection?.remoteAddress,
        userAgent: req.headers['user-agent'],
      });
    }
  }

  /**
   * Log user behavior
   */
  _logUserBehavior(req, correlationId) {
    if (req.user) {
      safeLogger.debug('User behavior tracked', {
        userId: req.user._id,
        email: req.user.email,
        action: req.method,
        resource: req.originalUrl || req.url,
        correlationId,
        timestamp: new Date().toISOString(),
      });
    }
  }

  /**
   * Log performance metrics
   */
  _logPerformanceMetrics(req, res, responseTime, responseSize, correlationId) {
    if (responseTime > 1000) {
      safeLogger.warn('Slow request detected', {
        method: req.method,
        url: req.originalUrl || req.url,
        responseTime: `${responseTime}ms`,
        responseSize: `${responseSize} bytes`,
        correlationId,
        userId: req.user?._id,
      });
    }
  }

  /**
   * Log analytics data
   */
  _logAnalytics(req, res, responseTime, correlationId) {
    const analyticsData = {
      endpoint: req.originalUrl || req.url,
      method: req.method,
      statusCode: res.statusCode,
      responseTime,
      userId: req.user?._id,
      userRole: req.user?.role?.name || req.user?.role || 'anonymous',
      timestamp: new Date().toISOString(),
      correlationId,
    };
    
    safeLogger.debug('Analytics data', analyticsData);
  }

  /**
   * Sanitize request body for logging
   */
  _sanitizeRequestBody(body) {
    if (!body || typeof body !== 'object') return body;
    
    const sanitized = { ...body };
    const sensitiveFields = ['password', 'token', 'secret', 'key', 'authorization'];
    
    sensitiveFields.forEach(field => {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    });
    
    return sanitized;
  }

  /**
   * Sanitize headers for logging
   */
  _sanitizeHeaders(headers) {
    if (!headers || typeof headers !== 'object') return headers;
    
    const sanitized = { ...headers };
    const sensitiveHeaders = ['authorization', 'cookie', 'x-api-key'];
    
    sensitiveHeaders.forEach(header => {
      if (sanitized[header]) {
        sanitized[header] = '[REDACTED]';
      }
    });
    
    return sanitized;
  }

  /**
   * Check if IP is private
   */
  _isPrivateIP(ip) {
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^127\./,
      /^169\.254\./,
      /^::1$/,
      /^fc00:/,
      /^fe80:/,
    ];
    
    return privateRanges.some(range => range.test(ip));
  }

  /**
   * Start metrics collection
   */
  _startMetricsCollection() {
    setInterval(() => {
      this._resetMetrics();
    }, 300000); // Reset every 5 minutes
  }

  /**
   * Reset metrics
   */
  _resetMetrics() {
    this.metrics = {
      totalRequests: 0,
      totalErrors: 0,
      averageResponseTime: 0,
      slowRequests: 0,
      statusCodes: {},
      userAgents: {},
      ipAddresses: {},
      endpoints: {},
      errorTypes: {},
      lastReset: Date.now(),
    };
  }

  /**
   * Get current metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      uptime: Date.now() - this.metrics.lastReset,
      errorRate: this.metrics.totalRequests > 0 
        ? (this.metrics.totalErrors / this.metrics.totalRequests * 100).toFixed(2)
        : 0,
    };
  }

  /**
   * Get performance summary
   */
  getPerformanceSummary() {
    return {
      totalRequests: this.metrics.totalRequests,
      averageResponseTime: `${this.metrics.averageResponseTime.toFixed(2)}ms`,
      slowRequests: this.metrics.slowRequests,
      errorRate: `${this.getMetrics().errorRate}%`,
      topEndpoints: Object.entries(this.metrics.endpoints)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 5)
        .map(([endpoint, count]) => ({ endpoint, count })),
      topStatusCodes: Object.entries(this.metrics.statusCodes)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 5)
        .map(([status, count]) => ({ status, count })),
    };
  }
}

// ✅ Create singleton instance
const simpleLoggingMiddleware = new SimpleLoggingMiddleware();

// ✅ Export middleware function
export const loggingMiddleware = (req, res, next) => {
  simpleLoggingMiddleware.log(req, res, next);
};

// ✅ Export error logging
export const logError = (req, res, error) => {
  simpleLoggingMiddleware.logError(req, res, error);
};

// ✅ Export metrics and utility functions
export const getLoggingMetrics = () => simpleLoggingMiddleware.getMetrics();
export const getPerformanceSummary = () => simpleLoggingMiddleware.getPerformanceSummary();

// ✅ Export default
export default simpleLoggingMiddleware;
