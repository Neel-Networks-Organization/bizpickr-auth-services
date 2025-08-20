import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';

/**
 * Smart Performance Middleware
 * Basic performance monitoring without over-engineering
 */

/**
 * Performance configuration
 */
const PERFORMANCE_CONFIG = {
  // Slow request threshold (1 second)
  slowRequestThreshold: 1000,

  // Enable performance logging
  enabled: true,

  // Log slow requests
  logSlowRequests: true,

  // Log all requests
  logAllRequests: false,

  // Exclude paths from performance monitoring
  excludePaths: ['/health', '/metrics', '/favicon.ico'],
};

/**
 * Check if path should be excluded
 */
function shouldExcludePath(path) {
  return PERFORMANCE_CONFIG.excludePaths.some(excludePath =>
    path.startsWith(excludePath)
  );
}

/**
 * Main performance middleware
 */
export const performanceMiddleware = (options = {}) => {
  const config = { ...PERFORMANCE_CONFIG, ...options };

  return (req, res, next) => {
    if (!config.enabled) {
      return next();
    }

    const correlationId = getCorrelationId();
    const startTime = Date.now();

    // Skip performance monitoring for excluded paths
    if (shouldExcludePath(req.path)) {
      return next();
    }

    // Override response end to measure performance
    const originalEnd = res.end;
    res.end = function (...args) {
      const duration = Date.now() - startTime;

      // Log slow requests
      if (config.logSlowRequests && duration > config.slowRequestThreshold) {
        safeLogger.warn('Slow request detected', {
          correlationId,
          method: req.method,
          path: req.path,
          duration: `${duration}ms`,
          threshold: `${config.slowRequestThreshold}ms`,
          userId: req.user?.id || 'anonymous',
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          timestamp: new Date().toISOString(),
        });
      }

      // Log all requests if enabled
      if (config.logAllRequests) {
        safeLogger.info('Request performance', {
          correlationId,
          method: req.method,
          path: req.path,
          duration: `${duration}ms`,
          statusCode: res.statusCode,
          userId: req.user?.id || 'anonymous',
          timestamp: new Date().toISOString(),
        });
      }

      // Set performance headers
      res.set('X-Response-Time', `${duration}ms`);

      originalEnd.apply(this, args);
    };

    next();
  };
};

/**
 * Memory usage monitoring middleware
 */
export const memoryMonitor = (req, res, next) => {
  const correlationId = getCorrelationId();

  try {
    const memoryUsage = process.memoryUsage();
    const memoryMB = {
      rss: Math.round(memoryUsage.rss / 1024 / 1024),
      heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024),
      heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024),
      external: Math.round(memoryUsage.external / 1024 / 1024),
    };

    // Log high memory usage
    if (memoryMB.heapUsed > 100) {
      // 100MB threshold
      safeLogger.warn('High memory usage detected', {
        correlationId,
        path: req.path,
        memoryUsage: memoryMB,
        timestamp: new Date().toISOString(),
      });
    }

    // Set memory headers
    res.set('X-Memory-Usage', `${memoryMB.heapUsed}MB`);

    next();
  } catch (error) {
    safeLogger.error('Memory monitoring error', {
      error: error.message,
      correlationId,
    });
    next();
  }
};

/**
 * Database query timing middleware (if using Sequelize)
 */
export const queryTimer = (req, res, next) => {
  const correlationId = getCorrelationId();

  try {
    // This would integrate with Sequelize if available
    // For now, just pass through
    next();
  } catch (error) {
    safeLogger.error('Query timer error', {
      error: error.message,
      correlationId,
    });
    next();
  }
};

/**
 * Response size monitoring middleware
 */
export const responseSizeMonitor = (req, res, next) => {
  const correlationId = getCorrelationId();

  try {
    // Override response methods to monitor size
    const originalSend = res.send;
    const originalJson = res.json;

    res.send = function (body) {
      const size = body ? body.length : 0;

      // Log large responses
      if (size > 1024 * 1024) {
        // 1MB threshold
        safeLogger.warn('Large response detected', {
          correlationId,
          path: req.path,
          responseSize: `${Math.round((size / 1024 / 1024) * 100) / 100}MB`,
          timestamp: new Date().toISOString(),
        });
      }

      // Set size header
      res.set('X-Response-Size', `${size} bytes`);

      return originalSend.call(this, body);
    };

    res.json = function (body) {
      const jsonString = JSON.stringify(body);
      const size = jsonString.length;

      // Log large JSON responses
      if (size > 1024 * 1024) {
        // 1MB threshold
        safeLogger.warn('Large JSON response detected', {
          correlationId,
          path: req.path,
          responseSize: `${Math.round((size / 1024 / 1024) * 100) / 100}MB`,
          timestamp: new Date().toISOString(),
        });
      }

      // Set size header
      res.set('X-Response-Size', `${size} bytes`);

      return originalJson.call(this, body);
    };

    next();
  } catch (error) {
    safeLogger.error('Response size monitor error', {
      error: error.message,
      correlationId,
    });
    next();
  }
};

/**
 * Combined performance middleware
 */
export const fullPerformanceMiddleware = (options = {}) => {
  return [performanceMiddleware(options), memoryMonitor, responseSizeMonitor];
};

/**
 * Get performance configuration
 */
export const getPerformanceConfig = () => {
  return { ...PERFORMANCE_CONFIG };
};

/**
 * Update performance configuration
 */
export const updatePerformanceConfig = newConfig => {
  Object.assign(PERFORMANCE_CONFIG, newConfig);
  safeLogger.info('Performance configuration updated', {
    newConfig: PERFORMANCE_CONFIG,
  });
};

export default {
  performanceMiddleware,
  memoryMonitor,
  queryTimer,
  responseSizeMonitor,
  fullPerformanceMiddleware,
  getPerformanceConfig,
  updatePerformanceConfig,
};
