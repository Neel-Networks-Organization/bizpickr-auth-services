import { performance } from 'perf_hooks';
import { safeLogger } from '../config/logger.js';
/**
 * Performance Middleware
 *
 * Features:
 * - Request timing and performance monitoring
 * - Response time tracking
 * - Memory usage monitoring
 * - Performance metrics collection
 * - Slow request detection
 * - Performance alerts
 * - Request/response size tracking
 * - Database query timing (if applicable)
 * - Performance profiling
 * - Metrics aggregation
 */
// ✅ Performance Configuration
const PERFORMANCE_CONFIG = {
  slowRequestThreshold: 1000, // 1 second
  memoryThreshold: 100 * 1024 * 1024, // 100MB
  enableProfiling: process.env.NODE_ENV === 'development',
  metricsCollection: true,
  alertOnSlowRequests: true,
  trackMemoryUsage: true,
  trackResponseSize: true,
  trackRequestSize: true,
};
// ✅ Performance Metrics Storage
const performanceMetrics = {
  totalRequests: 0,
  slowRequests: 0,
  averageResponseTime: 0,
  totalResponseTime: 0,
  memoryUsage: [],
  responseSizes: [],
  requestSizes: [],
  errors: 0,
  startTime: Date.now(),
};
// ✅ Performance Alert System
const performanceAlerts = {
  slowRequests: [],
  highMemoryUsage: [],
  errors: [],
};
/**
 * Calculate average response time
 */
function calculateAverageResponseTime() {
  if (performanceMetrics.totalRequests > 0) {
    performanceMetrics.averageResponseTime =
      performanceMetrics.totalResponseTime / performanceMetrics.totalRequests;
  }
  return performanceMetrics.averageResponseTime;
}
/**
 * Get performance statistics
 */
export function getPerformanceStats() {
  return {
    ...performanceMetrics,
    averageResponseTime: calculateAverageResponseTime(),
    uptime: Date.now() - performanceMetrics.startTime,
    requestsPerSecond:
      performanceMetrics.totalRequests /
      ((Date.now() - performanceMetrics.startTime) / 1000),
    slowRequestPercentage:
      performanceMetrics.totalRequests > 0
        ? (performanceMetrics.slowRequests / performanceMetrics.totalRequests) *
          100
        : 0,
    errorRate:
      performanceMetrics.totalRequests > 0
        ? (performanceMetrics.errors / performanceMetrics.totalRequests) * 100
        : 0,
  };
}
/**
 * Performance monitoring middleware
 */
export const performanceMiddleware = (req, res, next) => {
  const startTime = performance.now();
  const startMemory = process.memoryUsage();
  const requestSize = req.headers['content-length']
    ? parseInt(req.headers['content-length'])
    : 0;
  // ✅ Track request start
  performanceMetrics.totalRequests++;
  if (PERFORMANCE_CONFIG.trackRequestSize && requestSize > 0) {
    performanceMetrics.requestSizes.push(requestSize);
  }
  // ✅ Store original send method
  const originalSend = res.send;
  const originalJson = res.json;
  const originalEnd = res.end;

  // Set X-Request-ID as soon as possible
  if (!res.headersSent) {
    res.setHeader('X-Request-ID', req.correlationId);
  }

  // Helper to set X-Response-Time before sending response
  function setResponseTimeHeader() {
    const endTime = performance.now();
    const responseTime = endTime - startTime;
    if (!res.headersSent) {
      res.setHeader('X-Response-Time', `${responseTime.toFixed(2)}ms`);
    }
  }

  // ✅ Override response methods to track response size and set headers
  res.send = function(data) {
    setResponseTimeHeader();
    if (PERFORMANCE_CONFIG.trackResponseSize) {
      const responseSize =
        typeof data === 'string'
          ? Buffer.byteLength(data)
          : JSON.stringify(data).length;
      performanceMetrics.responseSizes.push(responseSize);
    }
    return originalSend.call(this, data);
  };
  res.json = function(data) {
    setResponseTimeHeader();
    if (PERFORMANCE_CONFIG.trackResponseSize) {
      const responseSize = JSON.stringify(data).length;
      performanceMetrics.responseSizes.push(responseSize);
    }
    return originalJson.call(this, data);
  };
  res.end = function(data) {
    setResponseTimeHeader();
    if (PERFORMANCE_CONFIG.trackResponseSize && data) {
      const responseSize =
        typeof data === 'string' ? Buffer.byteLength(data) : data.length;
      performanceMetrics.responseSizes.push(responseSize);
    }
    return originalEnd.call(this, data);
  };

  // ✅ Track response completion (metrics, logging, etc.)
  res.on('finish', () => {
    const endTime = performance.now();
    const responseTime = endTime - startTime;
    const endMemory = process.memoryUsage();
    // ✅ Update metrics
    performanceMetrics.totalResponseTime += responseTime;
    // ✅ Track memory usage
    if (PERFORMANCE_CONFIG.trackMemoryUsage) {
      const memoryDiff = {
        heapUsed: endMemory.heapUsed - startMemory.heapUsed,
        heapTotal: endMemory.heapTotal - startMemory.heapTotal,
        external: endMemory.external - startMemory.external,
        rss: endMemory.rss - startMemory.rss,
        timestamp: Date.now(),
      };
      performanceMetrics.memoryUsage.push(memoryDiff);
      // ✅ Keep only last 1000 memory readings
      if (performanceMetrics.memoryUsage.length > 1000) {
        performanceMetrics.memoryUsage =
          performanceMetrics.memoryUsage.slice(-1000);
      }
    }
    // ✅ Track errors
    if (res.statusCode >= 400) {
      performanceMetrics.errors++;
    }
    // ✅ Slow request detection
    if (responseTime > PERFORMANCE_CONFIG.slowRequestThreshold) {
      performanceMetrics.slowRequests++;
      if (PERFORMANCE_CONFIG.alertOnSlowRequests) {
        const slowRequestAlert = {
          url: req.url,
          method: req.method,
          responseTime,
          statusCode: res.statusCode,
          timestamp: new Date().toISOString(),
          correlationId: req.correlationId,
          userAgent: req.get('User-Agent'),
          ip: req.ip,
        };
        performanceAlerts.slowRequests.push(slowRequestAlert);
        // ✅ Keep only last 100 slow request alerts
        if (performanceAlerts.slowRequests.length > 100) {
          performanceAlerts.slowRequests =
            performanceAlerts.slowRequests.slice(-100);
        }
        safeLogger.warn('Slow request detected', slowRequestAlert);
      }
    }
    // ✅ High memory usage detection
    if (
      PERFORMANCE_CONFIG.trackMemoryUsage &&
      endMemory.heapUsed > PERFORMANCE_CONFIG.memoryThreshold
    ) {
      const memoryAlert = {
        heapUsed: endMemory.heapUsed,
        heapTotal: endMemory.heapTotal,
        external: endMemory.external,
        rss: endMemory.rss,
        url: req.url,
        method: req.method,
        timestamp: new Date().toISOString(),
        correlationId: req.correlationId,
      };
      performanceAlerts.highMemoryUsage.push(memoryAlert);
      // ✅ Keep only last 50 memory alerts
      if (performanceAlerts.highMemoryUsage.length > 50) {
        performanceAlerts.highMemoryUsage =
          performanceAlerts.highMemoryUsage.slice(-50);
      }
      safeLogger.warn('High memory usage detected', memoryAlert);
    }
    // ✅ Performance logging
    if (PERFORMANCE_CONFIG.enableProfiling) {
      safeLogger.debug('Request performance', {
        url: req.url,
        method: req.method,
        responseTime: `${responseTime.toFixed(2)}ms`,
        statusCode: res.statusCode,
        correlationId: req.correlationId,
        memoryUsage: endMemory,
        requestSize,
        responseSize:
          performanceMetrics.responseSizes[
            performanceMetrics.responseSizes.length - 1
          ] || 0,
      });
    }
    // ✅ Update app-level metrics
    if (req.app) {
      req.app.set('totalRequests', performanceMetrics.totalRequests);
      req.app.set('averageResponseTime', calculateAverageResponseTime());
      req.app.set('slowRequests', performanceMetrics.slowRequests);
    }
  });
  // ✅ Add performance context to request
  req.performanceContext = {
    startTime,
    startMemory,
    requestSize,
    correlationId: req.correlationId,
  };
  next();
};
/**
 * Get performance alerts
 */
export function getPerformanceAlerts() {
  return performanceAlerts;
}
/**
 * Clear performance metrics
 */
export function clearPerformanceMetrics() {
  Object.assign(performanceMetrics, {
    totalRequests: 0,
    slowRequests: 0,
    averageResponseTime: 0,
    totalResponseTime: 0,
    memoryUsage: [],
    responseSizes: [],
    requestSizes: [],
    errors: 0,
    startTime: Date.now(),
  });
}
/**
 * Performance monitoring endpoint middleware
 */
export const performanceMonitoringMiddleware = (req, res, next) => {
  if (req.path === '/metrics' || req.path === '/performance') {
    const stats = getPerformanceStats();
    const alerts = getPerformanceAlerts();
    res.json({
      timestamp: new Date().toISOString(),
      stats,
      alerts,
      config: PERFORMANCE_CONFIG,
    });
  } else {
    next();
  }
};
/**
 * Performance profiling middleware (development only)
 */
export const performanceProfilingMiddleware = (req, res, next) => {
  if (!PERFORMANCE_CONFIG.enableProfiling) {
    return next();
  }
  const profile = {
    url: req.url,
    method: req.method,
    startTime: performance.now(),
    memoryStart: process.memoryUsage(),
    steps: [],
  };
  // ✅ Add profiling to request
  req.profile = profile;
  // ✅ Override next to track middleware execution
  const originalNext = next;
  next = function(err) {
    const stepTime = performance.now() - profile.startTime;
    profile.steps.push({
      step: 'middleware',
      time: stepTime,
      memory: process.memoryUsage(),
    });
    if (err) {
      profile.error = err;
    }
    originalNext.call(this, err);
  };
  // ✅ Track response completion
  res.on('finish', () => {
    const totalTime = performance.now() - profile.startTime;
    profile.totalTime = totalTime;
    profile.memoryEnd = process.memoryUsage();
    safeLogger.debug('Request profiling', profile);
  });
  next();
};
export default performanceMiddleware;
