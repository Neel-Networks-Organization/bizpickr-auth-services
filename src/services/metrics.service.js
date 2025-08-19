import { safeLogger } from '../config/logger.js';

/**
 * Simple Metrics Service
 * Basic metrics collection for backward compatibility
 */

class MetricsService {
  constructor() {
    this.metrics = {
      totalErrors: 0,
      cacheWarming: 0,
      deviceRegistrations: 0,
      deviceRemovals: 0,
      deviceFingerprint: 0,
      suspiciousDevice: 0,
      metricsAccess: 0,
      responseTimes: [],
      securityEvents: [],
      lastReset: Date.now(),
    };
  }

  /**
   * Increment a metric
   */
  incrementMetric(metricName, value = 1, tags = {}) {
    if (this.metrics[metricName] !== undefined) {
      this.metrics[metricName] += value;
    } else {
      this.metrics[metricName] = value;
    }

    safeLogger.debug('Metric incremented', { metricName, value, tags });
  }

  /**
   * Record response time
   */
  recordResponseTime(responseTime) {
    this.metrics.responseTimes.push(responseTime);

    // Keep only last 1000 response times
    if (this.metrics.responseTimes.length > 1000) {
      this.metrics.responseTimes = this.metrics.responseTimes.slice(-1000);
    }
  }

  /**
   * Record security event
   */
  recordSecurityEvent(eventType, severity, details = {}) {
    this.metrics.securityEvents.push({
      type: eventType,
      severity,
      details,
      timestamp: Date.now(),
    });

    // Keep only last 1000 security events
    if (this.metrics.securityEvents.length > 1000) {
      this.metrics.securityEvents = this.metrics.securityEvents.slice(-1000);
    }
  }

  /**
   * Get all metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      uptime: Date.now() - this.metrics.lastReset,
      averageResponseTime:
        this.metrics.responseTimes.length > 0
          ? this.metrics.responseTimes.reduce((a, b) => a + b, 0) /
            this.metrics.responseTimes.length
          : 0,
    };
  }

  /**
   * Get health status
   */
  getHealthStatus() {
    return {
      status: 'healthy',
      uptime: Date.now() - this.metrics.lastReset,
      metrics: Object.keys(this.metrics).length,
      timestamp: Date.now(),
    };
  }

  /**
   * Get error summary
   */
  getErrorSummary() {
    return {
      totalErrors: this.metrics.totalErrors,
      lastError: this.metrics.lastReset,
      errorRate: '0%', // Placeholder
    };
  }

  /**
   * Reset metrics
   */
  resetMetrics() {
    this.metrics = {
      totalErrors: 0,
      cacheWarming: 0,
      deviceRegistrations: 0,
      deviceRemovals: 0,
      deviceFingerprint: 0,
      suspiciousDevice: 0,
      metricsAccess: 0,
      responseTimes: [],
      securityEvents: [],
      lastReset: Date.now(),
    };

    safeLogger.info('Metrics reset successfully');
  }
}

// Create singleton instance
const metricsService = new MetricsService();

// Export default
export default metricsService;

// Export named exports for backward compatibility
export { metricsService };
export const {
  incrementMetric,
  recordResponseTime,
  recordSecurityEvent,
  getMetrics,
  getHealthStatus,
  getErrorSummary,
  resetMetrics,
} = metricsService;
