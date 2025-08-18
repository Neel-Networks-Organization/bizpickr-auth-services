/**
 * Simple Monitoring Utility
 * Provides basic metrics and monitoring for the service
 */

class SimpleMonitor {
  constructor() {
    this.metrics = {
      requests: {
        total: 0,
        successful: 0,
        failed: 0,
        byMethod: {},
        byPath: {}
      },
      performance: {
        responseTimes: [],
        averageResponseTime: 0
      },
      errors: {
        total: 0,
        byType: {},
        recent: []
      },
      system: {
        startTime: Date.now(),
        uptime: 0
      }
    };
    
    // Update uptime every minute
    setInterval(() => {
      this.metrics.system.uptime = Date.now() - this.metrics.system.startTime;
    }, 60000);
  }

  /**
   * Record a request
   */
  recordRequest(method, path, statusCode, responseTime) {
    // Total requests
    this.metrics.requests.total++;
    
    // By status
    if (statusCode >= 200 && statusCode < 400) {
      this.metrics.requests.successful++;
    } else {
      this.metrics.requests.failed++;
    }
    
    // By method
    if (!this.metrics.requests.byMethod[method]) {
      this.metrics.requests.byMethod[method] = 0;
    }
    this.metrics.requests.byMethod[method]++;
    
    // By path
    if (!this.metrics.requests.byPath[path]) {
      this.metrics.requests.byPath[path] = 0;
    }
    this.metrics.requests.byPath[path]++;
    
    // Performance
    this.metrics.performance.responseTimes.push(responseTime);
    if (this.metrics.performance.responseTimes.length > 100) {
      this.metrics.performance.responseTimes.shift();
    }
    
    // Calculate average response time
    const total = this.metrics.performance.responseTimes.reduce((sum, time) => sum + time, 0);
    this.metrics.performance.averageResponseTime = total / this.metrics.performance.responseTimes.length;
  }

  /**
   * Record an error
   */
  recordError(error, req) {
    this.metrics.errors.total++;
    
    // By error type
    const errorType = error.name || 'Unknown';
    if (!this.metrics.errors.byType[errorType]) {
      this.metrics.errors.byType[errorType] = 0;
    }
    this.metrics.errors.byType[errorType]++;
    
    // Recent errors (keep last 50)
    this.metrics.errors.recent.push({
      timestamp: new Date().toISOString(),
      type: errorType,
      message: error.message,
      path: req?.path,
      method: req?.method,
      statusCode: error.statusCode || 500
    });
    
    if (this.metrics.errors.recent.length > 50) {
      this.metrics.errors.recent.shift();
    }
  }

  /**
   * Get current metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      system: {
        ...this.metrics.system,
        uptime: Date.now() - this.metrics.system.startTime
      }
    };
  }

  /**
   * Get health status
   */
  getHealthStatus() {
    const errorRate = this.metrics.requests.total > 0 
      ? (this.metrics.errors.total / this.metrics.requests.total) * 100 
      : 0;
    
    const avgResponseTime = this.metrics.performance.averageResponseTime;
    
    let status = 'healthy';
    if (errorRate > 10 || avgResponseTime > 5000) {
      status = 'degraded';
    }
    if (errorRate > 25 || avgResponseTime > 10000) {
      status = 'unhealthy';
    }
    
    return {
      status,
      errorRate: errorRate.toFixed(2),
      averageResponseTime: avgResponseTime.toFixed(2),
      totalRequests: this.metrics.requests.total,
      totalErrors: this.metrics.errors.total
    };
  }

  /**
   * Reset metrics (for testing)
   */
  reset() {
    this.metrics = {
      requests: {
        total: 0,
        successful: 0,
        failed: 0,
        byMethod: {},
        byPath: {}
      },
      performance: {
        responseTimes: [],
        averageResponseTime: 0
      },
      errors: {
        total: 0,
        byType: {},
        recent: []
      },
      system: {
        startTime: Date.now(),
        uptime: 0
      }
    };
  }
}

// Create singleton instance
const monitor = new SimpleMonitor();

export default monitor;

/**
 * Middleware to record request metrics
 */
export function monitoringMiddleware(req, res, next) {
  const startTime = Date.now();
  
  // Override res.end to capture response time
  const originalEnd = res.end;
  res.end = function(...args) {
    const responseTime = Date.now() - startTime;
    monitor.recordRequest(req.method, req.path, res.statusCode, responseTime);
    originalEnd.apply(this, args);
  };
  
  next();
}

/**
 * Middleware to record errors
 */
export function errorMonitoringMiddleware(error, req, res, next) {
  monitor.recordError(error, req);
  next(error);
}
