/**
 * Metrics Controller - Analytics and Monitoring Endpoints
 *
 * Provides endpoints for:
 * - Real-time metrics retrieval
 * - Cache warming operations
 * - Device analytics
 * - Error statistics
 * - Performance monitoring
 */
import { metricsService } from '../services/metrics.service.js';
import { cacheWarmingService } from '../services/cacheWarming.service.js';
import { deviceFingerprintService } from '../services/deviceFingerprint.service.js';
import { safeLogger } from '../config/logger.js';
import { asyncErrorHandler } from '../middlewares/enhancedErrorHandler.middleware.js';

class MetricsController {
  /**
   * Get comprehensive metrics
   */
  getMetrics = asyncErrorHandler(async (req, res) => {
    const startTime = Date.now();

    try {
      const metrics = await metricsService.getMetrics();
      const cacheWarmingStatus = cacheWarmingService.getWarmingStatus();

      const response = {
        ...metrics,
        cacheWarming: cacheWarmingStatus,
        responseTime: Date.now() - startTime,
        timestamp: new Date().toISOString(),
      };

      // Set cache headers
      res.set('Cache-Control', 'public, max-age=30'); // Cache for 30 seconds
      res.set('X-Metrics-Version', '1.0');

      res.json(response);

      // Record metrics access
      metricsService.incrementMetric('metricsAccess', 1);
    } catch (error) {
      safeLogger.error('Failed to get metrics', { error: error.message });
      throw error;
    }
  });

  /**
   * Get business metrics only
   */
  getBusinessMetrics = asyncErrorHandler(async (req, res) => {
    try {
      const businessMetrics = await metricsService.getMetrics();

      const response = {
        business: businessMetrics.business,
        health: metricsService.getHealthStatus(),
        timestamp: new Date().toISOString(),
      };

      res.set('Cache-Control', 'public, max-age=60'); // Cache for 1 minute
      res.json(response);
    } catch (error) {
      safeLogger.error('Failed to get business metrics', {
        error: error.message,
      });
      throw error;
    }
  });

  /**
   * Get technical metrics only
   */
  getTechnicalMetrics = asyncErrorHandler(async (req, res) => {
    try {
      const metrics = await metricsService.getMetrics();

      const response = {
        technical: metrics.technical,
        cache: metrics.cache,
        database: metrics.database,
        timestamp: new Date().toISOString(),
      };

      res.set('Cache-Control', 'public, max-age=30'); // Cache for 30 seconds
      res.json(response);
    } catch (error) {
      safeLogger.error('Failed to get technical metrics', {
        error: error.message,
      });
      throw error;
    }
  });

  /**
   * Get health status
   */
  getHealth = asyncErrorHandler(async (req, res) => {
    try {
      const healthStatus = metricsService.getHealthStatus();
      const cacheWarmingStatus = cacheWarmingService.getWarmingStatus();

      const response = {
        status: healthStatus.status,
        issues: healthStatus.issues,
        cacheWarming: cacheWarmingStatus,
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
      };

      // Set appropriate status code based on health
      const statusCode =
        healthStatus.status === 'healthy'
          ? 200
          : healthStatus.status === 'warning'
            ? 200
            : 503;

      res.status(statusCode).json(response);
    } catch (error) {
      safeLogger.error('Failed to get health status', { error: error.message });
      res.status(503).json({
        status: 'error',
        message: 'Health check failed',
        timestamp: new Date().toISOString(),
      });
    }
  });

  /**
   * Reset metrics
   */
  resetMetrics = asyncErrorHandler(async (req, res) => {
    try {
      // Check if user has permission to reset metrics
      if (req.user?.role !== 'super_admin' && req.user?.role !== 'admin') {
        return res.status(403).json({
          error: {
            message: 'Insufficient permissions to reset metrics',
            code: 'INSUFFICIENT_PERMISSIONS',
          },
        });
      }

      await metricsService.resetMetrics();

      safeLogger.info('Metrics reset by user', {
        userId: req.user.id,
        userRole: req.user.role,
      });

      res.json({
        message: 'Metrics reset successfully',
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      safeLogger.error('Failed to reset metrics', { error: error.message });
      throw error;
    }
  });

  /**
   * Get cache warming status
   */
  getCacheWarmingStatus = asyncErrorHandler(async (req, res) => {
    try {
      const status = cacheWarmingService.getWarmingStatus();

      res.json({
        cacheWarming: status,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      safeLogger.error('Failed to get cache warming status', {
        error: error.message,
      });
      throw error;
    }
  });

  /**
   * Trigger cache warming
   */
  triggerCacheWarming = asyncErrorHandler(async (req, res) => {
    try {
      // Check if user has permission
      if (req.user?.role !== 'super_admin' && req.user?.role !== 'admin') {
        return res.status(403).json({
          error: {
            message: 'Insufficient permissions to trigger cache warming',
            code: 'INSUFFICIENT_PERMISSIONS',
          },
        });
      }

      const cacheType = req.body.cacheType || 'all';

      let result;
      if (cacheType === 'all') {
        result = await cacheWarmingService.warmAllCaches();
      } else {
        const strategy = cacheWarmingService.warmingStrategies[cacheType];
        if (strategy) {
          await strategy();
          result = { successCount: 1, totalCount: 1, successRate: 100 };
        } else {
          return res.status(400).json({
            error: {
              message: `Invalid cache type: ${cacheType}`,
              code: 'INVALID_CACHE_TYPE',
              validTypes: Object.keys(cacheWarmingService.warmingStrategies),
            },
          });
        }
      }

      safeLogger.info('Cache warming triggered by user', {
        userId: req.user.id,
        cacheType,
        result,
      });

      res.json({
        message: 'Cache warming triggered successfully',
        cacheType,
        result,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      safeLogger.error('Failed to trigger cache warming', {
        error: error.message,
      });
      throw error;
    }
  });

  /**
   * Get device analytics
   */
  getDeviceAnalytics = asyncErrorHandler(async (req, res) => {
    try {
      const userId = req.params.userId || req.user?.id;

      if (!userId) {
        return res.status(400).json({
          error: {
            message: 'User ID is required',
            code: 'MISSING_USER_ID',
          },
        });
      }

      // Check permissions
      if (
        req.user?.role !== 'super_admin' &&
        req.user?.role !== 'admin' &&
        req.user?.id !== userId
      ) {
        return res.status(403).json({
          error: {
            message: 'Insufficient permissions to access device analytics',
            code: 'INSUFFICIENT_PERMISSIONS',
          },
        });
      }

      const analytics =
        await deviceFingerprintService.getDeviceAnalytics(userId);

      if (!analytics) {
        return res.status(404).json({
          error: {
            message: 'Device analytics not found',
            code: 'ANALYTICS_NOT_FOUND',
          },
        });
      }

      res.json({
        userId,
        analytics,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      safeLogger.error('Failed to get device analytics', {
        error: error.message,
      });
      throw error;
    }
  });

  /**
   * Get error statistics
   */
  getErrorStats = asyncErrorHandler(async (req, res) => {
    try {
      // Check permissions
      if (req.user?.role !== 'super_admin' && req.user?.role !== 'admin') {
        return res.status(403).json({
          error: {
            message: 'Insufficient permissions to access error statistics',
            code: 'INSUFFICIENT_PERMISSIONS',
          },
        });
      }

      const errorSummary = metricsService.getErrorSummary();

      res.json({
        errorStats: errorSummary,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      safeLogger.error('Failed to get error statistics', {
        error: error.message,
      });
      throw error;
    }
  });

  /**
   * Get performance metrics
   */
  getPerformanceMetrics = asyncErrorHandler(async (req, res) => {
    try {
      const metrics = await metricsService.getMetrics();

      const performanceMetrics = {
        responseTime: {
          average: metrics.business.averageResponseTime,
          p95: 0, // Would calculate from actual data
          p99: 0, // Would calculate from actual data
        },
        throughput: {
          requestsPerSecond:
            metrics.business.totalRequests / (process.uptime() || 1),
          totalRequests: metrics.business.totalRequests,
        },
        cache: {
          hitRate: metrics.business.cacheHitRate,
          efficiency: 'high', // Would calculate based on hit rate
        },
        database: {
          queryTime: metrics.business.databaseQueryTime,
          connections: metrics.database.connections || 0,
        },
        memory: {
          usage: process.memoryUsage(),
          heapUsed: process.memoryUsage().heapUsed,
          heapTotal: process.memoryUsage().heapTotal,
        },
        cpu: {
          usage: process.cpuUsage(),
          load: 0, // Would get from system metrics
        },
      };

      res.json({
        performance: performanceMetrics,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      safeLogger.error('Failed to get performance metrics', {
        error: error.message,
      });
      throw error;
    }
  });
}

export const metricsController = new MetricsController();
