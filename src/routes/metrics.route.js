/**
 * Metrics Routes - Analytics and Monitoring Endpoints
 *
 * Provides routes for:
 * - Real-time metrics retrieval
 * - Cache warming operations
 * - Device analytics
 * - Error statistics
 * - Performance monitoring
 */
import express from 'express';
import monitor from '../utils/monitoring.js';

const router = express.Router();

/**
 * @route GET /metrics
 * @desc Get service metrics
 * @access Public
 */
router.get('/', (req, res) => {
  try {
    const metrics = monitor.getMetrics();
    const healthStatus = monitor.getHealthStatus();
    
    res.status(200).json({
      timestamp: new Date().toISOString(),
      service: 'AuthService',
      version: process.env.npm_package_version || '1.0.0',
      health: healthStatus,
      metrics: {
        requests: metrics.requests,
        performance: metrics.performance,
        errors: metrics.errors,
        system: metrics.system
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to get metrics',
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * @route GET /metrics/health
 * @desc Get service health metrics
 * @access Public
 */
router.get('/health', (req, res) => {
  try {
    const healthStatus = monitor.getHealthStatus();
    
    res.status(200).json({
      timestamp: new Date().toISOString(),
      service: 'AuthService',
      health: healthStatus
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to get health metrics',
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * @route POST /metrics/reset
 * @desc Reset metrics (development only)
 * @access Public
 */
router.post('/reset', (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({
      error: 'Metrics reset not allowed in production',
      timestamp: new Date().toISOString()
    });
  }
  
  try {
    monitor.reset();
    res.status(200).json({
      message: 'Metrics reset successfully',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to reset metrics',
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

export default router;
