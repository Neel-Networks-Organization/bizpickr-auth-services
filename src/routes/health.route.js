import express from 'express';
import { checkDb, checkRedis, checkRabbitMQ, checkGrpc, checkMongoDB, checkCircuitBreaker } from '../utils/healthChecks.js';

const router = express.Router();

/**
 * @route GET /health
 * @desc Get service health status
 * @access Public
 */
router.get('/', async (req, res) => {
  try {
    const startTime = Date.now();
    
    // Check all service dependencies
    const healthChecks = await Promise.allSettled([
      checkDb(),
      checkRedis(),
      checkRabbitMQ(),
      checkGrpc(),
      checkMongoDB(),
      checkCircuitBreaker()
    ]);

    const results = {
      database: healthChecks[0].status === 'fulfilled' ? healthChecks[0].value : 'down',
      redis: healthChecks[1].status === 'fulfilled' ? healthChecks[1].value : 'down',
      rabbitmq: healthChecks[2].status === 'fulfilled' ? healthChecks[2].value : 'down',
      grpc: healthChecks[3].status === 'fulfilled' ? healthChecks[3].value : 'down',
      mongodb: healthChecks[4].status === 'fulfilled' ? healthChecks[4].value : 'down',
      circuitBreaker: healthChecks[5].status === 'fulfilled' ? healthChecks[5].value : 'down'
    };

    // Determine overall health
    const allHealthy = Object.values(results).every(result => 
      result === 'up' || (typeof result === 'object' && result.status === 'healthy')
    );

    const responseTime = Date.now() - startTime;

    const healthResponse = {
      status: allHealthy ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
      service: 'AuthService',
      version: process.env.npm_package_version || '1.0.0',
      uptime: process.uptime(),
      responseTime: `${responseTime}ms`,
      checks: results
    };

    const statusCode = allHealthy ? 200 : 503;
    res.status(statusCode).json(healthResponse);

  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      service: 'AuthService',
      error: error.message
    });
  }
});

/**
 * @route GET /health/ready
 * @desc Check if service is ready to accept requests
 * @access Public
 */
router.get('/ready', async (req, res) => {
  try {
    // Check critical dependencies only
    const criticalChecks = await Promise.allSettled([
      checkDb(),
      checkRedis()
    ]);

    const isReady = criticalChecks.every(check => 
      check.status === 'fulfilled' && check.value === 'up'
    );

    if (isReady) {
      res.status(200).json({
        status: 'ready',
        timestamp: new Date().toISOString(),
        service: 'AuthService'
      });
    } else {
      res.status(503).json({
        status: 'not ready',
        timestamp: new Date().toISOString(),
        service: 'AuthService'
      });
    }
  } catch (error) {
    res.status(503).json({
      status: 'not ready',
      timestamp: new Date().toISOString(),
      service: 'AuthService',
      error: error.message
    });
  }
});

/**
 * @route GET /health/live
 * @desc Check if service is alive (basic liveness check)
 * @access Public
 */
router.get('/live', (req, res) => {
  res.status(200).json({
    status: 'alive',
    timestamp: new Date().toISOString(),
    service: 'AuthService'
  });
});

export default router;
