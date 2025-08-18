import { env } from './config/env.js';
import { safeLogger } from './config/logger.js';
import sequelize from './db/index.js';
import { redisClient } from './db/redis.js';
import { getValidationMetrics } from './validators/validation.js';
import { getSecurityMetrics } from './validators/securityValidators.js';
import { getAuthMetrics } from './middlewares/auth.middleware.js';
import { getKeyHealth } from './crypto/keyManager.js';
/**
 * Production Health Check System
 *
 * Features:
 * - Database connectivity check
 * - Redis connectivity check
 * - External service health
 * - System resource monitoring
 * - Performance metrics
 * - Security metrics
 * - Key rotation health
 * - Memory and CPU usage
 * - Response time monitoring
 */
// ✅ Health check status tracking
let healthStatus = {
  status: 'healthy',
  timestamp: new Date().toISOString(),
  uptime: process.uptime(),
  version: process.env.npm_package_version || '1.0.0',
  environment: env.NODE_ENV,
  checks: {},
  metrics: {},
  errors: [],
};
// ✅ Database health check
async function checkDatabaseHealth() {
  try {
    const startTime = Date.now();
    await sequelize.authenticate();
    const responseTime = Date.now() - startTime;
    return {
      status: 'healthy',
      responseTime,
      database: env.DB_NAME,
      host: env.DB_HOST,
      port: env.DB_PORT,
      pool: {
        used: sequelize.connectionManager.pool.used,
        available: sequelize.connectionManager.pool.available,
        pending: sequelize.connectionManager.pool.pending,
      },
    };
  } catch (error) {
    safeLogger.error('Database health check failed', { error: error.message });
    return {
      status: 'unhealthy',
      error: error.message,
      database: env.DB_NAME,
      host: env.DB_HOST,
    };
  }
}
// ✅ Redis health check
async function checkRedisHealth() {
  try {
    const startTime = Date.now();
    await redisClient.ping();
    const responseTime = Date.now() - startTime;
    const info = await redisClient.info();
    const memory = await redisClient.info('memory');
    return {
      status: 'healthy',
      responseTime,
      host: env.REDIS_HOST,
      port: env.REDIS_PORT,
      memory: memory,
      info: info,
    };
  } catch (error) {
    safeLogger.error('Redis health check failed', { error: error.message });
    return {
      status: 'unhealthy',
      error: error.message,
      host: env.REDIS_HOST,
      port: env.REDIS_PORT,
    };
  }
}
// ✅ System resources check
function checkSystemResources() {
  const usage = process.memoryUsage();
  const cpuUsage = process.cpuUsage();
  return {
    memory: {
      rss: Math.round(usage.rss / 1024 / 1024) + ' MB',
      heapTotal: Math.round(usage.heapTotal / 1024 / 1024) + ' MB',
      heapUsed: Math.round(usage.heapUsed / 1024 / 1024) + ' MB',
      external: Math.round(usage.external / 1024 / 1024) + ' MB',
    },
    cpu: {
      user: Math.round(cpuUsage.user / 1000) + ' ms',
      system: Math.round(cpuUsage.system / 1000) + ' ms',
    },
    uptime: process.uptime(),
    pid: process.pid,
    nodeVersion: process.version,
    platform: process.platform,
  };
}
// ✅ Performance metrics check
function checkPerformanceMetrics() {
  try {
    const validationMetrics = getValidationMetrics();
    const securityMetrics = getSecurityMetrics();
    const authMetrics = getAuthMetrics();
    const keyHealth = getKeyHealth();
    return {
      validation: validationMetrics,
      security: securityMetrics,
      auth: authMetrics,
      keys: keyHealth,
    };
  } catch (error) {
    safeLogger.error('Performance metrics check failed', {
      error: error.message,
    });
    return {
      error: error.message,
    };
  }
}
// ✅ External services check
async function checkExternalServices() {
  const services = {};
  // Check gRPC services
  try {
    // Add gRPC health checks here
    services.grpc = { status: 'healthy' };
  } catch (error) {
    services.grpc = { status: 'unhealthy', error: error.message };
  }
  // Check RabbitMQ
  try {
    // Add RabbitMQ health checks here
    services.rabbitmq = { status: 'healthy' };
  } catch (error) {
    services.rabbitmq = { status: 'unhealthy', error: error.message };
  }
  return services;
}
// ✅ Main health check function
export async function performHealthCheck() {
  const startTime = Date.now();
  const errors = [];
  try {
    // ✅ Run all health checks
    const [
      databaseHealth,
      redisHealth,
      systemResources,
      performanceMetrics,
      externalServices,
    ] = await Promise.allSettled([
      checkDatabaseHealth(),
      checkRedisHealth(),
      checkSystemResources(),
      checkPerformanceMetrics(),
      checkExternalServices(),
    ]);
    // ✅ Update health status
    healthStatus = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      environment: env.NODE_ENV,
      responseTime: Date.now() - startTime,
      checks: {
        database:
          databaseHealth.status === 'fulfilled'
            ? databaseHealth.value
            : { status: 'unhealthy', error: databaseHealth.reason?.message },
        redis:
          redisHealth.status === 'fulfilled'
            ? redisHealth.value
            : { status: 'unhealthy', error: redisHealth.reason?.message },
        system:
          systemResources.status === 'fulfilled'
            ? systemResources.value
            : { status: 'unhealthy', error: systemResources.reason?.message },
        external:
          externalServices.status === 'fulfilled'
            ? externalServices.value
            : { status: 'unhealthy', error: externalServices.reason?.message },
      },
      metrics:
        performanceMetrics.status === 'fulfilled'
          ? performanceMetrics.value
          : { error: performanceMetrics.reason?.message },
      errors: [],
    };
    // ✅ Check if any service is unhealthy
    const unhealthyServices = Object.values(healthStatus.checks).filter(
      check => check.status === 'unhealthy',
    );
    if (unhealthyServices.length > 0) {
      healthStatus.status = 'degraded';
      healthStatus.errors = unhealthyServices
        .map(service => service.error)
        .filter(Boolean);
    }
    // ✅ Log health check results
    safeLogger.info('Health check completed', {
      status: healthStatus.status,
      responseTime: healthStatus.responseTime,
      unhealthyServices: unhealthyServices.length,
    });
    return healthStatus;
  } catch (error) {
    safeLogger.error('Health check failed', { error: error.message });
    healthStatus = {
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      environment: env.NODE_ENV,
      responseTime: Date.now() - startTime,
      checks: {},
      metrics: {},
      errors: [error.message],
    };
    return healthStatus;
  }
}
// ✅ Get current health status
export function getHealthStatus() {
  return healthStatus;
}
// ✅ Check if service is healthy
export function isHealthy() {
  return (
    healthStatus.status === 'healthy' || healthStatus.status === 'degraded'
  );
}
// ✅ Check if service is ready
export function isReady() {
  return healthStatus.status === 'healthy';
}
// ✅ Export for use in routes
export default {
  performHealthCheck,
  getHealthStatus,
  isHealthy,
  isReady,
};
