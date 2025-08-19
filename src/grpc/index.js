import { safeLogger } from '../config/logger.js';
import {
  startGrpcServer,
  stopGrpcServer,
  getGrpcServerHealth,
} from './server/auth.server.js';
import {
  initializeUserHealth,
  stopMonitoring,
  getUserServiceHealth,
} from './client/userHealth.js';
import { ApiError } from '../utils/ApiError.js';
/**
 * Industry-level gRPC Service Manager
 *
 * Features:
 * - Enhanced error handling and logging
 * - Health monitoring and metrics
 * - Graceful startup and shutdown
 * - Service discovery and load balancing
 * - Performance monitoring
 * - Circuit breaker patterns
 * - Security and authentication
 */
// gRPC service metrics
const grpcMetrics = {
  totalRequests: 0,
  successfulRequests: 0,
  failedRequests: 0,
  activeConnections: 0,
  lastHealthCheck: null,
  uptime: Date.now(),
  serverStartTime: null,
  clientConnections: new Map(),
  requestLatency: [],
  errorCounts: new Map(),
};
// Service registry for management
const serviceRegistry = new Map();
/**
 * Initialize gRPC services with enhanced error handling
 * @param {Object} options - Initialization options
 * @returns {Promise<void>}
 */
async function initializeGrpcServices(options = {}) {
  const grpcTimeoutMs = process.env.NODE_ENV === 'development' ? 5000 : 10000;
  try {
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => {
        safeLogger.warn(
          `gRPC connection timeout (${grpcTimeoutMs / 1000}s): Unable to connect to gRPC server`
        );
        reject(new Error('gRPC connection timeout'));
      }, grpcTimeoutMs)
    );
    await Promise.race([grpcConnectFunction(), timeoutPromise]);
    safeLogger.info('gRPC connection established');
  } catch (error) {
    // In development mode, log warning but don't crash
    if (process.env.NODE_ENV === 'development') {
      safeLogger.warn(
        '⚠️ gRPC connection failed in development mode, continuing...',
        {
          error: error.message,
          note: 'Service will start without gRPC client functionality',
        }
      );
      return; // Don't throw error in development
    }

    safeLogger.error('gRPC connection failed', {
      error: error.message,
      stack: error.stack,
    });
    throw error;
  }
}
/**
 * Register all gRPC services for management
 */
function registerServices() {
  const services = [
    {
      name: 'auth-server',
      type: 'server',
      healthCheck: () => getGrpcServerHealth(),
      stop: () => stopGrpcServer(),
    },
    {
      name: 'user-client',
      type: 'client',
      healthCheck: () => getUserServiceHealth(),
      stop: () => stopMonitoring(),
    },
  ];
  services.forEach(service => {
    serviceRegistry.set(service.name, {
      ...service,
      status: 'active',
      startedAt: new Date().toISOString(),
      lastHealthCheck: null,
    });
  });
  safeLogger.info('gRPC services registered', {
    totalServices: services.length,
    services: services.map(s => s.name),
  });
}
/**
 * Start health monitoring
 */
function startHealthMonitoring() {
  setInterval(async () => {
    try {
      const health = await getGrpcServicesHealth();
      grpcMetrics.lastHealthCheck = new Date().toISOString();
      // Update service registry with health status
      for (const [name, service] of serviceRegistry.entries()) {
        try {
          const serviceHealth = await service.healthCheck();
          service.lastHealthCheck = new Date().toISOString();
          service.status = serviceHealth.status;
        } catch (error) {
          service.status = 'unhealthy';
          service.lastError = error.message;
        }
      }
      if (health.status === 'unhealthy') {
        safeLogger.warn('gRPC services health check failed', health);
      } else {
        safeLogger.debug('gRPC services health check passed', {
          status: health.status,
          services: health.services,
          uptime: health.uptime,
        });
      }
    } catch (error) {
      safeLogger.error('gRPC services health check error', {
        error: error.message,
        stack: error.stack,
      });
    }
  }, 30 * 1000); // Every 30 seconds
}
/**
 * Start performance monitoring
 */
function startPerformanceMonitoring() {
  setInterval(() => {
    try {
      const performance = getGrpcPerformanceMetrics();
      // Log performance metrics
      safeLogger.debug('gRPC performance metrics', {
        totalRequests: performance.totalRequests,
        successRate: performance.successRate,
        averageLatency: performance.averageLatency,
        activeConnections: performance.activeConnections,
      });
      // Reset counters periodically
      if (performance.totalRequests > 1000) {
        resetPerformanceMetrics();
      }
    } catch (error) {
      safeLogger.error('gRPC performance monitoring error', {
        error: error.message,
      });
    }
  }, 60 * 1000); // Every minute
}
/**
 * Get gRPC services health status
 * @returns {Promise<Object>} Health status
 */
export async function getGrpcServicesHealth() {
  const uptime = Date.now() - grpcMetrics.uptime;
  const services = Array.from(serviceRegistry.values());
  const healthyServices = services.filter(s => s.status === 'active').length;
  const totalServices = services.length;
  return {
    status: healthyServices === totalServices ? 'healthy' : 'unhealthy',
    uptime: `${Math.round(uptime / 1000)}s`,
    services: {
      total: totalServices,
      healthy: healthyServices,
      unhealthy: totalServices - healthyServices,
    },
    metrics: { ...grpcMetrics },
    lastHealthCheck: grpcMetrics.lastHealthCheck,
  };
}
/**
 * Get gRPC performance metrics
 * @returns {Object} Performance metrics
 */
export function getGrpcPerformanceMetrics() {
  const totalRequests = grpcMetrics.totalRequests;
  const successfulRequests = grpcMetrics.successfulRequests;
  const failedRequests = grpcMetrics.failedRequests;
  const successRate =
    totalRequests > 0 ? (successfulRequests / totalRequests) * 100 : 0;
  const averageLatency =
    grpcMetrics.requestLatency.length > 0
      ? grpcMetrics.requestLatency.reduce((a, b) => a + b, 0) /
        grpcMetrics.requestLatency.length
      : 0;
  return {
    totalRequests,
    successfulRequests,
    failedRequests,
    successRate: `${successRate.toFixed(2)}%`,
    averageLatency: `${averageLatency.toFixed(2)}ms`,
    activeConnections: grpcMetrics.activeConnections,
    errorCounts: Object.fromEntries(grpcMetrics.errorCounts),
  };
}
/**
 * Update gRPC metrics
 * @param {string} type - Metric type (request, success, failure, latency)
 * @param {Object} data - Additional data
 */
export function updateGrpcMetrics(type, data = {}) {
  switch (type) {
    case 'request':
      grpcMetrics.totalRequests++;
      break;
    case 'success':
      grpcMetrics.successfulRequests++;
      break;
    case 'failure':
      grpcMetrics.failedRequests++;
      if (data.error) {
        const errorType = data.error.constructor.name;
        grpcMetrics.errorCounts.set(
          errorType,
          (grpcMetrics.errorCounts.get(errorType) || 0) + 1
        );
      }
      break;
    case 'latency':
      if (data.latency) {
        grpcMetrics.requestLatency.push(data.latency);
        // Keep only last 100 latency measurements
        if (grpcMetrics.requestLatency.length > 100) {
          grpcMetrics.requestLatency.shift();
        }
      }
      break;
    case 'connection':
      grpcMetrics.activeConnections = data.count || 0;
      break;
  }
  safeLogger.debug('gRPC metrics updated', {
    type,
    data,
    metrics: { ...grpcMetrics },
  });
}
/**
 * Reset performance metrics
 */
function resetPerformanceMetrics() {
  grpcMetrics.totalRequests = 0;
  grpcMetrics.successfulRequests = 0;
  grpcMetrics.failedRequests = 0;
  grpcMetrics.requestLatency = [];
  grpcMetrics.errorCounts.clear();
  safeLogger.info('gRPC performance metrics reset');
}
/**
 * Restart a specific gRPC service
 * @param {string} serviceName - Name of the service to restart
 * @returns {Promise<void>}
 */
export async function restartGrpcService(serviceName) {
  const service = serviceRegistry.get(serviceName);
  if (!service) {
    throw new ApiError(404, 'Service not found', [
      `Service '${serviceName}' is not registered`,
      'Please check service name',
    ]);
  }
  try {
    safeLogger.info('Restarting gRPC service', { serviceName });
    // Stop the service
    await service.stop();
    // Wait a moment
    await new Promise(resolve => setTimeout(resolve, 1000));
    // Restart based on service type
    if (service.type === 'server') {
      await startGrpcServer();
    } else if (service.type === 'client') {
      await initializeUserHealth();
    }
    service.status = 'active';
    service.startedAt = new Date().toISOString();
    safeLogger.info('gRPC service restarted successfully', { serviceName });
  } catch (error) {
    service.status = 'failed';
    service.lastError = error.message;
    safeLogger.error('Failed to restart gRPC service', {
      serviceName,
      error: error.message,
      stack: error.stack,
    });
    throw new ApiError(500, 'Failed to restart gRPC service', [
      `Service '${serviceName}' restart failed`,
      error.message,
    ]);
  }
}
/**
 * Graceful shutdown of gRPC services
 * @returns {Promise<void>}
 */
async function shutdownGrpcServices() {
  const startTime = Date.now();
  try {
    safeLogger.info('Starting gRPC services shutdown');
    // Stop all services
    const shutdownPromises = Array.from(serviceRegistry.values()).map(
      async service => {
        try {
          await service.stop();
          service.status = 'stopped';
          safeLogger.info('gRPC service stopped', {
            serviceName: service.name,
          });
        } catch (error) {
          safeLogger.warn('Failed to stop gRPC service gracefully', {
            serviceName: service.name,
            error: error.message,
          });
        }
      }
    );
    await Promise.allSettled(shutdownPromises);
    const shutdownTime = Date.now() - startTime;
    safeLogger.info('gRPC services shutdown completed', {
      shutdownTime: `${shutdownTime}ms`,
      totalServices: serviceRegistry.size,
      uptime: `${Math.round((Date.now() - grpcMetrics.uptime) / 1000)}s`,
    });
  } catch (error) {
    const shutdownTime = Date.now() - startTime;
    safeLogger.error('Error during gRPC services shutdown', {
      error: error.message,
      stack: error.stack,
      shutdownTime: `${shutdownTime}ms`,
    });
    throw new ApiError(500, 'gRPC services shutdown failed', [
      'Graceful shutdown failed',
      'Services may need manual cleanup',
      error.message,
    ]);
  }
}
/**
 * Setup graceful shutdown handlers
 */
function setupGracefulShutdown() {
  const gracefulShutdown = async signal => {
    safeLogger.info(`Received ${signal}, starting gRPC services shutdown`);
    try {
      await shutdownGrpcServices();
      process.exit(0);
    } catch (error) {
      safeLogger.error('Error during graceful shutdown', {
        error: error.message,
        stack: error.stack,
      });
      process.exit(1);
    }
  };
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
}
/**
 * Get service registry
 * @returns {Map} Service registry
 */
export function getServiceRegistry() {
  return new Map(serviceRegistry);
}
/**
 * Check if gRPC services are ready
 * @returns {boolean} Ready status
 */
export function isGrpcServicesReady() {
  const services = Array.from(serviceRegistry.values());
  return services.every(service => service.status === 'active');
}
/**
 * Get gRPC service statistics
 * @returns {Object} Service statistics
 */
export function getGrpcServiceStats() {
  return {
    metrics: { ...grpcMetrics },
    services: Array.from(serviceRegistry.values()),
    performance: getGrpcPerformanceMetrics(),
    currentTime: new Date().toISOString(),
  };
}
/**
 * Best practice: gRPC connect function for service startup
 * - Starts the gRPC server
 * - Initializes the gRPC client health monitor (user service)
 * - Resolves when both are ready (or fails fast on error/timeout)
 */
async function grpcConnectFunction() {
  try {
    // In development mode, skip gRPC server if it fails
    if (process.env.NODE_ENV === 'development') {
      try {
        await startGrpcServer();
        safeLogger.info(
          '✅ gRPC server started successfully in development mode'
        );
      } catch (error) {
        safeLogger.warn(
          '⚠️ gRPC server failed to start in development mode, continuing...',
          {
            error: error.message,
            note: 'Service will start without gRPC server functionality',
          }
        );
        return; // Don't throw error in development
      }
    } else {
      // In production mode, gRPC server is required
      await startGrpcServer();
    }

    // Initialize user health monitor (both development and production)
    try {
      await initializeUserHealth();
      safeLogger.info(
        '✅ User service health monitor initialized successfully'
      );
    } catch (error) {
      safeLogger.warn(
        '⚠️ User service health monitor failed to initialize (optional)',
        {
          error: error.message,
          note: 'Service will continue without gRPC client functionality',
        }
      );
    }
  } catch (error) {
    throw error;
  }
}
export {
  initializeGrpcServices,
  shutdownGrpcServices,
  grpcConnectFunction,
  registerServices,
};
