import Redis from 'ioredis';
import {
  redisConfig,
  getRedisConnectionOptions,
  getRedisRetryStrategy,
  validateRedisConfig,
} from '../config/redis.js';
import { safeLogger } from '../config/logger.js';
import { ApiError } from '../utils/ApiError.js';

/**
 * Industry-level Redis Client
 *
 * Features:
 * - Enhanced error handling and logging
 * - Connection pooling and clustering
 * - Performance monitoring and metrics
 * - Health checks and diagnostics
 * - Security configurations
 * - Graceful shutdown handling
 * - Retry mechanisms and circuit breaker
 */
// Redis metrics
const redisMetrics = {
  totalConnections: 0,
  activeConnections: 0,
  connectionErrors: 0,
  commandCount: 0,
  slowCommands: 0,
  lastHealthCheck: null,
  uptime: Date.now(),
  memoryUsage: 0,
  connectedClients: 0,
  keyspaceHits: 0,
  keyspaceMisses: 0,
};
// Redis client instance
let redis = null;
let healthCheckInterval = null;
let reconnectAttempts = 0;
const maxReconnectAttempts = redisConfig.maxReconnectAttempts;
/**
 * Initialize Redis connection with enhanced error handling
 * @returns {Promise<Redis>} Redis client instance
 */
// export async function initRedis() {
//   return new Promise((resolve, reject) => {
//     let timeout = setTimeout(() => {
//       safeLogger.error(
//         "Redis connection timeout (10s): Unable to connect to Redis server"
//       );
//       reject(
//         new ApiError(504, "Redis connection timeout", [
//           "Redis did not become ready within 10 seconds",
//           "Please check Redis server status and network connectivity",
//         ])
//       );
//     }, 10000); // 10 seconds

//     if (redis && redis.status === "ready") {
//       clearTimeout(timeout);
//       safeLogger.info("Redis client already initialized and ready");
//       return resolve(redis);
//     }

//     try {
//       // Validate Redis configuration
//       validateRedisConfig();

//       const connectionOptions = getRedisConnectionOptions();
//       const retryStrategy = getRedisRetryStrategy();

//       safeLogger.info("Initializing Redis connection", {
//         host: redisConfig.host,
//         port: redisConfig.port,
//         db: redisConfig.db,
//         cluster: redisConfig.cluster.enabled,
//         sentinel: redisConfig.sentinel.enabled,
//       });

//       redis = new Redis({
//         ...connectionOptions,
//         retryStrategy,
//       });

//       // Set up event listeners
//       setupRedisEventListeners(
//         (client) => {
//           clearTimeout(timeout);
//           resolve(client);
//         },
//         (err) => {
//           clearTimeout(timeout);
//           reject(err);
//         }
//       );
//     } catch (error) {
//       clearTimeout(timeout);
//       safeLogger.error("Failed to create Redis client", {
//         error: error.message,
//         stack: error.stack,
//         config: {
//           host: redisConfig.host,
//           port: redisConfig.port,
//         },
//       });
//       reject(
//         new ApiError(503, "Redis client creation failed", [
//           "Unable to create Redis client",
//           "Please check Redis configuration and network connectivity",
//         ])
//       );
//     }
//   });
// }
export async function initRedis() {
  return new Promise((resolve, reject) => {
    let timeout = setTimeout(() => {
      safeLogger.error(
        'Redis connection timeout (10s): Unable to connect to Redis server'
      );
      reject(
        new ApiError(504, 'Redis connection timeout', [
          'Redis did not become ready within 10 seconds',
          'Please check Redis server status and network connectivity',
        ])
      );
    }, 10000); // 10 seconds

    safeLogger.debug('Redis client status', {
      status: redis ? redis.status : 'not defined',
    });

    if (redis && redis.status === 'ready') {
      safeLogger.debug('Redis already ready, returning client');
      clearTimeout(timeout);
      safeLogger.info('Redis client already initialized and ready');
      return resolve(redis);
    }

    try {
      safeLogger.debug('Validating Redis config');
      validateRedisConfig();

      const connectionOptions = getRedisConnectionOptions();
      const retryStrategy = getRedisRetryStrategy();

      safeLogger.info('Initializing Redis connection', {
        host: redisConfig.host,
        port: redisConfig.port,
        db: redisConfig.db,
        cluster: redisConfig.cluster.enabled,
        sentinel: redisConfig.sentinel.enabled,
      });

      safeLogger.debug('Creating new Redis client');
      redis = new Redis({
        ...connectionOptions,
        retryStrategy,
      });
      // console.log("Redis client created:", redis);
      setupRedisEventListeners(
        client => {
          safeLogger.debug('Redis connected, resolving promise');
          clearTimeout(timeout);
          resolve(client);
        },
        err => {
          safeLogger.error('Error in Redis connection', { error: err.message });
          clearTimeout(timeout);
          reject(err);
        }
      );
    } catch (error) {
      safeLogger.error('Error caught during Redis client creation', {
        error: error.message,
      });
      clearTimeout(timeout);
      safeLogger.error('Failed to create Redis client', {
        error: error.message,
        stack: error.stack,
        config: {
          host: redisConfig.host,
          port: redisConfig.port,
        },
      });
      reject(
        new ApiError(503, 'Redis client creation failed', [
          'Unable to create Redis client',
          'Please check Redis configuration and network connectivity',
        ])
      );
    }
  });
}

/**
 * Setup Redis event listeners for monitoring
 * @param {Function} resolve - Promise resolve function
 * @param {Function} reject - Promise reject function
 */
function setupRedisEventListeners(resolve, reject) {
  // Connection events
  redis.on('connect', () => {
    redisMetrics.totalConnections++;
    redisMetrics.activeConnections++;
    reconnectAttempts = 0;
    safeLogger.info('Redis connected successfully', {
      host: redisConfig.host,
      port: redisConfig.port,
      activeConnections: redisMetrics.activeConnections,
    });
  });
  redis.on('ready', () => {
    safeLogger.info('Redis client is ready', {
      host: redisConfig.host,
      port: redisConfig.port,
      status: redis.status,
    });
    // Start health monitoring
    startHealthMonitoring();
    resolve(redis);
  });
  redis.on('error', err => {
    redisMetrics.connectionErrors++;
    const errorMessage =
      err.code === 'ECONNREFUSED'
        ? 'Redis connection refused'
        : 'Redis encountered an error';
    safeLogger.error(errorMessage, {
      error: err.message,
      code: err.code,
      stack: err.stack,
      connectionErrors: redisMetrics.connectionErrors,
      reconnectAttempts,
    });
    if (reconnectAttempts >= maxReconnectAttempts) {
      safeLogger.error('Redis max reconnection attempts exceeded', {
        maxReconnectAttempts,
        reconnectAttempts,
      });
      reject(
        new ApiError(503, 'Redis connection failed after max retries', [
          'Unable to establish Redis connection',
          'Please check Redis server status and configuration',
        ])
      );
    }
  });
  redis.on('reconnecting', () => {
    reconnectAttempts++;
    safeLogger.warn('Reconnecting to Redis', {
      attempt: reconnectAttempts,
      maxAttempts: maxReconnectAttempts,
      host: redisConfig.host,
      port: redisConfig.port,
    });
  });
  redis.on('close', () => {
    redisMetrics.activeConnections = Math.max(
      0,
      redisMetrics.activeConnections - 1
    );
    safeLogger.warn('Redis connection closed', {
      activeConnections: redisMetrics.activeConnections,
      reconnectAttempts,
    });
  });
  redis.on('end', () => {
    safeLogger.info('Redis connection ended', {
      totalConnections: redisMetrics.totalConnections,
      connectionErrors: redisMetrics.connectionErrors,
    });
  });
  // Command events
  redis.on('command', command => {
    redisMetrics.commandCount++;
    safeLogger.debug('Redis command executed', {
      command: command[0],
      args: command.slice(1),
      totalCommands: redisMetrics.commandCount,
    });
  });
  // Slow command detection
  redis.on('slow', (command, duration) => {
    redisMetrics.slowCommands++;
    safeLogger.warn('Slow Redis command detected', {
      command: command[0],
      args: command.slice(1),
      duration: `${duration}ms`,
      threshold: `${redisConfig.slowCommandThreshold}ms`,
      slowCommands: redisMetrics.slowCommands,
    });
  });
}
/**
 * Start health monitoring
 */
function startHealthMonitoring() {
  if (healthCheckInterval) {
    clearInterval(healthCheckInterval);
  }
  healthCheckInterval = setInterval(async () => {
    try {
      // Basic health check
      await redis.ping();
      // Get Redis info
      const info = await redis.info();
      const memoryInfo = await redis.memory('USAGE', 'total');
      const clientList = await redis.client('LIST');
      // Parse info for metrics
      const lines = info.split('\r\n');
      const metrics = {};
      for (const line of lines) {
        const [key, value] = line.split(':');
        if (key && value) {
          metrics[key] = value;
        }
      }
      // Update metrics
      redisMetrics.lastHealthCheck = new Date().toISOString();
      redisMetrics.memoryUsage = parseInt(memoryInfo) || 0;
      redisMetrics.connectedClients = parseInt(metrics.connected_clients) || 0;
      redisMetrics.keyspaceHits = parseInt(metrics.keyspace_hits) || 0;
      redisMetrics.keyspaceMisses = parseInt(metrics.keyspace_misses) || 0;
      safeLogger.debug('Redis health check passed', {
        status: redis.status,
        memoryUsage: `${Math.round(redisMetrics.memoryUsage / 1024 / 1024)}MB`,
        connectedClients: redisMetrics.connectedClients,
        uptime: `${Math.round((Date.now() - redisMetrics.uptime) / 1000)}s`,
      });
    } catch (error) {
      safeLogger.error('Redis health check failed', {
        error: error.message,
        connectionErrors: redisMetrics.connectionErrors,
        reconnectAttempts,
      });
    }
  }, redisConfig.healthCheckInterval); // Use configured interval
}
/**
 * Get Redis client with validation
 * @returns {Redis} Redis client instance
 */
export function getRedisClient() {
  if (!redis) {
    const errorMsg = 'Redis client not initialized. Call initRedis() first.';
    safeLogger.error(errorMsg);
    throw new ApiError(503, 'Redis client not initialized', [
      'Redis service is not available',
      'Please ensure Redis is properly configured and running',
    ]);
  }
  if (redis.status !== 'ready') {
    const errorMsg = `Redis client not ready. Status: ${redis.status}`;
    safeLogger.error(errorMsg);
    throw new ApiError(503, 'Redis client not ready', [
      'Redis connection is not established',
      'Please check Redis server status',
    ]);
  }
  return redis;
}
/**
 * Close Redis connection gracefully
 * @returns {Promise<void>}
 */
export async function closeRedisConnection() {
  try {
    if (healthCheckInterval) {
      clearInterval(healthCheckInterval);
      healthCheckInterval = null;
    }
    if (redis) {
      await redis.quit();
      redis = null;
      safeLogger.info('Redis connection closed gracefully', {
        totalConnections: redisMetrics.totalConnections,
        totalCommands: redisMetrics.commandCount,
        slowCommands: redisMetrics.slowCommands,
        connectionErrors: redisMetrics.connectionErrors,
      });
    }
  } catch (error) {
    safeLogger.error('Error closing Redis connection', {
      error: error.message,
      stack: error.stack,
    });
    throw error;
  }
}
/**
 * Get Redis instance (for backward compatibility)
 * @returns {Redis|null} Redis instance
 */
export function getRedis() {
  return redis;
}
/**
 * Check if Redis is connected
 * @returns {boolean} Connection status
 */
export function isRedisConnected() {
  return redis && redis.status === 'ready';
}
/**
 * Get Redis health status
 * @returns {Object} Health status
 */
export function getRedisHealth() {
  const uptime = Date.now() - redisMetrics.uptime;
  return {
    status: redis ? redis.status : 'disconnected',
    uptime: `${Math.round(uptime / 1000)}s`,
    metrics: { ...redisMetrics },
    config: {
      host: redisConfig.host,
      port: redisConfig.port,
      db: redisConfig.db,
      cluster: redisConfig.cluster.enabled,
      sentinel: redisConfig.sentinel.enabled,
    },
    lastHealthCheck: redisMetrics.lastHealthCheck,
  };
}
/**
 * Get Redis info with error handling
 * @returns {Promise<string>} Redis info
 */
export async function getRedisInfo() {
  try {
    const client = getRedisClient();
    return await client.info();
  } catch (error) {
    safeLogger.error('Failed to get Redis info', {
      error: error.message,
      stack: error.stack,
    });
    throw new ApiError(503, 'Failed to get Redis information', [
      'Redis info command failed',
      'Please check Redis connection',
    ]);
  }
}
/**
 * Execute Redis command with retry logic
 * @param {string} command - Redis command
 * @param {...any} args - Command arguments
 * @returns {Promise<any>} Command result
 */
export async function executeRedisCommand(command, ...args) {
  const maxRetries = redisConfig.maxRetriesPerRequest;
  const retryDelay = redisConfig.retryDelay;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const client = getRedisClient();
      const result = await client[command](...args);
      safeLogger.debug('Redis command executed successfully', {
        command,
        args,
        attempt,
        result: typeof result === 'string' ? result.substring(0, 100) : result,
      });
      return result;
    } catch (error) {
      if (attempt === maxRetries) {
        safeLogger.error('Redis command failed after all retries', {
          command,
          args,
          error: error.message,
          stack: error.stack,
          attempts: attempt,
        });
        throw error;
      }
      safeLogger.warn('Redis command failed, retrying', {
        command,
        args,
        error: error.message,
        attempt,
        maxRetries,
        delay: `${retryDelay}ms`,
      });
      await new Promise(resolve => setTimeout(resolve, retryDelay));
    }
  }
}
/**
 * Get Redis metrics
 * @returns {Object} Redis metrics
 */
export function getRedisMetrics() {
  return {
    ...redisMetrics,
    currentTime: new Date().toISOString(),
    config: {
      host: redisConfig.host,
      port: redisConfig.port,
      db: redisConfig.db,
      cluster: redisConfig.cluster.enabled,
      sentinel: redisConfig.sentinel.enabled,
    },
  };
}
/**
 * Clear Redis metrics
 * @returns {Object} Cleared metrics
 */
export function clearRedisMetrics() {
  const oldMetrics = { ...redisMetrics };
  Object.assign(redisMetrics, {
    totalConnections: 0,
    activeConnections: 0,
    connectionErrors: 0,
    commandCount: 0,
    slowCommands: 0,
    memoryUsage: 0,
    connectedClients: 0,
    keyspaceHits: 0,
    keyspaceMisses: 0,
  });
  safeLogger.info('Redis metrics cleared', {
    previousMetrics: oldMetrics,
  });
  return oldMetrics;
}
/**
 * Redis client object with all necessary methods
 * This is the main export used by other modules
 */
export const redisClient = {
  /**
   * Initialize Redis connection
   * @returns {Promise<Redis>} Redis client instance
   */
  async init() {
    return await initRedis();
  },
  /**
   * Get Redis client instance
   * @returns {Redis} Redis client
   */
  getClient() {
    return getRedisClient();
  },
  /**
   * Check if Redis is connected
   * @returns {boolean} Connection status
   */
  isConnected() {
    return isRedisConnected();
  },
  /**
   * Get Redis health status
   * @returns {Object} Health status
   */
  getHealth() {
    return getRedisHealth();
  },
  /**
   * Execute Redis command
   * @param {string} command - Redis command
   * @param {...any} args - Command arguments
   * @returns {Promise<any>} Command result
   */
  async execute(command, ...args) {
    return await executeRedisCommand(command, ...args);
  },
  /**
   * Get Redis metrics
   * @returns {Object} Redis metrics
   */
  getMetrics() {
    return getRedisMetrics();
  },
  /**
   * Clear Redis metrics
   * @returns {Object} Cleared metrics
   */
  clearMetrics() {
    return clearRedisMetrics();
  },
  /**
   * Close Redis connection
   * @returns {Promise<void>}
   */
  async close() {
    return await closeRedisConnection();
  },
  /**
   * Get Redis info
   * @returns {Promise<string>} Redis info
   */
  async getInfo() {
    return await getRedisInfo();
  },
};
// Graceful shutdown handling
process.on('SIGTERM', async () => {
  safeLogger.info('Received SIGTERM, closing Redis connection');
  await closeRedisConnection();
  process.exit(0);
});
process.on('SIGINT', async () => {
  safeLogger.info('Received SIGINT, closing Redis connection');
  await closeRedisConnection();
  process.exit(0);
});
