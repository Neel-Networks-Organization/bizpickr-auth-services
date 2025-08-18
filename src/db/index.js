import { Sequelize } from 'sequelize';
import {
  databaseConfig,
  getDatabaseConnectionOptions,
  validateDatabaseConfig,
} from '../config/database.js';
import { safeLogger } from '../config/logger.js';
import { ApiError } from '../utils/ApiError.js';

/**
 * Industry-level Database Client
 *
 * Features:
 * - Enhanced error handling and logging
 * - Connection pooling optimization
 * - Performance monitoring
 * - Health checks and diagnostics
 * - Security configurations
 * - Graceful shutdown handling
 */
// Database metrics
const dbMetrics = {
  totalConnections: 0,
  activeConnections: 0,
  idleConnections: 0,
  connectionErrors: 0,
  queryCount: 0,
  slowQueries: 0,
  lastHealthCheck: null,
  uptime: Date.now(),
};
// Create Sequelize instance
const sequelize = new Sequelize(
  databaseConfig.mysql.database,
  databaseConfig.mysql.username,
  databaseConfig.mysql.password,
  {
    ...getDatabaseConnectionOptions(),
    logging: false, // Disable database logging in development
  },
);
/**
 * Initialize database connection with enhanced error handling
 * @returns {Promise<Sequelize>} Sequelize instance
 */
export async function initializeDatabase() {
  try {
    // Validate database configuration
    validateDatabaseConfig();

    const connectionOptions = getDatabaseConnectionOptions();
    const { mysql } = databaseConfig;

    safeLogger.info('Initializing database connection', {
      host: mysql.host,
      port: mysql.port,
      database: mysql.database,
      username: mysql.username,
      poolSize: `${mysql.pool.min}-${mysql.pool.max}`,
    });

    // Timeout logic for DB connection
    const dbTimeoutMs = 10000;
    const dbTimeoutPromise = new Promise((_, reject) =>
      setTimeout(() => {
        safeLogger.error(
          'Database connection timeout (10s): Unable to connect to DB',
        );
        reject(
          new ApiError(504, 'Database connection timeout', [
            'Database did not become ready within 10 seconds',
            'Please check DB server status and network connectivity',
          ]),
        );
      }, dbTimeoutMs),
    );
    // Test connection with timeout
    await Promise.race([sequelize.authenticate(), dbTimeoutPromise]);
    await sequelize.sync({ force: false });
    safeLogger.info('Database connection established successfully', {
      dialect: mysql.dialect,
      database: mysql.database,
    });

    // Set up event listeners
    setupDatabaseEventListeners();
    // Start health monitoring
    startHealthMonitoring();
    return sequelize;
  } catch (error) {
    safeLogger.error('Database connection failed', {
      error: error.message,
      stack: error.stack,
      host: databaseConfig.mysql.host,
      database: databaseConfig.mysql.database,
    });
    throw new ApiError(503, 'Database connection failed', [
      'Unable to connect to the database',
      'Please check database configuration and network connectivity',
    ]);
  }
}
/**
 * Setup database event listeners for monitoring
 */
function setupDatabaseEventListeners() {
  // Connection pool events
  sequelize.connectionManager.on('connect', connection => {
    dbMetrics.totalConnections++;
    dbMetrics.activeConnections++;
    safeLogger.debug('Database connection established', {
      connectionId: connection.threadId,
      activeConnections: dbMetrics.activeConnections,
    });
  });
  sequelize.connectionManager.on('disconnect', connection => {
    dbMetrics.activeConnections = Math.max(0, dbMetrics.activeConnections - 1);
    safeLogger.debug('Database connection closed', {
      connectionId: connection.threadId,
      activeConnections: dbMetrics.activeConnections,
    });
  });
  // Query events
  sequelize.beforeQuery(options => {
    dbMetrics.queryCount++;
    options.startTime = Date.now();
  });
  sequelize.afterQuery(options => {
    const queryTime = Date.now() - options.startTime;
    if (queryTime > 1000) {
      // Log slow queries (>1s)
      dbMetrics.slowQueries++;
      safeLogger.warn('Slow database query detected', {
        query: options.sql,
        time: `${queryTime}ms`,
        slowQueries: dbMetrics.slowQueries,
      });
    }
  });
  // Error events
  sequelize.connectionManager.on('error', error => {
    dbMetrics.connectionErrors++;
    safeLogger.error('Database connection error', {
      error: error.message,
      stack: error.stack,
      connectionErrors: dbMetrics.connectionErrors,
    });
  });
}
/**
 * Start health monitoring
 */
function startHealthMonitoring() {
  // Health check interval
  setInterval(async() => {
    try {
      await sequelize.authenticate();
      dbMetrics.lastHealthCheck = new Date().toISOString();
      // Update pool metrics
      const pool = sequelize.connectionManager.pool;
      if (pool) {
        dbMetrics.activeConnections = pool.using.length;
        dbMetrics.idleConnections = pool.pending.length;
      }
      safeLogger.debug('Database health check passed', {
        activeConnections: dbMetrics.activeConnections,
        idleConnections: dbMetrics.idleConnections,
        uptime: `${Math.round((Date.now() - dbMetrics.uptime) / 1000)}s`,
      });
    } catch (error) {
      safeLogger.error('Database health check failed', {
        error: error.message,
        connectionErrors: dbMetrics.connectionErrors,
      });
    }
  }, 30 * 1000); // Every 30 seconds
}
/**
 * Get database health status
 * @returns {Object} Health status
 */
export function getDatabaseHealth() {
  const uptime = Date.now() - dbMetrics.uptime;
  return {
    status: sequelize.connectionManager.pool ? 'connected' : 'disconnected',
    uptime: `${Math.round(uptime / 1000)}s`,
    metrics: { ...dbMetrics },
    pool: sequelize.connectionManager.pool
      ? {
        size: sequelize.connectionManager.pool.size,
        available: sequelize.connectionManager.pool.available,
        pending: sequelize.connectionManager.pool.pending.length,
        using: sequelize.connectionManager.pool.using.length,
      }
      : null,
    lastHealthCheck: dbMetrics.lastHealthCheck,
  };
}
/**
 * Close database connection gracefully
 * @returns {Promise<void>}
 */
export async function closeDatabase() {
  try {
    safeLogger.info('Closing database connection');
    await sequelize.close();
    safeLogger.info('Database connection closed successfully', {
      totalConnections: dbMetrics.totalConnections,
      totalQueries: dbMetrics.queryCount,
      slowQueries: dbMetrics.slowQueries,
      connectionErrors: dbMetrics.connectionErrors,
    });
  } catch (error) {
    safeLogger.error('Error closing database connection', {
      error: error.message,
      stack: error.stack,
    });
    throw error;
  }
}
/**
 * Execute database transaction with retry logic
 * @param {Function} callback - Transaction callback
 * @param {Object} options - Transaction options
 * @returns {Promise<any>} Transaction result
 */
export async function executeTransaction(callback, options = {}) {
  const maxRetries = options.maxRetries || databaseConfig.mysql.retry.max;
  const backoffBase =
    options.backoffBase || databaseConfig.mysql.retry.backoffBase;
  const backoffExponent =
    options.backoffExponent || databaseConfig.mysql.retry.backoffExponent;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await sequelize.transaction(async transaction => {
        return await callback(transaction);
      }, options);
    } catch (error) {
      if (attempt === maxRetries) {
        safeLogger.error('Transaction failed after all retries', {
          error: error.message,
          stack: error.stack,
          attempts: attempt,
        });
        throw error;
      }
      // Check if error is retryable
      if (isRetryableError(error)) {
        const delay = backoffBase * Math.pow(backoffExponent, attempt - 1);
        safeLogger.warn('Transaction failed, retrying', {
          error: error.message,
          attempt,
          maxRetries,
          delay: `${delay}ms`,
        });
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      // Non-retryable error
      throw error;
    }
  }
}
/**
 * Check if error is retryable
 * @param {Error} error - Error to check
 * @returns {boolean} Whether error is retryable
 */
function isRetryableError(error) {
  const retryableErrors = [
    'ECONNRESET',
    'ECONNREFUSED',
    'ETIMEDOUT',
    'ENOTFOUND',
    'PROTOCOL_CONNECTION_LOST',
    'ER_ACCESS_DENIED_ERROR',
    'ER_BAD_DB_ERROR',
    'ER_CON_COUNT_ERROR',
    'ER_HOST_IS_BLOCKED',
    'ER_HOST_NOT_PRIVILEGED',
    'ER_ILLEGAL_GRANT_FOR_TABLE',
    'ER_NO_SUCH_TABLE',
    'ER_TABLE_EXISTS_ERROR',
    'ER_UNKNOWN_STORAGE_ENGINE',
    'ER_WRONG_DB_NAME',
  ];
  return retryableErrors.some(
    retryableError =>
      error.message.includes(retryableError) || error.code === retryableError,
  );
}
/**
 * Get database metrics
 * @returns {Object} Database metrics
 */
export function getDatabaseMetrics() {
  const { mysql } = databaseConfig;
  return {
    ...dbMetrics,
    currentTime: new Date().toISOString(),
    config: {
      host: mysql.host,
      port: mysql.port,
      database: mysql.database,
      poolSize: `${mysql.pool.min}-${mysql.pool.max}`,
    },
  };
}
// Graceful shutdown handling
process.on('SIGTERM', async() => {
  safeLogger.info('Received SIGTERM, closing database connection');
  await closeDatabase();
  process.exit(0);
});
process.on('SIGINT', async() => {
  safeLogger.info('Received SIGINT, closing database connection');
  await closeDatabase();
  process.exit(0);
});
// Export the configured sequelize instance
export default sequelize;
export { sequelize };
