import { Sequelize } from 'sequelize';
import {
  databaseConfig,
  getDatabaseConnectionOptions,
  validateDatabaseConfig,
} from '../config/database.js';
import { safeLogger } from '../config/logger.js';
import { ApiError } from '../utils/index.js';

/**
 * Simple Database Client for authService
 *
 * Purpose: MySQL connection for user authentication and sessions
 * Features:
 * - Basic connection management
 * - Simple error handling
 * - Connection validation
 * - Graceful shutdown
 */

// Create Sequelize instance with proper timeout settings
const sequelize = new Sequelize(
  databaseConfig.mysql.database,
  databaseConfig.mysql.username,
  databaseConfig.mysql.password,
  {
    ...getDatabaseConnectionOptions(),
    logging: process.env.NODE_ENV === 'development' ? console.log : false,
    // Remove conflicting timeout settings - use config defaults
  }
);

/**
 * Initialize database connection
 * @returns {Promise<Sequelize>} Sequelize instance
 */
export async function initializeDatabase() {
  try {
    // Validate database configuration
    validateDatabaseConfig();

    const { mysql } = databaseConfig;

    safeLogger.info('Testing database connection...');

    // Test connection with proper error handling
    await sequelize.authenticate();

    // Sync database (create tables if they don't exist)
    await sequelize.sync({ force: true });

    safeLogger.info('Database connection established successfully', {
      dialect: mysql.dialect,
      database: mysql.database,
      host: mysql.host,
      port: mysql.port,
    });

    // Set up event listeners
    setupDatabaseEventListeners();

    return sequelize;
  } catch (error) {
    safeLogger.error('Database connection failed', {
      error: error.message,
      host: databaseConfig.mysql.host,
      database: databaseConfig.mysql.database,
      port: databaseConfig.mysql.port,
    });

    throw new ApiError(503, 'Database connection failed', [
      'Unable to connect to the database',
      'Please check database configuration and network connectivity',
    ]);
  }
}

/**
 * Setup database event listeners
 */
function setupDatabaseEventListeners() {
  sequelize.addHook('afterConnect', connection => {
    safeLogger.debug('Database connection established', {
      connectionId: connection.threadId || connection.id,
    });
  });

  sequelize.addHook('beforeDisconnect', connection => {
    safeLogger.debug('Database connection closed', {
      connectionId: connection.threadId || connection.id,
    });
  });

  // Query events for basic monitoring
  sequelize.beforeQuery(options => {
    options.startTime = Date.now();
  });

  sequelize.afterQuery(options => {
    if (options.startTime) {
      const duration = Date.now() - options.startTime;
      if (duration > 1000) {
        // Log slow queries (>1s)
        safeLogger.warn('Slow database query detected', {
          duration: `${duration}ms`,
          sql: options.sql,
        });
      }
    }
  });
}

/**
 * Get database instance
 * @returns {Sequelize} Sequelize instance
 */
export function getDatabase() {
  return sequelize;
}

/**
 * Check if database is connected
 * @returns {boolean} Connection status
 */
export function isDatabaseConnected() {
  try {
    return sequelize.connectionManager.hasValidConnections();
  } catch {
    return false;
  }
}

/**
 * Close database connection
 * @returns {Promise<void>}
 */
export async function closeDatabase() {
  try {
    safeLogger.info('Closing database connection');
    await sequelize.close();
    safeLogger.info('Database connection closed successfully');
  } catch (error) {
    safeLogger.error('Error closing database connection', {
      error: error.message,
    });
    throw error;
  }
}

/**
 * Test database connection
 * @returns {Promise<boolean>} Connection status
 */
export async function testDatabaseConnection() {
  try {
    await sequelize.authenticate();
    return true;
  } catch (error) {
    safeLogger.error('Database connection test failed', {
      error: error.message,
    });
    return false;
  }
}

/**
 * Health check for database
 * @returns {Promise<Object>} Health status
 */
export async function getDatabaseHealth() {
  try {
    const isConnected = await testDatabaseConnection();
    const poolStatus = sequelize.connectionManager.pool;

    return {
      status: isConnected ? 'healthy' : 'unhealthy',
      connected: isConnected,
      pool: {
        total: poolStatus.size,
        idle: poolStatus.idle,
        using: poolStatus.using,
      },
      timestamp: new Date().toISOString(),
    };
  } catch (error) {
    return {
      status: 'error',
      error: error.message,
      timestamp: new Date().toISOString(),
    };
  }
}

export default sequelize;
