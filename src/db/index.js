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

// Create Sequelize instance
const sequelize = new Sequelize(
  databaseConfig.mysql.database,
  databaseConfig.mysql.username,
  databaseConfig.mysql.password,
  {
    ...getDatabaseConnectionOptions(),
    logging: false, // Disable database logging
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

    const connectionOptions = getDatabaseConnectionOptions();
    const { mysql } = databaseConfig;

    // Timeout logic for DB connection
    const dbTimeoutMs = 10000;
    const dbTimeoutPromise = new Promise((_, reject) =>
      setTimeout(() => {
        safeLogger.error(
          'Database connection timeout (10s): Unable to connect to DB'
        );
        reject(
          new ApiError(504, 'Database connection timeout', [
            'Database did not become ready within 10 seconds',
            'Please check DB server status and network connectivity',
          ])
        );
      }, dbTimeoutMs)
    );

    // Test connection with timeout
    await Promise.race([sequelize.authenticate(), dbTimeoutPromise]);

    // Sync database (create tables)
    await sequelize.sync({ force: false }); // Don't force recreate tables

    safeLogger.info('Database connection established successfully', {
      dialect: mysql.dialect,
      database: mysql.database,
    });

    // Set up event listeners
    setupDatabaseEventListeners();

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
    return sequelize.authenticate() !== undefined;
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

export default sequelize;
