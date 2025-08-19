import { config } from 'dotenv';
config(); // Load .env file first

import { validateEnvType } from './utils.js';
import { safeLogger } from './logger.js';

/**
 * Database Configuration Module
 *
 * Features:
 * - Centralized database configuration
 * - Environment-based configuration
 * - Validation and type checking
 * - Security settings
 * - Performance optimizations
 * - Connection pooling settings
 * - SSL configuration
 */

// ✅ Database Configuration
export const databaseConfig = {
  // MySQL Configuration
  mysql: {
    host: process.env.DB_HOST || 'localhost',
    port: validateEnvType(process.env.DB_PORT, 'number', 3306),
    database: process.env.DB_NAME || 'auth_service',
    username: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    dialect: 'mysql',

    // Connection Pool
    pool: {
      max: validateEnvType(process.env.DB_POOL_MAX, 'number', 20),
      min: validateEnvType(process.env.DB_POOL_MIN, 'number', 5),
      acquire: validateEnvType(process.env.DB_POOL_ACQUIRE, 'number', 60000),
      idle: validateEnvType(process.env.DB_POOL_IDLE, 'number', 10000),
      evict: validateEnvType(process.env.DB_POOL_EVICT, 'number', 60000),
    },

    // Connection Options
    connectTimeout: validateEnvType(
      process.env.DB_CONNECT_TIMEOUT,
      'number',
      60000
    ),
    acquireTimeout: validateEnvType(
      process.env.DB_ACQUIRE_TIMEOUT,
      'number',
      60000
    ),
    timeout: validateEnvType(process.env.DB_TIMEOUT, 'number', 60000),

    // Logging
    logging: validateEnvType(process.env.DB_LOGGING, 'boolean', false),
    benchmark: process.env.NODE_ENV === 'development',

    // SSL Configuration
    ssl:
      process.env.NODE_ENV === 'production' ||
      validateEnvType(process.env.DB_SSL, 'boolean', false)
        ? {
            require: true,
            rejectUnauthorized: false,
          }
        : false,

    // Timezone and Character Set
    timezone: process.env.DB_TIMEZONE || '+00:00',
    charset: 'utf8mb4',
    collate: 'utf8mb4_unicode_ci',

    // Performance Settings
    supportBigNumbers: true,
    bigNumberStrings: true,
    dateStrings: true,
    decimalNumbers: true,
    multipleStatements: false, // Security: prevent SQL injection

    // Retry Configuration
    retry: {
      max: validateEnvType(process.env.DB_RETRY_MAX, 'number', 3),
      backoffBase: validateEnvType(
        process.env.DB_RETRY_BACKOFF_BASE,
        'number',
        1000
      ),
      backoffExponent: validateEnvType(
        process.env.DB_RETRY_BACKOFF_EXPONENT,
        'number',
        1.5
      ),
    },

    // Model Settings
    define: {
      timestamps: true,
      underscored: true,
      freezeTableName: true,
      charset: 'utf8mb4',
      collate: 'utf8mb4_unicode_ci',
    },

    // Transaction Settings
    isolationLevel: 'READ_COMMITTED',
  },
};

// Debug print
// console.log("DATABASE CONFIG DEBUG:", {
//   host: databaseConfig.mysql.host,
//   port: databaseConfig.mysql.port,
//   database: databaseConfig.mysql.database,
//   username: databaseConfig.mysql.username,
//   password: databaseConfig.mysql.password
//     ? `${databaseConfig.mysql.password.substring(0, 3)}***`
//     : "empty",
//   processEnvPassword: process.env.DB_PASSWORD ? "exists" : "missing",
// });

// ✅ Database URL Construction
export const getDatabaseUrl = () => {
  if (process.env.DATABASE_URL) {
    return process.env.DATABASE_URL;
  }

  const { host, port, database, username, password } = databaseConfig.mysql;
  const auth = password ? `${username}:${password}@` : `${username}@`;
  return `mysql://${auth}${host}:${port}/${database}`;
};

// ✅ Database Connection Options
export const getDatabaseConnectionOptions = () => {
  const { mysql } = databaseConfig;

  return {
    host: mysql.host,
    port: mysql.port,
    dialect: mysql.dialect,
    database: mysql.database,
    username: mysql.username,
    password: mysql.password,

    // Pool configuration
    pool: mysql.pool,

    // Connection options
    dialectOptions: {
      connectTimeout: mysql.connectTimeout,
      // acquireTimeout: mysql.acquireTimeout,
      // timeout: mysql.timeout,
      charset: mysql.charset,
      supportBigNumbers: mysql.supportBigNumbers,
      bigNumberStrings: mysql.bigNumberStrings,
      dateStrings: mysql.dateStrings,
      decimalNumbers: mysql.decimalNumbers,
      multipleStatements: mysql.multipleStatements,
      ssl: mysql.ssl,
    },

    // Logging
    logging: mysql.logging
      ? msg => {
          if (process.env.NODE_ENV === 'development') {
            safeLogger.debug('Database Query', { query: msg });
          }
        }
      : false,

    // Benchmark
    benchmark: mysql.benchmark,

    // Model settings
    define: mysql.define,

    // Timezone
    timezone: mysql.timezone,
  };
};

// ✅ Database Configuration Validation
export const validateDatabaseConfig = () => {
  const errors = [];
  const { mysql } = databaseConfig;

  // Validate required fields
  if (!mysql.host) {
    errors.push('DB_HOST is required');
  }

  if (!mysql.port || mysql.port < 1 || mysql.port > 65535) {
    errors.push('DB_PORT must be a valid port number (1-65535)');
  }

  if (!mysql.database) {
    errors.push('DB_NAME is required');
  }

  if (!mysql.username) {
    errors.push('DB_USER is required');
  }

  // Validate pool configuration
  if (mysql.pool.max < mysql.pool.min) {
    errors.push('DB_POOL_MAX must be greater than or equal to DB_POOL_MIN');
  }

  if (mysql.pool.max <= 0) {
    errors.push('DB_POOL_MAX must be greater than 0');
  }

  if (errors.length > 0) {
    safeLogger.error('Database configuration validation failed', { errors });
    throw new Error(`Database configuration errors: ${errors.join(', ')}`);
  }
  safeLogger.info('Database configuration validation passed', {
    host: mysql.host,
    port: mysql.port,
    database: mysql.database,
    username: mysql.username,
    poolSize: `${mysql.pool.min}-${mysql.pool.max}`,
    ssl: !!mysql.ssl,
  });
};

// ✅ Export default configuration
export default databaseConfig;
