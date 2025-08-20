import { config } from 'dotenv';
config(); // Load .env file first

import { safeLogger } from './logger.js';

/**
 * Database Configuration Module - Industry Standard
 *
 * Purpose: MySQL database configuration for production microservices
 * Features:
 * - Core connection settings
 * - Connection pooling
 * - Security (SSL)
 * - Performance optimization
 * - Retry mechanisms
 */

// ✅ Database Configuration
export const databaseConfig = {
  // MySQL Configuration
  mysql: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT) || 3306,
    database: process.env.DB_NAME || 'auth_service',
    username: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    dialect: 'mysql',

    // Connection Pool
    pool: {
      max: parseInt(process.env.DB_POOL_MAX) || 20,
      min: parseInt(process.env.DB_POOL_MIN) || 5,
      acquire: parseInt(process.env.DB_POOL_ACQUIRE) || 60000,
      idle: parseInt(process.env.DB_POOL_IDLE) || 10000,
      evict: parseInt(process.env.DB_POOL_EVICT) || 60000,
    },

    // Connection Options
    connectTimeout: parseInt(process.env.DB_CONNECT_TIMEOUT) || 60000,
    acquireTimeout: parseInt(process.env.DB_ACQUIRE_TIMEOUT) || 60000,
    timeout: parseInt(process.env.DB_TIMEOUT) || 60000,

    // Logging
    logging: process.env.DB_LOGGING === 'true',
    benchmark: process.env.NODE_ENV === 'development',

    // SSL Configuration
    ssl:
      process.env.NODE_ENV === 'production' || process.env.DB_SSL === 'true'
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
      max: parseInt(process.env.DB_RETRY_MAX) || 3,
      backoffBase: parseInt(process.env.DB_RETRY_BACKOFF_BASE) || 1000,
      backoffExponent: parseFloat(process.env.DB_RETRY_BACKOFF_EXPONENT) || 1.5,
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

  safeLogger.info('Database configuration validated', {
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
