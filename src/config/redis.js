import { safeLogger } from './logger.js';

/**
 * Redis Configuration Module - Simple & Clean
 *
 * Purpose: Essential Redis configuration for authService caching
 * Features:
 * - Core connection settings
 * - Essential timeouts and retry
 * - Security (TLS)
 * - Performance optimization
 */

// ✅ Core Redis Configuration
export const redisConfig = {
  // Core Connection
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT) || 6379,
  password: process.env.REDIS_PASSWORD || undefined,
  db: parseInt(process.env.REDIS_DB) || 0,

  // Essential Timeouts
  connectTimeout: 10000,
  commandTimeout: 5000,
  keepAlive: 30000,

  // Retry Strategy
  maxRetriesPerRequest: 3,
  retryDelayOnFailover: 100,

  // Performance
  enableAutoPipelining: true,
  enableReadyCheck: true,
  enableOfflineQueue: true,

  // Security
  tls:
    process.env.REDIS_TLS === 'true'
      ? {
          rejectUnauthorized: false,
        }
      : undefined,

  // Key Management
  keyPrefix: process.env.REDIS_KEY_PREFIX || 'auth:',

  // Connection Options
  lazyConnect: false,
  family: 4, // IPv4
};

// ✅ Redis URL Construction
export const getRedisUrl = () => {
  if (process.env.REDIS_URL) {
    return process.env.REDIS_URL;
  }

  const { host, port, password, db } = redisConfig;
  const auth = password ? `:${password}@` : '';
  return `redis://${auth}${host}:${port}/${db}`;
};

// ✅ Redis Connection Options
export const getRedisConnectionOptions = () => {
  const options = {
    host: redisConfig.host,
    port: redisConfig.port,
    password: redisConfig.password,
    db: redisConfig.db,
    connectTimeout: redisConfig.connectTimeout,
    commandTimeout: redisConfig.commandTimeout,
    keepAlive: redisConfig.keepAlive,
    maxRetriesPerRequest: redisConfig.maxRetriesPerRequest,
    enableReadyCheck: redisConfig.enableReadyCheck,
    enableOfflineQueue: redisConfig.enableOfflineQueue,
    enableAutoPipelining: redisConfig.enableAutoPipelining,
    keyPrefix: redisConfig.keyPrefix,
    lazyConnect: redisConfig.lazyConnect,
    family: redisConfig.family,
  };

  // Add TLS if enabled
  if (redisConfig.tls) {
    options.tls = redisConfig.tls;
  }

  return options;
};

// ✅ Redis Retry Strategy
export const getRedisRetryStrategy = () => {
  return times => {
    const maxRetries = 5;
    const backoffDelay = Math.min(times * 100, 2000);

    if (times > maxRetries) {
      safeLogger.error('Redis max retries exceeded', { times, maxRetries });
      return null; // Stop retrying
    }

    return backoffDelay;
  };
};

// ✅ Basic Configuration Validation
export const validateRedisConfig = () => {
  const errors = [];

  if (!redisConfig.host) {
    errors.push('REDIS_HOST is required');
  }

  if (redisConfig.port < 1 || redisConfig.port > 65535) {
    errors.push('REDIS_PORT must be a valid port number (1-65535)');
  }

  if (errors.length > 0) {
    safeLogger.error('Redis configuration validation failed', { errors });
    throw new Error(`Redis configuration errors: ${errors.join(', ')}`);
  }

  safeLogger.info('Redis configuration validated', {
    host: redisConfig.host,
    port: redisConfig.port,
    tls: !!redisConfig.tls,
  });
};

// ✅ Export default configuration
export default redisConfig;
