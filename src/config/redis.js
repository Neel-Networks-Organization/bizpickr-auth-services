import { validateEnvType } from './utils.js';
import { safeLogger } from './logger.js';

/**
 * Redis Configuration Module
 *
 * Features:
 * - Centralized Redis configuration
 * - Environment-based configuration
 * - Validation and type checking
 * - Security settings
 * - Performance optimizations
 * - Cluster and Sentinel support
 * - Health monitoring settings
 */

// ✅ Redis Configuration
export const redisConfig = {
  // Basic Connection Settings
  host: process.env.REDIS_HOST || 'localhost',
  port: validateEnvType(process.env.REDIS_PORT, 'number', 6379),
  password: process.env.REDIS_PASSWORD || '',
  db: validateEnvType(process.env.REDIS_DB, 'number', 0),

  // Connection Options
  connectTimeout: validateEnvType(
    process.env.REDIS_CONNECT_TIMEOUT,
    'number',
    10000,
  ),
  commandTimeout: validateEnvType(
    process.env.REDIS_COMMAND_TIMEOUT,
    'number',
    5000,
  ),
  lazyConnect: false, // only true if you want to connect to redis on startup
  keepAlive: validateEnvType(process.env.REDIS_KEEPALIVE, 'number', 30000),

  // Retry Configuration
  maxRetriesPerRequest: validateEnvType(
    process.env.REDIS_MAX_RETRIES_PER_REQUEST,
    'number',
    3,
  ),
  maxReconnectAttempts: validateEnvType(
    process.env.REDIS_MAX_RECONNECT_ATTEMPTS,
    'number',
    5,
  ),
  retryDelay: validateEnvType(process.env.REDIS_RETRY_DELAY, 'number', 100),

  // Performance Settings
  enableReadyCheck: true,
  enableOfflineQueue: true,
  enableAutoPipelining: true,
  autoPipeliningIgnoredCommands: ['ping', 'info'],

  // Security Settings
  tls: validateEnvType(process.env.REDIS_TLS, 'boolean', false)
    ? {
      rejectUnauthorized: false,
    }
    : undefined,

  // Key Prefix
  keyPrefix: process.env.REDIS_KEY_PREFIX || 'authService:',

  // Family (IPv4/IPv6)
  family: validateEnvType(process.env.REDIS_FAMILY, 'number', 4),

  // Slow Command Detection
  slowCommandThreshold: validateEnvType(
    process.env.REDIS_SLOW_COMMAND_THRESHOLD,
    'number',
    100,
  ),

  // Health Monitoring
  healthCheckInterval: validateEnvType(
    process.env.REDIS_HEALTH_CHECK_INTERVAL,
    'number',
    30000,
  ),

  // Cluster Configuration
  cluster: {
    enabled: validateEnvType(
      process.env.REDIS_CLUSTER_ENABLED,
      'boolean',
      false,
    ),
    enableReadyCheck: true,
    scaleReads: process.env.REDIS_CLUSTER_SCALE_READS || 'slave',
    maxRedirections: validateEnvType(
      process.env.REDIS_CLUSTER_MAX_REDIRECTIONS,
      'number',
      16,
    ),
    retryDelayOnFailover: validateEnvType(
      process.env.REDIS_CLUSTER_RETRY_DELAY,
      'number',
      100,
    ),
  },

  // Sentinel Configuration
  sentinel: {
    enabled: validateEnvType(
      process.env.REDIS_SENTINEL_ENABLED,
      'boolean',
      false,
    ),
    password: process.env.REDIS_SENTINEL_PASSWORD,
    masterName: process.env.REDIS_SENTINEL_MASTER_NAME || 'mymaster',
    nodes: validateEnvType(process.env.REDIS_SENTINEL_NODES, 'array', []),
  },

  // Memory Management
  maxMemoryPolicy: process.env.REDIS_MAX_MEMORY_POLICY || 'allkeys-lru',
  maxMemory: process.env.REDIS_MAX_MEMORY,

  // Logging
  logging: {
    enabled: validateEnvType(
      process.env.REDIS_LOGGING_ENABLED,
      'boolean',
      true,
    ),
    level: process.env.REDIS_LOG_LEVEL || 'info',
    slowQueryLogging: validateEnvType(
      process.env.REDIS_SLOW_QUERY_LOGGING,
      'boolean',
      true,
    ),
  },
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
    lazyConnect: redisConfig.lazyConnect,
    keepAlive: redisConfig.keepAlive,
    maxRetriesPerRequest: redisConfig.maxRetriesPerRequest,
    enableReadyCheck: redisConfig.enableReadyCheck,
    enableOfflineQueue: redisConfig.enableOfflineQueue,
    enableAutoPipelining: redisConfig.enableAutoPipelining,
    autoPipeliningIgnoredCommands: redisConfig.autoPipeliningIgnoredCommands,
    keyPrefix: redisConfig.keyPrefix,
    family: redisConfig.family,
  };

  // Add TLS if enabled
  if (redisConfig.tls) {
    options.tls = redisConfig.tls;
  }

  // Add cluster configuration if enabled
  if (redisConfig.cluster.enabled) {
    options.cluster = {
      enableReadyCheck: redisConfig.cluster.enableReadyCheck,
      scaleReads: redisConfig.cluster.scaleReads,
      maxRedirections: redisConfig.cluster.maxRedirections,
      retryDelayOnFailover: redisConfig.cluster.retryDelayOnFailover,
    };
  }

  // Add sentinel configuration if enabled
  if (redisConfig.sentinel.enabled) {
    options.sentinels = redisConfig.sentinel.nodes;
    options.name = redisConfig.sentinel.masterName;
    if (redisConfig.sentinel.password) {
      options.sentinelPassword = redisConfig.sentinel.password;
    }
  }

  return options;
};

// ✅ Redis Retry Strategy
export const getRedisRetryStrategy = () => {
  return times => {
    const maxRetries = redisConfig.maxReconnectAttempts;
    const backoffDelay = Math.min(times * redisConfig.retryDelay, 2000);

    if (times > maxRetries) {
      safeLogger.error('Redis max retries exceeded', {
        times,
        maxRetries,
        host: redisConfig.host,
        port: redisConfig.port,
      });
      return null; // Stop retrying
    }

    safeLogger.warn('Redis retry attempt', {
      attempt: times,
      maxRetries,
      delay: `${backoffDelay}ms`,
    });

    return backoffDelay;
  };
};

// ✅ Redis Configuration Validation
export const validateRedisConfig = () => {
  const errors = [];

  // Validate required fields
  if (!redisConfig.host) {
    errors.push('REDIS_HOST is required');
  }

  if (!redisConfig.port || redisConfig.port < 1 || redisConfig.port > 65535) {
    errors.push('REDIS_PORT must be a valid port number (1-65535)');
  }

  // Validate cluster configuration
  if (redisConfig.cluster.enabled && redisConfig.sentinel.enabled) {
    errors.push('Cannot enable both Redis Cluster and Sentinel simultaneously');
  }

  // Validate sentinel configuration
  if (redisConfig.sentinel.enabled && redisConfig.sentinel.nodes.length === 0) {
    errors.push('REDIS_SENTINEL_NODES is required when Sentinel is enabled');
  }

  if (errors.length > 0) {
    safeLogger.error('Redis configuration validation failed', { errors });
    throw new Error(`Redis configuration errors: ${errors.join(', ')}`);
  }
  safeLogger.info('Redis config being used', getRedisConnectionOptions());
  safeLogger.info('Redis configuration validation passed', {
    host: redisConfig.host,
    port: redisConfig.port,
    cluster: redisConfig.cluster.enabled,
    sentinel: redisConfig.sentinel.enabled,
    tls: !!redisConfig.tls,
  });
};

// ✅ Export default configuration
export default redisConfig;
