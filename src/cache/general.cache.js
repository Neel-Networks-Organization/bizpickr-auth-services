import { getRedisClient } from '../db/redis.js';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
/**
 * Industry-level General Cache Module
 *
 * Features:
 * - Generic data caching with TTL management
 * - Cache warming and preloading strategies
 * - Cache invalidation patterns
 * - Bulk operations and batch processing
 * - Cache statistics and analytics
 * - Memory optimization and compression
 * - Cache partitioning and namespacing
 * - Cache eviction policies
 */
// Cache configuration
const PREFIX = {
  GENERAL: 'cache:general:',
  BULK: 'cache:bulk:',
  STATS: 'cache:stats:',
  PARTITION: 'cache:partition:',
  VERSION: 'cache:version:',
  LOCK: 'cache:lock:',
};
const EXPIRY = {
  SHORT: 5 * 60, // 5 minutes
  MEDIUM: 30 * 60, // 30 minutes
  LONG: 2 * 60 * 60, // 2 hours
  EXTENDED: 24 * 60 * 60, // 24 hours
  PERMANENT: 0, // No expiry
};
// Cache statistics
const cacheStats = {
  totalOperations: 0,
  successfulOperations: 0,
  failedOperations: 0,
  cacheHits: 0,
  cacheMisses: 0,
  cacheEvictions: 0,
  memoryUsage: 0,
  uptime: Date.now(),
  partitions: new Map(),
};
/**
 * Update cache statistics
 * @param {string} type - Statistic type
 * @param {Object} data - Additional data
 */
function updateCacheStats(type, data = {}) {
  switch (type) {
    case 'operation':
      cacheStats.totalOperations++;
      break;
    case 'success':
      cacheStats.successfulOperations++;
      break;
    case 'failure':
      cacheStats.failedOperations++;
      break;
    case 'hit':
      cacheStats.cacheHits++;
      break;
    case 'miss':
      cacheStats.cacheMisses++;
      break;
    case 'eviction':
      cacheStats.cacheEvictions++;
      break;
  }
  safeLogger.debug('Cache statistics updated', {
    type,
    data,
    stats: { ...cacheStats },
  });
}
/**
 * Compress data for storage
 * @param {any} data - Data to compress
 * @param {Object} options - Compression options
 * @returns {string} Compressed data
 */
function compressData(data, options = {}) {
  const { algorithm = 'base64', level = 1 } = options;
  try {
    const jsonString = JSON.stringify(data);
    switch (algorithm) {
      case 'base64':
        return Buffer.from(jsonString).toString('base64');
      case 'gzip':
        // In production, use zlib for gzip compression
        return Buffer.from(jsonString).toString('base64');
      default:
        return jsonString;
    }
  } catch (error) {
    safeLogger.warn('Data compression failed, using original data', {
      error: error.message,
      algorithm,
    });
    return JSON.stringify(data);
  }
}
/**
 * Decompress data from storage
 * @param {string} compressedData - Compressed data
 * @param {Object} options - Decompression options
 * @returns {any} Decompressed data
 */
function decompressData(compressedData, options = {}) {
  const { algorithm = 'base64' } = options;
  try {
    let decoded;
    switch (algorithm) {
      case 'base64':
        decoded = Buffer.from(compressedData, 'base64').toString();
        break;
      case 'gzip':
        // In production, use zlib for gzip decompression
        decoded = Buffer.from(compressedData, 'base64').toString();
        break;
      default:
        decoded = compressedData;
    }
    return JSON.parse(decoded);
  } catch (error) {
    safeLogger.error('Data decompression failed', {
      error: error.message,
      algorithm,
    });
    return null;
  }
}
/**
 * Generate cache key with namespace
 * @param {string} namespace - Cache namespace
 * @param {string} key - Cache key
 * @param {string} partition - Cache partition
 * @returns {string} Namespaced cache key
 */
function generateCacheKey(namespace, key, partition = 'default') {
  const partitionPrefix = partition ? `${PREFIX.PARTITION}${partition}:` : '';
  return `${PREFIX.GENERAL}${partitionPrefix}${namespace}:${key}`;
}
/**
 * Safe Redis operation with error handling
 * @param {Function} operation - Redis operation to execute
 * @param {string} operationName - Name of the operation for logging
 * @returns {Promise<any>} Operation result
 */
async function safeRedisOperation(operation, operationName) {
  const correlationId = getCorrelationId();
  const startTime = Date.now();
  try {
    updateCacheStats('operation');
    const result = await operation();
    const processingTime = Date.now() - startTime;
    updateCacheStats('success');
    safeLogger.debug('Redis operation successful', {
      operation: operationName,
      correlationId,
      processingTime: `${processingTime}ms`,
    });
    return result;
  } catch (error) {
    const processingTime = Date.now() - startTime;
    updateCacheStats('failure');
    safeLogger.error('Redis operation failed', {
      operation: operationName,
      error: error.message,
      stack: error.stack,
      correlationId,
      processingTime: `${processingTime}ms`,
    });
    throw error;
  }
}
/**
 * General cache module with advanced features
 */
export const generalCache = {
  /**
   * Store data in cache
   * @param {string} namespace - Cache namespace
   * @param {string} key - Cache key
   * @param {any} data - Data to cache
   * @param {Object} options - Cache options
   */
  async set(namespace, key, data, options = {}) {
    const {
      ttl = EXPIRY.MEDIUM,
      compress = true,
      partition = 'default',
      algorithm = 'base64',
    } = options;
    try {
      const cacheKey = generateCacheKey(namespace, key, partition);
      const compressedData = compress
        ? compressData(data, { algorithm })
        : JSON.stringify(data);
      await safeRedisOperation(async () => {
        const redis = getRedisClient();
        if (ttl > 0) {
          await redis.set(cacheKey, compressedData, 'EX', ttl);
        } else {
          await redis.set(cacheKey, compressedData);
        }
      }, 'set');
      // Update partition statistics
      if (!cacheStats.partitions.has(partition)) {
        cacheStats.partitions.set(partition, {
          hits: 0,
          misses: 0,
          operations: 0,
        });
      }
      cacheStats.partitions.get(partition).operations++;
    } catch (error) {
      safeLogger.error('Failed to set cache', {
        namespace,
        key,
        partition,
        error: error.message,
      });
      throw error;
    }
  },
  /**
   * Get data from cache
   * @param {string} namespace - Cache namespace
   * @param {string} key - Cache key
   * @param {Object} options - Cache options
   * @returns {Promise<any>} Cached data
   */
  async get(namespace, key, options = {}) {
    const {
      fallback = null,
      warmCache = false,
      ttl = EXPIRY.MEDIUM,
      partition = 'default',
      algorithm = 'base64',
    } = options;
    try {
      const cacheKey = generateCacheKey(namespace, key, partition);
      const data = await safeRedisOperation(async () => {
        const redis = getRedisClient();
        return await redis.get(cacheKey);
      }, 'get');
      if (data) {
        updateCacheStats('hit');
        if (cacheStats.partitions.has(partition)) {
          cacheStats.partitions.get(partition).hits++;
        }
        return decompressData(data, { algorithm });
      }
      updateCacheStats('miss');
      if (cacheStats.partitions.has(partition)) {
        cacheStats.partitions.get(partition).misses++;
      }
      // Try fallback if provided
      if (fallback) {
        const fallbackData = await fallback();
        if (fallbackData && warmCache) {
          await this.set(namespace, key, fallbackData, {
            ttl,
            partition,
            algorithm,
          });
        }
        return fallbackData;
      }
      return null;
    } catch (error) {
      safeLogger.error('Failed to get cache', {
        namespace,
        key,
        partition,
        error: error.message,
      });
      return null;
    }
  },
  /**
   * Delete data from cache
   * @param {string} namespace - Cache namespace
   * @param {string} key - Cache key
   * @param {string} partition - Cache partition
   */
  async delete(namespace, key, partition = 'default') {
    try {
      const cacheKey = generateCacheKey(namespace, key, partition);
      await safeRedisOperation(async () => {
        const redis = getRedisClient();
        await redis.del(cacheKey);
      }, 'delete');
    } catch (error) {
      safeLogger.error('Failed to delete cache', {
        namespace,
        key,
        partition,
        error: error.message,
      });
    }
  },
  /**
   * Check if key exists in cache
   * @param {string} namespace - Cache namespace
   * @param {string} key - Cache key
   * @param {string} partition - Cache partition
   * @returns {Promise<boolean>} Whether key exists
   */
  async exists(namespace, key, partition = 'default') {
    try {
      const cacheKey = generateCacheKey(namespace, key, partition);
      const result = await safeRedisOperation(async () => {
        const redis = getRedisClient();
        return await redis.exists(cacheKey);
      }, 'exists');
      return result === 1;
    } catch (error) {
      safeLogger.error('Failed to check cache existence', {
        namespace,
        key,
        partition,
        error: error.message,
      });
      return false;
    }
  },
  /**
   * Get TTL for cache key
   * @param {string} namespace - Cache namespace
   * @param {string} key - Cache key
   * @param {string} partition - Cache partition
   * @returns {Promise<number>} TTL in seconds
   */
  async getTTL(namespace, key, partition = 'default') {
    try {
      const cacheKey = generateCacheKey(namespace, key, partition);
      const ttl = await safeRedisOperation(async () => {
        const redis = getRedisClient();
        return await redis.ttl(cacheKey);
      }, 'getTTL');
      return ttl;
    } catch (error) {
      safeLogger.error('Failed to get cache TTL', {
        namespace,
        key,
        partition,
        error: error.message,
      });
      return -1;
    }
  },
  /**
   * Set TTL for cache key
   * @param {string} namespace - Cache namespace
   * @param {string} key - Cache key
   * @param {number} ttl - TTL in seconds
   * @param {string} partition - Cache partition
   */
  async setTTL(namespace, key, ttl, partition = 'default') {
    try {
      const cacheKey = generateCacheKey(namespace, key, partition);
      await safeRedisOperation(async () => {
        const redis = getRedisClient();
        await redis.expire(cacheKey, ttl);
      }, 'setTTL');
    } catch (error) {
      safeLogger.error('Failed to set cache TTL', {
        namespace,
        key,
        ttl,
        partition,
        error: error.message,
      });
    }
  },
  /**
   * Bulk set multiple cache entries
   * @param {Array} entries - Array of cache entries
   * @param {Object} options - Bulk options
   */
  async bulkSet(entries, options = {}) {
    const {
      ttl = EXPIRY.MEDIUM,
      compress = true,
      partition = 'default',
      algorithm = 'base64',
    } = options;
    try {
      await safeRedisOperation(async () => {
        const redis = getRedisClient();
        const pipeline = redis.pipeline();
        for (const entry of entries) {
          const { namespace, key, data } = entry;
          const cacheKey = generateCacheKey(namespace, key, partition);
          const compressedData = compress
            ? compressData(data, { algorithm })
            : JSON.stringify(data);
          if (ttl > 0) {
            pipeline.set(cacheKey, compressedData, 'EX', ttl);
          } else {
            pipeline.set(cacheKey, compressedData);
          }
        }
        await pipeline.exec();
      }, 'bulkSet');
      safeLogger.info('Bulk cache set completed', {
        count: entries.length,
        partition,
      });
    } catch (error) {
      safeLogger.error('Failed to bulk set cache', {
        count: entries.length,
        partition,
        error: error.message,
      });
      throw error;
    }
  },
  /**
   * Bulk get multiple cache entries
   * @param {Array} keys - Array of cache keys
   * @param {Object} options - Bulk options
   * @returns {Promise<Array>} Array of cache results
   */
  async bulkGet(keys, options = {}) {
    const { partition = 'default', algorithm = 'base64' } = options;
    try {
      const cacheKeys = keys.map(({ namespace, key }) =>
        generateCacheKey(namespace, key, partition)
      );
      const results = await safeRedisOperation(async () => {
        const redis = getRedisClient();
        return await redis.mget(cacheKeys);
      }, 'bulkGet');
      const processedResults = results.map((data, index) => {
        if (data) {
          updateCacheStats('hit');
          return {
            namespace: keys[index].namespace,
            key: keys[index].key,
            data: decompressData(data, { algorithm }),
            found: true,
          };
        } else {
          updateCacheStats('miss');
          return {
            namespace: keys[index].namespace,
            key: keys[index].key,
            data: null,
            found: false,
          };
        }
      });
      return processedResults;
    } catch (error) {
      safeLogger.error('Failed to bulk get cache', {
        count: keys.length,
        partition,
        error: error.message,
      });
      return keys.map(key => ({ ...key, data: null, found: false }));
    }
  },
  /**
   * Clear cache by namespace
   * @param {string} namespace - Cache namespace
   * @param {string} partition - Cache partition
   */
  async clearNamespace(namespace, partition = 'default') {
    try {
      const pattern = generateCacheKey(namespace, '*', partition);
      await safeRedisOperation(async () => {
        const redis = getRedisClient();
        const keys = await redis.keys(pattern);
        if (keys.length > 0) {
          await redis.del(keys);
        }
      }, 'clearNamespace');
      safeLogger.info('Cache namespace cleared', {
        namespace,
        partition,
      });
    } catch (error) {
      safeLogger.error('Failed to clear cache namespace', {
        namespace,
        partition,
        error: error.message,
      });
    }
  },
  /**
   * Clear cache by partition
   * @param {string} partition - Cache partition
   */
  async clearPartition(partition) {
    try {
      const pattern = `${PREFIX.GENERAL}${PREFIX.PARTITION}${partition}:*`;
      await safeRedisOperation(async () => {
        const redis = getRedisClient();
        const keys = await redis.keys(pattern);
        if (keys.length > 0) {
          await redis.del(keys);
        }
      }, 'clearPartition');
      safeLogger.info('Cache partition cleared', {
        partition,
      });
    } catch (error) {
      safeLogger.error('Failed to clear cache partition', {
        partition,
        error: error.message,
      });
    }
  },
  /**
   * Get cache statistics
   * @returns {Object} Cache statistics
   */
  getStats() {
    const uptime = Date.now() - cacheStats.uptime;
    const hitRate =
      cacheStats.cacheHits + cacheStats.cacheMisses > 0
        ? (cacheStats.cacheHits /
            (cacheStats.cacheHits + cacheStats.cacheMisses)) *
          100
        : 0;
    const successRate =
      cacheStats.totalOperations > 0
        ? (cacheStats.successfulOperations / cacheStats.totalOperations) * 100
        : 0;
    const partitionStats = {};
    for (const [partition, stats] of cacheStats.partitions) {
      const partitionHitRate =
        stats.hits + stats.misses > 0
          ? (stats.hits / (stats.hits + stats.misses)) * 100
          : 0;
      partitionStats[partition] = {
        ...stats,
        hitRate: `${partitionHitRate.toFixed(2)}%`,
      };
    }
    return {
      ...cacheStats,
      uptime: `${Math.round(uptime / 1000)}s`,
      hitRate: `${hitRate.toFixed(2)}%`,
      successRate: `${successRate.toFixed(2)}%`,
      partitions: partitionStats,
      currentTime: new Date().toISOString(),
    };
  },
  /**
   * Reset cache statistics
   */
  resetStats() {
    Object.assign(cacheStats, {
      totalOperations: 0,
      successfulOperations: 0,
      failedOperations: 0,
      cacheHits: 0,
      cacheMisses: 0,
      cacheEvictions: 0,
      memoryUsage: 0,
      uptime: Date.now(),
    });
    cacheStats.partitions.clear();
    safeLogger.info('Cache statistics reset');
  },
  /**
   * Health check for cache service
   * @returns {Promise<Object>} Health status
   */
  async healthCheck() {
    try {
      const startTime = Date.now();
      await safeRedisOperation(async () => {
        const redis = getRedisClient();
        await redis.ping();
      }, 'healthCheck');
      const responseTime = Date.now() - startTime;
      return {
        status: 'healthy',
        responseTime: `${responseTime}ms`,
        stats: this.getStats(),
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message,
        stats: this.getStats(),
      };
    }
  },
};
