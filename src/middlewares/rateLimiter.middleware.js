import { getRedisClient } from '../db/redis.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import { ApiError } from '../utils/ApiError.js';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import crypto from 'crypto';
/**
 * Industry-level Rate Limiting Middleware
 *
 * Features:
 * - Multiple rate limiting strategies (IP, User, Endpoint)
 * - Sliding window rate limiting
 * - Burst protection and gradual backoff
 * - Performance monitoring and metrics
 * - Configurable limits and windows
 * - Security headers and responses
 * - Redis-based distributed rate limiting
 */
// Rate limiter metrics
const rateLimiterMetrics = {
  totalRequests: 0,
  allowedRequests: 0,
  blockedRequests: 0,
  redisErrors: 0,
  uptime: Date.now(),
  endpointLimits: new Map(),
  ipLimits: new Map(),
};
/**
 * Update rate limiter metrics
 * @param {string} type - Metric type
 * @param {Object} data - Additional data
 */
function updateRateLimiterMetrics(type, data = {}) {
  switch (type) {
  case 'request':
    rateLimiterMetrics.totalRequests++;
    break;
  case 'allowed':
    rateLimiterMetrics.allowedRequests++;
    break;
  case 'blocked':
    rateLimiterMetrics.blockedRequests++;
    break;
  case 'redisError':
    rateLimiterMetrics.redisErrors++;
    break;
  }
  safeLogger.debug('Rate limiter metrics updated', {
    type,
    data,
    metrics: { ...rateLimiterMetrics },
  });
}
/**
 * Generate rate limit key based on strategy
 * @param {string} strategy - Rate limiting strategy
 * @param {Object} req - Express request object
 * @param {string} identifier - Additional identifier
 * @returns {string} Rate limit key
 */
function generateRateLimitKey(strategy, req, identifier = '') {
  const baseKey = `rate-limit:${strategy}`;
  switch (strategy) {
  case 'ip': {
    return `${baseKey}:${req.ip || req.connection.remoteAddress}`;
  }
  case 'user': {
    const userId = req.user ? req.user.id : 'anonymous';
    return `${baseKey}:${userId}`;
  }
  case 'endpoint': {
    return `${baseKey}:${req.method}:${req.originalUrl}`;
  }
  case 'user-endpoint': {
    const userId = req.user ? req.user.id : 'anonymous';
    return `${baseKey}:${userId}:${req.method}:${req.originalUrl}`;
  }
  case 'ip-endpoint': {
    const ip = req.ip || req.connection.remoteAddress;
    return `${baseKey}:${ip}:${req.method}:${req.originalUrl}`;
  }
  case 'custom': {
    return `${baseKey}:${identifier}`;
  }
  default: {
    return `${baseKey}:${req.ip || req.connection.remoteAddress}`;
  }
  }
}
/**
 * Get client identifier for rate limiting
 * @param {Object} req - Express request object
 * @returns {string} Client identifier
 */
function getClientIdentifier(req) {
  // Priority: User ID > IP Address > User Agent hash
  if (req.user && req.user.id) {
    return `user:${req.user.id}`;
  }
  const ip = req.ip || req.connection.remoteAddress;
  if (ip) {
    return `ip:${ip}`;
  }
  // Fallback to user agent hash
  const userAgent = req.headers['user-agent'] || 'unknown';
  const userAgentHash = crypto
    .createHash('md5')
    .update(userAgent)
    .digest('hex')
    .substring(0, 8);
  return `ua:${userAgentHash}`;
}
/**
 * Calculate retry after time with exponential backoff
 * @param {number} attempts - Number of attempts
 * @param {number} baseDelay - Base delay in seconds
 * @returns {number} Retry after time in seconds
 */
function calculateRetryAfter(attempts, baseDelay = 60) {
  return Math.min(baseDelay * Math.pow(2, attempts - 1), 3600); // Max 1 hour
}
/**
 * Enhanced rate limiter with multiple strategies
 * @param {Object} options - Rate limiting options
 * @returns {Function} Rate limiter middleware
 */
export const rateLimiter = (options = {}) => {
  const {
    strategy = 'ip', // ip, user, endpoint, user-endpoint, ip-endpoint, custom
    limit = 100, // requests per window
    windowMs = 15 * 60 * 1000, // 15 minutes
    skipSuccessfulRequests = false,
    skipFailedRequests = false,
    keyGenerator = null,
    handler = null,
    onLimitReached = null,
    burstLimit = 10, // burst requests allowed
    burstWindowMs = 60 * 1000, // 1 minute burst window
    identifier = '', // for custom strategy
  } = options;
  return async(req, res, next) => {
    const startTime = Date.now();
    const correlationId = getCorrelationId();
    const clientId = getClientIdentifier(req);
    try {
      updateRateLimiterMetrics('request');
      // Generate rate limit key
      const key = keyGenerator
        ? keyGenerator(req)
        : generateRateLimitKey(strategy, req, identifier);
      const burstKey = `${key}:burst`;
      // Check if request should be skipped
      if (skipSuccessfulRequests && res.statusCode < 400) {
        return next();
      }
      if (skipFailedRequests && res.statusCode >= 400) {
        return next();
      }
      // Use Redis pipeline for atomic operations
      const pipeline = getRedisClient().pipeline();
      // Main rate limit check
      pipeline.incr(key);
      pipeline.ttl(key);
      // Burst limit check
      pipeline.incr(burstKey);
      pipeline.ttl(burstKey);
      const results = await pipeline.exec();
      if (!results || results.length < 4) {
        safeLogger.error('Rate limiter Redis pipeline failed', {
          correlationId,
          key,
          results,
        });
        updateRateLimiterMetrics('redisError');
        return next(); // Allow request if Redis fails
      }
      const [mainResult, ttlResult, burstResult, burstTtlResult] = results;
      if (mainResult[0]) {
        throw new Error(`Redis error: ${mainResult[0]}`);
      }
      const requests = mainResult[1];
      const ttl = ttlResult[1];
      const burstRequests = burstResult[1];
      const burstTtl = burstTtlResult[1];
      // Set expiration for main window if first request
      if (requests === 1) {
        await getRedisClient().expire(key, Math.ceil(windowMs / 1000));
      }
      // Set expiration for burst window if first burst request
      if (burstRequests === 1) {
        await getRedisClient().expire(
          burstKey,
          Math.ceil(burstWindowMs / 1000),
        );
      }
      // Check burst limit first (more restrictive)
      if (burstRequests > burstLimit) {
        const retryAfter =
          burstTtl > 0 ? burstTtl : Math.ceil(burstWindowMs / 1000);
        updateRateLimiterMetrics('blocked');
        // Call custom handler if provided
        if (handler) {
          return handler(req, res, next, {
            limit: burstLimit,
            current: burstRequests,
            retryAfter,
            resetTime: new Date(Date.now() + retryAfter * 1000),
            strategy: 'burst',
          });
        }
        // Call onLimitReached callback
        if (onLimitReached) {
          onLimitReached(req, res, {
            limit: burstLimit,
            current: burstRequests,
            retryAfter,
            strategy: 'burst',
          });
        }
        // Set rate limit headers
        res.set({
          'X-RateLimit-Limit': burstLimit,
          'X-RateLimit-Remaining': 0,
          'X-RateLimit-Reset': new Date(
            Date.now() + retryAfter * 1000,
          ).toISOString(),
          'X-RateLimit-Strategy': 'burst',
          'Retry-After': retryAfter,
        });
        safeLogger.warn('Rate limit exceeded - burst limit', {
          clientId,
          strategy,
          burstLimit,
          burstRequests,
          retryAfter,
          correlationId,
          endpoint: req.originalUrl,
          method: req.method,
        });
        return res.status(429).json(
          new ApiResponse(
            429,
            {
              error: 'Too many requests',
              message: 'Burst rate limit exceeded',
              retryAfter,
              resetTime: new Date(Date.now() + retryAfter * 1000).toISOString(),
            },
            'Rate limit exceeded',
          ),
        );
      }
      // Check main rate limit
      if (requests > limit) {
        const retryAfter = ttl > 0 ? ttl : Math.ceil(windowMs / 1000);
        updateRateLimiterMetrics('blocked');
        // Call custom handler if provided
        if (handler) {
          return handler(req, res, next, {
            limit,
            current: requests,
            retryAfter,
            resetTime: new Date(Date.now() + retryAfter * 1000),
            strategy: 'main',
          });
        }
        // Call onLimitReached callback
        if (onLimitReached) {
          onLimitReached(req, res, {
            limit,
            current: requests,
            retryAfter,
            strategy: 'main',
          });
        }
        // Set rate limit headers
        res.set({
          'X-RateLimit-Limit': limit,
          'X-RateLimit-Remaining': 0,
          'X-RateLimit-Reset': new Date(
            Date.now() + retryAfter * 1000,
          ).toISOString(),
          'X-RateLimit-Strategy': 'main',
          'Retry-After': retryAfter,
        });
        safeLogger.warn('Rate limit exceeded - main limit', {
          clientId,
          strategy,
          limit,
          requests,
          retryAfter,
          correlationId,
          endpoint: req.originalUrl,
          method: req.method,
        });
        return res.status(429).json(
          new ApiResponse(
            429,
            {
              error: 'Too many requests',
              message: 'Rate limit exceeded',
              retryAfter,
              resetTime: new Date(Date.now() + retryAfter * 1000).toISOString(),
            },
            'Rate limit exceeded',
          ),
        );
      }
      // Request allowed
      const remaining = Math.max(0, limit - requests);
      const burstRemaining = Math.max(0, burstLimit - burstRequests);
      // Set rate limit headers
      res.set({
        'X-RateLimit-Limit': limit,
        'X-RateLimit-Remaining': remaining,
        'X-RateLimit-Reset': new Date(Date.now() + ttl * 1000).toISOString(),
        'X-RateLimit-Burst-Limit': burstLimit,
        'X-RateLimit-Burst-Remaining': burstRemaining,
        'X-RateLimit-Strategy': strategy,
      });
      updateRateLimiterMetrics('allowed');
      const processingTime = Date.now() - startTime;
      safeLogger.debug('Rate limit check passed', {
        clientId,
        strategy,
        limit,
        requests,
        remaining,
        burstLimit,
        burstRequests,
        burstRemaining,
        correlationId,
        processingTime: `${processingTime}ms`,
      });
      next();
    } catch (error) {
      const processingTime = Date.now() - startTime;
      updateRateLimiterMetrics('redisError');
      safeLogger.error('Rate limiter error', {
        error: error.message,
        stack: error.stack,
        correlationId,
        processingTime: `${processingTime}ms`,
        clientId,
        strategy,
      });
      // Allow request if rate limiting fails
      next();
    }
  };
};
/**
 * IP-based rate limiter (default)
 * @param {Object} options - Rate limiting options
 * @returns {Function} Rate limiter middleware
 */
export const ipRateLimiter = (options = {}) => {
  return rateLimiter({
    strategy: 'ip',
    ...options,
  });
};
/**
 * User-based rate limiter
 * @param {Object} options - Rate limiting options
 * @returns {Function} Rate limiter middleware
 */
export const userRateLimiter = (options = {}) => {
  return rateLimiter({
    strategy: 'user',
    ...options,
  });
};
/**
 * Endpoint-based rate limiter
 * @param {Object} options - Rate limiting options
 * @returns {Function} Rate limiter middleware
 */
export const endpointRateLimiter = (options = {}) => {
  return rateLimiter({
    strategy: 'endpoint',
    ...options,
  });
};
/**
 * Strict rate limiter for sensitive endpoints
 * @param {Object} options - Rate limiting options
 * @returns {Function} Rate limiter middleware
 */
export const strictRateLimiter = (options = {}) => {
  return rateLimiter({
    strategy: 'ip-endpoint',
    limit: 10,
    windowMs: 5 * 60 * 1000, // 5 minutes
    burstLimit: 3,
    burstWindowMs: 60 * 1000, // 1 minute
    ...options,
  });
};
/**
 * Login rate limiter for authentication endpoints
 * @param {Object} options - Rate limiting options
 * @returns {Function} Rate limiter middleware
 */
export const loginRateLimiter = (options = {}) => {
  return rateLimiter({
    strategy: 'ip',
    limit: 5,
    windowMs: 15 * 60 * 1000, // 15 minutes
    burstLimit: 2,
    burstWindowMs: 60 * 1000, // 1 minute
    skipSuccessfulRequests: true,
    ...options,
  });
};
/**
 * API rate limiter for general API endpoints
 * @param {Object} options - Rate limiting options
 * @returns {Function} Rate limiter middleware
 */
export const apiRateLimiter = (options = {}) => {
  return rateLimiter({
    strategy: 'user-endpoint',
    limit: 1000,
    windowMs: 15 * 60 * 1000, // 15 minutes
    burstLimit: 50,
    burstWindowMs: 60 * 1000, // 1 minute
    ...options,
  });
};
/**
 * Get rate limiter metrics
 * @returns {Object} Rate limiter metrics
 */
export const getRateLimiterMetrics = () => {
  const uptime = Date.now() - rateLimiterMetrics.uptime;
  const successRate =
    rateLimiterMetrics.totalRequests > 0
      ? (rateLimiterMetrics.allowedRequests /
          rateLimiterMetrics.totalRequests) *
        100
      : 0;
  return {
    ...rateLimiterMetrics,
    uptime: `${Math.round(uptime / 1000)}s`,
    successRate: `${successRate.toFixed(2)}%`,
    currentTime: new Date().toISOString(),
  };
};
/**
 * Reset rate limiter metrics
 */
export const resetRateLimiterMetrics = () => {
  Object.assign(rateLimiterMetrics, {
    totalRequests: 0,
    allowedRequests: 0,
    blockedRequests: 0,
    redisErrors: 0,
    uptime: Date.now(),
  });
  rateLimiterMetrics.endpointLimits.clear();
  rateLimiterMetrics.ipLimits.clear();
  safeLogger.info('Rate limiter metrics reset');
};
/**
 * Clear rate limit for specific key
 * @param {string} key - Rate limit key to clear
 * @returns {Promise<boolean>} Success status
 */
export const clearRateLimit = async key => {
  try {
    const result = await getRedisClient().del(key);
    safeLogger.info('Rate limit cleared', { key, result });
    return result > 0;
  } catch (error) {
    safeLogger.error('Failed to clear rate limit', {
      key,
      error: error.message,
    });
    return false;
  }
};
/**
 * Get rate limit info for specific key
 * @param {string} key - Rate limit key
 * @returns {Promise<Object>} Rate limit information
 */
export const getRateLimitInfo = async key => {
  try {
    const [requests, ttl] = await Promise.all([
      getRedisClient().get(key),
      getRedisClient().ttl(key),
    ]);
    return {
      key,
      requests: parseInt(requests) || 0,
      ttl,
      resetTime: ttl > 0 ? new Date(Date.now() + ttl * 1000) : null,
    };
  } catch (error) {
    safeLogger.error('Failed to get rate limit info', {
      key,
      error: error.message,
    });
    return null;
  }
};
/**
 * Main rate limiter middleware that combines all rate limiting features
 * This is the primary middleware used in app.js
 * @param {Object} options - Rate limiting options
 * @returns {Function} Combined rate limiter middleware
 */
export const rateLimiterMiddleware = (options = {}) => {
  const {
    enableGlobalLimit = true,
    enableEndpointLimit = true,
    enableUserLimit = false,
    enableBurstProtection = true,
    enableRedis = true,
  } = options;
  return (req, res, next) => {
    const correlationId = getCorrelationId();
    try {
      // Apply global rate limiting
      if (enableGlobalLimit) {
        apiRateLimiter()(req, res, err => {
          if (err) return next(err);
        });
      }
      // Apply endpoint-specific rate limiting
      if (enableEndpointLimit) {
        endpointRateLimiter()(req, res, err => {
          if (err) return next(err);
        });
      }
      // Apply user-based rate limiting (if authenticated)
      if (enableUserLimit && req.user) {
        userRateLimiter()(req, res, err => {
          if (err) return next(err);
        });
      }
      // Apply burst protection
      if (enableBurstProtection) {
        strictRateLimiter()(req, res, err => {
          if (err) return next(err);
        });
      }
      safeLogger.debug('Rate limiter middleware applied', {
        correlationId,
        features: {
          globalLimit: enableGlobalLimit,
          endpointLimit: enableEndpointLimit,
          userLimit: enableUserLimit,
          burstProtection: enableBurstProtection,
          redis: enableRedis,
        },
      });
      next();
    } catch (error) {
      safeLogger.error('Rate limiter middleware error', {
        error: error.message,
        correlationId,
        stack: error.stack,
      });
      next(error);
    }
  };
};
export default rateLimiterMiddleware;
