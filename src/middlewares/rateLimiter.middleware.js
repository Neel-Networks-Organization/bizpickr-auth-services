import { getRedisClient } from '../db/redis.js';
import { ApiResponse, ApiError } from '../utils/index.js';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';

/**
 * Smart Rate Limiting Middleware
 * Core rate limiting with Redis backend
 */

// Rate limiting configuration
const RATE_LIMIT_CONFIG = {
  // IP-based rate limiting
  ip: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 100,
  },
  // User-based rate limiting
  user: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 200,
  },
  // Endpoint-based rate limiting
  endpoint: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 50,
  },
  // Auth endpoints (stricter)
  auth: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 10,
  },
};

/**
 * Generate rate limit key
 */
function generateRateLimitKey(strategy, req, identifier = '') {
  const baseKey = `rate-limit:${strategy}`;

  switch (strategy) {
    case 'ip':
      return `${baseKey}:${req.ip || req.connection.remoteAddress}`;
    case 'user':
      const userId = req.user ? req.user.id : 'anonymous';
      return `${baseKey}:${userId}`;
    case 'endpoint':
      return `${baseKey}:${req.method}:${req.originalUrl}`;
    case 'auth':
      const ip = req.ip || req.connection.remoteAddress;
      return `${baseKey}:${ip}`;
    case 'custom':
      return `${baseKey}:${identifier}`;
    default:
      return `${baseKey}:${req.ip || req.connection.remoteAddress}`;
  }
}

/**
 * Check rate limit
 */
async function checkRateLimit(key, maxRequests, windowMs) {
  try {
    const redis = getRedisClient();
    const current = await redis.get(key);

    if (current && parseInt(current) >= maxRequests) {
      return false;
    }

    // Increment counter
    await redis
      .multi()
      .incr(key)
      .expire(key, Math.ceil(windowMs / 1000))
      .exec();

    return true;
  } catch (error) {
    safeLogger.error('Rate limit check failed', { error: error.message, key });
    // Allow request if Redis fails
    return true;
  }
}

/**
 * IP-based rate limiting
 */
export const ipRateLimit = async (req, res, next) => {
  const correlationId = getCorrelationId();
  const config = RATE_LIMIT_CONFIG.ip;
  const key = generateRateLimitKey('ip', req);

  try {
    const allowed = await checkRateLimit(
      key,
      config.maxRequests,
      config.windowMs
    );

    if (!allowed) {
      safeLogger.warn('IP rate limit exceeded', {
        ip: req.ip,
        correlationId,
        path: req.path,
      });

      return res.status(429).json({
        error: 'Rate limit exceeded',
        message: 'Too many requests from this IP',
        retryAfter: Math.ceil(config.windowMs / 1000),
        correlationId,
      });
    }

    next();
  } catch (error) {
    safeLogger.error('IP rate limit error', {
      error: error.message,
      correlationId,
    });
    next();
  }
};

/**
 * User-based rate limiting
 */
export const userRateLimit = async (req, res, next) => {
  if (!req.user) {
    return next();
  }

  const correlationId = getCorrelationId();
  const config = RATE_LIMIT_CONFIG.user;
  const key = generateRateLimitKey('user', req);

  try {
    const allowed = await checkRateLimit(
      key,
      config.maxRequests,
      config.windowMs
    );

    if (!allowed) {
      safeLogger.warn('User rate limit exceeded', {
        userId: req.user.id,
        correlationId,
        path: req.path,
      });

      return res.status(429).json({
        error: 'Rate limit exceeded',
        message: 'Too many requests from this user',
        retryAfter: Math.ceil(config.windowMs / 1000),
        correlationId,
      });
    }

    next();
  } catch (error) {
    safeLogger.error('User rate limit error', {
      error: error.message,
      correlationId,
    });
    next();
  }
};

/**
 * Endpoint-based rate limiting
 */
export const endpointRateLimit = async (req, res, next) => {
  const correlationId = getCorrelationId();
  const config = RATE_LIMIT_CONFIG.endpoint;
  const key = generateRateLimitKey('endpoint', req);

  try {
    const allowed = await checkRateLimit(
      key,
      config.maxRequests,
      config.windowMs
    );

    if (!allowed) {
      safeLogger.warn('Endpoint rate limit exceeded', {
        endpoint: req.originalUrl,
        correlationId,
        method: req.method,
      });

      return res.status(429).json({
        error: 'Rate limit exceeded',
        message: 'Too many requests to this endpoint',
        retryAfter: Math.ceil(config.windowMs / 1000),
        correlationId,
      });
    }

    next();
  } catch (error) {
    safeLogger.error('Endpoint rate limit error', {
      error: error.message,
      correlationId,
    });
    next();
  }
};

/**
 * Auth-specific rate limiting (stricter)
 */
export const authRateLimit = async (req, res, next) => {
  const correlationId = getCorrelationId();
  const config = RATE_LIMIT_CONFIG.auth;
  const key = generateRateLimitKey('auth', req);

  try {
    const allowed = await checkRateLimit(
      key,
      config.maxRequests,
      config.windowMs
    );

    if (!allowed) {
      safeLogger.warn('Auth rate limit exceeded', {
        ip: req.ip,
        correlationId,
        path: req.path,
      });

      return res.status(429).json({
        error: 'Rate limit exceeded',
        message: 'Too many authentication attempts',
        retryAfter: Math.ceil(config.windowMs / 1000),
        correlationId,
      });
    }

    next();
  } catch (error) {
    safeLogger.error('Auth rate limit error', {
      error: error.message,
      correlationId,
    });
    next();
  }
};

/**
 * Custom rate limiting
 */
export const customRateLimit = (maxRequests, windowMs, strategy = 'ip') => {
  return async (req, res, next) => {
    const correlationId = getCorrelationId();
    const key = generateRateLimitKey(strategy, req);

    try {
      const allowed = await checkRateLimit(key, maxRequests, windowMs);

      if (!allowed) {
        safeLogger.warn('Custom rate limit exceeded', {
          strategy,
          correlationId,
          path: req.path,
        });

        return res.status(429).json({
          error: 'Rate limit exceeded',
          message: 'Too many requests',
          retryAfter: Math.ceil(windowMs / 1000),
          correlationId,
        });
      }

      next();
    } catch (error) {
      safeLogger.error('Custom rate limit error', {
        error: error.message,
        correlationId,
      });
      next();
    }
  };
};

/**
 * Get rate limit info
 */
export const getRateLimitInfo = async req => {
  const redis = getRedisClient();
  const strategies = ['ip', 'user', 'endpoint', 'auth'];
  const info = {};

  for (const strategy of strategies) {
    const key = generateRateLimitKey(strategy, req);
    try {
      const current = await redis.get(key);
      const ttl = await redis.ttl(key);
      info[strategy] = {
        current: current ? parseInt(current) : 0,
        ttl: ttl > 0 ? ttl : 0,
        max: RATE_LIMIT_CONFIG[strategy]?.maxRequests || 100,
      };
    } catch (error) {
      info[strategy] = { error: 'Unable to fetch' };
    }
  }

  return info;
};

export default {
  ipRateLimit,
  userRateLimit,
  endpointRateLimit,
  authRateLimit,
  customRateLimit,
  getRateLimitInfo,
};
