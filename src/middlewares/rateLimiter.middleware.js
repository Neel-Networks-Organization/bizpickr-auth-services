import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import redisClient from '../db/redis.js';
import { env } from '../config/env.js';

/**
 * Rate Limiting Middleware
 * Production-ready Redis-based rate limiting
 */

/**
 * Redis-based IP rate limiting middleware
 */
const ipRateLimit = (options = {}) => {
  const config = env.services.rateLimit;
  const {
    windowMs = config.defaultWindow || 15 * 60 * 1000,
    maxRequests = config.defaultLimit || 100,
  } = options;

  return async (req, res, next) => {
    const correlationId = getCorrelationId();

    try {
      const clientIP = req.ip || req.connection?.remoteAddress || 'unknown';
      const rateLimitKey = `rate_limit:${clientIP}:${req.path}`;
      const now = Date.now();
      const windowStart = now - windowMs;

      // ✅ Redis-based rate limiting
      if (redisClient && redisClient.isReady) {
        try {
          // Get current requests from Redis
          const currentRequests = await redisClient.zRangeByScore(
            rateLimitKey,
            windowStart,
            '+inf'
          );

          // Count valid requests in current window
          const validRequestCount = currentRequests.length;

          if (validRequestCount >= maxRequests) {
            safeLogger.warn('Rate limit exceeded', {
              correlationId,
              clientIP,
              path: req.path,
              requestCount: validRequestCount,
              limit: maxRequests,
              windowMs,
            });

            return res.status(429).json({
              error: 'Too Many Requests',
              message: `Rate limit exceeded for ${req.path}. Please try again later.`,
              correlationId,
              retryAfter: Math.ceil(windowMs / 1000),
              limit: maxRequests,
              remaining: 0,
              resetTime: new Date(now + windowMs).toISOString(),
            });
          }

          // Add current request to Redis with timestamp
          await redisClient.zAdd(rateLimitKey, {
            score: now,
            value: now.toString(),
          });

          // Set expiry for the key (windowMs + buffer time)
          const bufferTime = config.redisTTLBuffer * 60 * 1000; // Convert minutes to milliseconds
          await redisClient.expire(
            rateLimitKey,
            Math.ceil((windowMs + bufferTime) / 1000)
          );

          // Clean old entries outside the window
          await redisClient.zRemRangeByScore(
            rateLimitKey,
            '-inf',
            windowStart - 1
          );

          // Set rate limit headers
          res.setHeader('X-RateLimit-Limit', maxRequests);
          res.setHeader(
            'X-RateLimit-Remaining',
            Math.max(0, maxRequests - validRequestCount - 1)
          );
          res.setHeader(
            'X-RateLimit-Reset',
            new Date(now + windowMs).toISOString()
          );
          res.setHeader('X-RateLimit-Used', validRequestCount + 1);

          // ✅ DEBUG: Log rate limit info
          safeLogger.debug('Rate limit check (Redis)', {
            correlationId,
            clientIP,
            path: req.path,
            current: validRequestCount + 1,
            limit: maxRequests,
            remaining: Math.max(0, maxRequests - validRequestCount - 1),
            redisKey: rateLimitKey,
          });
        } catch (redisError) {
          safeLogger.error('Redis rate limiting error', {
            error: redisError.message,
            correlationId,
            clientIP,
            path: req.path,
          });

          // Fallback: Continue without rate limiting if Redis fails
          safeLogger.warn(
            'Falling back to no rate limiting due to Redis error'
          );
        }
      } else {
        // ✅ Fallback: In-memory rate limiting if Redis not available
        safeLogger.warn('Redis not available, using in-memory rate limiting', {
          correlationId,
          clientIP,
          path: req.path,
        });

        // In-memory fallback (for development/testing)
        if (!global.rateLimitStore) {
          global.rateLimitStore = new Map();
        }

        let userRequests = global.rateLimitStore.get(rateLimitKey) || [];
        userRequests = userRequests.filter(time => now - time < windowMs);

        if (userRequests.length >= maxRequests) {
          safeLogger.warn('Rate limit exceeded (in-memory)', {
            correlationId,
            clientIP,
            path: req.path,
            requestCount: userRequests.length,
            limit: maxRequests,
            windowMs,
          });

          return res.status(429).json({
            error: 'Too Many Requests',
            message: `Rate limit exceeded for ${req.path}. Please try again later.`,
            correlationId,
            retryAfter: Math.ceil(windowMs / 1000),
            limit: maxRequests,
            remaining: 0,
            resetTime: new Date(now + windowMs).toISOString(),
          });
        }

        userRequests.push(now);
        global.rateLimitStore.set(rateLimitKey, userRequests);

        // Set rate limit headers
        res.setHeader('X-RateLimit-Limit', maxRequests);
        res.setHeader(
          'X-RateLimit-Remaining',
          Math.max(0, maxRequests - userRequests.length)
        );
        res.setHeader(
          'X-RateLimit-Reset',
          new Date(now + windowMs).toISOString()
        );
        res.setHeader('X-RateLimit-Used', userRequests.length);
      }

      next();
    } catch (error) {
      safeLogger.error('Rate limiting error', {
        error: error.message,
        correlationId,
        clientIP: req.ip,
        path: req.path,
      });
      // Continue without rate limiting if there's an error
      next();
    }
  };
};

export default ipRateLimit;
