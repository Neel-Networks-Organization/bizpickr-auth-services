import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';

/**
 * Rate Limiting Middleware
 * Core rate limiting functionality
 */

/**
 * IP-based rate limiting middleware
 */
export const ipRateLimit = async(req, res, next) => {
  const correlationId = getCorrelationId();

  try {
    const clientIP = req.ip || req.connection?.remoteAddress || 'unknown';
    const rateLimitKey = `rate_limit:${clientIP}`;
    const now = Date.now();
    const windowMs = 15 * 60 * 1000; // 15 minutes
    const maxRequests = 1000; // Max requests per window

    // Simple in-memory rate limiting (for production, use Redis)
    if (!req.rateLimitStore) {
      req.rateLimitStore = new Map();
    }

    const userRequests = req.rateLimitStore.get(rateLimitKey) || [];
    const validRequests = userRequests.filter(time => now - time < windowMs);

    if (validRequests.length >= maxRequests) {
      safeLogger.warn('Rate limit exceeded', {
        correlationId,
        clientIP,
        requestCount: validRequests.length,
        limit: maxRequests,
        windowMs,
      });

      return res.status(429).json({
        error: 'Too Many Requests',
        message: 'Rate limit exceeded. Please try again later.',
        correlationId,
        retryAfter: Math.ceil(windowMs / 1000),
      });
    }

    // Add current request timestamp
    validRequests.push(now);
    req.rateLimitStore.set(rateLimitKey, validRequests);

    // Set rate limit headers
    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader(
      'X-RateLimit-Remaining',
      Math.max(0, maxRequests - validRequests.length),
    );
    res.setHeader('X-RateLimit-Reset', new Date(now + windowMs).toISOString());

    next();
  } catch (error) {
    safeLogger.error('Rate limiting error', {
      error: error.message,
      correlationId,
    });
    // Continue without rate limiting if there's an error
    next();
  }
};

export default {
  ipRateLimit,
};
