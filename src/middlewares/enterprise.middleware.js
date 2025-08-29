import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import { ApiError } from '../utils/index.js';
import { v4 as uuidv4 } from 'uuid';
import redisClient from '../db/redis.js';

/**
 * Enterprise-Grade Middlewares for SaaS Projects
 * Essential features without over-engineering
 */

// ✅ Correlation ID Middleware (Essential for SaaS)
export const correlationIdMiddleware = (req, res, next) => {
  // Get correlation ID from header or generate new one
  const correlationId =
    req.headers['x-correlation-id'] || req.headers['x-request-id'] || uuidv4();

  // Set correlation ID in request and response
  req.correlationId = correlationId;
  res.setHeader('X-Correlation-ID', correlationId);
  res.setHeader('X-Request-ID', correlationId);

  next();
};

// ✅ Enterprise Logging Middleware
export const enterpriseLoggingMiddleware = (req, res, next) => {
  const startTime = Date.now();
  const correlationId = req.correlationId;

  // Log request start
  safeLogger.info('Request started', {
    correlationId,
    method: req.method,
    url: req.url,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id || 'anonymous',
  });

  // Override res.end to log response
  const originalEnd = res.end;
  res.end = function (...args) {
    const duration = Date.now() - startTime;

    safeLogger.info('Request completed', {
      correlationId,
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      userId: req.user?.id || 'anonymous',
    });

    originalEnd.apply(this, args);
  };

  next();
};

// ✅ Enterprise Rate Limiting (Redis-Based)
export const enterpriseRateLimit = (
  maxRequests = 100,
  windowMs = 15 * 60 * 1000
) => {
  // Redis client is imported at the top - no circular dependency exists
  // In-memory fallback store
  const requests = new Map();

  return async (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    const windowStart = now - windowMs;
    const rateLimitKey = `enterprise_rate_limit:${ip}`;

    try {
      // ✅ Redis-based rate limiting (primary)
      if (redisClient && redisClient.isReady) {
        try {
          // Get current requests from Redis
          const currentRequests = await redisClient.zRangeByScore(
            rateLimitKey,
            windowStart,
            '+inf'
          );

          const validRequestCount = currentRequests.length;

          if (validRequestCount >= maxRequests) {
            safeLogger.warn('Enterprise rate limit exceeded (Redis)', {
              correlationId: req.correlationId,
              ip,
              path: req.path,
              requestCount: validRequestCount,
              limit: maxRequests,
              windowMs,
            });

            // Set rate limit headers
            res.setHeader('X-RateLimit-Limit', maxRequests);
            res.setHeader('X-RateLimit-Remaining', 0);
            res.setHeader(
              'X-RateLimit-Reset',
              new Date(now + windowMs).toISOString()
            );
            res.setHeader('X-RateLimit-Used', validRequestCount);

            return res.status(429).json({
              error: 'Rate limit exceeded',
              message: 'Too many requests from this IP (Global limit)',
              retryAfter: Math.ceil(windowMs / 1000),
              correlationId: req.correlationId,
              limit: maxRequests,
              remaining: 0,
              resetTime: new Date(now + windowMs).toISOString(),
            });
          }

          // Add current request to Redis
          await redisClient.zAdd(rateLimitKey, {
            score: now,
            value: now.toString(),
          });

          // Set expiry for the key (windowMs + 1 hour buffer)
          await redisClient.expire(
            rateLimitKey,
            Math.ceil((windowMs + 60 * 60 * 1000) / 1000)
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

          // ✅ DEBUG: Log enterprise rate limit info
          safeLogger.debug('Enterprise rate limit check (Redis)', {
            correlationId: req.correlationId,
            ip,
            path: req.path,
            current: validRequestCount + 1,
            limit: maxRequests,
            remaining: Math.max(0, maxRequests - validRequestCount - 1),
            redisKey: rateLimitKey,
          });
        } catch (redisError) {
          safeLogger.error('Redis enterprise rate limiting error', {
            error: redisError.message,
            correlationId: req.correlationId,
            ip,
            path: req.path,
          });

          // Fallback to in-memory rate limiting if Redis fails
          safeLogger.warn(
            'Falling back to in-memory enterprise rate limiting due to Redis error'
          );
        }
      }

      // ✅ Fallback: In-memory rate limiting if Redis not available
      if (!redisClient || !redisClient.isReady) {
        // Clean old requests
        if (requests.has(ip)) {
          requests.set(
            ip,
            requests.get(ip).filter(time => time > windowStart)
          );
        }

        const currentRequests = requests.get(ip) || [];

        if (currentRequests.length >= maxRequests) {
          safeLogger.warn('Enterprise rate limit exceeded (in-memory)', {
            correlationId: req.correlationId,
            ip,
            path: req.path,
            requestCount: currentRequests.length,
            limit: maxRequests,
            windowMs,
          });

          // Set rate limit headers
          res.setHeader('X-RateLimit-Limit', maxRequests);
          res.setHeader('X-RateLimit-Remaining', 0);
          res.setHeader(
            'X-RateLimit-Reset',
            new Date(now + windowMs).toISOString()
          );
          res.setHeader('X-RateLimit-Used', currentRequests.length);

          return res.status(429).json({
            error: 'Rate limit exceeded',
            message: 'Too many requests from this IP (Global limit)',
            retryAfter: Math.ceil(windowMs / 1000),
            correlationId: req.correlationId,
            limit: maxRequests,
            remaining: 0,
            resetTime: new Date(now + windowMs).toISOString(),
          });
        }

        currentRequests.push(now);
        requests.set(ip, currentRequests);

        // Set rate limit headers
        res.setHeader('X-RateLimit-Limit', maxRequests);
        res.setHeader(
          'X-RateLimit-Remaining',
          Math.max(0, maxRequests - currentRequests.length)
        );
        res.setHeader(
          'X-RateLimit-Reset',
          new Date(now + windowMs).toISOString()
        );
        res.setHeader('X-RateLimit-Used', currentRequests.length);
      }

      next();
    } catch (error) {
      safeLogger.error('Enterprise rate limiting error', {
        error: error.message,
        correlationId: req.correlationId,
        ip,
        path: req.path,
      });
      // Continue without rate limiting if there's an error
      next();
    }
  };
};

// ✅ Enterprise Security Headers
export const enterpriseSecurityMiddleware = (req, res, next) => {
  // Essential security headers for SaaS
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader(
    'Permissions-Policy',
    'geolocation=(), microphone=(), camera=()'
  );

  next();
};

// ✅ Enterprise Request Validation
export const enterpriseValidationMiddleware = (req, res, next) => {
  const correlationId = req.correlationId;

  // Check content length (10MB limit for SaaS)
  const contentLength = parseInt(req.headers['content-length'] || '0');
  if (contentLength > 10 * 1024 * 1024) {
    // 10MB
    safeLogger.warn('Request too large', {
      correlationId,
      contentLength,
      path: req.path,
    });

    return res.status(413).json({
      error: 'Request too large',
      message: 'Maximum request size is 10MB',
      correlationId,
    });
  }

  // Check content type for POST/PUT requests
  if (
    (req.method === 'POST' || req.method === 'PUT') &&
    req.headers['content-type'] &&
    !req.headers['content-type'].includes('application/json')
  ) {
    safeLogger.warn('Invalid content type', {
      correlationId,
      contentType: req.headers['content-type'],
      path: req.path,
    });

    return res.status(400).json({
      error: 'Invalid content type',
      message: 'Content-Type must be application/json',
      correlationId,
    });
  }

  next();
};

// ✅ Enterprise Error Handler
export const enterpriseErrorHandler = (error, req, res, next) => {
  const correlationId = req.correlationId;

  safeLogger.error('Error occurred', {
    metadata: {
      correlationId,
      error: error.message,
      stack: error.stack,
      url: req.url,
      method: req.method,
      userId: req.user?.id || 'anonymous',
    },
  });

  // ✅ Handle Sequelize Validation Errors (User-friendly messages)
  if (error.name === 'SequelizeValidationError') {
    const validationErrors = error.errors.map(err => ({
      field: err.path,
      message: err.message,
      value: err.value,
    }));

    const errorResponse = {
      error: 'Validation Error',
      message: 'Please check your input data',
      details: validationErrors,
      correlationId,
      timestamp: new Date().toISOString(),
      requestId: req.headers['x-request-id'] || req.correlationId,
      path: req.originalUrl,
      method: req.method,
      statusCode: 400,
    };

    return res.status(400).json(errorResponse);
  }

  // ✅ Handle Sequelize Unique Constraint Errors
  if (error.name === 'SequelizeUniqueConstraintError') {
    const field = error.errors[0]?.path || 'field';
    const value = error.errors[0]?.value || 'value';

    const errorResponse = {
      error: 'Duplicate Entry',
      message: `${field} already exists with value: ${value}`,
      correlationId,
      timestamp: new Date().toISOString(),
      requestId: req.headers['x-request-id'] || req.correlationId,
      path: req.originalUrl,
      method: req.method,
      statusCode: 409,
    };

    return res.status(409).json(errorResponse);
  }

  // ✅ Handle Sequelize Foreign Key Errors
  if (error.name === 'SequelizeForeignKeyConstraintError') {
    const errorResponse = {
      error: 'Reference Error',
      message: 'Referenced record does not exist',
      correlationId,
      timestamp: new Date().toISOString(),
      requestId: req.headers['x-request-id'] || req.correlationId,
      path: req.originalUrl,
      method: req.method,
      statusCode: 400,
    };

    return res.status(400).json(errorResponse);
  }

  // ✅ Handle Database Connection Errors
  if (
    error.name === 'SequelizeConnectionError' ||
    error.name === 'SequelizeConnectionTimedOutError'
  ) {
    const errorResponse = {
      error: 'Database Connection Error',
      message: 'Unable to connect to database. Please try again later.',
      correlationId,
      timestamp: new Date().toISOString(),
      requestId: req.headers['x-request-id'] || req.correlationId,
      path: req.originalUrl,
      method: req.method,
      statusCode: 503,
    };

    return res.status(503).json(errorResponse);
  }

  // ✅ Handle API Errors (Custom errors)
  if (error instanceof ApiError) {
    const apiErrorResponse = {
      error: error.name,
      message: error.message,
      correlationId,
      timestamp: new Date().toISOString(),
      requestId: req.headers['x-request-id'] || req.correlationId,
      path: req.originalUrl,
      method: req.method,
      statusCode: error.statusCode,
      ...(error.details && { details: error.details }),
    };

    // Add development debug info
    if (process.env.NODE_ENV === 'development') {
      apiErrorResponse.debug = {
        userAgent: req.get('User-Agent'),
        ip: req.ip,
        stack: error.stack,
      };
    }

    return res.status(error.statusCode).json(apiErrorResponse);
  }

  // ✅ Default error - enhanced industry standard response
  const errorResponse = {
    error: 'Internal Server Error',
    message:
      process.env.NODE_ENV === 'production'
        ? 'Something went wrong. Please try again later.'
        : error.message,
    correlationId,
    timestamp: new Date().toISOString(),
    requestId: req.headers['x-request-id'] || req.correlationId,
    path: req.originalUrl,
    method: req.method,
    statusCode: 500,
  };

  // Add stack trace and details in development mode
  if (process.env.NODE_ENV === 'development') {
    errorResponse.stack = error.stack;
    errorResponse.details = error.message;
    errorResponse.name = error.name;
    errorResponse.debug = {
      userAgent: req.get('User-Agent'),
      ip: req.ip,
      headers: req.headers,
    };
  }

  res.status(500).json(errorResponse);
};

export const enterpriseCorsMiddleware = (options = {}) => {
  let corsOrigins;

  corsOrigins = process.env.CORS_ORIGINS?.split(',').map(origin =>
    origin.trim()
  ) || [
    'http://localhost:3000',
    'http://localhost:3001',
    'http://localhost:3002',
  ];

  const config = {
    origin: corsOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'X-API-Key',
      'X-Correlation-ID',
    ],
    exposedHeaders: ['X-Correlation-ID', 'X-Request-ID'],
    maxAge: 86400, // 24 hours
    ...options,
  };

  return (req, res, next) => {
    const correlationId = getCorrelationId();

    try {
      const origin = req.headers.origin;

      // Check if origin is allowed
      if (origin && config.origin.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
      }

      // Set CORS headers
      res.setHeader('Access-Control-Allow-Credentials', config.credentials);
      res.setHeader('Access-Control-Allow-Methods', config.methods.join(', '));
      res.setHeader(
        'Access-Control-Allow-Headers',
        config.allowedHeaders.join(', ')
      );
      res.setHeader(
        'Access-Control-Expose-Headers',
        config.exposedHeaders.join(', ')
      );
      res.setHeader('Access-Control-Max-Age', config.maxAge);

      // Handle preflight requests
      if (req.method === 'OPTIONS') {
        return res.status(200).end();
      }

      next();
    } catch (error) {
      safeLogger.error('CORS middleware error', {
        error: error.message,
        correlationId,
      });
      next();
    }
  };
};
