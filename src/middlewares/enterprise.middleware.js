import { safeLogger } from '../config/logger.js';
import { ApiError } from '../utils/index.js';
import { v4 as uuidv4 } from 'uuid';

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
  res.end = function(...args) {
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

// ✅ Enterprise Rate Limiting
export const enterpriseRateLimit = (
  maxRequests = 100,
  windowMs = 15 * 60 * 1000,
) => {
  const requests = new Map();

  return (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    const windowStart = now - windowMs;

    // Clean old requests
    if (requests.has(ip)) {
      requests.set(
        ip,
        requests.get(ip).filter(time => time > windowStart),
      );
    }

    const currentRequests = requests.get(ip) || [];

    if (currentRequests.length >= maxRequests) {
      safeLogger.warn('Rate limit exceeded', {
        correlationId: req.correlationId,
        ip,
        path: req.path,
      });

      return res.status(429).json({
        error: 'Rate limit exceeded',
        message: 'Too many requests from this IP',
        retryAfter: '15 minutes',
        correlationId: req.correlationId,
      });
    }

    currentRequests.push(now);
    requests.set(ip, currentRequests);

    next();
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
    'geolocation=(), microphone=(), camera=()',
  );

  next();
};

// ✅ Enterprise Request Validation
export const enterpriseValidationMiddleware = (req, res, next) => {
  const correlationId = req.correlationId;

  // Check content length (10MB limit for SaaS)
  const contentLength = parseInt(req.headers['content-length'] || '0');
  if (contentLength > 10 * 1024 * 1024) {
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
    correlationId,
    error: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    userId: req.user?.id || 'anonymous',
  });

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

  // Default error - enhanced industry standard response
  const errorResponse = {
    error: 'Internal Server Error',
    message: 'Something went wrong',
    correlationId,
    timestamp: new Date().toISOString(),
    requestId: req.headers['x-request-id'] || req.correlationId,
    path: req.originalUrl,
    method: req.method,
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
