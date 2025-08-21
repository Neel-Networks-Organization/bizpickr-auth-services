import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';

/**
 * Security Middleware
 * Core security functionality for the application
 */

/**
 * Security headers middleware
 */
export const securityHeaders = (options = {}) => {
  const config = {
    enableCSP: true,
    enableHSTS: true,
    enableXSS: true,
    enableFrameOptions: true,
    enableContentTypeOptions: true,
    ...options,
  };

  return (req, res, next) => {
    const correlationId = getCorrelationId();

    try {
      // Content Security Policy
      if (config.enableCSP) {
        res.setHeader(
          'Content-Security-Policy',
          "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'none';"
        );
      }

      // HTTP Strict Transport Security
      if (config.enableHSTS) {
        res.setHeader(
          'Strict-Transport-Security',
          'max-age=31536000; includeSubDomains; preload'
        );
      }

      // X-XSS-Protection
      if (config.enableXSS) {
        res.setHeader('X-XSS-Protection', '1; mode=block');
      }

      // X-Frame-Options
      if (config.enableFrameOptions) {
        res.setHeader('X-Frame-Options', 'DENY');
      }

      // X-Content-Type-Options
      if (config.enableContentTypeOptions) {
        res.setHeader('X-Content-Type-Options', 'nosniff');
      }

      // Additional security headers
      res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
      res.setHeader(
        'Permissions-Policy',
        'geolocation=(), microphone=(), camera=()'
      );

      next();
    } catch (error) {
      safeLogger.error('Security headers error', {
        error: error.message,
        correlationId,
      });
      next();
    }
  };
};

/**
 * CORS middleware with enhanced security
 */
export const corsMiddleware = (options = {}) => {
  const config = {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || [
      'http://localhost:3000',
    ],
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

/**
 * Request size limit middleware
 */
export const requestSizeLimit = (maxSize = '10mb') => {
  const maxBytes = parseSize(maxSize);

  return (req, res, next) => {
    const correlationId = getCorrelationId();

    try {
      let dataLength = 0;

      req.on('data', chunk => {
        dataLength += chunk.length;

        if (dataLength > maxBytes) {
          req.destroy();
          return res.status(413).json({
            error: 'Payload Too Large',
            message: `Request size exceeds limit of ${maxSize}`,
            correlationId,
          });
        }
      });

      req.on('end', () => {
        if (dataLength > maxBytes) {
          return res.status(413).json({
            error: 'Payload Too Large',
            message: `Request size exceeds limit of ${maxSize}`,
            correlationId,
          });
        }
        next();
      });
    } catch (error) {
      safeLogger.error('Request size limit error', {
        error: error.message,
        correlationId,
      });
      next();
    }
  };
};

/**
 * Input sanitization middleware
 */
export const sanitizeInput = (req, res, next) => {
  const correlationId = getCorrelationId();

  try {
    // Safety check for req object
    if (!req || typeof req !== 'object') {
      safeLogger.warn('Invalid request object in sanitizeInput', {
        correlationId,
        reqType: typeof req,
      });
      return next();
    }

    // Sanitize query parameters
    if (req.query && typeof req.query === 'object') {
      Object.keys(req.query).forEach(key => {
        if (typeof req.query[key] === 'string') {
          req.query[key] = req.query[key].trim();
        }
      });
    }

    // Sanitize body parameters
    if (req.body && typeof req.body === 'object') {
      sanitizeObject(req.body);
    }

    next();
  } catch (error) {
    safeLogger.error('Input sanitization error', {
      error: error.message,
      correlationId,
    });
    next();
  }
};

/**
 * Recursively sanitize object values
 */
function sanitizeObject(obj) {
  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      if (typeof obj[key] === 'string') {
        obj[key] = obj[key].trim();
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        sanitizeObject(obj[key]);
      }
    }
  }
}

/**
 * Parse size string to bytes
 */
function parseSize(size) {
  const units = {
    b: 1,
    kb: 1024,
    mb: 1024 * 1024,
    gb: 1024 * 1024 * 1024,
  };

  const match = size.toLowerCase().match(/^(\d+)([bkmg]b?)?$/);
  if (!match) return 1024 * 1024; // Default to 1MB

  const value = parseInt(match[1]);
  const unit = match[2] || 'b';

  return value * (units[unit] || 1);
}

export default {
  securityHeaders,
  corsMiddleware,
  requestSizeLimit,
  sanitizeInput,
};
