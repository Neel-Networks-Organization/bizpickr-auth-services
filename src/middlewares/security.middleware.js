import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import { ApiError } from '../utils/index.js';

/**
 * Smart Security Middleware
 * Core security headers and CORS handling
 */

/**
 * Security headers middleware
 */
export const securityHeaders = (options = {}) => {
  const {
    enableHSTS = true,
    enableCSP = true,
    enableXSS = true,
    enableFrameOptions = true,
    enableContentType = true,
    enableReferrerPolicy = true,
    enablePermissionsPolicy = true,
  } = options;

  return (req, res, next) => {
    const correlationId = getCorrelationId();

    try {
      // HSTS (HTTP Strict Transport Security)
      if (enableHSTS) {
        res.setHeader(
          'Strict-Transport-Security',
          'max-age=31536000; includeSubDomains; preload'
        );
      }

      // Content Security Policy
      if (enableCSP) {
        const csp = [
          "default-src 'self'",
          "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
          "style-src 'self' 'unsafe-inline'",
          "img-src 'self' data: https:",
          "font-src 'self'",
          "connect-src 'self'",
          "frame-ancestors 'none'",
          "base-uri 'self'",
          "form-action 'self'",
        ].join('; ');
        res.setHeader('Content-Security-Policy', csp);
      }

      // XSS Protection
      if (enableXSS) {
        res.setHeader('X-XSS-Protection', '1; mode=block');
      }

      // Frame Options
      if (enableFrameOptions) {
        res.setHeader('X-Frame-Options', 'DENY');
      }

      // Content Type Options
      if (enableContentType) {
        res.setHeader('X-Content-Type-Options', 'nosniff');
      }

      // Referrer Policy
      if (enableReferrerPolicy) {
        res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
      }

      // Permissions Policy
      if (enablePermissionsPolicy) {
        res.setHeader(
          'Permissions-Policy',
          'geolocation=(), microphone=(), camera=()'
        );
      }

      // Additional security headers
      res.setHeader('X-DNS-Prefetch-Control', 'off');
      res.setHeader('X-Download-Options', 'noopen');
      res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');

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
 * CORS middleware
 */
export const corsMiddleware = (options = {}) => {
  const {
    origin = process.env.ALLOWED_ORIGINS?.split(',') || [
      'http://localhost:3000',
    ],
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders = ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials = true,
    maxAge = 86400, // 24 hours
  } = options;

  return (req, res, next) => {
    const correlationId = getCorrelationId();
    const requestOrigin = req.headers.origin;

    try {
      // Handle preflight request
      if (req.method === 'OPTIONS') {
        res.setHeader('Access-Control-Allow-Origin', requestOrigin || '*');
        res.setHeader('Access-Control-Allow-Methods', methods.join(', '));
        res.setHeader(
          'Access-Control-Allow-Headers',
          allowedHeaders.join(', ')
        );
        res.setHeader(
          'Access-Control-Allow-Credentials',
          credentials.toString()
        );
        res.setHeader('Access-Control-Max-Age', maxAge.toString());
        res.status(200).end();
        return;
      }

      // Set CORS headers for actual request
      if (requestOrigin && origin.includes(requestOrigin)) {
        res.setHeader('Access-Control-Allow-Origin', requestOrigin);
      } else if (origin.includes('*')) {
        res.setHeader('Access-Control-Allow-Origin', '*');
      }

      if (credentials) {
        res.setHeader('Access-Control-Allow-Credentials', 'true');
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
 * Request size limiting middleware
 */
export const requestSizeLimit = (maxSize = '10mb') => {
  return (req, res, next) => {
    const correlationId = getCorrelationId();

    try {
      const contentLength = parseInt(req.headers['content-length'] || '0');
      const maxSizeBytes = parseSize(maxSize);

      if (contentLength > maxSizeBytes) {
        safeLogger.warn('Request size limit exceeded', {
          contentLength,
          maxSize: maxSizeBytes,
          correlationId,
          path: req.path,
        });

        return res.status(413).json({
          error: 'Request too large',
          message: `Request size exceeds limit of ${maxSize}`,
          correlationId,
        });
      }

      next();
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
 * Content type validation middleware
 */
export const validateContentType = (allowedTypes = ['application/json']) => {
  return (req, res, next) => {
    const correlationId = getCorrelationId();

    try {
      if (req.method === 'GET' || req.method === 'DELETE') {
        return next();
      }

      const contentType = req.headers['content-type'];

      if (!contentType) {
        safeLogger.warn('Missing content type', {
          correlationId,
          path: req.path,
        });
        return res.status(400).json({
          error: 'Missing content type',
          message: 'Content-Type header is required',
          correlationId,
        });
      }

      const isValidType = allowedTypes.some(type => contentType.includes(type));

      if (!isValidType) {
        safeLogger.warn('Invalid content type', {
          contentType,
          allowedTypes,
          correlationId,
          path: req.path,
        });

        return res.status(400).json({
          error: 'Invalid content type',
          message: `Content-Type must be one of: ${allowedTypes.join(', ')}`,
          correlationId,
        });
      }

      next();
    } catch (error) {
      safeLogger.error('Content type validation error', {
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
    // Sanitize query parameters
    if (req.query) {
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
    if (obj.hasOwnProperty(key)) {
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

/**
 * Security monitoring middleware
 */
export const securityMonitoring = (req, res, next) => {
  const correlationId = getCorrelationId();

  try {
    // Log suspicious requests
    const suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /union\s+select/i,
      /drop\s+table/i,
      /exec\s*\(/i,
    ];

    const userInput = [
      req.url,
      JSON.stringify(req.query),
      JSON.stringify(req.body),
      req.headers['user-agent'] || '',
    ].join(' ');

    const hasSuspiciousPattern = suspiciousPatterns.some(pattern =>
      pattern.test(userInput)
    );

    if (hasSuspiciousPattern) {
      safeLogger.warn('Suspicious request detected', {
        correlationId,
        path: req.path,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        suspiciousInput: userInput.substring(0, 200), // Limit log size
      });
    }

    next();
  } catch (error) {
    safeLogger.error('Security monitoring error', {
      error: error.message,
      correlationId,
    });
    next();
  }
};

export default {
  securityHeaders,
  corsMiddleware,
  requestSizeLimit,
  validateContentType,
  sanitizeInput,
  securityMonitoring,
};
