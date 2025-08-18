import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import { ApiError } from '../utils/ApiError.js';
/**
 * Industry-level Security Middleware
 *
 * Features:
 * - Security headers configuration
 * - CORS handling
 * - Input sanitization and validation
 * - Request size limiting
 * - Content type validation
 * - Security monitoring and logging
 * - XSS and injection protection
 */
// Security metrics
const securityMetrics = {
  totalRequests: 0,
  blockedRequests: 0,
  sanitizedRequests: 0,
  corsRequests: 0,
  uptime: Date.now(),
  securityEvents: [],
};
/**
 * Update security metrics
 * @param {string} type - Metric type
 * @param {Object} data - Additional data
 */
function updateSecurityMetrics(type, data = {}) {
  switch (type) {
  case 'request':
    securityMetrics.totalRequests++;
    break;
  case 'blocked':
    securityMetrics.blockedRequests++;
    break;
  case 'sanitized':
    securityMetrics.sanitizedRequests++;
    break;
  case 'cors':
    securityMetrics.corsRequests++;
    break;
  }
  // Keep only last 100 security events
  if (securityMetrics.securityEvents.length > 100) {
    securityMetrics.securityEvents.shift();
  }
  safeLogger.debug('Security middleware metrics updated', {
    type,
    data,
    metrics: { ...securityMetrics },
  });
}
/**
 * Security headers middleware
 * @param {Object} options - Security headers options
 * @returns {Function} Middleware function
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
          'max-age=31536000; includeSubDomains; preload',
        );
      }
      // Content Security Policy
      if (enableCSP) {
        const csp = [
          'default-src \'self\'',
          'script-src \'self\' \'unsafe-inline\' \'unsafe-eval\'',
          'style-src \'self\' \'unsafe-inline\'',
          'img-src \'self\' data: https:',
          'font-src \'self\'',
          'connect-src \'self\'',
          'frame-ancestors \'none\'',
          'base-uri \'self\'',
          'form-action \'self\'',
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
        const permissionsPolicy = [
          'camera=()',
          'microphone=()',
          'geolocation=()',
          'payment=()',
          'usb=()',
        ].join(', ');
        res.setHeader('Permissions-Policy', permissionsPolicy);
      }
      // Additional security headers
      res.setHeader('X-Download-Options', 'noopen');
      res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
      res.setHeader('X-DNS-Prefetch-Control', 'off');
      // Remove potentially dangerous headers
      res.removeHeader('X-Powered-By');
      res.removeHeader('Server');
      safeLogger.debug('Security headers applied', {
        correlationId,
        headers: {
          hsts: enableHSTS,
          csp: enableCSP,
          xss: enableXSS,
          frameOptions: enableFrameOptions,
        },
      });
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
 * @param {Object} options - CORS options
 * @returns {Function} Middleware function
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
    preflightContinue = false,
  } = options;
  return (req, res, next) => {
    const correlationId = getCorrelationId();
    const requestOrigin = req.headers.origin;
    try {
      updateSecurityMetrics('cors');
      // Check if origin is allowed
      const isOriginAllowed = Array.isArray(origin)
        ? origin.includes(requestOrigin) || origin.includes('*')
        : origin === requestOrigin || origin === '*';
      if (requestOrigin && !isOriginAllowed) {
        safeLogger.warn('CORS blocked request', {
          requestOrigin,
          allowedOrigins: origin,
          correlationId,
          ip: req.ip,
        });
        updateSecurityMetrics('blocked');
        return res.status(403).json({
          error: 'CORS policy violation',
          message: 'Origin not allowed',
        });
      }
      // Set CORS headers
      if (requestOrigin) {
        res.setHeader('Access-Control-Allow-Origin', requestOrigin);
      }
      res.setHeader('Access-Control-Allow-Methods', methods.join(', '));
      res.setHeader('Access-Control-Allow-Headers', allowedHeaders.join(', '));
      res.setHeader('Access-Control-Max-Age', maxAge);
      if (credentials) {
        res.setHeader('Access-Control-Allow-Credentials', 'true');
      }
      // Handle preflight requests
      if (req.method === 'OPTIONS') {
        if (preflightContinue) {
          return next();
        }
        return res.status(200).end();
      }
      safeLogger.debug('CORS headers applied', {
        requestOrigin,
        correlationId,
        method: req.method,
      });
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
 * Input sanitization middleware
 * @param {Object} options - Sanitization options
 * @returns {Function} Middleware function
 */
export const inputSanitizer = (options = {}) => {
  const {
    sanitizeBody = true,
    sanitizeQuery = true,
    sanitizeParams = true,
    removeScripts = true,
    removeHtml = false,
    maxLength = 10000,
  } = options;
  return (req, res, next) => {
    const correlationId = getCorrelationId();
    try {
      updateSecurityMetrics('request');
      // Sanitize request body
      if (sanitizeBody && req.body) {
        req.body = sanitizeObject(req.body, {
          removeScripts,
          removeHtml,
          maxLength,
        });
        updateSecurityMetrics('sanitized');
      }
      // Sanitize query parameters (avoid mutating req.query directly if read-only)
      if (sanitizeQuery && req.query) {
        try {
          const sanitizedQuery = sanitizeObject(req.query, {
            removeScripts,
            removeHtml,
            maxLength,
          });
          // Only assign if not read-only
          if (
            Object.getOwnPropertyDescriptor(req, 'query')?.writable !== false
          ) {
            req.query = sanitizedQuery;
          }
        } catch (err) {
          // If assignment fails, skip updating req.query
          safeLogger.warn(
            'Skipping req.query sanitization due to read-only property',
            { correlationId },
          );
        }
        updateSecurityMetrics('sanitized');
      }
      // Sanitize URL parameters
      if (sanitizeParams && req.params) {
        req.params = sanitizeObject(req.params, {
          removeScripts,
          removeHtml,
          maxLength,
        });
        updateSecurityMetrics('sanitized');
      }
      safeLogger.debug('Input sanitization completed', {
        correlationId,
        sanitized: {
          body: sanitizeBody,
          query: sanitizeQuery,
          params: sanitizeParams,
        },
      });
      next();
    } catch (error) {
      safeLogger.error('Input sanitization error', {
        error: error.message,
        correlationId,
      });
      next();
    }
  };
};
/**
 * Sanitize object recursively
 * @param {any} obj - Object to sanitize
 * @param {Object} options - Sanitization options
 * @returns {any} Sanitized object
 */
function sanitizeObject(obj, options = {}) {
  const {
    removeScripts = true,
    removeHtml = false,
    maxLength = 10000,
  } = options;
  if (typeof obj === 'string') {
    let sanitized = obj;
    // Check length
    if (sanitized.length > maxLength) {
      sanitized = sanitized.substring(0, maxLength);
    }
    // Remove script tags
    if (removeScripts) {
      sanitized = sanitized.replace(
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        '',
      );
    }
    // Remove HTML tags
    if (removeHtml) {
      sanitized = sanitized.replace(/<[^>]*>/g, '');
    }
    // Basic XSS protection
    sanitized = sanitized
      .replace(/javascript:/gi, '')
      .replace(/on\w+\s*=/gi, '')
      .replace(/<iframe/gi, '')
      .replace(/<object/gi, '')
      .replace(/<embed/gi, '');
    return sanitized;
  }
  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item, options));
  }
  if (obj && typeof obj === 'object') {
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      // Do NOT attempt to parse or mutate string fields into objects.
      // Only sanitize strings as strings. Do not try to parse JSON or change types.
      sanitized[key] = sanitizeObject(value, options);
    }
    return sanitized;
  }
  return obj;
}
/**
 * Request size limiter middleware
 * @param {Object} options - Size limiting options
 * @returns {Function} Middleware function
 */
export const requestSizeLimiter = (options = {}) => {
  const {
    maxBodySize = '10mb',
    maxUrlLength = 2048,
    maxHeaderSize = 8192,
  } = options;
  return (req, res, next) => {
    const correlationId = getCorrelationId();
    try {
      // Check URL length
      if (req.url.length > maxUrlLength) {
        updateSecurityMetrics('blocked');
        safeLogger.warn('Request blocked - URL too long', {
          urlLength: req.url.length,
          maxUrlLength,
          correlationId,
          ip: req.ip,
        });
        throw new ApiError(414, 'Request URI too long', [
          'URL exceeds maximum allowed length',
          `Maximum length: ${maxUrlLength} characters`,
        ]);
      }
      // Check header size
      const headerSize = JSON.stringify(req.headers).length;
      if (headerSize > maxHeaderSize) {
        updateSecurityMetrics('blocked');
        safeLogger.warn('Request blocked - headers too large', {
          headerSize,
          maxHeaderSize,
          correlationId,
          ip: req.ip,
        });
        throw new ApiError(431, 'Request header fields too large', [
          'Request headers exceed maximum allowed size',
          `Maximum size: ${maxHeaderSize} bytes`,
        ]);
      }
      safeLogger.debug('Request size validation passed', {
        correlationId,
        urlLength: req.url.length,
        headerSize,
      });
      next();
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      safeLogger.error('Request size limiter error', {
        error: error.message,
        correlationId,
      });
      next();
    }
  };
};
/**
 * Content type validator middleware
 * @param {Object} options - Content type options
 * @returns {Function} Middleware function
 */
export const contentTypeValidator = (options = {}) => {
  const {
    allowedTypes = ['application/json', 'application/x-www-form-urlencoded'],
    strict = true,
  } = options;
  return (req, res, next) => {
    const correlationId = getCorrelationId();
    const contentType = req.headers['content-type'];
    try {
      // Skip for GET requests and requests without body
      if (req.method === 'GET' || !contentType) {
        return next();
      }
      // Check if content type is allowed
      const isAllowed = allowedTypes.some(type => contentType.includes(type));
      if (!isAllowed) {
        updateSecurityMetrics('blocked');
        safeLogger.warn('Request blocked - invalid content type', {
          contentType,
          allowedTypes,
          correlationId,
          ip: req.ip,
        });
        throw new ApiError(415, 'Unsupported media type', [
          'Content type not allowed',
          `Allowed types: ${allowedTypes.join(', ')}`,
          `Received: ${contentType}`,
        ]);
      }
      safeLogger.debug('Content type validation passed', {
        contentType,
        correlationId,
      });
      next();
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      safeLogger.error('Content type validator error', {
        error: error.message,
        correlationId,
      });
      next();
    }
  };
};
/**
 * Security monitoring middleware
 * @param {Object} options - Monitoring options
 * @returns {Function} Middleware function
 */
export const securityMonitor = (options = {}) => {
  const {
    logSuspiciousActivity = true,
    blockSuspiciousRequests = false,
    suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /union\s+select/i,
      /drop\s+table/i,
      /exec\s*\(/i,
    ],
  } = options;
  return (req, res, next) => {
    const correlationId = getCorrelationId();
    try {
      const suspiciousActivity = [];
      // Check request URL
      if (suspiciousPatterns.some(pattern => pattern.test(req.url))) {
        suspiciousActivity.push('Suspicious URL pattern');
      }
      // Check request body
      if (req.body && typeof req.body === 'string') {
        if (suspiciousPatterns.some(pattern => pattern.test(req.body))) {
          suspiciousActivity.push('Suspicious body content');
        }
      }
      // Check headers
      const userAgent = req.headers['user-agent'] || '';
      if (suspiciousPatterns.some(pattern => pattern.test(userAgent))) {
        suspiciousActivity.push('Suspicious user agent');
      }
      // Log suspicious activity
      if (suspiciousActivity.length > 0 && logSuspiciousActivity) {
        const securityEvent = {
          timestamp: new Date().toISOString(),
          correlationId,
          ip: req.ip,
          userAgent: req.headers['user-agent'],
          url: req.url,
          method: req.method,
          suspiciousActivity,
        };
        securityMetrics.securityEvents.push(securityEvent);
        safeLogger.warn('Suspicious activity detected', securityEvent);
        // Block request if configured
        if (blockSuspiciousRequests) {
          updateSecurityMetrics('blocked');
          throw new ApiError(403, 'Suspicious activity detected', [
            'Request blocked due to suspicious activity',
            'Please contact support if this is a false positive',
          ]);
        }
      }
      next();
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      safeLogger.error('Security monitor error', {
        error: error.message,
        correlationId,
      });
      next();
    }
  };
};
/**
 * Get security middleware metrics
 * @returns {Object} Security metrics
 */
export const getSecurityMetrics = () => {
  const uptime = Date.now() - securityMetrics.uptime;
  const blockRate =
    securityMetrics.totalRequests > 0
      ? (securityMetrics.blockedRequests / securityMetrics.totalRequests) * 100
      : 0;
  return {
    ...securityMetrics,
    uptime: `${Math.round(uptime / 1000)}s`,
    blockRate: `${blockRate.toFixed(2)}%`,
    currentTime: new Date().toISOString(),
  };
};
/**
 * Reset security middleware metrics
 */
export const resetSecurityMetrics = () => {
  Object.assign(securityMetrics, {
    totalRequests: 0,
    blockedRequests: 0,
    sanitizedRequests: 0,
    corsRequests: 0,
    uptime: Date.now(),
    securityEvents: [],
  });
  safeLogger.info('Security middleware metrics reset');
};
/**
 * Main security middleware that combines all security features
 * This is the primary middleware used in app.js
 * @param {Object} options - Security options
 * @returns {Function} Combined security middleware
 */
export const securityMiddleware = (options = {}) => {
  const {
    enableHeaders = true,
    enableCors = true,
    enableSanitization = true,
    enableSizeLimiting = true,
    enableContentTypeValidation = true,
    enableMonitoring = true,
  } = options;
  return (req, res, next) => {
    const correlationId = getCorrelationId();
    try {
      updateSecurityMetrics('request');
      // Apply security headers
      if (enableHeaders) {
        securityHeaders()(req, res, err => {
          if (err) return next(err);
        });
      }
      // Apply CORS middleware
      if (enableCors) {
        corsMiddleware()(req, res, err => {
          if (err) return next(err);
        });
      }
      // Apply input sanitization
      if (enableSanitization) {
        inputSanitizer()(req, res, err => {
          if (err) return next(err);
        });
      }
      // Apply request size limiting
      if (enableSizeLimiting) {
        requestSizeLimiter()(req, res, err => {
          if (err) return next(err);
        });
      }
      // Apply content type validation
      if (enableContentTypeValidation) {
        contentTypeValidator()(req, res, err => {
          if (err) return next(err);
        });
      }
      // Apply security monitoring
      if (enableMonitoring) {
        securityMonitor()(req, res, err => {
          if (err) return next(err);
        });
      }
      safeLogger.debug('Security middleware applied', {
        correlationId,
        features: {
          headers: enableHeaders,
          cors: enableCors,
          sanitization: enableSanitization,
          sizeLimiting: enableSizeLimiting,
          contentTypeValidation: enableContentTypeValidation,
          monitoring: enableMonitoring,
        },
      });
      next();
    } catch (error) {
      safeLogger.error('Security middleware error', {
        error: error.message,
        correlationId,
        stack: error.stack,
      });
      next(error);
    }
  };
};
export default securityMiddleware;
