/**
 * Shared Utilities Package
 *
 * This file consolidates common utilities used across services
 * to eliminate code duplication and standardize patterns.
 */

import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';

/**
 * Standardized Error Response Format
 */
export const createErrorResponse = (
  statusCode,
  message,
  details = [],
  stack = null,
) => ({
  success: false,
  message,
  errors: Array.isArray(details) ? details : [details],
  ...(process.env.NODE_ENV === 'production' ? {} : { stack }),
});

/**
 * Standardized Success Response Format
 */
export const createSuccessResponse = (data, message = 'Success') => ({
  success: true,
  message,
  data,
});

/**
 * Standardized Logging Patterns
 */
export const logInfo = (message, data = {}) => {
  safeLogger.info(message, {
    ...data,
    correlationId: getCorrelationId(),
    timestamp: new Date().toISOString(),
  });
};

export const logError = (message, error, data = {}) => {
  safeLogger.error(message, {
    ...data,
    error: {
      message: error.message,
      stack: error.stack,
      name: error.name,
      code: error.code,
    },
    correlationId: getCorrelationId(),
    timestamp: new Date().toISOString(),
  });
};

export const logWarn = (message, data = {}) => {
  safeLogger.warn(message, {
    ...data,
    correlationId: getCorrelationId(),
    timestamp: new Date().toISOString(),
  });
};

export const logDebug = (message, data = {}) => {
  safeLogger.debug(message, {
    ...data,
    correlationId: getCorrelationId(),
    timestamp: new Date().toISOString(),
  });
};

/**
 * Standardized Database Connection Patterns
 */
export const createDatabaseConnection = config => {
  const {
    host,
    port,
    database,
    username,
    password,
    dialect = 'mysql',
    logging = false,
    pool = {
      max: 10,
      min: 0,
      acquire: 30000,
      idle: 10000,
    },
  } = config;

  return {
    host,
    port,
    database,
    username,
    password,
    dialect,
    logging: process.env.NODE_ENV === 'development' ? logging : false,
    pool,
  };
};

/**
 * Standardized Environment Variable Handling
 */
export const getEnvVar = (key, defaultValue = null, required = false) => {
  const value = process.env[key];

  if (required && !value) {
    throw new Error(`Required environment variable ${key} is not set`);
  }

  return value || defaultValue;
};

/**
 * Standardized Configuration Patterns
 */
export const createServiceConfig = serviceName => ({
  port: getEnvVar('PORT', 3000),
  host: getEnvVar('HOST', 'localhost'),
  environment: getEnvVar('NODE_ENV', 'development'),
  logLevel: getEnvVar('LOG_LEVEL', 'info'),
  corsOrigin: getEnvVar('CORS_ORIGIN', 'http://localhost:3000'),
  database: {
    host: getEnvVar('DB_HOST', 'localhost'),
    port: getEnvVar('DB_PORT', 3306),
    name: getEnvVar('DB_NAME', 'bizpicker'),
    user: getEnvVar('DB_USER', 'root'),
    password: getEnvVar('DB_PASS', ''),
  },
  redis: {
    host: getEnvVar('REDIS_HOST', 'localhost'),
    port: getEnvVar('REDIS_PORT', 6379),
    password: getEnvVar('REDIS_PASSWORD', ''),
  },
  serviceName,
});

/**
 * Standardized Health Check Patterns
 */
export const createHealthCheck = checks => {
  return async(req, res) => {
    const results = {};
    let overallStatus = 'healthy';

    for (const [name, check] of Object.entries(checks)) {
      try {
        const result = await check();
        results[name] = {
          status: result.status || 'healthy',
          message: result.message || 'OK',
          timestamp: new Date().toISOString(),
        };

        if (result.status === 'unhealthy') {
          overallStatus = 'unhealthy';
        }
      } catch (error) {
        results[name] = {
          status: 'unhealthy',
          message: error.message,
          timestamp: new Date().toISOString(),
        };
        overallStatus = 'unhealthy';
      }
    }

    const statusCode = overallStatus === 'healthy' ? 200 : 503;

    res.status(statusCode).json({
      status: overallStatus,
      timestamp: new Date().toISOString(),
      checks: results,
    });
  };
};

/**
 * Standardized Rate Limiting Patterns
 */
export const createRateLimiter = (options = {}) => {
  const {
    windowMs = 15 * 60 * 1000, // 15 minutes
    max = 100, // limit each IP to 100 requests per windowMs
    message = 'Too many requests from this IP, please try again later.',
    standardHeaders = true,
    legacyHeaders = false,
  } = options;

  const requests = new Map();

  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const windowStart = now - windowMs;

    // Clean old entries
    if (requests.has(ip)) {
      const userRequests = requests.get(ip).filter(time => time > windowStart);
      requests.set(ip, userRequests);
    } else {
      requests.set(ip, []);
    }

    const userRequests = requests.get(ip);

    if (userRequests.length >= max) {
      return res.status(429).json({
        success: false,
        message,
        retryAfter: Math.ceil(windowMs / 1000),
      });
    }

    userRequests.push(now);
    next();
  };
};

/**
 * Standardized CORS Patterns
 */
export const createCorsConfig = (allowedOrigins = []) => {
  const origins = Array.isArray(allowedOrigins)
    ? allowedOrigins
    : [allowedOrigins];

  return {
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) return callback(null, true);

      if (origins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['Content-Range', 'X-Content-Range'],
    maxAge: 86400, // 24 hours
  };
};

/**
 * Standardized Request Validation Patterns
 */
export const validateRequest = schema => {
  return (req, res, next) => {
    try {
      const { error } = schema.validate(req.body);
      if (error) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: error.details.map(detail => detail.message),
        });
      }
      next();
    } catch (error) {
      logError('Request validation error', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  };
};

/**
 * Standardized Response Headers
 */
export const setStandardHeaders = (req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': 'default-src \'self\'',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  });
  next();
};

/**
 * Standardized Error Handling Middleware
 */
export const errorHandler = (err, req, res, next) => {
  logError('Unhandled error', err, {
    url: req.originalUrl,
    method: req.method,
    userAgent: req.headers['user-agent'],
    ip: req.ip,
  });

  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';

  res
    .status(statusCode)
    .json(createErrorResponse(statusCode, message, err.details, err.stack));
};

/**
 * Standardized Async Handler (Simplified Version)
 */
export const asyncHandler = fn => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Standardized Performance Monitoring
 */
export const performanceMonitor = (req, res, next) => {
  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;
    logInfo('Request completed', {
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      userAgent: req.headers['user-agent'],
      ip: req.ip,
    });
  });

  next();
};

/**
 * Standardized Request ID Generation
 */
export const generateRequestId = () => {
  return `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
};

/**
 * Standardized Request ID Middleware
 */
export const requestIdMiddleware = (req, res, next) => {
  req.requestId = req.headers['x-request-id'] || generateRequestId();
  res.setHeader('X-Request-ID', req.requestId);
  next();
};

// All utilities are exported individually above
