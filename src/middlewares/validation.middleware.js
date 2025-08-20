import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import { ApiError } from '../utils/index.js';
import Joi from 'joi';

/**
 * Smart Validation Middleware
 * HTTP request validation using Joi schemas
 */

/**
 * Main validation middleware function
 */
export const validateRequest = (schema, options = {}) => {
  const {
    abortEarly = false,
    allowUnknown = false,
    stripUnknown = true,
    cacheValidation = true,
  } = options;

  // Validation cache for performance
  const validationCache = new Map();

  return (req, res, next) => {
    const correlationId = getCorrelationId();
    const startTime = Date.now();

    try {
      // Get cached validation function if available
      let validateFunction;
      if (cacheValidation && validationCache.has(schema)) {
        validateFunction = validationCache.get(schema);
      } else {
        validateFunction = schema.validate.bind(schema);
        if (cacheValidation) {
          validationCache.set(schema, validateFunction);
        }
      }

      // Validate request data
      const dataToValidate = {
        body: req.body,
        query: req.query,
        params: req.params,
        headers: req.headers,
      };

      const { error, value } = validateFunction(dataToValidate, {
        abortEarly,
        allowUnknown,
        stripUnknown,
      });

      if (error) {
        const validationErrors = error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message,
          type: detail.type,
        }));

        safeLogger.warn('Validation failed', {
          correlationId,
          path: req.path,
          method: req.method,
          errors: validationErrors,
          processingTime: Date.now() - startTime,
        });

        return res.status(400).json({
          error: 'Validation failed',
          message: 'Request data validation failed',
          details: validationErrors,
          correlationId,
        });
      }

      // Update request with validated data
      if (value.body) req.body = value.body;
      if (value.query) req.query = value.query;
      if (value.params) req.params = value.params;

      const processingTime = Date.now() - startTime;
      safeLogger.debug('Validation successful', {
        correlationId,
        path: req.path,
        method: req.method,
        processingTime: `${processingTime}ms`,
      });

      next();
    } catch (error) {
      safeLogger.error('Validation middleware error', {
        error: error.message,
        correlationId,
        path: req.path,
        method: req.method,
      });

      return res.status(500).json({
        error: 'Validation error',
        message: 'Internal validation error',
        correlationId,
      });
    }
  };
};

/**
 * Validate specific request parts
 */
export const validateBody = (schema, options = {}) => {
  return validateRequest(
    Joi.object({
      body: schema,
    }),
    options
  );
};

export const validateQuery = (schema, options = {}) => {
  return validateRequest(
    Joi.object({
      query: schema,
    }),
    options
  );
};

export const validateParams = (schema, options = {}) => {
  return validateRequest(
    Joi.object({
      params: schema,
    }),
    options
  );
};

export const validateHeaders = (schema, options = {}) => {
  return validateRequest(
    Joi.object({
      headers: schema,
    }),
    options
  );
};

/**
 * Common validation schemas
 */
export const commonSchemas = {
  // ID validation
  id: Joi.string().uuid().required(),

  // Pagination
  pagination: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(10),
    sortBy: Joi.string()
      .valid('createdAt', 'updatedAt', 'name', 'email')
      .default('createdAt'),
    sortOrder: Joi.string().valid('asc', 'desc').default('desc'),
  }),

  // Search
  search: Joi.object({
    q: Joi.string().min(1).max(100),
    fields: Joi.array().items(Joi.string()).max(10),
  }),

  // Date range
  dateRange: Joi.object({
    startDate: Joi.date().iso(),
    endDate: Joi.date().iso().min(Joi.ref('startDate')),
  }),

  // File upload
  fileUpload: Joi.object({
    fieldname: Joi.string().required(),
    originalname: Joi.string().required(),
    encoding: Joi.string().required(),
    mimetype: Joi.string().required(),
    size: Joi.number().max(10 * 1024 * 1024), // 10MB max
  }),
};

/**
 * Custom validation functions
 */
export const customValidators = {
  // Validate email format
  email: (value, helpers) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(value)) {
      return helpers.error('any.invalid');
    }
    return value;
  },

  // Validate password strength
  password: (value, helpers) => {
    if (value.length < 8) {
      return helpers.error('any.invalid');
    }
    if (!/(?=.*[a-z])/.test(value)) {
      return helpers.error('any.invalid');
    }
    if (!/(?=.*[A-Z])/.test(value)) {
      return helpers.error('any.invalid');
    }
    if (!/(?=.*\d)/.test(value)) {
      return helpers.error('any.invalid');
    }
    return value;
  },

  // Validate phone number
  phone: (value, helpers) => {
    const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
    if (!phoneRegex.test(value.replace(/\s/g, ''))) {
      return helpers.error('any.invalid');
    }
    return value;
  },

  // Validate URL
  url: (value, helpers) => {
    try {
      new URL(value);
      return value;
    } catch {
      return helpers.error('any.invalid');
    }
  },

  // Validate IP address
  ipAddress: (value, helpers) => {
    const ipRegex =
      /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!ipRegex.test(value)) {
      return helpers.error('any.invalid');
    }
    return value;
  },
};

/**
 * Sanitize and validate data
 */
export const sanitizeAndValidate = (data, schema, options = {}) => {
  try {
    const { error, value } = schema.validate(data, {
      abortEarly: false,
      allowUnknown: false,
      stripUnknown: true,
      ...options,
    });

    if (error) {
      return {
        isValid: false,
        errors: error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message,
          type: detail.type,
        })),
        data: null,
      };
    }

    return {
      isValid: true,
      errors: [],
      data: value,
    };
  } catch (error) {
    return {
      isValid: false,
      errors: [
        { field: 'unknown', message: 'Validation failed', type: 'unknown' },
      ],
      data: null,
    };
  }
};

/**
 * Get validation statistics
 */
export const getValidationStats = () => {
  return {
    cacheSize: validationCache.size,
    cachedSchemas: Array.from(validationCache.keys()).map(schema =>
      schema.describe().keys ? 'object' : 'primitive'
    ),
  };
};

export default {
  validateRequest,
  validateBody,
  validateQuery,
  validateParams,
  validateHeaders,
  commonSchemas,
  customValidators,
  sanitizeAndValidate,
  getValidationStats,
};
