import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import { ApiError } from '../utils/ApiError.js';
import Joi from 'joi';
/**
 * Socket.IO Validation Middleware
 *
 * Features:
 * - Message validation using Joi schemas
 * - Data sanitization and cleaning
 * - Rate limiting for validation attempts
 * - Detailed error responses
 * - Performance monitoring
 * - Security validation
 */
class ValidationMiddleware {
  constructor() {
    this.validationCache = new Map();
    this.errorCounts = new Map();
    this.maxErrorsPerMinute = 10;
    this.errorWindow = 60000; // 1 minute
  }
  /**
   * Main validation middleware function
   * @param {Object} socket - Socket.IO socket instance
   * @param {Function} next - Next middleware function
   */
  validate(socket, next) {
    const correlationId = getCorrelationId();
    const startTime = Date.now();
    try {
      // Add validation methods to socket
      this._addValidationMethods(socket);
      // Validate handshake data
      this._validateHandshake(socket);
      // Add event validation wrapper
      this._wrapSocketEvents(socket);
      const processingTime = Date.now() - startTime;
      safeLogger.debug('Validation middleware applied successfully', {
        socketId: socket.id,
        correlationId,
        processingTime,
      });
      next();
    } catch (error) {
      safeLogger.error('Validation middleware error', {
        error: error.message,
        socketId: socket.id,
        correlationId,
      });
      next(new Error('Validation failed'));
    }
  }
  /**
   * Add validation methods to socket
   * @private
   */
  _addValidationMethods(socket) {
    // Add validation method to socket
    socket.validateMessage = (event, data, schema) => {
      return this._validateMessage(event, data, schema, socket);
    };
    // Add sanitization method to socket
    socket.sanitizeData = data => {
      return this._sanitizeData(data);
    };
    // Add validation helper
    socket.validateAndSanitize = (event, data, schema) => {
      const validated = this._validateMessage(event, data, schema, socket);
      return this._sanitizeData(validated);
    };
  }
  /**
   * Validate handshake data
   * @private
   */
  _validateHandshake(socket) {
    const correlationId = getCorrelationId();
    try {
      // Validate headers
      const headers = socket.handshake.headers;
      // Check for required headers
      if (!headers['user-agent']) {
        throw new ApiError(400, 'User-Agent header required');
      }
      // Validate origin if present
      if (headers.origin) {
        const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [];
        if (
          allowedOrigins.length > 0 &&
          !allowedOrigins.includes(headers.origin)
        ) {
          throw new ApiError(403, 'Origin not allowed');
        }
      }
      // Validate IP address
      const ip = socket.handshake.address;
      if (!this._isValidIP(ip)) {
        throw new ApiError(400, 'Invalid IP address');
      }
      safeLogger.debug('Handshake validation passed', {
        socketId: socket.id,
        correlationId,
        ip,
        userAgent: headers['user-agent'],
      });
    } catch (error) {
      safeLogger.warn('Handshake validation failed', {
        error: error.message,
        socketId: socket.id,
        correlationId,
      });
      throw error;
    }
  }
  /**
   * Wrap socket events with validation
   * @private
   */
  _wrapSocketEvents(socket) {
    const originalEmit = socket.emit;
    const originalOn = socket.on;
    // Wrap emit to validate outgoing data
    socket.emit = (event, data, ...args) => {
      try {
        const sanitizedData = this._sanitizeData(data);
        return originalEmit.call(socket, event, sanitizedData, ...args);
      } catch (error) {
        safeLogger.error('Error sanitizing outgoing data', {
          error: error.message,
          socketId: socket.id,
          event,
        });
        return originalEmit.call(socket, event, data, ...args);
      }
    };
    // Wrap on to add validation for incoming events
    socket.on = (event, handler) => {
      const wrappedHandler = async(...args) => {
        try {
          // Get schema for event if exists
          const schema = this._getEventSchema(event);
          if (schema && args.length > 0) {
            // Validate first argument (data)
            const validatedData = await this._validateMessage(
              event,
              args[0],
              schema,
              socket,
            );
            args[0] = validatedData;
          }
          // Call original handler
          return await handler.apply(socket, args);
        } catch (error) {
          await this._handleValidationError(socket, event, error);
        }
      };
      return originalOn.call(socket, event, wrappedHandler);
    };
  }
  /**
   * Validate message against schema
   * @private
   */
  async _validateMessage(event, data, schema, socket) {
    const correlationId = getCorrelationId();
    const startTime = Date.now();
    try {
      // Check error rate limiting
      this._checkErrorRateLimit(socket.id);
      // Validate against schema
      const { error, value } = schema.validate(data, {
        abortEarly: false,
        allowUnknown: false,
        stripUnknown: true,
      });
      if (error) {
        const validationError = new ApiError(400, 'Validation failed', {
          details: error.details.map(detail => ({
            field: detail.path.join('.'),
            message: detail.message,
            value: detail.context?.value,
          })),
        });
        this._incrementErrorCount(socket.id);
        throw validationError;
      }
      const processingTime = Date.now() - startTime;
      safeLogger.debug('Message validation successful', {
        socketId: socket.id,
        event,
        correlationId,
        processingTime,
        dataSize: JSON.stringify(value).length,
      });
      return value;
    } catch (error) {
      const processingTime = Date.now() - startTime;
      safeLogger.error('Message validation failed', {
        error: error.message,
        socketId: socket.id,
        event,
        correlationId,
        processingTime,
      });
      throw error;
    }
  }
  /**
   * Sanitize data to prevent XSS and injection attacks
   * @private
   */
  _sanitizeData(data) {
    if (!data) return data;
    const sanitized = JSON.parse(JSON.stringify(data));
    return this._recursiveSanitize(sanitized);
  }
  /**
   * Recursively sanitize object/array
   * @private
   */
  _recursiveSanitize(obj) {
    if (Array.isArray(obj)) {
      return obj.map(item => this._recursiveSanitize(item));
    }
    if (obj && typeof obj === 'object') {
      const sanitized = {};
      for (const [key, value] of Object.entries(obj)) {
        sanitized[key] = this._recursiveSanitize(value);
      }
      return sanitized;
    }
    if (typeof obj === 'string') {
      return this._sanitizeString(obj);
    }
    return obj;
  }
  /**
   * Sanitize string to prevent XSS
   * @private
   */
  _sanitizeString(str) {
    if (typeof str !== 'string') return str;
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;')
      .trim();
  }
  /**
   * Get schema for specific event
   * @private
   */
  _getEventSchema(event) {
    // Define schemas for different events
    const schemas = {
      message: Joi.object({
        content: Joi.string().min(1).max(1000).required(),
        type: Joi.string().valid('text', 'image', 'file').optional(),
        metadata: Joi.object().optional(),
      }),
      join_room: Joi.object({
        room: Joi.string().min(1).max(100).required(),
        password: Joi.string().optional(),
      }),
      leave_room: Joi.object({
        room: Joi.string().min(1).max(100).required(),
      }),
      user_status: Joi.object({
        status: Joi.string()
          .valid('online', 'away', 'busy', 'offline')
          .required(),
        message: Joi.string().max(200).optional(),
      }),
      typing: Joi.object({
        room: Joi.string().min(1).max(100).required(),
        isTyping: Joi.boolean().required(),
      }),
      ping: Joi.object({
        timestamp: Joi.number().optional(),
      }),
      get_info: Joi.object({}),
    };
    return schemas[event];
  }
  /**
   * Handle validation errors
   * @private
   */
  async _handleValidationError(socket, event, error) {
    const correlationId = getCorrelationId();
    try {
      // Emit error to client
      socket.emit('validation_error', {
        event,
        error: error.message,
        details: error.details || [],
        timestamp: Date.now(),
        code: error.statusCode || 400,
      });
      // Log error
      safeLogger.warn('Validation error sent to client', {
        socketId: socket.id,
        event,
        error: error.message,
        correlationId,
      });
    } catch (emitError) {
      safeLogger.error('Failed to emit validation error', {
        error: emitError.message,
        originalError: error.message,
        socketId: socket.id,
        event,
        correlationId,
      });
    }
  }
  /**
   * Check error rate limiting
   * @private
   */
  _checkErrorRateLimit(socketId) {
    const now = Date.now();
    const errorCount = this.errorCounts.get(socketId) || {
      count: 0,
      resetTime: now + this.errorWindow,
    };
    // Reset counter if window has passed
    if (now > errorCount.resetTime) {
      errorCount.count = 0;
      errorCount.resetTime = now + this.errorWindow;
    }
    // Check if limit exceeded
    if (errorCount.count >= this.maxErrorsPerMinute) {
      throw new ApiError(429, 'Too many validation errors');
    }
    this.errorCounts.set(socketId, errorCount);
  }
  /**
   * Increment error count for socket
   * @private
   */
  _incrementErrorCount(socketId) {
    const errorCount = this.errorCounts.get(socketId) || {
      count: 0,
      resetTime: Date.now() + this.errorWindow,
    };
    errorCount.count++;
    this.errorCounts.set(socketId, errorCount);
  }
  /**
   * Validate IP address
   * @private
   */
  _isValidIP(ip) {
    if (!ip) return false;
    // Basic IP validation
    const ipv4Regex =
      /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return (
      ipv4Regex.test(ip) ||
      ipv6Regex.test(ip) ||
      ip === '::1' ||
      ip === 'localhost'
    );
  }
  /**
   * Clean up resources
   */
  cleanup() {
    this.validationCache.clear();
    this.errorCounts.clear();
  }
  /**
   * Get validation statistics
   */
  getStats() {
    return {
      cacheSize: this.validationCache.size,
      errorCounts: Object.fromEntries(this.errorCounts),
      maxErrorsPerMinute: this.maxErrorsPerMinute,
    };
  }
}
// Create singleton instance
const validationMiddleware = new ValidationMiddleware();
// Export middleware function
export default (socket, next) => validationMiddleware.validate(socket, next);
// Export class for direct usage
export { ValidationMiddleware };
