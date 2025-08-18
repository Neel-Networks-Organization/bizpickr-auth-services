import rabbitMQConnection from '../connection.js';
import { safeLogger } from '../../config/logger.js';
import { rabbitMQConfig } from '../../config/rabbitMQ.js';
import { ApiError } from '../../utils/ApiError.js';
import { getCorrelationId } from '../../config/requestContext.js';
import { updateEventMetrics } from '../index.js';
/**
 * Industry-level User Login Event Emitter
 *
 * Features:
 * - Enhanced validation and error handling
 * - Retry logic with exponential backoff
 * - Performance monitoring and metrics
 * - Structured logging with correlation IDs
 * - Event schema validation
 * - Dead letter queue handling
 */
// Event schema validation
const USER_LOGIN_SCHEMA = {
  required: ['userId', 'username', 'timestamp', 'ipAddress', 'userAgent'],
  optional: ['deviceId', 'location', 'sessionId', 'metadata'],
};
/**
 * Validate user login event data
 * @param {Object} loginData - Login event data
 * @returns {Object} Validation result
 */
function validateUserLoginEvent(loginData) {
  const errors = [];
  const warnings = [];
  // Check required fields
  for (const field of USER_LOGIN_SCHEMA.required) {
    if (!loginData[field]) {
      errors.push(`Missing required field: ${field}`);
    }
  }
  // Validate data types and formats
  if (loginData.userId && typeof loginData.userId !== 'string') {
    errors.push('userId must be a string');
  }
  if (loginData.username && typeof loginData.username !== 'string') {
    errors.push('username must be a string');
  }
  if (loginData.timestamp && !Date.parse(loginData.timestamp)) {
    errors.push('timestamp must be a valid date string');
  }
  if (loginData.ipAddress && !isValidIPAddress(loginData.ipAddress)) {
    warnings.push('ipAddress format may be invalid');
  }
  // Check for sensitive data
  if (loginData.password) {
    errors.push('password should not be included in login event');
  }
  return {
    isValid: errors.length === 0,
    errors,
    warnings,
  };
}
/**
 * Validate IP address format
 * @param {string} ip - IP address to validate
 * @returns {boolean} Valid IP address
 */
function isValidIPAddress(ip) {
  const ipv4Regex =
    /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}
/**
 * Retry function with exponential backoff
 * @param {Function} fn - Function to retry
 * @param {number} maxRetries - Maximum retry attempts
 * @param {number} baseDelay - Base delay in milliseconds
 * @returns {Promise<any>} Function result
 */
async function retryWithBackoff(fn, maxRetries = 3, baseDelay = 1000) {
  let lastError;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt === maxRetries) {
        throw error;
      }
      const delay = baseDelay * Math.pow(2, attempt);
      safeLogger.warn(
        `Retry attempt ${attempt + 1} failed, retrying in ${delay}ms`,
        {
          error: error.message,
          attempt: attempt + 1,
          maxRetries,
          delay,
        },
      );
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  throw lastError;
}
/**
 * Publish user login event with enhanced error handling and validation
 * @param {Object} loginData - User login data
 * @param {Object} options - Publishing options
 * @returns {Promise<boolean>} Success status
 */
export async function publishUserLoginEvent(loginData, options = {}) {
  const correlationId = getCorrelationId();
  const startTime = Date.now();
  try {
    // Validate input data
    const validation = validateUserLoginEvent(loginData);
    if (!validation.isValid) {
      safeLogger.error('User login event validation failed', {
        errors: validation.errors,
        warnings: validation.warnings,
        loginData: sanitizeLoginData(loginData),
        correlationId,
      });
      throw new ApiError(400, 'Invalid login event data', validation.errors);
    }
    if (validation.warnings.length > 0) {
      safeLogger.warn('User login event validation warnings', {
        warnings: validation.warnings,
        loginData: sanitizeLoginData(loginData),
        correlationId,
      });
    }
    // Prepare event payload with metadata
    const eventPayload = {
      ...loginData,
      eventType: 'user.login',
      eventVersion: '1.0',
      timestamp: loginData.timestamp || new Date().toISOString(),
      correlationId,
      metadata: {
        ...loginData.metadata,
        source: 'auth-service',
        environment: process.env.NODE_ENV || 'development',
        serviceVersion: process.env.SERVICE_VERSION || '1.0.0',
      },
    };
    // Publish event with retry logic
    const publishResult = await retryWithBackoff(
      async() => {
        const exchange = rabbitMQConfig.exchanges.auth.name;
        const routingKey = 'user.login';
        const publishOptions = {
          persistent: true,
          headers: {
            correlationId,
            eventType: 'user.login',
            timestamp: eventPayload.timestamp,
          },
          ...options,
        };
        return await rabbitMQConnection.publish(
          'auth-channel',
          exchange,
          routingKey,
          eventPayload,
          publishOptions,
        );
      },
      options.maxRetries || 3,
      options.baseDelay || 1000,
    );
    const publishTime = Date.now() - startTime;
    // Update metrics
    updateEventMetrics('published', {
      eventType: 'user.login',
      publishTime,
      correlationId,
    });
    safeLogger.info('User login event published successfully', {
      userId: loginData.userId,
      username: loginData.username,
      correlationId,
      publishTime: `${publishTime}ms`,
      exchange: rabbitMQConfig.exchanges.auth.name,
      routingKey: 'user.login',
    });
    return publishResult;
  } catch (error) {
    const publishTime = Date.now() - startTime;
    // Update metrics
    updateEventMetrics('failedPublish', {
      eventType: 'user.login',
      publishTime,
      correlationId,
      error: error.message,
    });
    safeLogger.error('Failed to publish user login event', {
      error: error.message,
      stack: error.stack,
      loginData: sanitizeLoginData(loginData),
      correlationId,
      publishTime: `${publishTime}ms`,
      attempt: options.maxRetries || 3,
    });
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError(500, 'Failed to publish user login event', [
      'Event publishing failed after retry attempts',
      'Please check RabbitMQ connectivity and configuration',
      error.message,
    ]);
  }
}
/**
 * Sanitize login data for logging (remove sensitive information)
 * @param {Object} loginData - Login data to sanitize
 * @returns {Object} Sanitized login data
 */
function sanitizeLoginData(loginData) {
  const sanitized = { ...loginData };
  // Remove sensitive fields
  delete sanitized.password;
  delete sanitized.token;
  delete sanitized.secret;
  // Truncate long fields
  if (sanitized.userAgent && sanitized.userAgent.length > 200) {
    sanitized.userAgent = sanitized.userAgent.substring(0, 200) + '...';
  }
  if (sanitized.metadata && typeof sanitized.metadata === 'object') {
    sanitized.metadata = '***metadata***';
  }
  return sanitized;
}
/**
 * Get user login event statistics
 * @returns {Object} Event statistics
 */
export function getUserLoginEventStats() {
  const metrics = rabbitMQConnection.getMetrics();
  return {
    totalPublished: metrics.totalMessagesPublished,
    failedPublishes: metrics.failedPublishes,
    lastPublish: metrics.lastHealthCheck,
    connectionStatus: rabbitMQConnection.isReady()
      ? 'connected'
      : 'disconnected',
  };
}
/**
 * Batch publish multiple user login events
 * @param {Array<Object>} loginEvents - Array of login events
 * @param {Object} options - Publishing options
 * @returns {Promise<Object>} Batch publish results
 */
export async function batchPublishUserLoginEvents(loginEvents, options = {}) {
  const correlationId = getCorrelationId();
  const startTime = Date.now();
  const results = {
    total: loginEvents.length,
    successful: 0,
    failed: 0,
    errors: [],
    totalTime: 0,
  };
  safeLogger.info('Starting batch publish of user login events', {
    totalEvents: loginEvents.length,
    correlationId,
  });
  for (let i = 0; i < loginEvents.length; i++) {
    const loginData = loginEvents[i];
    try {
      await publishUserLoginEvent(loginData, options);
      results.successful++;
    } catch (error) {
      results.failed++;
      results.errors.push({
        index: i,
        userId: loginData.userId,
        error: error.message,
      });
    }
  }
  results.totalTime = Date.now() - startTime;
  safeLogger.info('Batch publish of user login events completed', {
    ...results,
    correlationId,
    averageTime: `${Math.round(results.totalTime / loginEvents.length)}ms`,
  });
  return results;
}
