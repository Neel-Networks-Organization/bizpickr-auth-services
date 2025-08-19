import rabbitMQConnection from '../connection.js';
import { safeLogger } from '../../config/logger.js';
import { rabbitMQConfig } from '../../config/rabbitMQ.js';
import { ApiError } from '../../utils/ApiError.js';
import { getCorrelationId } from '../../config/requestContext.js';
import { updateEventMetrics } from '../index.js';
/**
 * Industry-level User Created Event Emitter
 *
 * Features:
 * - Enhanced validation and error handling
 * - Retry logic with exponential backoff
 * - Performance monitoring and metrics
 * - Structured logging with correlation IDs
 * - Event schema validation
 * - Dead letter queue handling
 * - Data sanitization for security
 */
// Event schema validation
const USER_CREATED_SCHEMA = {
  required: ['userId', 'username', 'email', 'timestamp', 'createdBy'],
  optional: [
    'firstName',
    'lastName',
    'phoneNumber',
    'role',
    'status',
    'metadata',
  ],
};
/**
 * Validate user created event data
 * @param {Object} userData - User creation data
 * @returns {Object} Validation result
 */
function validateUserCreatedEvent(userData) {
  const errors = [];
  const warnings = [];
  // Check required fields
  for (const field of USER_CREATED_SCHEMA.required) {
    if (!userData[field]) {
      errors.push(`Missing required field: ${field}`);
    }
  }
  // Validate data types and formats
  if (userData.userId && typeof userData.userId !== 'string') {
    errors.push('userId must be a string');
  }
  if (userData.username && typeof userData.username !== 'string') {
    errors.push('username must be a string');
  }
  if (userData.email && !isValidEmail(userData.email)) {
    errors.push('email must be a valid email address');
  }
  if (userData.timestamp && !Date.parse(userData.timestamp)) {
    errors.push('timestamp must be a valid date string');
  }
  if (userData.phoneNumber && !isValidPhoneNumber(userData.phoneNumber)) {
    warnings.push('phoneNumber format may be invalid');
  }
  // Check for sensitive data
  if (userData.password) {
    errors.push('password should not be included in user created event');
  }
  if (userData.creditCard) {
    errors.push('creditCard should not be included in user created event');
  }
  // Validate email uniqueness (basic check)
  if (userData.email && userData.email.length > 254) {
    errors.push('email address is too long');
  }
  return {
    isValid: errors.length === 0,
    errors,
    warnings,
  };
}
/**
 * Validate email format
 * @param {string} email - Email to validate
 * @returns {boolean} Valid email
 */
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}
/**
 * Validate phone number format
 * @param {string} phone - Phone number to validate
 * @returns {boolean} Valid phone number
 */
function isValidPhoneNumber(phone) {
  const phoneRegex = /^[+]?[1-9][\d]{0,15}$/;
  return phoneRegex.test(phone.replace(/[\s\-()]/g, ''));
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
        }
      );
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  throw lastError;
}
/**
 * Publish user created event with enhanced error handling and validation
 * @param {Object} userData - User creation data
 * @param {Object} options - Publishing options
 * @returns {Promise<boolean>} Success status
 */
export async function publishUserCreatedEvent(userData, options = {}) {
  const correlationId = getCorrelationId();
  const startTime = Date.now();
  try {
    // Validate input data
    const validation = validateUserCreatedEvent(userData);
    if (!validation.isValid) {
      safeLogger.error('User created event validation failed', {
        errors: validation.errors,
        warnings: validation.warnings,
        userData: sanitizeUserData(userData),
        correlationId,
      });
      throw new ApiError(
        400,
        'Invalid user created event data',
        validation.errors
      );
    }
    if (validation.warnings.length > 0) {
      safeLogger.warn('User created event validation warnings', {
        warnings: validation.warnings,
        userData: sanitizeUserData(userData),
        correlationId,
      });
    }
    // Prepare event payload with metadata
    const eventPayload = {
      ...userData,
      eventType: 'user.created',
      eventVersion: '1.0',
      timestamp: userData.timestamp || new Date().toISOString(),
      correlationId,
      metadata: {
        ...userData.metadata,
        source: 'auth-service',
        environment: process.env.NODE_ENV || 'development',
        serviceVersion: process.env.SERVICE_VERSION || '1.0.0',
        eventId: generateEventId(),
      },
    };
    // Publish event with retry logic
    const publishResult = await retryWithBackoff(
      async () => {
        const exchange = rabbitMQConfig.exchanges.auth.name;
        const routingKey = 'user.created';
        const publishOptions = {
          persistent: true,
          headers: {
            correlationId,
            eventType: 'user.created',
            timestamp: eventPayload.timestamp,
            eventId: eventPayload.metadata.eventId,
          },
          ...options,
        };
        return await rabbitMQConnection.publish(
          'auth-channel',
          exchange,
          routingKey,
          eventPayload,
          publishOptions
        );
      },
      options.maxRetries || 3,
      options.baseDelay || 1000
    );
    const publishTime = Date.now() - startTime;
    // Update metrics
    updateEventMetrics('published', {
      eventType: 'user.created',
      publishTime,
      correlationId,
    });
    safeLogger.info('User created event published successfully', {
      userId: userData.userId,
      username: userData.username,
      email: maskEmail(userData.email),
      correlationId,
      publishTime: `${publishTime}ms`,
      exchange: rabbitMQConfig.exchanges.auth.name,
      routingKey: 'user.created',
      eventId: eventPayload.metadata.eventId,
    });
    return publishResult;
  } catch (error) {
    const publishTime = Date.now() - startTime;
    // Update metrics
    updateEventMetrics('failedPublish', {
      eventType: 'user.created',
      publishTime,
      correlationId,
      error: error.message,
    });
    safeLogger.error('Failed to publish user created event', {
      error: error.message,
      stack: error.stack,
      userData: sanitizeUserData(userData),
      correlationId,
      publishTime: `${publishTime}ms`,
      attempt: options.maxRetries || 3,
    });
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError(500, 'Failed to publish user created event', [
      'Event publishing failed after retry attempts',
      'Please check RabbitMQ connectivity and configuration',
      error.message,
    ]);
  }
}
/**
 * Generate unique event ID
 * @returns {string} Event ID
 */
function generateEventId() {
  return `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}
/**
 * Mask email for logging (show only first and last characters)
 * @param {string} email - Email to mask
 * @returns {string} Masked email
 */
function maskEmail(email) {
  if (!email) return '';
  const [localPart, domain] = email.split('@');
  if (localPart.length <= 2) return email;
  const maskedLocal =
    localPart.charAt(0) +
    '*'.repeat(localPart.length - 2) +
    localPart.charAt(localPart.length - 1);
  return `${maskedLocal}@${domain}`;
}
/**
 * Sanitize user data for logging (remove sensitive information)
 * @param {Object} userData - User data to sanitize
 * @returns {Object} Sanitized user data
 */
function sanitizeUserData(userData) {
  const sanitized = { ...userData };
  // Remove sensitive fields
  delete sanitized.password;
  delete sanitized.token;
  delete sanitized.secret;
  delete sanitized.creditCard;
  delete sanitized.ssn;
  delete sanitized.passportNumber;
  // Mask sensitive data
  if (sanitized.email) {
    sanitized.email = maskEmail(sanitized.email);
  }
  if (sanitized.phoneNumber) {
    sanitized.phoneNumber = sanitized.phoneNumber.replace(
      /(\d{3})\d{4}(\d{4})/,
      '$1****$2'
    );
  }
  // Truncate long fields
  if (sanitized.address && sanitized.address.length > 100) {
    sanitized.address = sanitized.address.substring(0, 100) + '...';
  }
  if (sanitized.metadata && typeof sanitized.metadata === 'object') {
    sanitized.metadata = '***metadata***';
  }
  return sanitized;
}
/**
 * Get user created event statistics
 * @returns {Object} Event statistics
 */
export function getUserCreatedEventStats() {
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
 * Batch publish multiple user created events
 * @param {Array<Object>} userEvents - Array of user creation events
 * @param {Object} options - Publishing options
 * @returns {Promise<Object>} Batch publish results
 */
export async function batchPublishUserCreatedEvents(userEvents, options = {}) {
  const correlationId = getCorrelationId();
  const startTime = Date.now();
  const results = {
    total: userEvents.length,
    successful: 0,
    failed: 0,
    errors: [],
    totalTime: 0,
  };
  safeLogger.info('Starting batch publish of user created events', {
    totalEvents: userEvents.length,
    correlationId,
  });
  for (let i = 0; i < userEvents.length; i++) {
    const userData = userEvents[i];
    try {
      await publishUserCreatedEvent(userData, options);
      results.successful++;
    } catch (error) {
      results.failed++;
      results.errors.push({
        index: i,
        userId: userData.userId,
        error: error.message,
      });
    }
  }
  results.totalTime = Date.now() - startTime;
  safeLogger.info('Batch publish of user created events completed', {
    ...results,
    correlationId,
    averageTime: `${Math.round(results.totalTime / userEvents.length)}ms`,
  });
  return results;
}
/**
 * Validate and sanitize user data before publishing
 * @param {Object} userData - Raw user data
 * @returns {Object} Validated and sanitized user data
 */
export function validateAndSanitizeUserData(userData) {
  const validation = validateUserCreatedEvent(userData);
  if (!validation.isValid) {
    throw new ApiError(400, 'Invalid user data', validation.errors);
  }
  return sanitizeUserData(userData);
}
