/**
 * User Created Consumer - Handles user creation events
 *
 * This consumer processes user creation events and integrates with:
 * - Notification Service (for welcome notifications)
 * - Email Service (for welcome emails)
 * - User Service (for user profile creation)
 */
import rabbitMQConnection from '../connection.js';
import { safeLogger } from '../../config/logger.js';
import { getCorrelationId } from '../../config/requestContext.js';
import { ApiError } from '../../utils/ApiError.js';
import { MESSAGE_PRIORITIES } from '../../config/rabbitMQ.js';

// Consumer configuration
const CONSUMER_CONFIG = {
  queueName: 'user_created_queue',
  consumerTag: 'user-created-consumer',
  prefetchCount: 5,
  retryAttempts: 3,
  retryDelay: 5000,
};

// Event processing metrics
const processingMetrics = {
  totalProcessed: 0,
  successfulProcessed: 0,
  failedProcessed: 0,
  lastProcessedAt: null,
  averageProcessingTime: 0,
};

/**
 * Process user created event (triggered on first login)
 * @param {Object} eventData - User creation event data
 * @returns {Promise<Object>} Processing result
 */
async function processUserCreatedEvent(eventData) {
  const correlationId = getCorrelationId();
  const startTime = Date.now();

  try {
    const {
      userId,
      email,
      fullName,
      type,
      role,
      phone,
      ipAddress,
      userAgent,
      timestamp,
    } = eventData;

    safeLogger.info('Processing user created event (first login)', {
      userId,
      email,
      type,
      role,
      correlationId,
    });

    // Validate required fields
    if (!userId || !email || !fullName) {
      throw new Error('Missing required fields in user created event');
    }

    // TODO: Integrate with Notification Service
    // This would typically involve:
    // 1. Sending welcome notification (on first login)
    // 2. Setting up notification preferences
    // 3. Creating notification channels

    // TODO: Integrate with Email Service
    // This would typically involve:
    // 1. Sending welcome email (on first login)
    // 2. Setting up email preferences
    // 3. Creating email templates

    // For now, we'll log the event and simulate processing
    await simulateUserServiceIntegration(userId, email, fullName, type, role);
    await simulateNotificationServiceIntegration(userId, email, fullName, type);
    await simulateEmailServiceIntegration(userId, email, fullName, type);

    const processingTime = Date.now() - startTime;
    updateProcessingMetrics('success', processingTime);

    safeLogger.info('User created event processed successfully (first login)', {
      userId,
      email,
      processingTime: `${processingTime}ms`,
      correlationId,
    });

    return {
      success: true,
      userId,
      email,
      processingTime,
    };
  } catch (error) {
    const processingTime = Date.now() - startTime;
    updateProcessingMetrics('failure', processingTime);

    safeLogger.error('Failed to process user created event', {
      error: error.message,
      stack: error.stack,
      eventData,
      processingTime: `${processingTime}ms`,
      correlationId,
    });

    throw new ApiError(500, 'Failed to process user created event', [
      error.message,
    ]);
  }
}

/**
 * Simulate User Service integration
 * @param {string} userId - User ID
 * @param {string} email - User email
 * @param {string} fullName - User full name
 * @param {string} type - User type
 * @param {string} role - User role
 * @returns {Promise<void>}
 */
async function simulateUserServiceIntegration(
  userId,
  email,
  fullName,
  type,
  role
) {
  // Simulate API call to user service
  await new Promise(resolve => setTimeout(resolve, 100));

  safeLogger.info('User service integration simulated', {
    userId,
    email,
    type,
    role,
    service: 'user-service',
  });
}

/**
 * Simulate Notification Service integration
 * @param {string} userId - User ID
 * @param {string} email - User email
 * @param {string} fullName - User full name
 * @param {string} type - User type
 * @returns {Promise<void>}
 */
async function simulateNotificationServiceIntegration(
  userId,
  email,
  fullName,
  type
) {
  // Simulate API call to notification service
  await new Promise(resolve => setTimeout(resolve, 150));

  safeLogger.info('Notification service integration simulated', {
    userId,
    email,
    type,
    service: 'notification-service',
    notificationType: 'welcome',
  });
}

/**
 * Simulate Email Service integration
 * @param {string} userId - User ID
 * @param {string} email - User email
 * @param {string} fullName - User full name
 * @param {string} type - User type
 * @returns {Promise<void>}
 */
async function simulateEmailServiceIntegration(userId, email, fullName, type) {
  // Simulate API call to email service
  await new Promise(resolve => setTimeout(resolve, 200));

  safeLogger.info('Email service integration simulated', {
    userId,
    email,
    type,
    service: 'email-service',
    emailType: 'welcome',
  });
}

/**
 * Update processing metrics
 * @param {string} status - Processing status (success/failure)
 * @param {number} processingTime - Processing time in milliseconds
 */
function updateProcessingMetrics(status, processingTime) {
  processingMetrics.totalProcessed++;
  processingMetrics.lastProcessedAt = new Date().toISOString();

  if (status === 'success') {
    processingMetrics.successfulProcessed++;
  } else {
    processingMetrics.failedProcessed++;
  }

  // Update average processing time
  const currentAvg = processingMetrics.averageProcessingTime;
  const totalProcessed = processingMetrics.totalProcessed;
  processingMetrics.averageProcessingTime =
    (currentAvg * (totalProcessed - 1) + processingTime) / totalProcessed;
}

/**
 * Get consumer metrics
 * @returns {Object} Consumer metrics
 */
export function getUserCreatedConsumerMetrics() {
  return {
    ...processingMetrics,
    successRate:
      processingMetrics.totalProcessed > 0
        ? (processingMetrics.successfulProcessed /
            processingMetrics.totalProcessed) *
          100
        : 0,
    failureRate:
      processingMetrics.totalProcessed > 0
        ? (processingMetrics.failedProcessed /
            processingMetrics.totalProcessed) *
          100
        : 0,
  };
}

/**
 * Start user created consumer
 * @param {Object} options - Consumer options
 * @returns {Promise<void>}
 */
export async function startUserCreatedConsumer(options = {}) {
  const correlationId = getCorrelationId();

  try {
    safeLogger.info('Starting user created consumer', {
      queueName: CONSUMER_CONFIG.queueName,
      consumerTag: CONSUMER_CONFIG.consumerTag,
      correlationId,
    });

    // Get RabbitMQ channel
    const channel = await rabbitMQConnection.getChannel(
      'user-created-consumer'
    );

    // Set prefetch
    await channel.prefetch(CONSUMER_CONFIG.prefetchCount);

    // Start consuming messages
    await channel.consume(
      CONSUMER_CONFIG.queueName,
      async message => {
        if (!message) {
          safeLogger.warn('Received null message from queue');
          return;
        }

        const correlationId =
          message.properties.headers?.correlationId || getCorrelationId();

        try {
          // Parse message content
          const eventData = JSON.parse(message.content.toString());

          safeLogger.debug('Received user created event', {
            userId: eventData.userId,
            email: eventData.email,
            correlationId,
          });

          // Process the event
          await processUserCreatedEvent(eventData);

          // Acknowledge message
          channel.ack(message);

          safeLogger.debug('User created event acknowledged', {
            userId: eventData.userId,
            correlationId,
          });
        } catch (error) {
          safeLogger.error('Failed to process user created message', {
            error: error.message,
            stack: error.stack,
            correlationId,
          });

          // Reject message and requeue if retry attempts not exceeded
          const retryCount = message.properties.headers?.retryCount || 0;

          if (retryCount < CONSUMER_CONFIG.retryAttempts) {
            // Increment retry count and requeue
            message.properties.headers = {
              ...message.properties.headers,
              retryCount: retryCount + 1,
            };

            channel.nack(message, false, true);

            safeLogger.warn('User created message requeued for retry', {
              retryCount: retryCount + 1,
              maxRetries: CONSUMER_CONFIG.retryAttempts,
              correlationId,
            });
          } else {
            // Reject message without requeuing (send to dead letter queue)
            channel.nack(message, false, false);

            safeLogger.error('User created message sent to dead letter queue', {
              retryCount,
              maxRetries: CONSUMER_CONFIG.retryAttempts,
              correlationId,
            });
          }
        }
      },
      {
        consumerTag: CONSUMER_CONFIG.consumerTag,
        noAck: false,
      }
    );

    safeLogger.info('User created consumer started successfully', {
      queueName: CONSUMER_CONFIG.queueName,
      consumerTag: CONSUMER_CONFIG.consumerTag,
      prefetchCount: CONSUMER_CONFIG.prefetchCount,
      correlationId,
    });
  } catch (error) {
    safeLogger.error('Failed to start user created consumer', {
      error: error.message,
      stack: error.stack,
      queueName: CONSUMER_CONFIG.queueName,
      correlationId,
    });
    throw new ApiError(500, 'Failed to start user created consumer', [
      error.message,
    ]);
  }
}

/**
 * Stop user created consumer
 * @returns {Promise<void>}
 */
export async function stopUserCreatedConsumer() {
  const correlationId = getCorrelationId();

  try {
    const channel = await rabbitMQConnection.createChannel(
      'user-created-consumer-stop'
    );
    await channel.cancel(CONSUMER_CONFIG.consumerTag);

    safeLogger.info('User created consumer stopped successfully', {
      consumerTag: CONSUMER_CONFIG.consumerTag,
      correlationId,
    });
  } catch (error) {
    safeLogger.error('Failed to stop user created consumer', {
      error: error.message,
      consumerTag: CONSUMER_CONFIG.consumerTag,
      correlationId,
    });
    throw error;
  }
}
