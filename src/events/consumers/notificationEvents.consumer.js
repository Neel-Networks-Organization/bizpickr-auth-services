import { safeLogger } from '../../config/logger.js';
import rabbitMQConnection from '../connection.js';

/**
 * Notification Events Consumer
 * Receives notification-related events from other microservices
 */

let notificationConsumer = null;
let isConsuming = false;

/**
 * Start consuming notification events
 * @param {Object} options - Consumer options
 */
export async function startNotificationEventsConsumer(options = {}) {
  if (isConsuming) {
    safeLogger.warn('Notification events consumer is already running');
    return;
  }

  try {
    safeLogger.info('Starting notification events consumer...');

    const channel = await rabbitMQConnection.getChannel(
      'notification-consumer',
    );

    // Ensure queue exists
    await channel.assertQueue('notification.events', {
      durable: true,
      autoDelete: false,
    });

    // Bind to auth events exchange
    await channel.bindQueue(
      'notification.events',
      'events_exchange',
      'notification.*',
    ); // Fixed: Use correct exchange name

    // Start consuming
    notificationConsumer = await channel.consume(
      'notification.events',
      async message => {
        if (!message) return;

        try {
          const eventData = JSON.parse(message.content.toString());
          const { eventType, eventData: payload, metadata } = eventData;

          safeLogger.info('Received notification event', {
            eventType,
            correlationId: metadata?.correlationId,
            source: metadata?.source,
          });

          // Process different notification event types
          await processNotificationEvent(eventType, payload, metadata);

          // Acknowledge message
          channel.ack(message);

          safeLogger.info('Notification event processed successfully', {
            eventType,
            correlationId: metadata?.correlationId,
          });
        } catch (error) {
          safeLogger.error('Failed to process notification event', {
            error: error.message,
            eventData: message.content.toString(),
          });

          // Reject message and requeue
          channel.nack(message, false, true);
        }
      },
    );

    isConsuming = true;
    safeLogger.info('Notification events consumer started successfully');
  } catch (error) {
    safeLogger.error('Failed to start notification events consumer', {
      error: error.message,
      stack: error.stack,
    });
    throw error;
  }
}

/**
 * Process different notification event types
 * @param {string} eventType - Type of notification event
 * @param {Object} payload - Event payload
 * @param {Object} metadata - Event metadata
 */
async function processNotificationEvent(eventType, payload, metadata) {
  try {
    switch (eventType) {
    case 'notification.sent':
      await handleNotificationSent(payload, metadata);
      break;

    case 'notification.delivered':
      await handleNotificationDelivered(payload, metadata);
      break;

    case 'notification.failed':
      await handleNotificationFailed(payload, metadata);
      break;

    case 'notification.read':
      await handleNotificationRead(payload, metadata);
      break;

    case 'notification.action_taken':
      await handleNotificationActionTaken(payload, metadata);
      break;

    default:
      safeLogger.warn('Unknown notification event type', {
        eventType,
        correlationId: metadata?.correlationId,
      });
    }
  } catch (error) {
    safeLogger.error('Error processing notification event', {
      eventType,
      error: error.message,
      correlationId: metadata?.correlationId,
    });
    throw error;
  }
}

/**
 * Handle notification sent event
 * @param {Object} payload - Notification sent data
 * @param {Object} metadata - Event metadata
 */
async function handleNotificationSent(payload, metadata) {
  const { notificationId, userId, notificationType, sentAt, channel } = payload;

  safeLogger.info('Notification sent successfully', {
    notificationId,
    userId,
    notificationType,
    channel,
    sentAt,
    correlationId: metadata?.correlationId,
  });

  // TODO: Update notification status, log activity, etc.
}

/**
 * Handle notification delivered event
 * @param {Object} payload - Notification delivered data
 * @param {Object} metadata - Event metadata
 */
async function handleNotificationDelivered(payload, metadata) {
  const { notificationId, userId, notificationType, deliveredAt, channel } =
    payload;

  safeLogger.info('Notification delivered successfully', {
    notificationId,
    userId,
    notificationType,
    channel,
    deliveredAt,
    correlationId: metadata?.correlationId,
  });

  // TODO: Update delivery status, trigger follow-up actions, etc.
}

/**
 * Handle notification failed event
 * @param {Object} payload - Notification failed data
 * @param {Object} metadata - Event metadata
 */
async function handleNotificationFailed(payload, metadata) {
  const {
    notificationId,
    userId,
    notificationType,
    failedAt,
    reason,
    channel,
  } = payload;

  safeLogger.error('Notification failed to send', {
    notificationId,
    userId,
    notificationType,
    channel,
    failedAt,
    reason,
    correlationId: metadata?.correlationId,
  });

  // TODO: Handle failed notification, retry logic, user notification, etc.
}

/**
 * Handle notification read event
 * @param {Object} payload - Notification read data
 * @param {Object} metadata - Event metadata
 */
async function handleNotificationRead(payload, metadata) {
  const { notificationId, userId, notificationType, readAt, channel } = payload;

  safeLogger.info('Notification read', {
    notificationId,
    userId,
    notificationType,
    channel,
    readAt,
    correlationId: metadata?.correlationId,
  });

  // TODO: Track engagement, update analytics, etc.
}

/**
 * Handle notification action taken event
 * @param {Object} payload - Notification action data
 * @param {Object} metadata - Event metadata
 */
async function handleNotificationActionTaken(payload, metadata) {
  const {
    notificationId,
    userId,
    notificationType,
    actionTaken,
    actionTime,
    channel,
  } = payload;

  safeLogger.info('Notification action taken', {
    notificationId,
    userId,
    notificationType,
    actionTaken,
    channel,
    actionTime,
    correlationId: metadata?.correlationId,
  });

  // TODO: Track user actions, update analytics, trigger workflows, etc.
}

/**
 * Stop notification events consumer
 */
export async function stopNotificationEventsConsumer() {
  if (!isConsuming || !notificationConsumer) {
    safeLogger.warn('Notification events consumer is not running');
    return;
  }

  try {
    safeLogger.info('Stopping notification events consumer...');

    const channel = await rabbitMQConnection.getChannel(
      'notification-consumer',
    );
    await channel.cancel(notificationConsumer.consumerTag);

    isConsuming = false;
    notificationConsumer = null;

    safeLogger.info('Notification events consumer stopped successfully');
  } catch (error) {
    safeLogger.error('Failed to stop notification events consumer', {
      error: error.message,
      stack: error.stack,
    });
    throw error;
  }
}

/**
 * Check if notification events consumer is running
 * @returns {boolean} Consumer status
 */
export function isNotificationEventsConsumerRunning() {
  return isConsuming;
}

/**
 * Get notification events consumer status
 * @returns {Object} Consumer status
 */
export function getNotificationEventsConsumerStatus() {
  return {
    isRunning: isConsuming,
    consumerTag: notificationConsumer?.consumerTag,
    queueName: 'notification.events',
  };
}
