import { safeLogger } from '../../config/logger.js';
import rabbitMQConnection from '../connection.js';

/**
 * User Events Consumer
 * Receives user-related events from userService
 */

let userConsumer = null;
let isConsuming = false;

/**
 * Start consuming user events
 * @param {Object} options - Consumer options
 */
export async function startUserEventsConsumer(options = {}) {
  if (isConsuming) {
    safeLogger.warn('User events consumer is already running');
    return;
  }

  try {
    safeLogger.info('Starting user events consumer...');

    const channel = await rabbitMQConnection.getChannel('user-consumer');

    // Ensure queue exists
    await channel.assertQueue('user.events', {
      durable: true,
      autoDelete: false,
    });

    // Bind to auth events exchange
    await channel.bindQueue('user.events', 'events_exchange', 'user.*'); // Fixed: Use correct exchange name

    // Start consuming
    userConsumer = await channel.consume('user.events', async message => {
      if (!message) return;

      try {
        const eventData = JSON.parse(message.content.toString());
        const { eventType, eventData: payload, metadata } = eventData;

        safeLogger.info('Received user event', {
          eventType,
          correlationId: metadata?.correlationId,
          source: metadata?.source,
        });

        // Process different user event types
        await processUserEvent(eventType, payload, metadata);

        // Acknowledge message
        channel.ack(message);

        safeLogger.info('User event processed successfully', {
          eventType,
          correlationId: metadata?.correlationId,
        });
      } catch (error) {
        safeLogger.error('Failed to process user event', {
          error: error.message,
          eventData: message.content.toString(),
        });

        // Reject message and requeue
        channel.nack(message, false, true);
      }
    });

    isConsuming = true;
    safeLogger.info('User events consumer started successfully');
  } catch (error) {
    safeLogger.error('Failed to start user events consumer', {
      error: error.message,
      stack: error.stack,
    });
    throw error;
  }
}

/**
 * Process different user event types
 * @param {string} eventType - Type of user event
 * @param {Object} payload - Event payload
 * @param {Object} metadata - Event metadata
 */
async function processUserEvent(eventType, payload, metadata) {
  try {
    switch (eventType) {
    case 'user.profile_updated':
      await handleUserProfileUpdated(payload, metadata);
      break;

    case 'user.preferences_changed':
      await handleUserPreferencesChanged(payload, metadata);
      break;

    case 'user.status_changed':
      await handleUserStatusChanged(payload, metadata);
      break;

    case 'user.role_changed':
      await handleUserRoleChanged(payload, metadata);
      break;

    case 'user.deleted':
      await handleUserDeleted(payload, metadata);
      break;

    default:
      safeLogger.warn('Unknown user event type', {
        eventType,
        correlationId: metadata?.correlationId,
      });
    }
  } catch (error) {
    safeLogger.error('Error processing user event', {
      eventType,
      error: error.message,
      correlationId: metadata?.correlationId,
    });
    throw error;
  }
}

/**
 * Handle user profile updated event
 * @param {Object} payload - User profile data
 * @param {Object} metadata - Event metadata
 */
async function handleUserProfileUpdated(payload, metadata) {
  const { userId, email, fullName, updatedFields, updatedAt } = payload;

  safeLogger.info('User profile updated', {
    userId,
    email,
    updatedFields,
    updatedAt,
    correlationId: metadata?.correlationId,
  });

  // TODO: Update auth service user data, sync changes, etc.
  // This is where you'd sync profile changes between services
}

/**
 * Handle user preferences changed event
 * @param {Object} payload - User preferences data
 * @param {Object} metadata - Event metadata
 */
async function handleUserPreferencesChanged(payload, metadata) {
  const { userId, email, preferences, changedAt } = payload;

  safeLogger.info('User preferences changed', {
    userId,
    email,
    preferences,
    changedAt,
    correlationId: metadata?.correlationId,
  });

  // TODO: Update auth service preferences, sync changes, etc.
}

/**
 * Handle user status changed event
 * @param {Object} payload - User status data
 * @param {Object} metadata - Event metadata
 */
async function handleUserStatusChanged(payload, metadata) {
  const { userId, email, oldStatus, newStatus, reason, changedAt } = payload;

  safeLogger.info('User status changed', {
    userId,
    email,
    oldStatus,
    newStatus,
    reason,
    changedAt,
    correlationId: metadata?.correlationId,
  });

  // TODO: Update auth service user status, handle status changes, etc.
  // This is critical for auth service to stay in sync
}

/**
 * Handle user role changed event
 * @param {Object} payload - User role data
 * @param {Object} metadata - Event metadata
 */
async function handleUserRoleChanged(payload, metadata) {
  const { userId, email, oldRole, newRole, changedAt } = payload;

  safeLogger.info('User role changed', {
    userId,
    email,
    oldRole,
    newRole,
    changedAt,
    correlationId: metadata?.correlationId,
  });

  // TODO: Update auth service user role, handle permission changes, etc.
  // This affects JWT tokens and authentication
}

/**
 * Handle user deleted event
 * @param {Object} payload - User deletion data
 * @param {Object} metadata - Event metadata
 */
async function handleUserDeleted(payload, metadata) {
  const { userId, email, deletedAt, reason } = payload;

  safeLogger.info('User deleted', {
    userId,
    email,
    deletedAt,
    reason,
    correlationId: metadata?.correlationId,
  });

  // TODO: Clean up auth service data, revoke all sessions, etc.
  // This is critical for security
}

/**
 * Stop user events consumer
 */
export async function stopUserEventsConsumer() {
  if (!isConsuming || !userConsumer) {
    safeLogger.warn('User events consumer is not running');
    return;
  }

  try {
    safeLogger.info('Stopping user events consumer...');

    const channel = await rabbitMQConnection.getChannel('user-consumer');
    await channel.cancel(userConsumer.consumerTag);

    isConsuming = false;
    userConsumer = null;

    safeLogger.info('User events consumer stopped successfully');
  } catch (error) {
    safeLogger.error('Failed to stop user events consumer', {
      error: error.message,
      stack: error.stack,
    });
    throw error;
  }
}

/**
 * Check if user events consumer is running
 * @returns {boolean} Consumer status
 */
export function isUserEventsConsumerRunning() {
  return isConsuming;
}

/**
 * Get user events consumer status
 * @returns {Object} Consumer status
 */
export function getUserEventsConsumerStatus() {
  return {
    isRunning: isConsuming,
    consumerTag: userConsumer?.consumerTag,
    queueName: 'user.events',
  };
}
