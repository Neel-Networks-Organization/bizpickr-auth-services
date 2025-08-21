import { safeLogger } from '../../config/logger.js';
import rabbitMQConnection from '../connection.js';

/**
 * Email Events Consumer
 * Receives email-related events from other microservices
 */

let emailConsumer = null;
let isConsuming = false;

/**
 * Start consuming email events
 * @param {Object} options - Consumer options
 */
export async function startEmailEventsConsumer(options = {}) {
  if (isConsuming) {
    safeLogger.warn('Email events consumer is already running');
    return;
  }

  try {
    safeLogger.info('Starting email events consumer...');

    const channel = await rabbitMQConnection.getChannel('email-consumer');

    // Ensure queue exists
    await channel.assertQueue('email.events', {
      durable: true,
      autoDelete: false,
    });

    // Bind to auth events exchange
    await channel.bindQueue('email.events', 'events_exchange', 'email.*'); // Fixed: Use correct exchange name

    // Start consuming
    emailConsumer = await channel.consume('email.events', async message => {
      if (!message) return;

      try {
        const eventData = JSON.parse(message.content.toString());
        const { eventType, eventData: payload, metadata } = eventData;

        safeLogger.info('Received email event', {
          eventType,
          correlationId: metadata?.correlationId,
          source: metadata?.source,
        });

        // Process different email event types
        await processEmailEvent(eventType, payload, metadata);

        // Acknowledge message
        channel.ack(message);

        safeLogger.info('Email event processed successfully', {
          eventType,
          correlationId: metadata?.correlationId,
        });
      } catch (error) {
        safeLogger.error('Failed to process email event', {
          error: error.message,
          eventData: message.content.toString(),
        });

        // Reject message and requeue
        channel.nack(message, false, true);
      }
    });

    isConsuming = true;
    safeLogger.info('Email events consumer started successfully');
  } catch (error) {
    safeLogger.error('Failed to start email events consumer', {
      error: error.message,
      stack: error.stack,
    });
    throw error;
  }
}

/**
 * Process different email event types
 * @param {string} eventType - Type of email event
 * @param {Object} payload - Event payload
 * @param {Object} metadata - Event metadata
 */
async function processEmailEvent(eventType, payload, metadata) {
  try {
    switch (eventType) {
    case 'email.sent':
      await handleEmailSent(payload, metadata);
      break;

    case 'email.delivered':
      await handleEmailDelivered(payload, metadata);
      break;

    case 'email.failed':
      await handleEmailFailed(payload, metadata);
      break;

    case 'email.bounced':
      await handleEmailBounced(payload, metadata);
      break;

    case 'email.opened':
      await handleEmailOpened(payload, metadata);
      break;

    case 'email.clicked':
      await handleEmailClicked(payload, metadata);
      break;

    default:
      safeLogger.warn('Unknown email event type', {
        eventType,
        correlationId: metadata?.correlationId,
      });
    }
  } catch (error) {
    safeLogger.error('Error processing email event', {
      eventType,
      error: error.message,
      correlationId: metadata?.correlationId,
    });
    throw error;
  }
}

/**
 * Handle email sent event
 * @param {Object} payload - Email sent data
 * @param {Object} metadata - Event metadata
 */
async function handleEmailSent(payload, metadata) {
  const { emailId, userId, emailType, sentAt } = payload;

  safeLogger.info('Email sent successfully', {
    emailId,
    userId,
    emailType,
    sentAt,
    correlationId: metadata?.correlationId,
  });

  // TODO: Update email verification status, log email activity, etc.
  // This is where you'd integrate with your email verification system
}

/**
 * Handle email delivered event
 * @param {Object} payload - Email delivered data
 * @param {Object} metadata - Event metadata
 */
async function handleEmailDelivered(payload, metadata) {
  const { emailId, userId, emailType, deliveredAt } = payload;

  safeLogger.info('Email delivered successfully', {
    emailId,
    userId,
    emailType,
    deliveredAt,
    correlationId: metadata?.correlationId,
  });

  // TODO: Update delivery status, trigger follow-up actions, etc.
}

/**
 * Handle email failed event
 * @param {Object} payload - Email failed data
 * @param {Object} metadata - Event metadata
 */
async function handleEmailFailed(payload, metadata) {
  const { emailId, userId, emailType, failedAt, reason } = payload;

  safeLogger.error('Email failed to send', {
    emailId,
    userId,
    emailType,
    failedAt,
    reason,
    correlationId: metadata?.correlationId,
  });

  // TODO: Handle failed email, retry logic, user notification, etc.
}

/**
 * Handle email bounced event
 * @param {Object} payload - Email bounced data
 * @param {Object} metadata - Event metadata
 */
async function handleEmailBounced(payload, metadata) {
  const { emailId, userId, emailType, bouncedAt, bounceType, reason } = payload;

  safeLogger.warn('Email bounced', {
    emailId,
    userId,
    emailType,
    bouncedAt,
    bounceType,
    reason,
    correlationId: metadata?.correlationId,
  });

  // TODO: Handle bounced email, update user status, etc.
}

/**
 * Handle email opened event
 * @param {Object} payload - Email opened data
 * @param {Object} metadata - Event metadata
 */
async function handleEmailOpened(payload, metadata) {
  const { emailId, userId, emailType, openedAt, ipAddress, userAgent } =
    payload;

  safeLogger.info('Email opened', {
    emailId,
    userId,
    emailType,
    openedAt,
    ipAddress,
    userAgent,
    correlationId: metadata?.correlationId,
  });

  // TODO: Track email engagement, update analytics, etc.
}

/**
 * Handle email clicked event
 * @param {Object} payload - Email clicked data
 * @param {Object} metadata - Event metadata
 */
async function handleEmailClicked(payload, metadata) {
  const {
    emailId,
    userId,
    emailType,
    clickedAt,
    linkUrl,
    ipAddress,
    userAgent,
  } = payload;

  safeLogger.info('Email link clicked', {
    emailId,
    userId,
    emailType,
    clickedAt,
    linkUrl,
    ipAddress,
    userAgent,
    correlationId: metadata?.correlationId,
  });

  // TODO: Track link clicks, update user engagement, etc.
}

/**
 * Stop email events consumer
 */
export async function stopEmailEventsConsumer() {
  if (!isConsuming || !emailConsumer) {
    safeLogger.warn('Email events consumer is not running');
    return;
  }

  try {
    safeLogger.info('Stopping email events consumer...');

    const channel = await rabbitMQConnection.getChannel('email-consumer');
    await channel.cancel(emailConsumer.consumerTag);

    isConsuming = false;
    emailConsumer = null;

    safeLogger.info('Email events consumer stopped successfully');
  } catch (error) {
    safeLogger.error('Failed to stop email events consumer', {
      error: error.message,
      stack: error.stack,
    });
    throw error;
  }
}

/**
 * Check if email events consumer is running
 * @returns {boolean} Consumer status
 */
export function isEmailEventsConsumerRunning() {
  return isConsuming;
}

/**
 * Get email events consumer status
 * @returns {Object} Consumer status
 */
export function getEmailEventsConsumerStatus() {
  return {
    isRunning: isConsuming,
    consumerTag: emailConsumer?.consumerTag,
    queueName: 'email.events',
  };
}
