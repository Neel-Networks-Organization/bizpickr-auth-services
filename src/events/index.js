import rabbitMQConnection from './connection.js';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import {
  startEmailEventsConsumer,
  stopEmailEventsConsumer,
} from './consumers/emailEvents.consumer.js';
import {
  startNotificationEventsConsumer,
  stopNotificationEventsConsumer,
} from './consumers/notificationEvents.consumer.js';
import {
  startUserEventsConsumer,
  stopUserEventsConsumer,
} from './consumers/userEvents.consumer.js';

/**
 * Simple Event System Manager
 * Essential RabbitMQ event publishing and consuming
 */

// Simple event tracking
const eventStatus = {
  isHealthy: true,
  lastEventTime: null,
};

// Consumer registry
const consumerRegistry = new Map();

/**
 * Publish event to RabbitMQ
 * @param {string} eventType - Event type (e.g., "user.registered")
 * @param {Object} eventData - Event data payload
 * @param {Object} options - Publishing options
 * @returns {Promise<boolean>} Success status
 */
export async function publishEvent(eventType, eventData = {}, options = {}) {
  const correlationId = getCorrelationId();
  const startTime = Date.now();

  try {
    // Validate inputs
    if (!eventType || typeof eventType !== 'string') {
      throw new Error('Event type is required and must be a string');
    }

    // Check if RabbitMQ is ready
    if (!rabbitMQConnection.isHealthy()) {
      throw new Error('RabbitMQ connection is not ready');
    }

    // Prepare event payload
    const eventPayload = {
      eventType,
      eventData,
      metadata: {
        correlationId,
        timestamp: new Date().toISOString(),
        source: 'auth-service',
        version: '1.0.0',
      },
      ...options,
    };

    // Get channel
    const channel = await rabbitMQConnection.getChannel();

    // Ensure exchange exists
    const exchangeName = 'events_exchange'; // Fixed: Use correct exchange name from RabbitMQ config
    await channel.assertExchange(exchangeName, 'topic', {
      durable: true,
      autoDelete: false,
    });

    // Publish event
    const routingKey = eventType.replace(/\./g, '_');
    const message = JSON.stringify(eventPayload);

    const published = channel.publish(
      exchangeName,
      routingKey,
      Buffer.from(message),
      {
        persistent: true,
        contentType: 'application/json',
        headers: {
          correlationId,
          eventType,
          timestamp: new Date().toISOString(),
        },
      }
    );

    if (!published) {
      throw new Error('Failed to publish event to RabbitMQ');
    }

    // Update status
    eventStatus.lastEventTime = new Date().toISOString();

    safeLogger.info('Event published successfully', {
      eventType,
      correlationId,
      routingKey,
    });

    return true;
  } catch (error) {
    // Update status
    eventStatus.isHealthy = false;

    safeLogger.error('Failed to publish event', {
      eventType,
      correlationId,
    });

    throw error;
  }
}

/**
 * Get event system status
 * @returns {Object} Event status
 */
export function getEventStatus() {
  return {
    isHealthy: eventStatus.isHealthy,
    lastEventTime: eventStatus.lastEventTime,
    status: eventStatus.isHealthy ? 'operational' : 'error',
  };
}

/**
 * Reset event status
 */
export function resetEventStatus() {
  eventStatus.isHealthy = true;
  eventStatus.lastEventTime = null;
  safeLogger.info('Event status reset');
}

/**
 * Initialize RabbitMQ
 */
export async function initializeRabbitMQ(options = {}) {
  try {
    safeLogger.info('Initializing RabbitMQ connection...');

    // Initialize connection
    await rabbitMQConnection.init(); // Fixed: Use init() instead of connect()

    // Setup basic exchanges and queues
    await rabbitMQConnection.setupExchangesAndQueues();

    // Start consumers
    await startAllConsumers(options);

    safeLogger.info('RabbitMQ initialized successfully');
    return true;
  } catch (error) {
    safeLogger.error('Failed to initialize RabbitMQ', {
      error: error.message,
      stack: error.stack,
    });
    throw error;
  }
}

/**
 * Start all consumers
 * @param {Object} options - Consumer options
 */
async function startAllConsumers(options = {}) {
  const consumers = [
    { name: 'email', startFn: startEmailEventsConsumer },
    { name: 'notification', startFn: startNotificationEventsConsumer },
    { name: 'user', startFn: startUserEventsConsumer },
  ];

  for (const consumer of consumers) {
    try {
      await consumer.startFn(options);
      consumerRegistry.set(consumer.name, {
        name: consumer.name,
        status: 'active',
        startedAt: new Date().toISOString(),
      });
      safeLogger.info(`Consumer started successfully: ${consumer.name}`);
    } catch (error) {
      safeLogger.error(`Failed to start consumer: ${consumer.name}`, {
        error: error.message,
      });
      consumerRegistry.set(consumer.name, {
        name: consumer.name,
        status: 'failed',
        error: error.message,
        startedAt: new Date().toISOString(),
      });
    }
  }
}

/**
 * Shutdown RabbitMQ
 */
export async function shutdownRabbitMQ() {
  try {
    safeLogger.info('Shutting down RabbitMQ...');

    // Stop all consumers
    await stopAllConsumers();

    // Close connection
    await rabbitMQConnection.close();

    safeLogger.info('RabbitMQ shutdown complete');
    return true;
  } catch (error) {
    safeLogger.error('Error during RabbitMQ shutdown', {
      error: error.message,
      stack: error.stack,
    });
    throw error;
  }
}

/**
 * Stop all consumers
 */
async function stopAllConsumers() {
  const consumers = [
    { name: 'email', stopFn: stopEmailEventsConsumer },
    { name: 'notification', stopFn: stopNotificationEventsConsumer },
    { name: 'user', stopFn: stopUserEventsConsumer },
  ];

  for (const consumer of consumers) {
    try {
      await consumer.stopFn();
      const consumerInfo = consumerRegistry.get(consumer.name);
      if (consumerInfo) {
        consumerInfo.status = 'stopped';
        consumerInfo.stoppedAt = new Date().toISOString();
      }
      safeLogger.info(`Consumer stopped successfully: ${consumer.name}`);
    } catch (error) {
      safeLogger.error(`Failed to stop consumer: ${consumer.name}`, {
        error: error.message,
      });
    }
  }
}

/**
 * Check if RabbitMQ is healthy
 * @returns {boolean} Health status
 */
export function isRabbitMQHealthy() {
  return rabbitMQConnection.isHealthy();
}

/**
 * Get RabbitMQ connection status
 * @returns {Object} Connection status
 */
export function getRabbitMQStatus() {
  return {
    isHealthy: rabbitMQConnection.isHealthy(),
    isConnected: rabbitMQConnection.isConnected(),
    connectionInfo: rabbitMQConnection.getConnectionInfo(),
  };
}

/**
 * Get consumer status
 * @returns {Object} Consumer status
 */
export function getConsumerStatus() {
  const status = {};
  for (const [name, info] of consumerRegistry.entries()) {
    status[name] = info;
  }
  return status;
}

/**
 * Restart a specific consumer
 * @param {string} consumerName - Name of the consumer to restart
 */
export async function restartConsumer(consumerName) {
  const consumerInfo = consumerRegistry.get(consumerName);
  if (!consumerInfo) {
    throw new Error(`Consumer '${consumerName}' not found`);
  }

  try {
    safeLogger.info(`Restarting consumer: ${consumerName}`);

    // Stop consumer
    if (consumerName === 'email') {
      await stopEmailEventsConsumer();
    } else if (consumerName === 'notification') {
      await stopNotificationEventsConsumer();
    } else if (consumerName === 'user') {
      await stopUserEventsConsumer();
    }

    // Start consumer
    if (consumerName === 'email') {
      await startEmailEventsConsumer();
    } else if (consumerName === 'notification') {
      await startNotificationEventsConsumer();
    } else if (consumerName === 'user') {
      await startUserEventsConsumer();
    }

    consumerInfo.status = 'active';
    consumerInfo.restartedAt = new Date().toISOString();

    safeLogger.info(`Consumer restarted successfully: ${consumerName}`);
  } catch (error) {
    consumerInfo.status = 'failed';
    consumerInfo.error = error.message;
    safeLogger.error(`Failed to restart consumer: ${consumerName}`, {
      error: error.message,
    });
    throw error;
  }
}
