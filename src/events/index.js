import rabbitMQConnection from './connection.js';
import { safeLogger } from '../config/logger.js';
import { startUserVerifiedConsumer } from './consumers/userVerifiedConsumer.js';
import { startUserCreatedConsumer } from './consumers/userCreatedConsumer.js';
import { ApiError } from '../utils/ApiError.js';
import { getCorrelationId } from '../config/requestContext.js';
/**
 * Industry-level Event System Manager
 *
 * Features:
 * - Enhanced error handling and logging
 * - Health monitoring and metrics
 * - Graceful startup and shutdown
 * - Consumer management and monitoring
 * - Performance tracking
 * - Circuit breaker patterns
 */
// Event system metrics
const eventMetrics = {
  totalEventsPublished: 0,
  totalEventsConsumed: 0,
  failedPublishes: 0,
  failedConsumes: 0,
  activeConsumers: 0,
  lastHealthCheck: null,
  uptime: Date.now(),
  reconnectionAttempts: 0,
  lastReconnection: null,
};
// Consumer registry for management
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
    const exchangeName = 'auth_events';
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
      },
    );

    if (!published) {
      throw new Error('Failed to publish event to RabbitMQ');
    }

    // Update metrics
    updateEventMetrics('published', {
      eventType,
      correlationId,
      publishTime: Date.now() - startTime,
    });

    safeLogger.info('Event published successfully', {
      eventType,
      correlationId,
      publishTime: `${Date.now() - startTime}ms`,
      routingKey,
    });

    return true;
  } catch (error) {
    // Update failed metrics
    updateEventMetrics('failedPublish', {
      eventType,
      correlationId,
      error: error.message,
    });

    safeLogger.error('Failed to publish event', {
      eventType,
      correlationId,
      error: error.message,
      stack: error.stack,
      publishTime: `${Date.now() - startTime}ms`,
    });

    // Don't throw error for event publishing failures
    // This prevents breaking the main application flow
    return false;
  }
}
/**
 * Initialize RabbitMQ event system with enhanced error handling
 * @param {Object} options - Initialization options
 * @returns {Promise<void>}
 */
export async function initializeRabbitMQ(options = {}) {
  const startTime = Date.now();
  try {
    safeLogger.info('Initializing RabbitMQ event system', {
      options,
      timestamp: new Date().toISOString(),
    });
    // Initialize RabbitMQ connection
    await rabbitMQConnection.init();
    // Wait for connection to be fully established
    await waitForConnectionReady();
    safeLogger.info('RabbitMQ connection initialized successfully', {
      connectionTime: `${Date.now() - startTime}ms`,
    });
    // Start all consumers
    await startAllConsumers(options);
    // Start health monitoring
    startHealthMonitoring();
    // Set up graceful shutdown handlers
    setupGracefulShutdown();
    safeLogger.info('RabbitMQ event system initialized successfully', {
      totalTime: `${Date.now() - startTime}ms`,
      activeConsumers: eventMetrics.activeConsumers,
    });
  } catch (error) {
    const totalTime = Date.now() - startTime;
    
    // In development mode, log warning but don't crash
    if (process.env.NODE_ENV === 'development') {
      safeLogger.warn('⚠️ RabbitMQ initialization failed in development mode, continuing...', {
        error: error.message,
        note: 'Service will start without RabbitMQ functionality',
        totalTime: `${totalTime}ms`,
      });
      return; // Don't throw error in development
    }
    
    safeLogger.error('Failed to initialize RabbitMQ event system', {
      error: error.message,
      stack: error.stack,
      totalTime: `${totalTime}ms`,
      reconnectionAttempts: eventMetrics.reconnectionAttempts,
    });
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError(503, 'Failed to initialize event system', [
      'Event system initialization failed',
      'Please check RabbitMQ configuration and connectivity',
    ]);
  }
}
/**
 * Wait for RabbitMQ connection to be fully ready
 * @param {number} timeout - Timeout in milliseconds
 * @returns {Promise<void>}
 */
async function waitForConnectionReady(timeout = 60000) { // Increased timeout to 60 seconds
  const startTime = Date.now();
  console.log('🔍 DEBUG: Waiting for RabbitMQ connection to be ready...');
  while (Date.now() - startTime < timeout) {
    const isHealthy = rabbitMQConnection.isHealthy();
    console.log(`🔍 DEBUG: RabbitMQ health check: ${isHealthy} (${Date.now() - startTime}ms elapsed)`);
    if (isHealthy) {
      console.log('✅ DEBUG: RabbitMQ connection is healthy!');
      return;
    }
    await new Promise(resolve => setTimeout(resolve, 500)); // Increased polling interval
  }
  console.log('❌ DEBUG: RabbitMQ connection timeout after 60 seconds');
  throw new ApiError(503, 'RabbitMQ connection timeout', [
    'Connection did not become ready within timeout period',
    'Please check RabbitMQ server status',
  ]);
}
/**
 * Start all registered consumers
 * @param {Object} options - Consumer options
 * @returns {Promise<void>}
 */
async function startAllConsumers(options = {}) {
  const consumers = [
    { name: 'userVerified', startFn: startUserVerifiedConsumer },
    { name: 'userCreated', startFn: startUserCreatedConsumer },
    // Add more consumers here as needed
  ];
  const consumerPromises = consumers.map(async({ name, startFn }) => {
    try {
      await startFn(options);
      eventMetrics.activeConsumers++;
      // Register consumer for management
      consumerRegistry.set(name, {
        name,
        startFn,
        status: 'active',
        startedAt: new Date().toISOString(),
        options,
      });
      safeLogger.info('Consumer started successfully', {
        consumerName: name,
        activeConsumers: eventMetrics.activeConsumers,
      });
    } catch (error) {
      safeLogger.error('Failed to start consumer', {
        consumerName: name,
        error: error.message,
        stack: error.stack,
      });
      // Register failed consumer
      consumerRegistry.set(name, {
        name,
        startFn,
        status: 'failed',
        error: error.message,
        startedAt: new Date().toISOString(),
        options,
      });
      throw error;
    }
  });
  await Promise.allSettled(consumerPromises);
  const successfulConsumers = Array.from(consumerRegistry.values()).filter(
    consumer => consumer.status === 'active',
  ).length;
  safeLogger.info('Consumer startup completed', {
    totalConsumers: consumers.length,
    successfulConsumers,
    failedConsumers: consumers.length - successfulConsumers,
    activeConsumers: eventMetrics.activeConsumers,
  });
}
/**
 * Start health monitoring
 */
function startHealthMonitoring() {
  setInterval(async() => {
    try {
      const health = await getEventSystemHealth();
      eventMetrics.lastHealthCheck = new Date().toISOString();
      if (health.status === 'unhealthy') {
        safeLogger.warn('Event system health check failed', health);
      } else {
        safeLogger.debug('Event system health check passed', {
          status: health.status,
          activeConsumers: health.activeConsumers,
          uptime: health.uptime,
        });
      }
    } catch (error) {
      safeLogger.error('Event system health check error', {
        error: error.message,
        stack: error.stack,
      });
    }
  }, 30 * 1000); // Every 30 seconds
}
/**
 * Get event system health status
 * @returns {Promise<Object>} Health status
 */
export async function getEventSystemHealth() {
  const uptime = Date.now() - eventMetrics.uptime;
  const connectionHealth = await rabbitMQConnection.getHealth();
  const activeConsumers = Array.from(consumerRegistry.values()).filter(
    consumer => consumer.status === 'active',
  ).length;
  const failedConsumers = Array.from(consumerRegistry.values()).filter(
    consumer => consumer.status === 'failed',
  ).length;
  return {
    status:
      connectionHealth.status === 'connected' && activeConsumers > 0
        ? 'healthy'
        : 'unhealthy',
    uptime: `${Math.round(uptime / 1000)}s`,
    connection: connectionHealth,
    consumers: {
      total: consumerRegistry.size,
      active: activeConsumers,
      failed: failedConsumers,
    },
    metrics: { ...eventMetrics },
    lastHealthCheck: eventMetrics.lastHealthCheck,
  };
}
/**
 * Get event system metrics
 * @returns {Object} Event metrics
 */
export function getEventMetrics() {
  return {
    ...eventMetrics,
    currentTime: new Date().toISOString(),
    consumers: Array.from(consumerRegistry.values()),
  };
}
/**
 * Restart a specific consumer
 * @param {string} consumerName - Name of the consumer to restart
 * @returns {Promise<void>}
 */
export async function restartConsumer(consumerName) {
  const consumer = consumerRegistry.get(consumerName);
  if (!consumer) {
    throw new ApiError(404, 'Consumer not found', [
      `Consumer '${consumerName}' is not registered`,
      'Please check consumer name',
    ]);
  }
  try {
    safeLogger.info('Restarting consumer', { consumerName });
    // Update status to restarting
    consumer.status = 'restarting';
    consumer.restartAttempts = (consumer.restartAttempts || 0) + 1;
    consumer.lastRestartAttempt = new Date().toISOString();
    // Start the consumer
    await consumer.startFn(consumer.options);
    // Update status to active
    consumer.status = 'active';
    consumer.startedAt = new Date().toISOString();
    safeLogger.info('Consumer restarted successfully', { consumerName });
  } catch (error) {
    consumer.status = 'failed';
    consumer.error = error.message;
    safeLogger.error('Failed to restart consumer', {
      consumerName,
      error: error.message,
      stack: error.stack,
    });
    throw new ApiError(500, 'Failed to restart consumer', [
      `Consumer '${consumerName}' restart failed`,
      error.message,
    ]);
  }
}
/**
 * Restart all failed consumers
 * @returns {Promise<Object>} Restart results
 */
export async function restartFailedConsumers() {
  const failedConsumers = Array.from(consumerRegistry.values()).filter(
    consumer => consumer.status === 'failed',
  );
  const results = {
    total: failedConsumers.length,
    successful: 0,
    failed: 0,
    errors: [],
  };
  for (const consumer of failedConsumers) {
    try {
      await restartConsumer(consumer.name);
      results.successful++;
    } catch (error) {
      results.failed++;
      results.errors.push({
        consumer: consumer.name,
        error: error.message,
      });
    }
  }
  safeLogger.info('Failed consumers restart completed', results);
  return results;
}
/**
 * Setup graceful shutdown handlers
 */
function setupGracefulShutdown() {
  const gracefulShutdown = async signal => {
    safeLogger.info(`Received ${signal}, starting graceful shutdown`);
    try {
      // Stop all consumers
      for (const [name, consumer] of consumerRegistry.entries()) {
        if (consumer.status === 'active') {
          try {
            // Cancel consumer if possible
            await rabbitMQConnection.cancelConsumer(
              `${name}-channel`,
              `${name}-consumer`,
            );
            consumer.status = 'stopped';
            safeLogger.info('Consumer stopped', { consumerName: name });
          } catch (error) {
            safeLogger.warn('Failed to stop consumer gracefully', {
              consumerName: name,
              error: error.message,
            });
          }
        }
      }
      // Close RabbitMQ connection
      await rabbitMQConnection.close();
      safeLogger.info('Event system shutdown completed successfully', {
        totalEventsPublished: eventMetrics.totalEventsPublished,
        totalEventsConsumed: eventMetrics.totalEventsConsumed,
        uptime: `${Math.round((Date.now() - eventMetrics.uptime) / 1000)}s`,
      });
      process.exit(0);
    } catch (error) {
      safeLogger.error('Error during graceful shutdown', {
        error: error.message,
        stack: error.stack,
      });
      process.exit(1);
    }
  };
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
}
/**
 * Update event metrics
 * @param {string} type - Metric type (published, consumed, failed)
 * @param {Object} data - Additional data
 */
export function updateEventMetrics(type, data = {}) {
  switch (type) {
  case 'published':
    eventMetrics.totalEventsPublished++;
    break;
  case 'consumed':
    eventMetrics.totalEventsConsumed++;
    break;
  case 'failedPublish':
    eventMetrics.failedPublishes++;
    break;
  case 'failedConsume':
    eventMetrics.failedConsumes++;
    break;
  case 'reconnection':
    eventMetrics.reconnectionAttempts++;
    eventMetrics.lastReconnection = new Date().toISOString();
    break;
  }
  safeLogger.debug('Event metrics updated', {
    type,
    data,
    metrics: { ...eventMetrics },
  });
}
/**
 * Get consumer registry
 * @returns {Map} Consumer registry
 */
export function getConsumerRegistry() {
  return new Map(consumerRegistry);
}
/**
 * Check if event system is ready
 * @returns {boolean} Ready status
 */
export function isEventSystemReady() {
      return rabbitMQConnection.isHealthy() && eventMetrics.activeConsumers > 0;
}
/**
 * Shutdown RabbitMQ connection and all consumers
 * @returns {Promise<void>}
 */
export async function shutdownRabbitMQ() {
  const correlationId = getCorrelationId();
  try {
    safeLogger.info('Shutting down RabbitMQ connection', { correlationId });
    // Stop all consumers
    for (const [name, consumer] of consumerRegistry.entries()) {
      if (consumer.status === 'active') {
        try {
          // Cancel consumer if possible
          await rabbitMQConnection.cancelConsumer(
            `${name}-channel`,
            `${name}-consumer`,
          );
          consumer.status = 'stopped';
          safeLogger.info('Consumer stopped', {
            consumerName: name,
            correlationId,
          });
        } catch (error) {
          safeLogger.warn('Failed to stop consumer gracefully', {
            consumerName: name,
            error: error.message,
            correlationId,
          });
        }
      }
    }
    // Close RabbitMQ connection
    await rabbitMQConnection.close();
    safeLogger.info('RabbitMQ shutdown completed successfully', {
      correlationId,
      totalEventsPublished: eventMetrics.totalEventsPublished,
      totalEventsConsumed: eventMetrics.totalEventsConsumed,
      uptime: `${Math.round((Date.now() - eventMetrics.uptime) / 1000)}s`,
    });
  } catch (error) {
    safeLogger.error('Error during RabbitMQ shutdown', {
      error: error.message,
      stack: error.stack,
      correlationId,
    });
    throw error;
  }
}
export { rabbitMQConnection };
