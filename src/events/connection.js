import amqplib from 'amqplib';
import { rabbitMQConfig } from '../config/rabbitMQ.js';
import { safeLogger } from '../config/logger.js';

/**
 * Smart RabbitMQ Connection - Essential Only
 * Basic RabbitMQ operations without over-engineering
 */

class RabbitMQConnection {
  constructor() {
    this.connection = null;
    this.channels = new Map();
    this.isConnecting = false;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectInterval = 1000;
  }

  /**
   * Initialize connection
   */
  async init() {
    if (this.connection || this.isConnecting) return;

    try {
      this.isConnecting = true;
      safeLogger.info('Connecting to RabbitMQ', {
        attempt: this.reconnectAttempts + 1,
      });

      safeLogger.info('Attempting RabbitMQ connection', {
        url: rabbitMQConfig.connection.url,
        host: rabbitMQConfig.connection.host,
        port: rabbitMQConfig.connection.port,
        username: rabbitMQConfig.connection.username,
        vhost: rabbitMQConfig.connection.vhost,
      });

      // Try simple connection first
      try {
        this.connection = await amqplib.connect(rabbitMQConfig.connection.url, {
          heartbeat: rabbitMQConfig.connection.heartbeat,
          timeout: rabbitMQConfig.connection.timeout,
        });
      } catch (error) {
        safeLogger.warn('Simple connection failed, trying detailed config', {
          error: error.message,
        });
        // Fallback to detailed configuration
        this.connection = await amqplib.connect(
          rabbitMQConfig.connection.url,
          rabbitMQConfig.connection
        );
      }

      this.reconnectAttempts = 0;
      this.isConnecting = false;

      safeLogger.info('Successfully connected to RabbitMQ');
      console.log('✅ DEBUG: RabbitMQ connection established');

      console.log('🔍 DEBUG: Setting up event listeners...');
      this._setupEventListeners();

      console.log('🔍 DEBUG: Setting up default exchanges...');
      await this._setupDefaultExchanges();

      console.log('🔍 DEBUG: Setting up default queues...');
      await this._setupDefaultQueues();

      console.log('✅ DEBUG: RabbitMQ setup completed');
    } catch (error) {
      this.isConnecting = false;
      safeLogger.error('Failed to connect to RabbitMQ', {
        error: error.message,
        attempt: this.reconnectAttempts + 1,
      });

      if (this.reconnectAttempts < this.maxReconnectAttempts) {
        this.reconnectAttempts++;
        setTimeout(() => this.init(), this.reconnectInterval);
      }
    }
  }

  /**
   * Setup event listeners
   */
  _setupEventListeners() {
    this.connection.on('error', error => {
      safeLogger.error('RabbitMQ connection error', { error: error.message });
      this._handleConnectionError();
    });

    this.connection.on('close', () => {
      safeLogger.warn('RabbitMQ connection closed');
      this._handleConnectionError();
    });
  }

  /**
   * Handle connection errors
   */
  _handleConnectionError() {
    if (this.connection) {
      this.connection.removeAllListeners();
      this.connection = null;
    }

    this.channels.clear();

    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      setTimeout(() => this.init(), this.reconnectInterval);
    }
  }

  /**
   * Setup default exchanges
   */
  async _setupDefaultExchanges() {
    try {
      const channel = await this.getChannel();

      // Setup main exchange
      await channel.assertExchange('auth.events', 'topic', {
        durable: true,
      });

      safeLogger.info('Default exchanges setup completed');
    } catch (error) {
      safeLogger.error('Failed to setup exchanges', { error: error.message });
    }
  }

  /**
   * Setup default queues
   */
  async _setupDefaultQueues() {
    try {
      const channel = await this.getChannel();

      // Setup user events queue
      await channel.assertQueue('user.events', {
        durable: true,
      });

      // Bind queue to exchange
      await channel.bindQueue('user.events', 'auth.events', 'user.*');

      safeLogger.info('Default queues setup completed');
    } catch (error) {
      safeLogger.error('Failed to setup queues', { error: error.message });
    }
  }

  /**
   * Get or create channel
   */
  async getChannel(name = 'default') {
    if (this.channels.has(name)) {
      return this.channels.get(name);
    }

    if (!this.connection) {
      throw new Error('No RabbitMQ connection');
    }

    const channel = await this.connection.createChannel();
    this.channels.set(name, channel);

    channel.on('error', error => {
      safeLogger.error('Channel error', { name, error: error.message });
      this.channels.delete(name);
    });

    channel.on('close', () => {
      safeLogger.warn('Channel closed', { name });
      this.channels.delete(name);
    });

    return channel;
  }

  /**
   * Publish message
   */
  async publishMessage(exchange, routingKey, message, options = {}) {
    try {
      const channel = await this.getChannel();
      const messageBuffer = Buffer.from(JSON.stringify(message));

      const result = channel.publish(exchange, routingKey, messageBuffer, {
        persistent: true,
        ...options,
      });

      if (result) {
        safeLogger.debug('Message published', { exchange, routingKey });
      } else {
        safeLogger.warn('Message publish failed', { exchange, routingKey });
      }

      return result;
    } catch (error) {
      safeLogger.error('Failed to publish message', {
        exchange,
        routingKey,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Consume messages
   */
  async consumeMessages(queue, handler, options = {}) {
    try {
      const channel = await this.getChannel();

      // Don't assert queue - just use existing one to avoid conflicts
      // This prevents PRECONDITION_FAILED errors when queue already exists

      const result = await channel.consume(
        queue,
        async msg => {
          if (msg) {
            try {
              const content = JSON.parse(msg.content.toString());
              await handler(content, msg);
              channel.ack(msg);
            } catch (error) {
              safeLogger.error('Message processing failed', {
                queue,
                error: error.message,
              });
              channel.nack(msg, false, false);
            }
          }
        },
        options
      );

      safeLogger.info('Started consuming messages', { queue });
      return result;
    } catch (error) {
      safeLogger.error('Failed to start consuming', {
        queue,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Close connection
   */
  async close() {
    try {
      // Close all channels
      for (const [name, channel] of this.channels) {
        await channel.close();
        this.channels.delete(name);
      }

      // Close connection
      if (this.connection) {
        await this.connection.close();
        this.connection = null;
      }

      safeLogger.info('RabbitMQ connection closed');
    } catch (error) {
      safeLogger.error('Error closing RabbitMQ connection', {
        error: error.message,
      });
    }
  }

  /**
   * Check connection health
   */
  isHealthy() {
    // For amqplib, check if connection exists and is not closed
    // amqplib connection doesn't have a 'closed' property
    // Instead, we check if connection exists and is not in error state
    const hasConnection = !!this.connection;
    const connectionState = this.connection
      ? this.connection.connection?.state || 'unknown'
      : 'no-connection';
    const isHealthy =
      hasConnection &&
      connectionState !== 'closed' &&
      connectionState !== 'error';

    console.log('🔍 DEBUG: isHealthy check:', {
      hasConnection,
      connectionState,
      result: isHealthy,
    });

    return isHealthy;
  }
}

// ✅ Create singleton instance
const rabbitMQConnection = new RabbitMQConnection();

// ✅ Export default
export default rabbitMQConnection;

// ✅ Export individual methods
export const {
  init,
  getChannel,
  publishMessage,
  consumeMessages,
  close,
  isHealthy,
} = rabbitMQConnection;

// ✅ Add missing methods for backward compatibility
export const getHealth = () => ({
  status: rabbitMQConnection.isHealthy() ? 'connected' : 'disconnected',
  timestamp: new Date().toISOString(),
});
export const getMetrics = () => ({
  totalMessages: 0,
  failedMessages: 0,
  timestamp: new Date().toISOString(),
});
export const isReady = () => rabbitMQConnection.isHealthy();
export const publish = (exchange, routingKey, message, options) =>
  rabbitMQConnection.publishMessage(exchange, routingKey, message, options);
export const createChannel = name => rabbitMQConnection.getChannel(name);
export const cancelConsumer = async (channelName, consumerTag) => {
  const channel = await rabbitMQConnection.getChannel(channelName);
  return channel.cancel(consumerTag);
};

// ✅ Add methods to the instance for backward compatibility
rabbitMQConnection.getHealth = getHealth;
rabbitMQConnection.getMetrics = getMetrics;
rabbitMQConnection.isReady = isReady;
rabbitMQConnection.publish = publish;
rabbitMQConnection.createChannel = createChannel;
rabbitMQConnection.cancelConsumer = cancelConsumer;
