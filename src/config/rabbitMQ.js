// src/config/rabbitMQ.js
import { env } from './env.js';
import { safeLogger } from './logger.js';

/**
 * RabbitMQ Configuration (Production-Ready, Industry Best Practice)
 *
 * - Centralized, explicit, and safe config structure
 * - All queue, exchange, and consumer options are defined here
 * - Per-queue overrides and global defaults
 * - Utility for safe consumer config access with logging
 */

// =========================
// Exchange Types
// =========================
export const EXCHANGE_TYPES = {
  DIRECT: 'direct',
  FANOUT: 'fanout',
  TOPIC: 'topic',
  HEADERS: 'headers',
};

// =========================
// Message Priorities
// =========================
export const MESSAGE_PRIORITIES = {
  LOW: 1,
  NORMAL: 5,
  HIGH: 10,
  CRITICAL: 15,
};

// =========================
// Message Types
// =========================
export const MESSAGE_TYPES = {
  USER_CREATED: 'user.created',
  USER_VERIFIED: 'user.verified',
  EMAIL_VERIFICATION: 'email.verification',
  PASSWORD_RESET: 'password.reset',
  LOGIN_ATTEMPT: 'login.attempt',
  NOTIFICATION: 'notification',
  WELCOME_EMAIL: 'welcome.email',
  ACCOUNT_ACTIVATION: 'account.activation',
};

// =========================
// RabbitMQ Main Config
// =========================
export const rabbitMQConfig = {
  // Connection configuration
  connection: {
    url: env.rabbitMQ?.url || process.env.RABBITMQ_URL || 'amqp://localhost',
    host: process.env.RABBITMQ_HOST || 'localhost',
    port: parseInt(process.env.RABBITMQ_PORT) || 5672,
    username: process.env.RABBITMQ_USERNAME || 'guest',
    password: process.env.RABBITMQ_PASSWORD || 'guest',
    vhost: process.env.RABBITMQ_VHOST || '/',
    heartbeat: parseInt(process.env.RABBITMQ_HEARTBEAT) || 60,
    timeout: parseInt(process.env.RABBITMQ_TIMEOUT) || 30000,
    frameMax: 0,
    channelMax: 0,
    ssl: process.env.RABBITMQ_SSL === 'true' || false,
    reconnect: {
      enabled: true,
      initialDelay: 1000,
      maxDelay: 30000,
      factor: 2,
      maxAttempts: 10,
    },
  },

  // Exchange configurations
  exchanges: {
    auth: {
      name: 'auth_exchange',
      type: EXCHANGE_TYPES.DIRECT,
      options: {
        durable: true,
        autoDelete: false,
        arguments: {
          'x-message-ttl': 86400000, // 24 hours
          'x-max-length': 10000,
          'x-overflow': 'drop-head',
        },
      },
    },

    events: {
      name: 'events_exchange',
      type: EXCHANGE_TYPES.TOPIC,
      options: {
        durable: true,
        autoDelete: false,
        arguments: {
          'x-message-ttl': 604800000, // 7 days
          'x-max-length': 50000,
        },
      },
    },
    audit: {
      name: 'audit_exchange',
      type: EXCHANGE_TYPES.DIRECT,
      options: {
        durable: true,
        autoDelete: false,
        arguments: {
          'x-message-ttl': 31536000000, // 1 year
          'x-max-length': 100000,
        },
      },
    },
    deadLetter: {
      name: 'auth_dlx',
      type: EXCHANGE_TYPES.DIRECT,
      options: {
        durable: true,
        autoDelete: false,
      },
    },
  },

  // Queue configurations
  queues: {
    userCreated: {
      name: 'user_created_queue',
      options: {
        durable: true,
        deadLetterExchange: 'auth_dlx',
        deadLetterRoutingKey: 'user.created.failed',
        messageTtl: 86400000,
        maxLength: 1000,
        maxPriority: MESSAGE_PRIORITIES.CRITICAL, // Changed from HIGH to CRITICAL
        arguments: {
          'x-queue-mode': 'lazy',
          'x-max-priority': MESSAGE_PRIORITIES.CRITICAL, // Changed from HIGH to CRITICAL
        },
      },
      bindings: [
        {
          exchange: 'auth_exchange',
          routingKey: MESSAGE_TYPES.USER_CREATED,
          arguments: {},
        },
      ],
    },
    userVerified: {
      name: 'user_verified_queue',
      options: {
        durable: true,
        deadLetterExchange: 'auth_dlx',
        deadLetterRoutingKey: 'user.verified.failed',
        messageTtl: 86400000,
        maxLength: 1000,
        maxPriority: MESSAGE_PRIORITIES.NORMAL,
        arguments: {
          'x-queue-mode': 'lazy',
          'x-max-priority': MESSAGE_PRIORITIES.NORMAL,
        },
      },
      bindings: [
        {
          exchange: 'auth_exchange',
          routingKey: MESSAGE_TYPES.USER_VERIFIED,
          arguments: {},
        },
      ],
    },
    emailVerification: {
      name: 'email_verification_queue',
      options: {
        durable: true,
        deadLetterExchange: 'auth_dlx',
        deadLetterRoutingKey: 'email.verification.failed',
        messageTtl: 3600000,
        maxLength: 5000,
        maxPriority: MESSAGE_PRIORITIES.HIGH,
        arguments: {
          'x-queue-mode': 'lazy',
          'x-max-priority': MESSAGE_PRIORITIES.HIGH,
          'x-message-ttl': 3600000,
        },
      },
      bindings: [
        {
          exchange: 'auth_exchange',
          routingKey: MESSAGE_TYPES.EMAIL_VERIFICATION,
          arguments: {},
        },
      ],
    },
    passwordReset: {
      name: 'password_reset_queue',
      options: {
        durable: true,
        deadLetterExchange: 'auth_dlx',
        deadLetterRoutingKey: 'password.reset.failed',
        messageTtl: 1800000,
        maxLength: 1000,
        maxPriority: MESSAGE_PRIORITIES.HIGH,
        arguments: {
          'x-queue-mode': 'lazy',
          'x-max-priority': MESSAGE_PRIORITIES.HIGH,
          'x-message-ttl': 1800000,
        },
      },
      bindings: [
        {
          exchange: 'auth_exchange',
          routingKey: MESSAGE_TYPES.PASSWORD_RESET,
          arguments: {},
        },
      ],
    },
    loginAttempt: {
      name: 'login_attempt_queue',
      options: {
        durable: true,
        deadLetterExchange: 'auth_dlx',
        deadLetterRoutingKey: 'login.attempt.failed',
        messageTtl: 86400000,
        maxLength: 10000,
        maxPriority: MESSAGE_PRIORITIES.NORMAL,
        arguments: {
          'x-queue-mode': 'lazy',
          'x-max-priority': MESSAGE_PRIORITIES.NORMAL,
        },
      },
      bindings: [
        {
          exchange: 'auth_exchange',
          routingKey: MESSAGE_TYPES.LOGIN_ATTEMPT,
          arguments: {},
        },
      ],
    },
    welcomeEmail: {
      name: 'welcome_email_queue',
      options: {
        durable: true,
        deadLetterExchange: 'auth_dlx',
        deadLetterRoutingKey: 'welcome.email.failed',
        messageTtl: 3600000, // 1 hour
        maxLength: 1000,
        maxPriority: MESSAGE_PRIORITIES.HIGH,
        arguments: {
          'x-queue-mode': 'lazy',
          'x-max-priority': MESSAGE_PRIORITIES.HIGH,
        },
      },
      bindings: [
        {
          exchange: 'auth_exchange',
          routingKey: MESSAGE_TYPES.WELCOME_EMAIL,
          arguments: {},
        },
      ],
    },
    securityEvent: {
      name: 'security_event_queue',
      options: {
        durable: true,
        deadLetterExchange: 'auth_dlx',
        deadLetterRoutingKey: 'security.event.failed',
        messageTtl: 604800000,
        maxLength: 5000,
        maxPriority: MESSAGE_PRIORITIES.CRITICAL,
        arguments: {
          'x-queue-mode': 'lazy',
          'x-max-priority': MESSAGE_PRIORITIES.CRITICAL,
        },
      },
      bindings: [
        {
          exchange: 'auth_exchange',
          routingKey: MESSAGE_TYPES.SECURITY_EVENT,
          arguments: {},
        },
      ],
    },
    auditLog: {
      name: 'audit_log_queue',
      options: {
        durable: true,
        deadLetterExchange: 'auth_dlx',
        deadLetterRoutingKey: 'audit.log.failed',
        messageTtl: 31536000000,
        maxLength: 50000,
        maxPriority: MESSAGE_PRIORITIES.LOW,
        arguments: {
          'x-queue-mode': 'lazy',
          'x-max-priority': MESSAGE_PRIORITIES.LOW,
        },
      },
      bindings: [
        {
          exchange: 'audit_exchange',
          routingKey: MESSAGE_TYPES.AUDIT_LOG,
          arguments: {},
        },
      ],
    },
    systemEvent: {
      name: 'system_event_queue',
      options: {
        durable: true,
        deadLetterExchange: 'auth_dlx',
        deadLetterRoutingKey: 'system.event.failed',
        messageTtl: 604800000,
        maxLength: 10000,
        maxPriority: MESSAGE_PRIORITIES.NORMAL,
        arguments: {
          'x-queue-mode': 'lazy',
          'x-max-priority': MESSAGE_PRIORITIES.NORMAL,
        },
      },
      bindings: [
        {
          exchange: 'events_exchange',
          routingKey: MESSAGE_TYPES.SYSTEM_EVENT,
          arguments: {},
        },
      ],
    },
  },

  // Dead letter exchange and queue configuration
  deadLetterExchange: {
    name: 'auth_dlx',
    type: EXCHANGE_TYPES.DIRECT,
    queue: 'auth_dlq',
    routingKey: '#',
    queueOptions: {
      durable: true,
      messageTtl: 604800000, // 7 days
      maxLength: 10000,
      arguments: {
        'x-queue-mode': 'lazy',
        'x-message-ttl': 604800000,
      },
    },
  },

  // Consumer configuration
  consumer: {
    // Global default for all consumers
    default: {
      prefetch: 10,
      priority: 0,
      retryAttempts: 3,
      retryDelay: 1000,
    },
    // Per-queue overrides
    userCreated: {
      prefetch: 5,
      priority: 10,
      retryAttempts: 3,
      retryDelay: 1000,
    },
    userVerified: {
      prefetch: 20,
      priority: 15,
      retryAttempts: 5,
      retryDelay: 5000,
    },
    // ...add other consumers as needed
  },

  // Publisher configuration (optional, add as needed)
  publisher: {
    default: {
      persistent: true,
      mandatory: false,
      immediate: false,
      priority: MESSAGE_PRIORITIES.NORMAL,
    },
    // ...per-message-type overrides
  },

  // Retry mechanism configuration (optional, add as needed)
  retryMechanism: {
    maxRetries: 3,
    initialInterval: 1000,
    multiplier: 2,
    maxInterval: 30000,
    randomize: true,
    backoffAlgorithm: 'exponential',
  },
};

// =========================
// Utility: Safe Consumer Option Access
// =========================
/**
 * Get merged consumer options for a given queue.
 * Logs a warning if per-queue config is missing.
 * Always returns a valid config object.
 */
export function getConsumerOptions(queueName) {
  const hasOverride = Object.prototype.hasOwnProperty.call(
    rabbitMQConfig.consumer,
    queueName
  );
  if (!hasOverride) {
    safeLogger.warn(
      `No specific consumer config for queue '${queueName}', using default options.`
    );
  }
  return {
    ...rabbitMQConfig.consumer.default,
    ...(rabbitMQConfig.consumer[queueName] || {}),
  };
}

// =========================
// Message Routing (optional, add as needed)
// =========================
export const messageRouting = {
  routes: {
    [MESSAGE_TYPES.USER_CREATED]: ['user_created_queue'],
    [MESSAGE_TYPES.USER_UPDATED]: ['user_updated_queue'],
    [MESSAGE_TYPES.USER_DELETED]: ['user_deleted_queue'],
    [MESSAGE_TYPES.USER_VERIFIED]: ['user_verified_queue'],
    [MESSAGE_TYPES.EMAIL_VERIFICATION]: ['email_verification_queue'],
    [MESSAGE_TYPES.PASSWORD_RESET]: ['password_reset_queue'],
    [MESSAGE_TYPES.LOGIN_ATTEMPT]: ['login_attempt_queue'],
    [MESSAGE_TYPES.WELCOME_EMAIL]: ['welcome_email_queue'],
    [MESSAGE_TYPES.ACCOUNT_ACTIVATION]: ['welcome_email_queue'],
    [MESSAGE_TYPES.SECURITY_EVENT]: ['security_event_queue'],
    [MESSAGE_TYPES.AUDIT_LOG]: ['audit_log_queue'],
    [MESSAGE_TYPES.SYSTEM_EVENT]: ['system_event_queue'],
  },
  priorities: {
    [MESSAGE_TYPES.USER_CREATED]: MESSAGE_PRIORITIES.CRITICAL, // Changed from HIGH to CRITICAL
    [MESSAGE_TYPES.USER_UPDATED]: MESSAGE_PRIORITIES.HIGH,
    [MESSAGE_TYPES.USER_DELETED]: MESSAGE_PRIORITIES.HIGH,
    [MESSAGE_TYPES.USER_VERIFIED]: MESSAGE_PRIORITIES.NORMAL,
    [MESSAGE_TYPES.EMAIL_VERIFICATION]: MESSAGE_PRIORITIES.HIGH,
    [MESSAGE_TYPES.PASSWORD_RESET]: MESSAGE_PRIORITIES.HIGH,
    [MESSAGE_TYPES.LOGIN_ATTEMPT]: MESSAGE_PRIORITIES.NORMAL,
    [MESSAGE_TYPES.WELCOME_EMAIL]: MESSAGE_PRIORITIES.HIGH,
    [MESSAGE_TYPES.ACCOUNT_ACTIVATION]: MESSAGE_PRIORITIES.HIGH,
    [MESSAGE_TYPES.SECURITY_EVENT]: MESSAGE_PRIORITIES.CRITICAL,
    [MESSAGE_TYPES.AUDIT_LOG]: MESSAGE_PRIORITIES.LOW,
    [MESSAGE_TYPES.SYSTEM_EVENT]: MESSAGE_PRIORITIES.NORMAL,
  },
  ttls: {
    [MESSAGE_TYPES.USER_CREATED]: 86400000,
    [MESSAGE_TYPES.USER_UPDATED]: 86400000,
    [MESSAGE_TYPES.USER_DELETED]: 86400000,
    [MESSAGE_TYPES.USER_VERIFIED]: 86400000,
    [MESSAGE_TYPES.EMAIL_VERIFICATION]: 3600000,
    [MESSAGE_TYPES.PASSWORD_RESET]: 1800000,
    [MESSAGE_TYPES.LOGIN_ATTEMPT]: 86400000,
    [MESSAGE_TYPES.WELCOME_EMAIL]: 3600000,
    [MESSAGE_TYPES.ACCOUNT_ACTIVATION]: 3600000,
    [MESSAGE_TYPES.SECURITY_EVENT]: 604800000,
    [MESSAGE_TYPES.AUDIT_LOG]: 31536000000,
    [MESSAGE_TYPES.SYSTEM_EVENT]: 604800000,
  },
};
