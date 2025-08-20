// src/config/rabbitMQ.js
import { env } from './env.js';
import { safeLogger } from './logger.js';

/**
 * RabbitMQ Configuration (Production-Ready, Industry Best Practice)
 * Integrated with Event System
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
// Event Types (Centralized)
// =========================
export const EVENT_TYPES = {
  // User Events
  USER_CREATED: 'user.created',
  USER_VERIFIED: 'user.verified',
  USER_UPDATED: 'user.updated',
  USER_DELETED: 'user.deleted',

  // Authentication Events
  EMAIL_VERIFICATION: 'email.verification',
  PASSWORD_RESET: 'password.reset',
  LOGIN_ATTEMPT: 'login.attempt',
  LOGOUT: 'logout',

  // Email Events
  WELCOME_EMAIL: 'welcome.email',
  ACCOUNT_ACTIVATION: 'account.activation',
  NOTIFICATION: 'notification',

  // Security Events
  SECURITY_ALERT: 'security.alert',
  SUSPICIOUS_ACTIVITY: 'suspicious.activity',

  // System Events
  SYSTEM_HEALTH: 'system.health',
  SERVICE_STARTUP: 'service.startup',
  SERVICE_SHUTDOWN: 'service.shutdown',
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
    notifications: {
      name: 'notifications_exchange',
      type: EXCHANGE_TYPES.FANOUT,
      options: {
        durable: true,
        autoDelete: false,
        arguments: {
          'x-message-ttl': 3600000, // 1 hour
          'x-max-length': 1000,
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
      name: 'auth_user_created_queue',
      options: {
        durable: true,
        deadLetterExchange: 'auth_dlx',
        deadLetterRoutingKey: 'user.created.failed',
        messageTtl: 86400000, // 24 hours
        maxLength: 1000,
        arguments: {
          'x-queue-mode': 'lazy',
          'x-max-priority': MESSAGE_PRIORITIES.CRITICAL,
        },
      },
      bindings: [
        {
          exchange: 'auth_exchange',
          routingKey: EVENT_TYPES.USER_CREATED,
        },
      ],
    },
    userVerified: {
      name: 'auth_user_verified_queue',
      options: {
        durable: true,
        deadLetterExchange: 'auth_dlx',
        deadLetterRoutingKey: 'user.verified.failed',
        messageTtl: 86400000, // 24 hours
        maxLength: 1000,
        arguments: {
          'x-queue-mode': 'lazy',
          'x-max-priority': MESSAGE_PRIORITIES.HIGH,
        },
      },
      bindings: [
        {
          exchange: 'auth_exchange',
          routingKey: EVENT_TYPES.USER_VERIFIED,
        },
      ],
    },
    emailVerification: {
      name: 'auth_email_verification_queue',
      options: {
        durable: true,
        deadLetterExchange: 'auth_dlx',
        deadLetterRoutingKey: 'email.verification.failed',
        messageTtl: 3600000, // 1 hour
        maxLength: 1000,
        arguments: {
          'x-queue-mode': 'lazy',
          'x-max-priority': MESSAGE_PRIORITIES.HIGH,
        },
      },
      bindings: [
        {
          exchange: 'auth_exchange',
          routingKey: EVENT_TYPES.EMAIL_VERIFICATION,
        },
      ],
    },
    passwordReset: {
      name: 'auth_password_reset_queue',
      options: {
        durable: true,
        deadLetterExchange: 'auth_dlx',
        deadLetterRoutingKey: 'password.reset.failed',
        messageTtl: 1800000, // 30 minutes
        maxLength: 1000,
        arguments: {
          'x-queue-mode': 'lazy',
          'x-max-priority': MESSAGE_PRIORITIES.HIGH,
        },
      },
      bindings: [
        {
          exchange: 'auth_exchange',
          routingKey: EVENT_TYPES.PASSWORD_RESET,
        },
      ],
    },
    welcomeEmail: {
      name: 'auth_welcome_email_queue',
      options: {
        durable: true,
        deadLetterExchange: 'auth_dlx',
        deadLetterRoutingKey: 'welcome.email.failed',
        messageTtl: 3600000, // 1 hour
        maxLength: 1000,
        arguments: {
          'x-queue-mode': 'lazy',
          'x-max-priority': MESSAGE_PRIORITIES.HIGH,
        },
      },
      bindings: [
        {
          exchange: 'auth_exchange',
          routingKey: EVENT_TYPES.WELCOME_EMAIL,
        },
      ],
    },
    securityEvent: {
      name: 'auth_security_event_queue',
      options: {
        durable: true,
        deadLetterExchange: 'auth_dlx',
        deadLetterRoutingKey: 'security.event.failed',
        messageTtl: 604800000, // 7 days
        maxLength: 5000,
        arguments: {
          'x-queue-mode': 'lazy',
          'x-max-priority': MESSAGE_PRIORITIES.CRITICAL,
        },
      },
      bindings: [
        {
          exchange: 'auth_exchange',
          routingKey: EVENT_TYPES.SECURITY_ALERT,
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
    default: {
      prefetch: 10,
      priority: 0,
      retryAttempts: 3,
      retryDelay: 1000,
    },
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
    emailVerification: {
      prefetch: 15,
      priority: 12,
      retryAttempts: 3,
      retryDelay: 2000,
    },
    passwordReset: {
      prefetch: 10,
      priority: 12,
      retryAttempts: 3,
      retryDelay: 2000,
    },
  },

  // Publisher configuration
  publisher: {
    default: {
      persistent: true,
      mandatory: false,
      immediate: false,
      priority: MESSAGE_PRIORITIES.NORMAL,
    },
    userEvents: {
      persistent: true,
      mandatory: true,
      immediate: false,
      priority: MESSAGE_PRIORITIES.HIGH,
    },
    securityEvents: {
      persistent: true,
      mandatory: true,
      immediate: true,
      priority: MESSAGE_PRIORITIES.CRITICAL,
    },
  },

  // Retry mechanism configuration
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
// Event Routing Configuration
// =========================
export const eventRouting = {
  routes: {
    [EVENT_TYPES.USER_CREATED]: ['auth_user_created_queue'],
    [EVENT_TYPES.USER_VERIFIED]: ['auth_user_verified_queue'],
    [EVENT_TYPES.EMAIL_VERIFICATION]: ['auth_email_verification_queue'],
    [EVENT_TYPES.PASSWORD_RESET]: ['auth_password_reset_queue'],
    [EVENT_TYPES.WELCOME_EMAIL]: ['auth_welcome_email_queue'],
    [EVENT_TYPES.SECURITY_ALERT]: ['auth_security_event_queue'],
  },
  priorities: {
    [EVENT_TYPES.USER_CREATED]: MESSAGE_PRIORITIES.CRITICAL,
    [EVENT_TYPES.USER_VERIFIED]: MESSAGE_PRIORITIES.HIGH,
    [EVENT_TYPES.EMAIL_VERIFICATION]: MESSAGE_PRIORITIES.HIGH,
    [EVENT_TYPES.PASSWORD_RESET]: MESSAGE_PRIORITIES.HIGH,
    [EVENT_TYPES.WELCOME_EMAIL]: MESSAGE_PRIORITIES.HIGH,
    [EVENT_TYPES.SECURITY_ALERT]: MESSAGE_PRIORITIES.CRITICAL,
  },
  ttls: {
    [EVENT_TYPES.USER_CREATED]: 86400000,
    [EVENT_TYPES.USER_VERIFIED]: 86400000,
    [EVENT_TYPES.EMAIL_VERIFICATION]: 3600000,
    [EVENT_TYPES.PASSWORD_RESET]: 1800000,
    [EVENT_TYPES.WELCOME_EMAIL]: 3600000,
    [EVENT_TYPES.SECURITY_ALERT]: 604800000,
  },
};

// =========================
// Utility Functions
// =========================
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

export function getPublisherOptions(eventType) {
  const baseOptions = rabbitMQConfig.publisher.default;

  if (eventType.includes('security') || eventType.includes('alert')) {
    return { ...baseOptions, ...rabbitMQConfig.publisher.securityEvents };
  }

  if (eventType.includes('user.')) {
    return { ...baseOptions, ...rabbitMQConfig.publisher.userEvents };
  }

  return baseOptions;
}

export function getEventTTL(eventType) {
  return eventRouting.ttls[eventType] || 86400000; // Default 24 hours
}

export function getEventPriority(eventType) {
  return eventRouting.priorities[eventType] || MESSAGE_PRIORITIES.NORMAL;
}
