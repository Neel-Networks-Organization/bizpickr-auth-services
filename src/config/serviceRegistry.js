/**
 * Service Registry Configuration
 *
 * Industry-standard service discovery and communication
 * for microservices architecture
 */
import { safeLogger } from './logger.js';

// Service Registry Configuration
export const serviceRegistry = {
  // Internal Services
  services: {
    auth: {
      name: 'auth-service',
      version: '1.0.0',
      port: process.env.AUTH_SERVICE_PORT || 3000,
      host: process.env.AUTH_SERVICE_HOST || 'localhost',
      health: '/health',
      metrics: '/metrics',
      endpoints: {
        login: '/api/v1/auth/login',
        register: '/api/v1/auth/register',
        verify: '/api/v1/auth/verify-token',
        refresh: '/api/v1/auth/refresh-token',
        logout: '/api/v1/auth/logout',
        jwks: '/api/v1/jwk/.well-known/jwks.json',
      },
    },
    user: {
      name: 'user-service',
      version: '1.0.0',
      port: process.env.USER_SERVICE_PORT || 3001,
      host: process.env.USER_SERVICE_HOST || 'localhost',
      health: '/health',
      metrics: '/metrics',
      grpc: {
        port: process.env.USER_GRPC_PORT || 50051,
        proto: 'user.proto',
      },
      endpoints: {
        profile: '/api/v1/user/profile',
        settings: '/api/v1/user/settings',
        preferences: '/api/v1/user/preferences',
        activity: '/api/v1/user/activity',
        stats: '/api/v1/user/stats',
      },
    },
    notification: {
      name: 'notification-service',
      version: '1.0.0',
      port: process.env.NOTIFICATION_SERVICE_PORT || 3002,
      host: process.env.NOTIFICATION_SERVICE_HOST || 'localhost',
      health: '/health',
      endpoints: {
        send: '/api/v1/notifications/send',
        templates: '/api/v1/notifications/templates',
        preferences: '/api/v1/notifications/preferences',
      },
    },
    payment: {
      name: 'payment-service',
      version: '1.0.0',
      port: process.env.PAYMENT_SERVICE_PORT || 3003,
      host: process.env.PAYMENT_SERVICE_HOST || 'localhost',
      health: '/health',
    },
    analytics: {
      name: 'analytics-service',
      version: '1.0.0',
      port: process.env.ANALYTICS_SERVICE_PORT || 3004,
      host: process.env.ANALYTICS_SERVICE_HOST || 'localhost',
      health: '/health',
    },
  },
  // External Services
  external: {
    email: {
      provider: process.env.EMAIL_PROVIDER || 'sendgrid',
      apiKey: process.env.EMAIL_API_KEY,
      endpoint: process.env.EMAIL_ENDPOINT,
    },
    sms: {
      provider: process.env.SMS_PROVIDER || 'twilio',
      accountSid: process.env.TWILIO_ACCOUNT_SID,
      authToken: process.env.TWILIO_AUTH_TOKEN,
    },
    storage: {
      provider: process.env.STORAGE_PROVIDER || 'aws',
      bucket: process.env.STORAGE_BUCKET,
      region: process.env.AWS_REGION,
    },
    search: {
      provider: process.env.SEARCH_PROVIDER || 'elasticsearch',
      endpoint: process.env.ELASTICSEARCH_ENDPOINT,
      index: process.env.ELASTICSEARCH_INDEX || 'users',
    },
  },
  // Service Mesh Configuration
  mesh: {
    enabled: process.env.SERVICE_MESH_ENABLED === 'true',
    provider: process.env.SERVICE_MESH_PROVIDER || 'istio',
    tracing: {
      enabled: process.env.TRACING_ENABLED === 'true',
      provider: process.env.TRACING_PROVIDER || 'jaeger',
      endpoint: process.env.JAEGER_ENDPOINT,
    },
    metrics: {
      enabled: process.env.METRICS_ENABLED === 'true',
      provider: process.env.METRICS_PROVIDER || 'prometheus',
      endpoint: process.env.PROMETHEUS_ENDPOINT,
    },
  },
};

/**
 * Get service URL by name
 * @param {string} serviceName - Name of the service
 * @param {string} endpoint - Specific endpoint
 * @returns {string} Service URL
 */
export const getServiceUrl = (serviceName, endpoint = '') => {
  const service = serviceRegistry.services[serviceName];
  if (!service) {
    throw new Error(`Service ${serviceName} not found in registry`);
  }
  const protocol = process.env.NODE_ENV === 'production' ? 'https' : 'http';
  return `${protocol}://${service.host}:${service.port}${endpoint}`;
};

/**
 * Get service health check URL
 * @param {string} serviceName - Name of the service
 * @returns {string} Health check URL
 */
export const getServiceHealthUrl = serviceName => {
  const service = serviceRegistry.services[serviceName];
  if (!service) {
    throw new Error(`Service ${serviceName} not found in registry`);
  }
  return getServiceUrl(serviceName, service.health);
};

/**
 * Get service metrics URL
 * @param {string} serviceName - Name of the service
 * @returns {string} Metrics URL
 */
export const getServiceMetricsUrl = serviceName => {
  const service = serviceRegistry.services[serviceName];
  if (!service?.metrics) {
    throw new Error(`Service ${serviceName} does not support metrics`);
  }
  return getServiceUrl(serviceName, service.metrics);
};

/**
 * Check if service is available
 * @param {string} serviceName - Name of the service
 * @returns {boolean} Service availability
 */
export const isServiceAvailable = serviceName => {
  try {
    const service = serviceRegistry.services[serviceName];
    return !!service;
  } catch {
    return false;
  }
};

/**
 * Get all available services
 * @returns {Array} List of service names
 */
export const getAvailableServices = () => {
  return Object.keys(serviceRegistry.services);
};

/**
 * Get service configuration
 * @param {string} serviceName - Name of the service
 * @returns {Object} Service configuration
 */
export const getServiceConfig = serviceName => {
  const service = serviceRegistry.services[serviceName];
  if (!service) {
    throw new Error(`Service ${serviceName} not found in registry`);
  }
  return { ...service };
};

export default serviceRegistry;
