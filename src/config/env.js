import { config } from 'dotenv';
import { safeLogger } from './logger.js';
import { validateEnvType } from './utils.js';

// Load environment variables
config();

/**
 * Cleaned Environment Configuration for AuthService
 *
 * Features:
 * - Essential environment variable management
 * - Environment validation and type checking
 * - Core service configuration
 * - Database configuration
 * - External service configuration
 * - Feature flags
 */

// ✅ Environment validation - only required variables for production
const requiredEnvVars = ['NODE_ENV', 'PORT'];

// ✅ Validate required environment variables
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    safeLogger.error(`Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

// ✅ Development mode - provide defaults for optional services
if (process.env.NODE_ENV === 'development') {
  // Set default values for development
  process.env.DB_HOST = process.env.DB_HOST || 'localhost';
  process.env.DB_NAME = process.env.DB_NAME || 'auth_service';
  process.env.DB_USER = process.env.DB_USER || 'root';
  process.env.DB_PASSWORD = process.env.DB_PASSWORD || '';
  process.env.REDIS_HOST = process.env.REDIS_HOST || 'localhost';
  process.env.REDIS_PORT = process.env.REDIS_PORT || '6379';
}

// Import database configuration
import { databaseConfig } from './database.js';

// ✅ Core Configuration - only what's actually used
const coreConfig = {
  // Server Configuration
  server: {
    port: validateEnvType(process.env.PORT, 'number', 3000),
    host: process.env.HOST || 'localhost',
    environment: process.env.NODE_ENV,
    version: process.env.APP_VERSION || '1.0.0',
  },

  // CORS Configuration (used in app.js)
  corsOrigins: validateEnvType(process.env.CORS_ORIGINS, 'array', [
    'http://localhost:3000',
    'http://localhost:3001',
    'http://localhost:3002',
  ]),

  // Cookie Configuration (used in app.js)
  cookieSecret: process.env.COOKIE_SECRET || 'default-cookie-secret',

  // JWT Configuration (used in auth middleware)
  jwtSecret: process.env.JWT_SECRET || 'default-jwt-secret',
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET || 'default-refresh-secret',

  // Database Configuration
  database: databaseConfig,

  // Redis Configuration
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: validateEnvType(process.env.REDIS_PORT, 'number', 6379),
    password: process.env.REDIS_PASSWORD || '',
    db: validateEnvType(process.env.REDIS_DB, 'number', 0),
  },

  // RabbitMQ Configuration
  rabbitMQ: {
    url: process.env.RABBITMQ_URL || 'amqp://localhost',
    host: process.env.RABBITMQ_HOST || 'localhost',
    port: validateEnvType(process.env.RABBITMQ_PORT, 'number', 5672),
    username: process.env.RABBITMQ_USERNAME || 'guest',
    password: process.env.RABBITMQ_PASSWORD || 'guest',
    vhost: process.env.RABBITMQ_VHOST || '/',
    heartbeat: validateEnvType(process.env.RABBITMQ_HEARTBEAT, 'number', 60),
    timeout: validateEnvType(process.env.RABBITMQ_TIMEOUT, 'number', 30000),
  },

  // gRPC Configuration
  grpc: {
    server: {
      host: process.env.GRPC_SERVER_HOST || 'localhost',
      port: validateEnvType(process.env.GRPC_SERVER_PORT, 'number', 50050),
    },
    clients: {
      userService: {
        host: process.env.GRPC_USER_SERVICE_HOST || 'localhost',
        port: validateEnvType(process.env.GRPC_USER_SERVICE_PORT, 'number', 50051),
        timeout: validateEnvType(process.env.GRPC_USER_SERVICE_TIMEOUT, 'number', 5000),
      },
    },
  },

  // Security Configuration
  security: {
    bcryptRounds: validateEnvType(process.env.BCRYPT_ROUNDS, 'number', 12),
    passwordMinLength: validateEnvType(process.env.PASSWORD_MIN_LENGTH, 'number', 8),
    passwordMaxLength: validateEnvType(process.env.PASSWORD_MAX_LENGTH, 'number', 128),
    rateLimitWindowMs: validateEnvType(process.env.RATE_LIMIT_WINDOW_MS, 'number', 15 * 60 * 1000),
    rateLimitMax: validateEnvType(process.env.RATE_LIMIT_MAX, 'number', 100),
  },

  // Email Configuration
  email: {
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: validateEnvType(process.env.EMAIL_PORT, 'number', 587),
    secure: process.env.EMAIL_SECURE === 'true',
    auth: {
      user: process.env.EMAIL_USER || '',
      pass: process.env.EMAIL_PASS || '',
    },
  },

  // Feature Flags
  features: {
    twoFactorAuth: process.env.FEATURE_2FA !== 'false',
    emailVerification: process.env.FEATURE_EMAIL_VERIFICATION !== 'false',
    oauth: process.env.FEATURE_OAUTH !== 'false',
    deviceFingerprinting: process.env.FEATURE_DEVICE_FINGERPRINTING !== 'false',
  },
};

// ✅ MongoDB Configuration
export const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/auth_service';

// ✅ Export configuration
export const env = coreConfig;
export default coreConfig;
