import { config } from 'dotenv';
import { safeLogger } from './logger.js';

// Load environment variables
config();

/**
 * Clean Environment Configuration - Single Source of Truth
 * Imports configurations from respective service files
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

// Import service configurations
import { databaseConfig } from './database.js';
import { redisConfig } from './redis.js';
import { rabbitMQConfig } from './rabbitMQ.js';

// ✅ Core Configuration - Single Source of Truth
const coreConfig = {
  // Server Configuration
  server: {
    port: parseInt(process.env.PORT) || 3000,
    host: process.env.HOST || 'localhost',
    environment: process.env.NODE_ENV,
    version: process.env.APP_VERSION || '1.0.0',
  },

  // CORS Configuration
  corsOrigins: process.env.CORS_ORIGINS?.split(',').map(origin =>
    origin.trim()
  ) || [
    'http://localhost:3000',
    'http://localhost:3001',
    'http://localhost:3002',
  ],

  // Cookie Configuration
  cookieSecret: process.env.COOKIE_SECRET || 'default-cookie-secret',

  // JWT Configuration
  jwt: {
    refreshSecret:
      process.env.JWT_REFRESH_SECRET || 'default-jwt-refresh-secret',
    accessAlgorithm: process.env.JWT_ACCESS_ALGORITHM || 'RS256',
    refreshAlgorithm: process.env.JWT_REFRESH_ALGORITHM || 'HS256',
    refreshTTL: process.env.JWT_REFRESH_TTL || '7d',
    accessTTL: process.env.JWT_ACCESS_TTL || '1h',
    issuer: process.env.JWT_ISSUER || 'bizPickr-auth-service',
    audience: process.env.JWT_AUDIENCE || 'bizPickr-api',
  },

  // Service Configurations - Imported from respective files
  database: databaseConfig,
  redis: redisConfig,
  rabbitMQ: rabbitMQConfig,

  // gRPC Configuration
  grpc: {
    server: {
      host: process.env.GRPC_SERVER_HOST || 'localhost',
      port: parseInt(process.env.GRPC_SERVER_PORT) || 50050,
    },
    clients: {
      userService: {
        host: process.env.GRPC_USER_SERVICE_HOST || 'localhost',
        port: parseInt(process.env.GRPC_USER_SERVICE_PORT) || 50051,
        timeout: parseInt(process.env.GRPC_USER_SERVICE_TIMEOUT) || 5000,
      },
    },
  },

  // Security Configuration
  security: {
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
    passwordMinLength: parseInt(process.env.PASSWORD_MIN_LENGTH) || 8,
    passwordMaxLength: parseInt(process.env.PASSWORD_MAX_LENGTH) || 128,
    rateLimitWindowMs:
      parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  },

  // Feature Flags
  features: {
    twoFactorAuth: process.env.FEATURE_2FA !== 'false',
    emailVerification: process.env.FEATURE_EMAIL_VERIFICATION !== 'false',
    oauth: process.env.FEATURE_OAUTH !== 'false',
  },
};

// ✅ MongoDB Configuration
export const MONGODB_URI =
  process.env.MONGODB_URI || 'mongodb://localhost:27017/auth_service';

// ✅ Export configuration
export const env = coreConfig;
export default coreConfig;
