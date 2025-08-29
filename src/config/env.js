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
    secret: process.env.JWT_SECRET || 'dev-jwt-secret-change-in-production',
    expiresIn: process.env.JWT_EXPIRY || '15m',
    refreshSecret:
      process.env.REFRESH_TOKEN_SECRET ||
      'dev-refresh-secret-change-in-production',
    refreshTTL: process.env.REFRESH_TOKEN_EXPIRY || '7d',
    accessAlgorithm: process.env.JWT_ACCESS_ALGORITHM || 'RS256',
    refreshAlgorithm: process.env.JWT_REFRESH_ALGORITHM || 'HS256',
    issuer: process.env.JWT_ISSUER || 'auth-service',
    audience: process.env.JWT_AUDIENCE || 'api-gateway',
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
    loginRateWindow: parseInt(process.env.LOGIN_RATE_WINDOW) || 15 * 60 * 1000,
    loginRateLimit: parseInt(process.env.LOGIN_RATE_LIMIT) || 10,
    maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5,
    lockoutDuration: parseInt(process.env.LOCKOUT_DURATION) || 15 * 60 * 1000,
    maxFailedAttempts: parseInt(process.env.MAX_FAILED_ATTEMPTS) || 10,
    accountLockDuration:
      parseInt(process.env.ACCOUNT_LOCK_DURATION) || 60 * 60 * 1000,
    sessionTTL: parseInt(process.env.SESSION_TTL) || 24,
    refreshTokenTTL: parseInt(process.env.REFRESH_TOKEN_TTL) || 7,
    recentSessionsLimit: parseInt(process.env.RECENT_SESSIONS_LIMIT) || 5,
  },

  // Feature Flags
  features: {
    twoFactorAuth: process.env.FEATURE_2FA !== 'false',
    emailVerification: process.env.FEATURE_EMAIL_VERIFICATION !== 'false',
    oauth: process.env.FEATURE_OAUTH !== 'false',
  },

  // Service-Specific Configurations
  services: {
    // Password Service Configuration
    password: {
      otpExpiry:
        parseInt(process.env.PASSWORD_OTP_EXPIRY_HOURS || '1') * 60 * 60 * 1000,
      saltRounds: parseInt(process.env.PASSWORD_SALT_ROUNDS || '10'),
      maxAttempts: parseInt(process.env.PASSWORD_MAX_ATTEMPTS || '5'),
      resendCooldown:
        parseInt(process.env.PASSWORD_RESEND_COOLDOWN_MINUTES || '1') *
        60 *
        1000,
      recentLimit: parseInt(process.env.PASSWORD_RECENT_LIMIT || '5'),
    },

    // JWK Service Configuration
    jwk: {
      keyRotationInterval:
        parseInt(process.env.JWK_ROTATION_INTERVAL_HOURS || '24') *
        60 *
        60 *
        1000,
      maxKeys: parseInt(process.env.JWK_MAX_KEYS || '5'),
      cacheTTL: parseInt(process.env.JWK_CACHE_TTL_HOURS || '1') * 3600,
      rsaKeySize: parseInt(process.env.JWK_RSA_KEY_SIZE || '2048'),
    },

    // Two Factor Service Configuration
    twoFactor: {
      backupCodesCount: parseInt(
        process.env.TWO_FACTOR_BACKUP_CODES_COUNT || '10'
      ),
      backupCodeLength: parseInt(
        process.env.TWO_FACTOR_BACKUP_CODE_LENGTH || '8'
      ),
      digits: parseInt(process.env.TWO_FACTOR_DIGITS || '6'),
      period: parseInt(process.env.TWO_FACTOR_PERIOD_SECONDS || '30'),
    },

    // Email Service Configuration
    email: {
      otpExpiry:
        parseInt(process.env.EMAIL_OTP_EXPIRY_HOURS || '1') * 60 * 60 * 1000,
      saltRounds: parseInt(process.env.EMAIL_SALT_ROUNDS || '10'),
    },

    // Session Service Configuration
    session: {
      sessionTTL: parseInt(process.env.SESSION_TTL_HOURS || '24') * 60 * 60,
      refreshTokenTTL:
        parseInt(process.env.SESSION_REFRESH_TTL_DAYS || '7') * 24 * 60 * 60,
      recentSessionsLimit: parseInt(
        process.env.SESSION_RECENT_SESSIONS_LIMIT || '5'
      ),
    },

    // Rate Limit Service Configuration
    rateLimit: {
      defaultWindow:
        parseInt(process.env.RATE_LIMIT_DEFAULT_WINDOW_MINUTES || '15') *
        60 *
        1000,
      defaultLimit: parseInt(process.env.RATE_LIMIT_DEFAULT_LIMIT || '100'),
      redisDb: parseInt(process.env.REDIS_RATE_LIMIT_DB || '1'),
      redisPrefix: process.env.REDIS_RATE_LIMIT_PREFIX || 'rate_limit:',
      redisTTLBuffer: parseInt(process.env.REDIS_RATE_LIMIT_TTL_BUFFER || '60'),
      cleanupInterval: parseInt(
        process.env.REDIS_RATE_LIMIT_CLEANUP_INTERVAL || '300000'
      ),
      enterprisePrefix:
        process.env.ENTERPRISE_RATE_LIMIT_PREFIX || 'enterprise_rate_limit:',
      enterpriseTTLBuffer: parseInt(
        process.env.ENTERPRISE_RATE_LIMIT_TTL_BUFFER || '60'
      ),
    },

    // Auth Service Configuration
    auth: {
      defaultLimit: parseInt(process.env.AUTH_DEFAULT_LIMIT || '20'),
      maxLoginAttempts: parseInt(process.env.AUTH_MAX_LOGIN_ATTEMPTS || '5'),
      lockoutDuration:
        parseInt(process.env.AUTH_LOCKOUT_DURATION_MINUTES || '15') * 60 * 1000,
      maxFailedAttempts: parseInt(process.env.AUTH_MAX_FAILED_ATTEMPTS || '10'),
      accountLockDuration:
        parseInt(process.env.AUTH_ACCOUNT_LOCK_DURATION_MINUTES || '60') *
        60 *
        1000,
      passwordMinLength: parseInt(process.env.AUTH_PASSWORD_MIN_LENGTH || '8'),
      passwordMaxLength: parseInt(
        process.env.AUTH_PASSWORD_MAX_LENGTH || '128'
      ),
      bcryptRounds: parseInt(process.env.AUTH_BCRYPT_ROUNDS || '10'),
      loginRateWindow:
        parseInt(process.env.AUTH_LOGIN_RATE_WINDOW_MINUTES || '15') *
        60 *
        1000,
      loginRateLimit: parseInt(process.env.AUTH_LOGIN_RATE_LIMIT || '10'),
    },

    // OAuth Configuration
    oauth: {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID || '',
        clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
        redirectUri:
          process.env.GOOGLE_REDIRECT_URI ||
          'http://localhost:3001/auth/google/callback',
      },
    },
  },
};

// ✅ MongoDB Configuration
export const MONGODB_URI =
  process.env.MONGODB_URI || 'mongodb://localhost:27017/auth_service';

// ✅ Export configuration
export const env = coreConfig;
export default coreConfig;

// ✅ Helper functions for service configurations
export const getServiceConfig = serviceName => {
  if (!coreConfig.services[serviceName]) {
    throw new Error(`Service configuration not found: ${serviceName}`);
  }
  return coreConfig.services[serviceName];
};

export const getAllServiceConfigs = () => {
  return coreConfig.services;
};

export const validateServiceConfigs = () => {
  const errors = [];

  // Validate required configurations
  const requiredServices = [
    'password',
    'jwk',
    'twoFactor',
    'email',
    'session',
    'rateLimit',
    'auth',
  ];

  for (const service of requiredServices) {
    if (!coreConfig.services[service]) {
      errors.push(`Missing service configuration: ${service}`);
    }
  }

  return errors;
};
