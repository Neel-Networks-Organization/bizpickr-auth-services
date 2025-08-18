/**
 * Development Environment Configuration
 *
 * This file contains all development-specific settings
 * Replace .env files with this structured configuration
 */

import { safeLogger } from "../logger.js";

// Development environment configuration
export const developmentConfig = {
  // ========================================
  // CORE CONFIGURATION
  // ========================================
  core: {
    nodeEnv: "development",
    port: 3001,
    host: "localhost",
    apiVersion: "v1",
    baseUrl: "http://localhost:3001",
  },

  // ========================================
  // DATABASE CONFIGURATION
  // ========================================
  database: {
    mysql: {
      host: "localhost",
      port: 3306,
      database: "auth_service_dev",
      username: "root",
      password: "Develop@NN!2345", // Change this in production
      pool: {
        max: 5,
        min: 0,
        acquire: 30000,
        idle: 10000,
      },
      logging: false, // Disable SQL logging in development
      timezone: "+00:00",
    },
    mongodb: {
      uri: "mongodb://localhost:27017/auth_service_dev",
    },
  },

  // ========================================
  // REDIS CONFIGURATION
  // ========================================
  redis: {
    host: "127.0.0.1",
    port: 6379,
    password: "",
    db: 0,
    retryDelay: 100,
    maxRetries: 3,
    clusterEnabled: false,
    sentinelEnabled: false,
  },

  // ========================================
  // RABBITMQ CONFIGURATION
  // ========================================
  rabbitmq: {
    url: "amqp://localhost",
    host: "localhost",
    port: 5672,
    username: "guest",
    password: "guest",
    vhost: "/",
    heartbeat: 60,
    timeout: 30000,
    prefetch: 10,
  },

  // ========================================
  // JWT & AUTHENTICATION
  // ========================================
  auth: {
    jwt: {
      secret: "dev-jwt-secret-change-in-production",
      expiry: "15m",
    },
    refreshToken: {
      secret: "dev-refresh-secret-change-in-production",
      expiry: "7d",
    },
    cookie: {
      secret: "dev-cookie-secret-change-in-production",
      domain: "localhost",
      httpOnly: true,
      secure: false, // false for development
      sameSite: "lax",
    },
  },

  // ========================================
  // SECURITY CONFIGURATION
  // ========================================
  security: {
    bcrypt: {
      rounds: 10,
    },
    password: {
      minLength: 8,
      maxLength: 128,
    },
    rateLimit: {
      windowMs: 900000, // 15 minutes
      max: 1000, // Increased for development
    },
    cors: {
      origins: [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:8080",
      ],
      credentials: true,
      maxAge: 86400,
    },
    headers: {
      enableHelmet: true,
      enableHsts: false, // Disabled for development
      enableCsp: true,
    },
    csrf: {
      enabled: false, // Disabled for development
      tokenLength: 32,
      tokenExpiry: 3600,
    },
    session: {
      secret: "dev-session-secret-change-in-production",
      maxAge: 86400000,
      secure: false, // false for development
    },
    encryption: {
      key: "dev-32-char-encryption-key-here",
      algorithm: "aes-256-gcm",
    },
  },

  // ========================================
  // gRPC CONFIGURATION
  // ========================================
  grpc: {
    server: {
      host: "localhost",
      port: 50051,
      maxReceiveLength: 4194304,
      maxSendLength: 4194304,
      keepaliveTime: 30000,
      keepaliveTimeout: 5000,
      maxPings: 2,
    },
    services: {
      user: {
        host: "localhost",
        port: 50051,
        timeout: 5000,
      },
    },
  },

  // ========================================
  // EXTERNAL SERVICES
  // ========================================
  services: {
    user: {
      url: "http://localhost:8900",
      timeout: 5000,
      retries: 3,
    },
    notification: {
      url: "http://localhost:8901",
      timeout: 5000,
      retries: 3,
    },
  },

  // ========================================
  // OAUTH PROVIDERS
  // ========================================
  oauth: {
    google: {
      enabled: false,
      clientId: "",
      clientSecret: "",
      redirectUri: "http://localhost:3001/auth/google/callback",
    },
    facebook: {
      enabled: false,
      clientId: "",
      clientSecret: "",
      redirectUri: "",
    },
    github: {
      enabled: false,
      clientId: "",
      clientSecret: "",
      redirectUri: "",
    },
  },

  // ========================================
  // CRYPTO & KEY MANAGEMENT
  // ========================================
  crypto: {
    privateKeyExpiry: "1h",
    keyRotationTime: "2h",
    privateKeyRetention: "2h",
    keySize: 2048,
  },

  // ========================================
  // FEATURE FLAGS
  // ========================================
  features: {
    emailVerification: false, // Disabled for development
    phoneVerification: false,
    twoFactorAuth: false,
    socialLogin: false,
    passwordReset: true,
    accountLockout: false, // Disabled for development
    auditLogging: false, // Disabled for development
    metrics: false, // Disabled for development
  },

  // ========================================
  // MONITORING & OBSERVABILITY
  // ========================================
  monitoring: {
    enabled: false, // Disabled for development
    metrics: {
      enabled: false,
      port: 9090,
      path: "/metrics",
    },
    healthCheck: {
      enabled: true,
      path: "/health",
      interval: 30000,
    },
    tracing: {
      enabled: false,
      jaeger: {
        host: "localhost",
        port: 6832,
      },
    },
  },

  // ========================================
  // LOGGING CONFIGURATION
  // ========================================
  logging: {
    level: "warn", // Only warnings and errors in development
    format: "json",
    timestamp: true,
    colorize: true,
    console: true,
    file: {
      enabled: false, // Disabled for development
      maxSize: "10m",
      maxFiles: "14d",
      compress: true,
    },
    external: {
      enabled: false,
      service: "",
      apiKey: "",
      endpoint: "",
    },
    // Development-specific logging controls
    audit: false, // Disable audit logging
    cache: false, // Disable cache logging
    grpc: false, // Disable gRPC logging
    rabbitmq: false, // Disable RabbitMQ logging
    database: false, // Disable database logging
    http: false, // Disable HTTP request logging
  },

  // ========================================
  // CACHE CONFIGURATION
  // ========================================
  cache: {
    enabled: true,
    ttl: 3600,
    maxSize: 1000,
    compression: true,
  },

  // ========================================
  // EMAIL CONFIGURATION
  // ========================================
  email: {
    enabled: false, // Disabled for development
    provider: "smtp",
    from: "dev@example.com",
    smtp: {
      host: "localhost",
      port: 1025,
      secure: false,
      username: "",
      password: "",
    },
    sendgrid: {
      apiKey: "",
    },
    aws: {
      region: "us-east-1",
      accessKeyId: "",
      secretAccessKey: "",
    },
  },

  // ========================================
  // SMS CONFIGURATION
  // ========================================
  sms: {
    enabled: false,
    provider: "twilio",
    twilio: {
      accountSid: "",
      authToken: "",
      fromNumber: "",
    },
  },

  // ========================================
  // COMPLIANCE CONFIGURATION
  // ========================================
  compliance: {
    gdpr: {
      enabled: false, // Disabled for development
      userDataRetention: 220752000000,
      auditLogsRetention: 63072000000,
      sessionDataRetention: 2592000000,
      consentRequired: false,
      dataMinimization: false,
      purposeLimitation: false,
    },
    sox: {
      enabled: false,
      auditTrail: false,
      dataIntegrity: false,
      accessControl: false,
    },
    pci: {
      enabled: false,
      dataEncryption: false,
      accessControl: false,
      auditLogging: false,
    },
  },

  // ========================================
  // DEVELOPMENT UTILITIES
  // ========================================
  dev: {
    debugMode: false,
    hotReload: true,
    autoSeed: true,
    mockData: false,
    // Development-specific features
    skipAuth: false, // Skip authentication for testing
    mockExternalServices: true, // Mock external service calls
    enableTestEndpoints: true, // Enable test-only endpoints
    verboseErrors: true, // Show detailed error messages
  },
};

// Development utilities
export const devUtils = {
  // Log development info
  logDevInfo: () => {
    safeLogger.info("🚀 Development environment loaded", {
      nodeEnv: developmentConfig.core.nodeEnv,
      port: developmentConfig.core.port,
      database: developmentConfig.database.mysql.host,
      logLevel: developmentConfig.logging.level,
      features: {
        auditLogging: developmentConfig.features.auditLogging,
        metrics: developmentConfig.features.metrics,
        emailVerification: developmentConfig.features.emailVerification,
      },
    });
  },

  // Check development requirements
  checkDevRequirements: () => {
    const required = ["DB_HOST", "DB_USER", "DB_PASSWORD", "JWT_SECRET"];
    const missing = required.filter((key) => !process.env[key]);

    if (missing.length > 0) {
      safeLogger.error("Missing required environment variables", { missing });
      safeLogger.info(
        "Using development config from config/environments/development.js"
      );
      return true; // Continue with development config
    }

    return true;
  },

  // Development health check
  devHealthCheck: async () => {
    try {
      // Check database connections
      const { sequelize } = await import("../../db/index.js");
      await sequelize.authenticate();

      const { connectMongo } = await import("../../db/mongoose.js");
      await connectMongo();

      safeLogger.info("✅ Development health check passed");
      return true;
    } catch (error) {
      safeLogger.error("❌ Development health check failed", {
        error: error.message,
      });
      return false;
    }
  },

  // Get development configuration
  getConfig: () => developmentConfig,

  // Check if feature is enabled
  isFeatureEnabled: (featureName) => {
    return developmentConfig.features[featureName] || false;
  },

  // Check if logging is enabled
  isLoggingEnabled: (logType) => {
    return developmentConfig.logging[logType] || false;
  },
};

export default developmentConfig;
