import { env } from './config/env.js';
import { app } from './app.js';
import sequelize, { initializeDatabase } from './db/index.js';
import { initRedis } from './db/redis.js';
import {
  initializeGrpcServices,
  registerServices,
  shutdownGrpcServices,
} from './grpc/index.js';
import { safeLogger } from './config/logger.js';
import { initializeRabbitMQ, shutdownRabbitMQ } from './events/index.js';
// Key rotation removed for simplicity
import { initializeCache, shutdownCache } from './cache/auth.cache.js';
// Performance monitoring simplified
import { initializeServices } from './services/initializeServices.js';
import { connectMongo } from './db/mongoose.js';

let isHealthy = false;
let startupComplete = false;
const gracefulShutdownConfig = {
  timeout: 30000, // 30 seconds
  forceTimeout: 10000,
  signals: ['SIGINT', 'SIGTERM', 'SIGUSR2'],
};

async function initializeCoreServices() {
  console.log('🚀 DEBUG: Starting initializeCoreServices');
  const startupSteps = [
    {
      name: 'Database Connection',
      fn: async () => {
        await initializeDatabase();
      },
    },
    {
      name: 'Redis Connection',
      fn: async () => {
        await initRedis();
      },
    },
    {
      name: 'Cache Initialization',
      fn: async () => {
        await initializeCache();
        await initializeServices();
      },
    },
    {
      name: 'gRPC Services',
      fn: async () => {
        await initializeGrpcServices();
        registerServices();
      },
    },
    {
      name: 'RabbitMQ Connection',
      fn: async () => {
        await initializeRabbitMQ();
      },
    },
    {
      name: 'MongoDB Connection',
      fn: async () => {
        await connectMongo();
      },
    },
  ];

  for (const step of startupSteps) {
    try {
      safeLogger.info(`🔄 Initializing ${step.name}...`);
      await step.fn();
      safeLogger.info(`✅ ${step.name} completed successfully`);
    } catch (error) {
      safeLogger.error(`❌ Failed to initialize ${step.name}`, {
        error: error.message,
        step: step.name,
      });
      throw error;
    }
  }
}
// ✅ Enhanced Server Startup
async function startServer() {
  try {
    safeLogger.info('🚀 Starting Auth Service...', {
      environment: env.NODE_ENV,
      port: env.PORT,
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      pid: process.pid,
    });
    await initializeCoreServices();

    console.log('🔍 DEBUG: Starting HTTP server on port', env.server.port);
    const server = app.listen(env.server.port, () => {
      startupComplete = true;
      isHealthy = true;
      safeLogger.info('⚙️ Server is running successfully', {
        port: env.server.port,
        uptime: process.uptime(),
        environment: env.NODE_ENV,
        version: process.env.npm_package_version || '1.0.0',
      });
      console.log('✅ DEBUG: HTTP server callback executed successfully');
    });

    console.log('🔍 DEBUG: HTTP server created, setting up event handlers');

    // ✅ Server Event Handlers
    server.on('error', error => {
      console.log('❌ DEBUG: Server error event triggered:', error.message);
      safeLogger.error('Server error', {
        error: error.message,
        code: error.code,
        stack: error.stack,
      });
    });

    // ✅ Enhanced Graceful Shutdown
    const gracefulShutdown = async signal => {
      safeLogger.info(`🔻 Graceful shutdown initiated by ${signal}`, {
        signal,
        uptime: process.uptime(),
      });
      isHealthy = false;
      startupComplete = false;
      // ✅ Set shutdown timeout
      const shutdownTimer = setTimeout(() => {
        safeLogger.error('Force shutdown due to timeout', {
          timeout: gracefulShutdownConfig.timeout,
        });
        process.exit(1);
      }, gracefulShutdownConfig.timeout);
      try {
        // ✅ Shutdown sequence
        const startTime = performance.now();
        const shutdownSteps = [
          {
            name: 'Stop accepting new connections',
            fn: () => {
              server.close();
              safeLogger.info('✅ Server stopped accepting new connections');
            },
          },
          {
            name: 'Shutdown gRPC Services',
            fn: async () => {
              await shutdownGrpcServices();
              safeLogger.info('✅ gRPC services shutdown complete');
            },
          },
          {
            name: 'Shutdown RabbitMQ',
            fn: async () => {
              await shutdownRabbitMQ();
              safeLogger.info('✅ RabbitMQ shutdown complete');
            },
          },

          {
            name: 'Shutdown Cache',
            fn: async () => {
              await shutdownCache();
              safeLogger.info('✅ Cache shutdown complete');
            },
          },
          {
            name: 'Close Database Connections',
            fn: async () => {
              await sequelize.close();
              safeLogger.info('✅ Database connections closed');
            },
          },
          {
            name: 'Close MongoDB Connection',
            fn: async () => {
              const { default: mongoose } = await import('./db/mongoose.js');
              await mongoose.connection.close();
              safeLogger.info('✅ MongoDB connection closed');
            },
          },
        ];
        for (const step of shutdownSteps) {
          try {
            safeLogger.info(`🔄 Shutting down ${step.name}...`);
            const stepStartTime = performance.now();
            await step.fn();
            const stepDuration = performance.now() - stepStartTime;
            safeLogger.info(
              `✅ ${step.name} completed in ${stepDuration.toFixed(2)}ms`
            );
          } catch (error) {
            safeLogger.error(`❌ Error during ${step.name} shutdown`, {
              error: error.message,
              step: step.name,
            });
          }
        }
        clearTimeout(shutdownTimer);
        const totalShutdownTime = performance.now() - startTime;
        safeLogger.info('🧹 Graceful shutdown completed', {
          totalShutdownTime: `${totalShutdownTime.toFixed(2)}ms`,
          uptime: process.uptime(),
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

    // ✅ Signal Handlers
    gracefulShutdownConfig.signals.forEach(signal => {
      process.on(signal, () => gracefulShutdown(signal));
    });

    // ✅ Health Monitoring
    setInterval(() => {
      const memUsage = process.memoryUsage();
      const cpuUsage = process.cpuUsage();
      // ✅ Memory threshold monitoring
      if (memUsage.heapUsed > 800 * 1024 * 1024) {
        // 800MB
        safeLogger.warn('High memory usage detected', {
          heapUsed: memUsage.heapUsed,
          heapTotal: memUsage.heapTotal,
          external: memUsage.external,
          rss: memUsage.rss,
        });
      }
      // ✅ CPU usage monitoring
      if (cpuUsage.user > 1000000) {
        // 1 second of CPU time
        safeLogger.warn('High CPU usage detected', {
          user: cpuUsage.user,
          system: cpuUsage.system,
        });
      }
      // ✅ Log periodic health status
      safeLogger.debug('Health check', {
        uptime: process.uptime(),
        memory: memUsage,
        cpu: cpuUsage,
        isHealthy,
        startupComplete,
      });
    }, 300000); // Every 5 minutes

    // ✅ Process Monitoring
    process.on('warning', warning => {
      safeLogger.warn('Process warning', {
        name: warning.name,
        message: warning.message,
        stack: warning.stack,
      });
    });

    // ✅ Uncaught Exception with Enhanced Logging
    process.on('uncaughtException', err => {
      safeLogger.error('Uncaught Exception', {
        message: err.message,
        stack: err.stack,
        correlationId: 'uncaught',
        timestamp: new Date().toISOString(),
        memory: process.memoryUsage(),
        cpu: process.cpuUsage(),
        uptime: process.uptime(),
      });
      gracefulShutdown('uncaughtException');
    });

    // ✅ Unhandled Rejection with Enhanced Logging
    process.on('unhandledRejection', (reason, promise) => {
      safeLogger.error('Unhandled Rejection', {
        reason: reason,
        promise: promise,
        correlationId: 'unhandled',
        timestamp: new Date().toISOString(),
        memory: process.memoryUsage(),
        cpu: process.cpuUsage(),
        uptime: process.uptime(),
      });
      gracefulShutdown('unhandledRejection');
    });

    console.log('✅ DEBUG: HTTP server setup completed successfully');
    return server;
  } catch (err) {
    safeLogger.error('❌ Startup failed', {
      message: err.message,
      stack: err.stack,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
    });
    // ✅ Attempt graceful shutdown on startup failure
    try {
      // Note: gracefulShutdown is defined inside the async function, so we can't call it here
      // Instead, we'll just exit the process
      safeLogger.error('Startup failed, exiting process');
      process.exit(1);
    } catch (shutdownError) {
      safeLogger.error('Failed to shutdown gracefully after startup failure', {
        error: shutdownError.message,
      });
      process.exit(1);
    }
  }
}

// ✅ Start the server
startServer();

// ✅ Export for testing
export { startServer, gracefulShutdownConfig };
