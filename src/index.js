import { env } from './config/env.js';
import { app } from './app.js';
import { initializeDatabase, closeDatabase } from './db/index.js';
import { initRedis } from './db/redis.js';
import { initializeGrpcServices, shutdownGrpcServices } from './grpc/index.js';
import { safeLogger } from './config/logger.js';
import { initializeRabbitMQ, shutdownRabbitMQ } from './events/index.js';
import { initializeCache, shutdownCache } from './cache/auth.cache.js';
import {
  initializeGeneralCache,
  shutdownGeneralCache,
} from './cache/general.cache.js';
import { connectMongo } from './db/mongoose.js';
import {
  initializeJWKService,
  shutdownJWKService,
} from './services/jwk.service.js';

async function initializeServices() {
  try {
    await initializeDatabase();
    await initRedis();
    await initializeCache();
    await initializeGeneralCache();
    await initializeGrpcServices();
    await initializeRabbitMQ();
    await connectMongo();
    await initializeJWKService();
    safeLogger.info('All services initialized successfully');
  } catch (error) {
    safeLogger.error('Service initialization failed', { error: error.message });
    throw error;
  }
}

async function startServer() {
  try {
    safeLogger.info('Starting Auth Service...', { port: env.server.port });
    await initializeServices();

    const server = app.listen(env.server.port, () => {
      safeLogger.info('Server running', { port: env.server.port });
    });

    const gracefulShutdown = async signal => {
      safeLogger.info(`Shutdown initiated by ${signal}`);
      try {
        server.close();
        await shutdownGrpcServices();
        await shutdownRabbitMQ();
        await shutdownCache();
        await shutdownGeneralCache();
        await shutdownJWKService();
        await closeDatabase();
        const { default: mongoose } = await import('./db/mongoose.js');
        await mongoose.connection.close();
        safeLogger.info('Graceful shutdown completed');
        process.exit(0);
      } catch (error) {
        safeLogger.error('Shutdown error', { error: error.message });
        process.exit(1);
      }
    };

    ['SIGINT', 'SIGTERM'].forEach(signal => {
      process.on(signal, () => gracefulShutdown(signal));
    });

    process.on('uncaughtException', err => {
      safeLogger.error('Uncaught Exception', { error: err.message });
      process.exit(1);
    });

    process.on('unhandledRejection', reason => {
      safeLogger.error('Unhandled Rejection', { reason });
      process.exit(1);
    });

    return server;
  } catch (err) {
    safeLogger.error('Startup failed', { error: err.message });
    process.exit(1);
  }
}

startServer();
export { startServer };
