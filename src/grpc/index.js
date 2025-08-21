import { safeLogger } from '../config/logger.js';
import {
  startGrpcServer,
  stopGrpcServer,
  getGrpcServerHealth,
} from './server/auth.server.js';

/**
 * Simple gRPC Service Manager
 * Only essential functionality for auth service
 */

/**
 * Initialize gRPC services
 */
async function initializeGrpcServices() {
  try {
    await startGrpcServer();
    safeLogger.info('gRPC server started successfully');
  } catch (error) {
    safeLogger.warn('gRPC server failed to start, continuing without gRPC...', {
      error: error.message,
    });
    // Don't crash the service if gRPC fails
  }
}

/**
 * Register gRPC services
 */
function registerServices() {
  safeLogger.info('gRPC services registered');
}

/**
 * Shutdown gRPC services
 */
async function shutdownGrpcServices() {
  try {
    await stopGrpcServer();
    safeLogger.info('gRPC server shutdown complete');
  } catch (error) {
    safeLogger.error('Error during gRPC server shutdown', {
      error: error.message,
    });
  }
}

export {
  initializeGrpcServices,
  registerServices,
  shutdownGrpcServices,
  getGrpcServerHealth,
};
