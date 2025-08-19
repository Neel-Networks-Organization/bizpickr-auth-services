import sequelize from '../db/index.js';
import { redisClient } from '../db/redis.js';
import { getServiceRegistry } from '../grpc/index.js';
import { rabbitMQConnection } from '../events/index.js';
import { healthCheck as userClientHealthCheck } from '../grpc/client/user.client.js';
import mongoose from '../db/mongoose.js';
import { safeLogger } from '../config/logger.js';
import { userServiceCircuitBreaker } from '../grpc/client/user.client.js';

export async function checkDb() {
  try {
    await sequelize.authenticate();
    return 'up';
  } catch (error) {
    safeLogger.error('Database connection failed', { error: error.message });
    return 'down';
  }
}

export async function checkRedis() {
  try {
    if (redisClient && typeof redisClient.isConnected === 'function') {
      if (redisClient.isConnected()) {
        return 'up';
      } else {
        // Debug log for why it's not connected
        const health = redisClient.getHealth();
        safeLogger.debug('Redis health check failed', { health });
        return 'down';
      }
    }
    return 'down';
  } catch (err) {
    safeLogger.error('Redis health check error', { error: err.message });
    return 'down';
  }
}

export async function checkRabbitMQ() {
  try {
    if (
      rabbitMQConnection &&
      typeof rabbitMQConnection.getHealth === 'function'
    ) {
      const health = await rabbitMQConnection.getHealth();
      return health.status === 'connected' ? 'up' : 'down';
    }
    return 'down';
  } catch (error) {
    safeLogger.error('RabbitMQ health check failed', { error: error.message });
    return 'down';
  }
}

export async function checkGrpc() {
  const registry = getServiceRegistry();
  const grpcStatus = {};

  // Real-time check for user-client
  try {
    const userClientHealth = await userClientHealthCheck();
    grpcStatus['user-client'] =
      userClientHealth && userClientHealth.status === 'healthy' ? 'up' : 'down';
  } catch (error) {
    safeLogger.error('gRPC user client health check failed', {
      error: error.message,
    });
    grpcStatus['user-client'] = 'down';
  }

  // Add other services from registry (e.g. auth-server)
  for (const [name, service] of registry.entries()) {
    if (name !== 'user-client') {
      try {
        grpcStatus[name] = service.status === 'active' ? 'up' : 'down';
      } catch (error) {
        grpcStatus[name] = 'down';
      }
    }
  }

  return grpcStatus;
}

export async function checkMongoDB() {
  try {
    // 1 = connected, 2 = connecting, 0 = disconnected, 3 = disconnecting
    if (mongoose.connection.readyState === 1) {
      // Optionally, you can also run a ping command for deeper check
      await mongoose.connection.db.admin().ping();
      return 'up';
    } else {
      return 'down';
    }
  } catch (err) {
    safeLogger.error('MongoDB health check error', { error: err.message });
    return 'down';
  }
}

/**
 * Check circuit breaker health
 */
export const checkCircuitBreaker = async () => {
  try {
    const stats = userServiceCircuitBreaker.stats;
    const state = userServiceCircuitBreaker.opened ? 'open' : 'closed';

    return {
      status: state === 'open' ? 'degraded' : 'healthy',
      details: {
        service: 'UserService',
        state: state,
        totalCount: stats.totalCount,
        errorCount: stats.errorCount,
        successCount: stats.successCount,
        fallbackCount: stats.fallbackCount,
        timeoutCount: stats.timeoutCount,
        rejectCount: stats.rejectCount,
        isOpen: userServiceCircuitBreaker.opened,
      },
    };
  } catch (error) {
    safeLogger.error('Circuit breaker health check failed', {
      error: error.message,
    });
    return {
      status: 'unhealthy',
      details: { error: error.message },
    };
  }
};
