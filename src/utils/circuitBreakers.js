/**
 * Circuit Breakers for Internal Service Communication
 *
 * Purpose: Protect authService from cascading failures when calling internal gRPC services
 * Features:
 * - Opossum-based circuit breakers
 * - Configurable timeouts and thresholds
 * - Event monitoring and logging
 * - Fallback handling
 */

import CircuitBreaker from 'opossum';
import { safeLogger } from '../config/logger.js';

/**
 * Circuit Breaker Configuration
 */
const CIRCUIT_BREAKER_CONFIG = {
  userService: {
    timeout: 5000, // 5 second timeout
    errorThresholdPercentage: 50, // Open after 50% errors
    resetTimeout: 30000, // Wait 30 seconds before retry
    volumeThreshold: 10, // Minimum calls before opening
    name: 'userService',
  },

  emailService: {
    timeout: 10000, // 10 second timeout
    errorThresholdPercentage: 30, // Open after 30% errors
    resetTimeout: 60000, // Wait 60 seconds before retry
    volumeThreshold: 5, // Minimum calls before opening
    name: 'emailService',
  },

  notificationService: {
    timeout: 5000, // 5 second timeout
    errorThresholdPercentage: 40, // Open after 40% errors
    resetTimeout: 30000, // Wait 30 seconds before retry
    volumeThreshold: 8, // Minimum calls before opening
    name: 'notificationService',
  },

  paymentService: {
    timeout: 15000, // 15 second timeout
    errorThresholdPercentage: 25, // Open after 25% errors
    resetTimeout: 120000, // Wait 2 minutes before retry
    volumeThreshold: 3, // Minimum calls before opening
    name: 'paymentService',
  },
};

/**
 * Create Circuit Breakers for Internal Services
 */
export const createCircuitBreakers = () => {
  const circuitBreakers = {};

  // Create circuit breaker for each service
  Object.entries(CIRCUIT_BREAKER_CONFIG).forEach(([serviceName, config]) => {
    circuitBreakers[serviceName] = new CircuitBreaker(async (...args) => {
      // This is a placeholder - actual service calls will be implemented
      // when the specific service clients are available
      throw new Error(`${serviceName} service call not implemented yet`);
    }, config);

    // Setup event listeners
    const breaker = circuitBreakers[serviceName];

    breaker.on('open', () => {
      safeLogger.warn(`Circuit breaker opened: ${serviceName}`, {
        service: serviceName,
        timestamp: new Date().toISOString(),
        stats: breaker.stats,
      });
    });

    breaker.on('close', () => {
      safeLogger.info(`Circuit breaker closed: ${serviceName}`, {
        service: serviceName,
        timestamp: new Date().toISOString(),
        stats: breaker.stats,
      });
    });

    breaker.on('halfOpen', () => {
      safeLogger.info(`Circuit breaker half-open: ${serviceName}`, {
        service: serviceName,
        timestamp: new Date().toISOString(),
      });
    });

    breaker.on('fallback', result => {
      safeLogger.info(`Using fallback for: ${serviceName}`, {
        service: serviceName,
        result,
        timestamp: new Date().toISOString(),
      });
    });

    breaker.on('timeout', () => {
      safeLogger.warn(`Circuit breaker timeout: ${serviceName}`, {
        service: serviceName,
        timestamp: new Date().toISOString(),
      });
    });

    breaker.on('reject', () => {
      safeLogger.warn(`Circuit breaker rejected: ${serviceName}`, {
        service: serviceName,
        timestamp: new Date().toISOString(),
      });
    });
  });

  return circuitBreakers;
};

/**
 * Get Circuit Breaker Health Status
 */
export const getCircuitBreakerHealth = circuitBreakers => {
  const health = {};

  Object.entries(circuitBreakers).forEach(([serviceName, breaker]) => {
    health[serviceName] = {
      state: breaker.opened
        ? 'OPEN'
        : breaker.halfOpen
          ? 'HALF_OPEN'
          : 'CLOSED',
      stats: {
        totalCount: breaker.stats.totalCount,
        errorCount: breaker.stats.errorCount,
        successCount: breaker.stats.successCount,
        fallbackCount: breaker.stats.fallbackCount,
        timeoutCount: breaker.stats.timeoutCount,
        rejectCount: breaker.stats.rejectCount,
        errorPercentage: breaker.stats.errorPercentage,
      },
      lastError: breaker.stats.lastError
        ? breaker.stats.lastError.message
        : null,
      lastSuccess: breaker.stats.lastSuccess
        ? new Date(breaker.stats.lastSuccess).toISOString()
        : null,
    };
  });

  return health;
};

/**
 * Reset All Circuit Breakers
 */
export const resetAllCircuitBreakers = circuitBreakers => {
  Object.entries(circuitBreakers).forEach(([serviceName, breaker]) => {
    breaker.close();
    safeLogger.info(`Reset circuit breaker: ${serviceName}`);
  });
};

/**
 * Get Circuit Breaker Statistics
 */
export const getCircuitBreakerStats = circuitBreakers => {
  const stats = {};

  Object.entries(circuitBreakers).forEach(([serviceName, breaker]) => {
    stats[serviceName] = {
      ...breaker.stats,
      lastError: breaker.stats.lastError
        ? breaker.stats.lastError.message
        : null,
      lastSuccess: breaker.stats.lastSuccess
        ? new Date(breaker.stats.lastSuccess).toISOString()
        : null,
    };
  });

  return stats;
};

export default {
  createCircuitBreakers,
  getCircuitBreakerHealth,
  resetAllCircuitBreakers,
  getCircuitBreakerStats,
};
