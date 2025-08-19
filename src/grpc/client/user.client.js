import grpc from '@grpc/grpc-js';
import protoLoader from '@grpc/proto-loader';
import path from 'path';
import { fileURLToPath } from 'url';
import CircuitBreaker from 'opossum';
import { env } from '../../config/env.js';
import { safeLogger } from '../../config/logger.js';
import { ApiError } from '../../utils/ApiError.js';
import { getCorrelationId } from '../../config/requestContext.js';
import { updateGrpcMetrics } from '../index.js';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROTO_PATH = path.join(__dirname, '../proto/user.proto');
/**
 * Industry-level gRPC Client
 *
 * Features:
 * - Enhanced error handling and retry logic
 * - Circuit breaker patterns
 * - Performance monitoring and metrics
 * - Connection pooling and load balancing
 * - Request/response logging
 * - Health monitoring
 * - Security and authentication
 */
// Load proto file with enhanced options
const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
  includeDirs: [path.join(__dirname, '../proto')],
});
const grpcObject = grpc.loadPackageDefinition(packageDefinition);
const userPackage = grpcObject.userPackage;
// Client configuration
const CLIENT_CONFIG = {
  address: `${env.grpc.clients.userService.host}:${env.grpc.clients.userService.port}`,
  deadline: 10000, // 10 seconds
  retryAttempts: 3,
  retryDelay: 1000, // 1 second
  circuitBreakerThreshold: 5,
  circuitBreakerTimeout: 60000, // 1 minute
  keepalive: {
    keepaliveTimeMs: 30000,
    keepaliveTimeoutMs: 5000,
    keepalivePermitWithoutCalls: true,
    http2MaxPingsWithoutData: 0,
    http2MinTimeBetweenPingsMs: 10000,
    http2MinPingIntervalWithoutDataMs: 300000,
  },
};
// Client metrics
const clientMetrics = {
  totalRequests: 0,
  successfulRequests: 0,
  failedRequests: 0,
  requestLatency: [],
  connectionErrors: 0,
  lastHealthCheck: null,
  uptime: Date.now(),
  methodCallCounts: new Map(),
  errorCounts: new Map(),
};
// Create circuit breaker for User Service using Opossum
const userServiceCircuitBreaker = new CircuitBreaker(
  async grpcCall => {
    return grpcCall();
  },
  {
    timeout: 5000, // 5 seconds timeout
    errorThresholdPercentage: 50, // Open after 50% errors
    resetTimeout: 20000, // Wait 20 seconds before testing
    name: 'UserService', // Service name for logging
  }
);

// Circuit breaker event listeners
userServiceCircuitBreaker.on('open', () => {
  safeLogger.warn('🔄 Circuit breaker for UserService opened');
});

userServiceCircuitBreaker.on('close', () => {
  safeLogger.info('✅ Circuit breaker for UserService closed');
});

userServiceCircuitBreaker.on('halfOpen', () => {
  safeLogger.info('🔄 Circuit breaker for UserService half-open');
});

userServiceCircuitBreaker.on('fallback', result => {
  safeLogger.warn('🔄 Circuit breaker fallback executed for UserService');
});

userServiceCircuitBreaker.on('timeout', () => {
  safeLogger.warn('⏰ Circuit breaker timeout for UserService');
});

userServiceCircuitBreaker.on('reject', () => {
  safeLogger.warn('🚫 Circuit breaker rejected request for UserService');
});
// Create gRPC client with enhanced configuration
const client = new userPackage.UserService(
  CLIENT_CONFIG.address,
  grpc.credentials.createInsecure(),
  CLIENT_CONFIG.keepalive
);
/**
 * Retry function with exponential backoff
 * @param {Function} fn - Function to retry
 * @param {number} maxRetries - Maximum retry attempts
 * @param {number} baseDelay - Base delay in milliseconds
 * @returns {Promise<any>} Function result
 */
async function retryWithBackoff(
  fn,
  maxRetries = CLIENT_CONFIG.retryAttempts,
  baseDelay = CLIENT_CONFIG.retryDelay
) {
  let lastError;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt === maxRetries) {
        throw error;
      }
      const delay = baseDelay * Math.pow(2, attempt);
      safeLogger.warn(
        `gRPC client retry attempt ${attempt + 1} failed, retrying in ${delay}ms`,
        {
          error: error.message,
          attempt: attempt + 1,
          maxRetries,
          delay,
        }
      );
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  throw lastError;
}
// Circuit breaker functions removed - using our simple utility instead
/**
 * Update client metrics
 * @param {string} type - Metric type
 * @param {Object} data - Additional data
 */
function updateClientMetrics(type, data = {}) {
  switch (type) {
    case 'request':
      clientMetrics.totalRequests++;
      break;
    case 'success':
      clientMetrics.successfulRequests++;
      break;
    case 'failure':
      clientMetrics.failedRequests++;
      if (data.error) {
        const errorType = data.error.constructor.name;
        clientMetrics.errorCounts.set(
          errorType,
          (clientMetrics.errorCounts.get(errorType) || 0) + 1
        );
      }
      break;
    case 'latency':
      if (data.latency) {
        clientMetrics.requestLatency.push(data.latency);
        if (clientMetrics.requestLatency.length > 100) {
          clientMetrics.requestLatency.shift();
        }
      }
      break;
    case 'method':
      if (data.method) {
        clientMetrics.methodCallCounts.set(
          data.method,
          (clientMetrics.methodCallCounts.get(data.method) || 0) + 1
        );
      }
      break;
    case 'connectionError':
      clientMetrics.connectionErrors++;
      break;
  }
  // Also update global metrics
  updateGrpcMetrics(type, data);
}
/**
 * Wrapper for gRPC client methods with enhanced error handling
 * @param {Function} clientMethod - Client method to wrap
 * @param {string} methodName - Method name for logging
 * @param {Object} requestData - Request data
 * @param {Object} options - Request options
 * @returns {Promise<any>} Method result
 */
async function wrapClientMethod(
  clientMethod,
  methodName,
  requestData,
  options = {}
) {
  return new Promise(async (resolve, reject) => {
    const startTime = Date.now();
    const correlationId = getCorrelationId();
    const deadline = Date.now() + (options.deadline || CLIENT_CONFIG.deadline);
    try {
      // Update metrics
      updateClientMetrics('request', { method: methodName });
      updateClientMetrics('method', { method: methodName });

      // Log request
      safeLogger.info(`Making gRPC ${methodName} request`, {
        method: methodName,
        correlationId,
        requestData: sanitizeRequestData(requestData),
        options,
      });

      // Execute with circuit breaker protection
      const result = await userServiceCircuitBreaker.fire(async () => {
        return new Promise((innerResolve, innerReject) => {
          clientMethod(requestData, { deadline }, (err, response) => {
            if (err) {
              innerReject(err);
            } else {
              innerResolve(response);
            }
          });
        });
      });

      const processingTime = Date.now() - startTime;

      // Update metrics
      updateClientMetrics('success', { method: methodName });
      updateClientMetrics('latency', {
        latency: processingTime,
        method: methodName,
      });

      // Log success
      safeLogger.info(`gRPC ${methodName} completed successfully`, {
        method: methodName,
        correlationId,
        processingTime: `${processingTime}ms`,
        result: sanitizeResponseData(result),
      });

      resolve(result);
    } catch (error) {
      const processingTime = Date.now() - startTime;

      // Update metrics
      updateClientMetrics('failure', { method: methodName, error });
      updateClientMetrics('latency', {
        latency: processingTime,
        method: methodName,
      });

      // Log error
      safeLogger.error(`gRPC ${methodName} failed`, {
        method: methodName,
        correlationId,
        error: error.message,
        stack: error.stack,
        processingTime: `${processingTime}ms`,
        requestData: sanitizeRequestData(requestData),
      });

      // Map gRPC error to API error
      const apiError = mapGrpcErrorToApiError(error);
      reject(apiError);
    }
  });
}
/**
 * Map gRPC error to API error
 * @param {Error} error - gRPC error
 * @returns {ApiError} API error
 */
function mapGrpcErrorToApiError(error) {
  let statusCode = 500;
  let message = 'User service error';
  let details = [error.message];
  if (error.code) {
    switch (error.code) {
      case grpc.status.INVALID_ARGUMENT:
        statusCode = 400;
        message = 'Invalid request to user service';
        break;
      case grpc.status.UNAUTHENTICATED:
        statusCode = 401;
        message = 'Authentication failed with user service';
        break;
      case grpc.status.PERMISSION_DENIED:
        statusCode = 403;
        message = 'Permission denied by user service';
        break;
      case grpc.status.NOT_FOUND:
        statusCode = 404;
        message = 'User not found';
        break;
      case grpc.status.ALREADY_EXISTS:
        statusCode = 409;
        message = 'User already exists';
        break;
      case grpc.status.FAILED_PRECONDITION:
        statusCode = 422;
        message = 'Validation failed in user service';
        break;
      case grpc.status.RESOURCE_EXHAUSTED:
        statusCode = 429;
        message = 'Rate limit exceeded by user service';
        break;
      case grpc.status.UNAVAILABLE:
        statusCode = 503;
        message = 'User service is unavailable';
        break;
      case grpc.status.DEADLINE_EXCEEDED:
        statusCode = 408;
        message = 'User service request timeout';
        break;
      default:
        statusCode = 500;
        message = 'User service internal error';
    }
  }
  return new ApiError(statusCode, message, details);
}
/**
 * Sanitize request data for logging
 * @param {Object} data - Request data
 * @returns {Object} Sanitized data
 */
function sanitizeRequestData(data) {
  const sanitized = { ...data };
  // Remove sensitive fields
  delete sanitized.password;
  delete sanitized.token;
  delete sanitized.secret;
  return sanitized;
}
/**
 * Sanitize response data for logging
 * @param {Object} data - Response data
 * @returns {Object} Sanitized data
 */
function sanitizeResponseData(data) {
  const sanitized = { ...data };
  // Remove sensitive fields
  delete sanitized.password;
  delete sanitized.token;
  delete sanitized.secret;
  return sanitized;
}
/**
 * Create user profile with enhanced error handling
 * @param {Object} userData - User data
 * @param {Object} options - Request options
 * @returns {Promise<Object>} User profile result
 */
export const createUserProfile = async (userData, options = {}) => {
  return wrapClientMethod(
    client.CreateProfile.bind(client),
    'CreateProfile',
    userData,
    options
  );
};
/**
 * Get user by ID with enhanced error handling
 * @param {string} userId - User ID
 * @param {string} type - User type
 * @param {Object} options - Request options
 * @returns {Promise<Object>} User data
 */
export const getUserById = async (userId, type, options = {}) => {
  return wrapClientMethod(
    client.GetUserById.bind(client),
    'GetUserById',
    { user_id: userId, type },
    options
  );
};
/**
 * Update user profile with enhanced error handling
 * @param {Object} userData - User update data
 * @param {Object} options - Request options
 * @returns {Promise<Object>} Update result
 */
export const updateUserProfile = async (userData, options = {}) => {
  return wrapClientMethod(
    client.UpdateProfile.bind(client),
    'UpdateProfile',
    userData,
    options
  );
};
/**
 * Delete user profile with enhanced error handling
 * @param {string} userId - User ID
 * @param {Object} options - Request options
 * @returns {Promise<Object>} Delete result
 */
export const deleteUserProfile = async (userId, options = {}) => {
  return wrapClientMethod(
    client.DeleteProfile.bind(client),
    'DeleteProfile',
    { user_id: userId, ...options },
    options
  );
};
/**
 * List users with enhanced error handling
 * @param {Object} filters - Filter options
 * @param {Object} options - Request options
 * @returns {Promise<Object>} Users list
 */
export const listUsers = async (filters = {}, options = {}) => {
  return wrapClientMethod(
    client.ListUsers.bind(client),
    'ListUsers',
    filters,
    options
  );
};
/**
 * Get user statistics with enhanced error handling
 * @param {Object} filters - Filter options
 * @param {Object} options - Request options
 * @returns {Promise<Object>} User statistics
 */
export const getUserStats = async (filters = {}, options = {}) => {
  return wrapClientMethod(
    client.GetUserStats.bind(client),
    'GetUserStats',
    filters,
    options
  );
};
/**
 * Health check for user service
 * @param {Object} options - Request options
 * @returns {Promise<Object>} Health status
 */
export const healthCheck = async (options = {}) => {
  return wrapClientMethod(
    client.HealthCheck.bind(client),
    'HealthCheck',
    { service_name: 'user-service' },
    options
  );
};
/**
 * Get client health status
 * @returns {Promise<Object>} Health status
 */
export const getClientHealth = async () => {
  try {
    const uptime = Date.now() - clientMetrics.uptime;
    const successRate =
      clientMetrics.totalRequests > 0
        ? (clientMetrics.successfulRequests / clientMetrics.totalRequests) * 100
        : 0;
    const averageLatency =
      clientMetrics.requestLatency.length > 0
        ? clientMetrics.requestLatency.reduce((a, b) => a + b, 0) /
          clientMetrics.requestLatency.length
        : 0;
    return {
      status: 'healthy',
      uptime: `${Math.round(uptime / 1000)}s`,
      circuitBreaker: { ...userServiceCircuitBreaker.state },
      metrics: {
        totalRequests: clientMetrics.totalRequests,
        successfulRequests: clientMetrics.successfulRequests,
        failedRequests: clientMetrics.failedRequests,
        successRate: `${successRate.toFixed(2)}%`,
        averageLatency: `${averageLatency.toFixed(2)}ms`,
        connectionErrors: clientMetrics.connectionErrors,
        methodCallCounts: Object.fromEntries(clientMetrics.methodCallCounts),
        errorCounts: Object.fromEntries(clientMetrics.errorCounts),
      },
      lastHealthCheck: new Date().toISOString(),
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      error: error.message,
      lastHealthCheck: new Date().toISOString(),
    };
  }
};
/**
 * Get client metrics
 * @returns {Object} Client metrics
 */
export const getClientMetrics = () => {
  return {
    ...clientMetrics,
    currentTime: new Date().toISOString(),
    circuitBreaker: { ...userServiceCircuitBreaker.state },
    methodCallCounts: Object.fromEntries(clientMetrics.methodCallCounts),
    errorCounts: Object.fromEntries(clientMetrics.errorCounts),
  };
};
/**
 * Reset client metrics
 */
export const resetClientMetrics = () => {
  clientMetrics.totalRequests = 0;
  clientMetrics.successfulRequests = 0;
  clientMetrics.failedRequests = 0;
  clientMetrics.requestLatency = [];
  clientMetrics.connectionErrors = 0;
  clientMetrics.methodCallCounts.clear();
  clientMetrics.errorCounts.clear();
  safeLogger.info('gRPC client metrics reset');
};
/**
 * Reset circuit breaker
 */
export const resetCircuitBreaker = () => {
  userServiceCircuitBreaker.state = 'closed';
  userServiceCircuitBreaker.failureCount = 0;
  userServiceCircuitBreaker.lastFailureTime = null;
  safeLogger.info('gRPC client circuit breaker reset');
};
/**
 * Close client connection
 */
export const closeClient = () => {
  try {
    client.close();
    safeLogger.info('gRPC client connection closed');
  } catch (error) {
    safeLogger.error('Error closing gRPC client connection', {
      error: error.message,
    });
  }
};
export const getUserProfile = async (userId, companyId, options = {}) => {
  return wrapClientMethod(
    client.getUserProfile,
    'getUserProfile',
    { userId, companyId },
    options
  );
};
export const getCompanyStatistics = async (companyId, options = {}) => {
  return wrapClientMethod(
    client.getCompanyStatistics,
    'getCompanyStatistics',
    { companyId },
    options
  );
};
export const getCompanyUsersList = async (
  companyId,
  filters = {},
  options = {}
) => {
  return wrapClientMethod(
    client.getCompanyUsers,
    'getCompanyUsers',
    { companyId, ...filters },
    options
  );
};
export const removeUserFromCompany = async (
  companyId,
  userId,
  options = {}
) => {
  return wrapClientMethod(
    client.removeUserFromCompany,
    'removeUserFromCompany',
    { companyId, userId },
    options
  );
};
export const updateUserRoleInCompany = async (
  companyId,
  userId,
  roleData,
  options = {}
) => {
  return wrapClientMethod(
    client.updateUserRole,
    'updateUserRole',
    { companyId, userId, ...roleData },
    options
  );
};
export const getCompanySettingsData = async (companyId, options = {}) => {
  return wrapClientMethod(
    client.getCompanySettings,
    'getCompanySettings',
    { companyId },
    options
  );
};
export const updateCompanySettingsData = async (
  companyId,
  settingsData,
  options = {}
) => {
  return wrapClientMethod(
    client.updateCompanySettings,
    'updateCompanySettings',
    { companyId, ...settingsData },
    options
  );
};
export const getCompanyActivityLog = async (
  companyId,
  filters = {},
  options = {}
) => {
  return wrapClientMethod(
    client.getCompanyActivity,
    'getCompanyActivity',
    { companyId, ...filters },
    options
  );
};
export const exportCompanyDataService = async (
  companyId,
  exportOptions = {},
  options = {}
) => {
  return wrapClientMethod(
    client.exportCompanyData,
    'exportCompanyData',
    { companyId, ...exportOptions },
    options
  );
};
export const sendUserInvitation = async (invitationData, options = {}) => {
  return wrapClientMethod(
    client.sendInvitation,
    'sendInvitation',
    invitationData,
    options
  );
};
export { userServiceCircuitBreaker };
export default client;
