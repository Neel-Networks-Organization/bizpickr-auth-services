import grpc from '@grpc/grpc-js';
import protoLoader from '@grpc/proto-loader';
import path from 'path';
import { fileURLToPath } from 'url';
import { env } from '../../config/env.js';
import { safeLogger } from '../../config/logger.js';
import { ApiError } from '../../utils/index.js';
import * as authService from '../services/authService.js';
import { getCorrelationId } from '../../config/requestContext.js';
import { updateGrpcMetrics } from '../index.js';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROTO_PATH = path.join(__dirname, '../proto/auth.proto');
/**
 * Industry-level gRPC Server
 *
 * Features:
 * - Enhanced error handling and validation
 * - Performance monitoring and metrics
 * - Security and authentication
 * - Request/response logging
 * - Health monitoring
 * - Circuit breaker patterns
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
const authPackage = grpcObject.authPackage;
// Server metrics
const serverMetrics = {
  totalRequests: 0,
  successfulRequests: 0,
  failedRequests: 0,
  requestLatency: [],
  activeConnections: 0,
  lastHealthCheck: null,
  uptime: Date.now(),
  methodCallCounts: new Map(),
  errorCounts: new Map(),
};
// Server instance
const server = new grpc.Server({
  'grpc.keepalive_time_ms': 30000,
  'grpc.keepalive_timeout_ms': 5000,
  'grpc.keepalive_permit_without_calls': true,
  'grpc.http2.max_pings_without_data': 0,
  'grpc.http2.min_time_between_pings_ms': 10000,
  'grpc.http2.min_ping_interval_without_data_ms': 300000,
});
/**
 * Map API errors to gRPC errors
 * @param {Error} error - Error to map
 * @returns {Object} gRPC error object
 */
function mapToGrpcError(error) {
  let grpcError = {
    code: grpc.status.INTERNAL,
    message: 'Internal server error',
    details: error.message,
  };
  if (error instanceof ApiError) {
    switch (error.statusCode) {
      case 400:
        grpcError.code = grpc.status.INVALID_ARGUMENT;
        grpcError.message = 'Invalid request';
        break;
      case 401:
        grpcError.code = grpc.status.UNAUTHENTICATED;
        grpcError.message = 'Authentication failed';
        break;
      case 403:
        grpcError.code = grpc.status.PERMISSION_DENIED;
        grpcError.message = 'Permission denied';
        break;
      case 404:
        grpcError.code = grpc.status.NOT_FOUND;
        grpcError.message = 'Resource not found';
        break;
      case 409:
        grpcError.code = grpc.status.ALREADY_EXISTS;
        grpcError.message = 'Resource already exists';
        break;
      case 422:
        grpcError.code = grpc.status.FAILED_PRECONDITION;
        grpcError.message = 'Validation failed';
        break;
      case 429:
        grpcError.code = grpc.status.RESOURCE_EXHAUSTED;
        grpcError.message = 'Rate limit exceeded';
        break;
      case 500:
        grpcError.code = grpc.status.INTERNAL;
        grpcError.message = 'Internal server error';
        break;
      case 503:
        grpcError.code = grpc.status.UNAVAILABLE;
        grpcError.message = 'Service unavailable';
        break;
      default:
        grpcError.code = grpc.status.INTERNAL;
        grpcError.message = 'Unknown error';
    }
  }
  return grpcError;
}
/**
 * Create gRPC status object
 * @param {number} code - Status code
 * @param {string} message - Status message
 * @param {Array} details - Error details
 * @returns {Object} gRPC status object
 */
function createGrpcStatus(code, message, details = []) {
  return {
    code,
    message,
    details: details.join(', '),
  };
}
/**
 * Validate request data
 * @param {Object} data - Request data
 * @param {Array} requiredFields - Required fields
 * @returns {Object} Validation result
 */
function validateRequest(data, requiredFields) {
  const errors = [];
  for (const field of requiredFields) {
    if (
      !data[field] ||
      (typeof data[field] === 'string' && data[field].trim() === '')
    ) {
      errors.push(`${field} is required`);
    }
  }
  return {
    isValid: errors.length === 0,
    errors,
  };
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
  delete sanitized.refresh_token;
  return sanitized;
}
/**
 * Update server metrics
 * @param {string} type - Metric type
 * @param {Object} data - Additional data
 */
function updateServerMetrics(type, data = {}) {
  switch (type) {
    case 'request':
      serverMetrics.totalRequests++;
      break;
    case 'success':
      serverMetrics.successfulRequests++;
      break;
    case 'failure':
      serverMetrics.failedRequests++;
      if (data.error) {
        const errorType = data.error.constructor.name;
        serverMetrics.errorCounts.set(
          errorType,
          (serverMetrics.errorCounts.get(errorType) || 0) + 1
        );
      }
      break;
    case 'latency':
      if (data.latency) {
        serverMetrics.requestLatency.push(data.latency);
        if (serverMetrics.requestLatency.length > 100) {
          serverMetrics.requestLatency.shift();
        }
      }
      break;
    case 'method':
      if (data.method) {
        serverMetrics.methodCallCounts.set(
          data.method,
          (serverMetrics.methodCallCounts.get(data.method) || 0) + 1
        );
      }
      break;
  }
  // Also update global metrics
  updateGrpcMetrics(type, data);
}
/**
 * Wrapper for gRPC service methods with enhanced error handling
 * @param {Function} serviceMethod - Service method to wrap
 * @param {string} methodName - Method name for logging
 * @returns {Function} Wrapped service method
 */
function wrapServiceMethod(serviceMethod, methodName) {
  return async (call, callback) => {
    const startTime = Date.now();
    const correlationId =
      call.metadata.get('correlationId')[0] || getCorrelationId();
    try {
      // Update metrics
      updateServerMetrics('request', { method: methodName });
      updateServerMetrics('method', { method: methodName });
      // Log request
      safeLogger.info(`Processing gRPC ${methodName} request`, {
        method: methodName,
        correlationId,
        requestData: sanitizeRequestData(call.request),
        metadata: Object.fromEntries(call.metadata.entries()),
      });
      // Execute service method
      const result = await serviceMethod(call, callback);
      const processingTime = Date.now() - startTime;
      // Update metrics
      updateServerMetrics('success', { method: methodName });
      updateServerMetrics('latency', {
        latency: processingTime,
        method: methodName,
      });
      // Log success
      safeLogger.info(`gRPC ${methodName} completed successfully`, {
        method: methodName,
        correlationId,
        processingTime: `${processingTime}ms`,
        result: sanitizeRequestData(result),
      });
      return result;
    } catch (error) {
      const processingTime = Date.now() - startTime;
      // Update metrics
      updateServerMetrics('failure', { method: methodName, error });
      updateServerMetrics('latency', {
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
        requestData: sanitizeRequestData(call.request),
      });
      // Map error to gRPC error
      const grpcError = mapToGrpcError(error);
      callback(grpcError);
    }
  };
}
// Enhanced gRPC service implementation
const authServiceImpl = {
  Login: wrapServiceMethod(async (call, callback) => {
    const { email, password, device_id, ip_address, user_agent, metadata } =
      call.request;
    // Validate request
    const validation = validateRequest(call.request, ['email', 'password']);
    if (!validation.isValid) {
      throw new ApiError(400, 'Validation Error', validation.errors);
    }
    // Execute login
    const result = await authService.login({
      email,
      password,
      deviceId: device_id,
      ipAddress: ip_address,
      userAgent: user_agent,
      metadata: metadata || {},
    });
    callback(null, {
      token: result.token,
      refresh_token: result.refreshToken || '',
      user_id: result.userId,
      email: result.email,
      name: result.name,
      role: result.role || 'USER',
      status: result.status || 'ACTIVE',
      expires_at: result.expiresAt,
      session: result.session,
    });
  }, 'Login'),
  Register: wrapServiceMethod(async (call, callback) => {
    const { email, password, name, phone_number, role, metadata } =
      call.request;
    // Validate request
    const validation = validateRequest(call.request, [
      'email',
      'password',
      'name',
    ]);
    if (!validation.isValid) {
      throw new ApiError(400, 'Validation Error', validation.errors);
    }
    // Execute registration
    const result = await authService.register({
      email,
      password,
      name,
      phoneNumber: phone_number,
      role: role || 'USER',
      metadata: metadata || {},
    });
    callback(null, {
      user_id: result.userId,
      email: result.email,
      name: result.name,
      status: result.status || 'PENDING_VERIFICATION',
      created_at: result.createdAt,
    });
  }, 'Register'),
  ValidateToken: wrapServiceMethod(async (call, callback) => {
    const { token, device_id, metadata } = call.request;
    // Validate request
    const validation = validateRequest(call.request, ['token']);
    if (!validation.isValid) {
      throw new ApiError(400, 'Validation Error', validation.errors);
    }
    // Execute token validation
    const result = await authService.validateToken(token, {
      deviceId: device_id,
      metadata: metadata || {},
    });
    callback(null, {
      valid: result.valid,
      user_id: result.userId,
      email: result.email,
      role: result.role,
      status: result.status,
      issued_at: result.issuedAt,
      expires_at: result.expiresAt,
      claims: result.claims || {},
    });
  }, 'ValidateToken'),
  RefreshToken: wrapServiceMethod(async (call, callback) => {
    const { refresh_token, device_id, metadata } = call.request;
    // Validate request
    const validation = validateRequest(call.request, ['refresh_token']);
    if (!validation.isValid) {
      throw new ApiError(400, 'Validation Error', validation.errors);
    }
    // Execute token refresh
    const result = await authService.refreshToken(refresh_token, {
      deviceId: device_id,
      metadata: metadata || {},
    });
    callback(null, {
      access_token: result.accessToken,
      refresh_token: result.refreshToken,
      expires_at: result.expiresAt,
    });
  }, 'RefreshToken'),
  Logout: wrapServiceMethod(async (call, callback) => {
    const { token, device_id, all_sessions, metadata } = call.request;
    // Validate request
    const validation = validateRequest(call.request, ['token']);
    if (!validation.isValid) {
      throw new ApiError(400, 'Validation Error', validation.errors);
    }
    // Execute logout
    const result = await authService.logout(token, {
      deviceId: device_id,
      allSessions: all_sessions || false,
      metadata: metadata || {},
    });
    callback(null, {
      success: result.success,
      sessions_terminated: result.sessionsTerminated || 1,
    });
  }, 'Logout'),
  GetSession: wrapServiceMethod(async (call, callback) => {
    const { user_id, device_id, metadata } = call.request;
    // Validate request
    const validation = validateRequest(call.request, ['user_id']);
    if (!validation.isValid) {
      throw new ApiError(400, 'Validation Error', validation.errors);
    }
    // Execute session retrieval
    const result = await authService.getSessions(user_id, {
      deviceId: device_id,
      metadata: metadata || {},
    });
    callback(null, {
      sessions: result.sessions || [],
      total_sessions: result.totalSessions || 0,
    });
  }, 'GetSession'),
  HealthCheck: wrapServiceMethod(async (call, callback) => {
    const { service_name, metadata } = call.request;
    // Execute health check
    const result = await authService.healthCheck({
      serviceName: service_name || 'auth-service',
      metadata: metadata || {},
    });
    callback(null, {
      status: result.status,
      version: result.version,
      timestamp: result.timestamp,
      details: result.details || {},
    });
  }, 'HealthCheck'),
};
// Add service to server
server.addService(authPackage.AuthService.service, authServiceImpl);
/**
 * Start gRPC server with enhanced error handling
 * @param {Object} options - Server options
 * @returns {Promise<void>}
 */
export const startGrpcServer = async (options = {}) => {
  // Use options port if provided, otherwise use config port
  const port = options.port || env.grpc.server.port || 50050;
  const host = options.host || env.grpc.server.host || 'localhost';
  const address = `${host}:${port}`;

  safeLogger.info('Starting gRPC server with address', {
    host,
    port,
    address,
    configPort: env.grpc?.server?.port,
    configHost: env.grpc?.server?.host,
  });
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    server.bindAsync(address, grpc.ServerCredentials.createInsecure(), err => {
      if (err) {
        const startupTime = Date.now() - startTime;
        safeLogger.error('Error starting gRPC server', {
          error: err.message,
          stack: err.stack,
          address,
          startupTime: `${startupTime}ms`,
        });
        reject(err);
        return;
      }
      const startupTime = Date.now() - startTime;
      safeLogger.info('gRPC server started successfully', {
        address,
        startupTime: `${startupTime}ms`,
        options,
      });
      resolve();
    });
  });
};
/**
 * Stop gRPC server gracefully
 * @returns {Promise<void>}
 */
export const stopGrpcServer = () => {
  return new Promise(resolve => {
    const shutdownTime = Date.now();
    server.tryShutdown(err => {
      const totalTime = Date.now() - shutdownTime;
      if (err) {
        safeLogger.error('Error during gRPC server graceful shutdown', {
          error: err.message,
          stack: err.stack,
          shutdownTime: `${totalTime}ms`,
        });
        // Force shutdown
        server.forceShutdown();
      }
      safeLogger.info('gRPC server stopped', {
        shutdownTime: `${totalTime}ms`,
        totalRequests: serverMetrics.totalRequests,
        successfulRequests: serverMetrics.successfulRequests,
        failedRequests: serverMetrics.failedRequests,
      });
      resolve();
    });
  });
};
/**
 * Get gRPC server health status
 * @returns {Promise<Object>} Health status
 */
export const getGrpcServerHealth = async () => {
  try {
    const uptime = Date.now() - serverMetrics.uptime;
    const successRate =
      serverMetrics.totalRequests > 0
        ? (serverMetrics.successfulRequests / serverMetrics.totalRequests) * 100
        : 0;
    const averageLatency =
      serverMetrics.requestLatency.length > 0
        ? serverMetrics.requestLatency.reduce((a, b) => a + b, 0) /
          serverMetrics.requestLatency.length
        : 0;
    return {
      status: 'healthy',
      uptime: `${Math.round(uptime / 1000)}s`,
      metrics: {
        totalRequests: serverMetrics.totalRequests,
        successfulRequests: serverMetrics.successfulRequests,
        failedRequests: serverMetrics.failedRequests,
        successRate: `${successRate.toFixed(2)}%`,
        averageLatency: `${averageLatency.toFixed(2)}ms`,
        methodCallCounts: Object.fromEntries(serverMetrics.methodCallCounts),
        errorCounts: Object.fromEntries(serverMetrics.errorCounts),
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
 * Get gRPC server metrics
 * @returns {Object} Server metrics
 */
export const getGrpcServerMetrics = () => {
  return {
    ...serverMetrics,
    currentTime: new Date().toISOString(),
    methodCallCounts: Object.fromEntries(serverMetrics.methodCallCounts),
    errorCounts: Object.fromEntries(serverMetrics.errorCounts),
  };
};
/**
 * Reset gRPC server metrics
 */
export const resetGrpcServerMetrics = () => {
  serverMetrics.totalRequests = 0;
  serverMetrics.successfulRequests = 0;
  serverMetrics.failedRequests = 0;
  serverMetrics.requestLatency = [];
  serverMetrics.methodCallCounts.clear();
  serverMetrics.errorCounts.clear();
  safeLogger.info('gRPC server metrics reset');
};
