import grpc from '@grpc/grpc-js';
import protoLoader from '@grpc/proto-loader';
import path from 'path';
import { fileURLToPath } from 'url';
import { env } from '../../config/env.js';
import { safeLogger } from '../../config/logger.js';
import { ApiError } from '../../utils/index.js';
import * as authService from '../services/authService.js';
import { getCorrelationId } from '../../config/requestContext.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROTO_PATH = path.join(__dirname, '../proto/auth.proto');

/**
 * Simple gRPC Server for Auth Service
 * Essential functionality only
 */

// Load proto file
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

// Server instance
const server = new grpc.Server();

/**
 * Map API errors to gRPC errors
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
 * Wrapper for gRPC service methods with error handling
 */
function grpcMethodWrapper(methodName, handler) {
  return async(call, callback) => {
    const correlationId = getCorrelationId();
    const startTime = Date.now();

    try {
      safeLogger.info(`Processing gRPC ${methodName} request`, {
        correlationId,
        method: methodName,
        timestamp: new Date().toISOString(),
      });

      const result = await handler(call.request, call.metadata);
      const responseTime = Date.now() - startTime;

      safeLogger.info(`gRPC ${methodName} completed successfully`, {
        correlationId,
        method: methodName,
        responseTime: `${responseTime}ms`,
      });

      callback(null, result);
    } catch (error) {
      const responseTime = Date.now() - startTime;

      safeLogger.error(`gRPC ${methodName} failed`, {
        correlationId,
        method: methodName,
        error: error.message,
        responseTime: `${responseTime}ms`,
      });

      // Map error to gRPC error
      const grpcError = mapToGrpcError(error);
      callback(grpcError);
    }
  };
}

// gRPC service implementation
const authServiceImpl = {
  login: grpcMethodWrapper('login', async request => {
    const { email, password, device_info } = request;
    const result = await authService.login({
      email,
      password,
      deviceInfo: device_info,
    });
    return result;
  }),

  register: grpcMethodWrapper('register', async request => {
    const { email, password, full_name, type, role } = request;
    const result = await authService.register({
      email,
      password,
      fullName: full_name,
      type,
      role,
    });
    return result;
  }),

  validateToken: grpcMethodWrapper('validateToken', async request => {
    const { token } = request;
    const result = await authService.validateToken(token, {
      correlationId: getCorrelationId(),
    });
    return result;
  }),

  refreshToken: grpcMethodWrapper('refreshToken', async request => {
    const { refresh_token } = request;
    const result = await authService.refreshToken(refresh_token, {
      correlationId: getCorrelationId(),
    });
    return result;
  }),

  logout: grpcMethodWrapper('logout', async request => {
    const { token } = request;
    const result = await authService.logout(token, {
      correlationId: getCorrelationId(),
    });
    return result;
  }),

  getSessions: grpcMethodWrapper('getSessions', async request => {
    const { user_id } = request;
    const result = await authService.getSessions(user_id, {
      correlationId: getCorrelationId(),
    });
    return result;
  }),

  healthCheck: grpcMethodWrapper('healthCheck', async() => {
    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'auth-service',
    };
  }),
};

// Add service to server
server.addService(authPackage.AuthService.service, authServiceImpl);

/**
 * Start gRPC server
 */
export const startGrpcServer = async(options = {}) => {
  return new Promise((resolve, reject) => {
    const port = options.port || env.grpc.server.port || 50050;
    const host = options.host || env.grpc.server.host || 'localhost';
    const address = `${host}:${port}`;

    safeLogger.info('Starting gRPC server', {
      address,
      configPort: env.grpc?.server?.port,
      configHost: env.grpc?.server?.host,
    });

    server.bindAsync(address, grpc.ServerCredentials.createInsecure(), err => {
      if (err) {
        safeLogger.error('Error starting gRPC server', {
          error: err.message,
          address,
        });
        reject(err);
        return;
      }

      server.start();
      safeLogger.info('gRPC server started successfully', {
        address,
        port,
        host,
      });
      resolve();
    });
  });
};

/**
 * Stop gRPC server
 */
export const stopGrpcServer = () => {
  return new Promise(resolve => {
    try {
      server.tryShutdown(() => {
        safeLogger.info('gRPC server stopped');
        resolve();
      });
    } catch (error) {
      safeLogger.error('Error during gRPC server graceful shutdown', {
        error: error.message,
      });
      resolve();
    }
  });
};

/**
 * Get gRPC server health status
 */
export const getGrpcServerHealth = async() => {
  try {
    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'auth-service-grpc',
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString(),
    };
  }
};
