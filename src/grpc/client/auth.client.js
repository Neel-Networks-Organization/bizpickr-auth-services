import grpc from '@grpc/grpc-js';
import protoLoader from '@grpc/proto-loader';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROTO_PATH = path.join(__dirname, '../proto/auth.proto');

/**
 * Clean gRPC Auth Client
 * For other services to call authService
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

/**
 * Create gRPC auth client
 * @param {string} host - Auth service host
 * @param {number} port - Auth service port
 * @returns {Object} gRPC client instance
 */
export function createAuthClient(host = 'localhost', port = 50050) {
  const address = `${host}:${port}`;
  return new authPackage.AuthService(
    address,
    grpc.credentials.createInsecure()
  );
}

/**
 * Auth Client Class
 * Provides clean methods for other services to call authService
 */
export class AuthClient {
  constructor(host = 'localhost', port = 50050) {
    this.client = createAuthClient(host, port);
    this.address = `${host}:${port}`;
  }

  /**
   * Wait for client to be ready
   * @param {number} timeoutMs - Timeout in milliseconds
   * @returns {Promise<boolean>}
   */
  async waitForReady(timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
      const deadline = new Date();
      deadline.setMilliseconds(deadline.getMilliseconds() + timeoutMs);

      this.client.waitForReady(deadline, error => {
        if (error) {
          reject(new Error(`gRPC client not ready: ${error.message}`));
        } else {
          resolve(true);
        }
      });
    });
  }

  /**
   * Get user by token
   * @param {string} token - JWT token
   * @returns {Promise<Object>} User information
   */
  async getUserByToken(token) {
    const result = await this.validateToken(token);
    if (result.valid) {
      return result.user;
    }
    throw new Error('Invalid token');
  }

  /**
   * Check if user is authenticated
   * @param {string} token - JWT token
   * @returns {Promise<boolean>} Is authenticated
   */
  async isAuthenticated(token) {
    try {
      const result = await this.validateToken(token);
      return result.valid;
    } catch (error) {
      return false;
    }
  }

  /**
   * Health check
   * @returns {Promise<Object>} Health status
   */
  async healthCheck() {
    return new Promise((resolve, reject) => {
      this.client.HealthCheck({}, (error, response) => {
        if (error) {
          reject(new Error(`Health check failed: ${error.message}`));
        } else {
          resolve(response);
        }
      });
    });
  }

  /**
   * Close client connection
   */
  close() {
    if (this.client) {
      this.client.close();
    }
  }
}

// Default client instance
export const authClient = new AuthClient();

// Export individual methods for convenience
export const { validateToken, getUserByToken, isAuthenticated, healthCheck } =
  authClient;
