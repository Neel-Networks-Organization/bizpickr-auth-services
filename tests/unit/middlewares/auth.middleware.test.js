import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from '@jest/globals';
import jwt from 'jsonwebtoken';
import { ApiError } from '../../../src/utils/index.js';
import {
  verifyJWT,
  requireRole,
  requirePermission,
} from '../../../src/middlewares/auth.middleware.js';

// Mock dependencies
jest.mock('../../../src/models/authUser.model.js');
jest.mock('../../../src/config/logger.js');
jest.mock('../../../src/config/env.js');

import AuthUser from '../../../src/models/authUser.model.js';
import { safeLogger } from '../../../src/config/logger.js';
import { env } from '../../../src/config/env.js';

describe('Auth Middleware Unit Tests', () => {
  let mockReq, mockRes, mockNext;

  beforeEach(() => {
    jest.clearAllMocks();

    mockReq = {
      headers: {},
      ip: '192.168.1.1',
      path: '/api/test',
      correlationId: 'test-correlation-id',
    };
    mockRes = {};
    mockNext = jest.fn();

    // Mock environment
    env.JWT_SECRET = 'test-secret';
  });

  describe('verifyJWT', () => {
    it('should authenticate user with valid token', async () => {
      // Arrange
      const mockToken = 'valid-token';
      const mockDecoded = { userId: 'user-123' };
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isActive: true,
        permissions: [{ name: 'read', scope: 'user' }],
        role: { name: 'user', permissions: ['read'] },
      };

      mockReq.headers.authorization = `Bearer ${mockToken}`;

      jwt.verify.mockReturnValue(mockDecoded);
      AuthUser.findById.mockReturnValue({
        select: jest.fn().mockReturnValue({
          populate: jest.fn().mockResolvedValue(mockUser),
        }),
      });

      // Act
      await verifyJWT(mockReq, mockRes, mockNext);

      // Assert
      expect(jwt.verify).toHaveBeenCalledWith(mockToken, env.JWT_SECRET);
      expect(AuthUser.findById).toHaveBeenCalledWith('user-123');
      expect(mockReq.user).toEqual(mockUser);
      expect(mockReq.token).toBe(mockToken);
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should throw error if no token provided', async () => {
      // Arrange
      mockReq.headers.authorization = undefined;

      // Act
      await verifyJWT(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 401,
          message: 'Access token required',
        })
      );
    });

    it('should throw error if token format is invalid', async () => {
      // Arrange
      mockReq.headers.authorization = 'InvalidFormat token';

      // Act
      await verifyJWT(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 401,
          message: 'Access token required',
        })
      );
    });

    it('should throw error if token is invalid', async () => {
      // Arrange
      mockReq.headers.authorization = 'Bearer invalid-token';
      jwt.verify.mockImplementation(() => {
        throw new Error('Invalid token');
      });

      // Act
      await verifyJWT(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 401,
          message: 'Invalid or expired token',
        })
      );
    });

    it('should throw error if user not found', async () => {
      // Arrange
      mockReq.headers.authorization = 'Bearer valid-token';
      const mockDecoded = { userId: 'user-123' };

      jwt.verify.mockReturnValue(mockDecoded);
      AuthUser.findById.mockReturnValue({
        select: jest.fn().mockReturnValue({
          populate: jest.fn().mockResolvedValue(null),
        }),
      });

      // Act
      await verifyJWT(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 401,
          message: 'User not found',
        })
      );
    });

    it('should throw error if user account is deactivated', async () => {
      // Arrange
      mockReq.headers.authorization = 'Bearer valid-token';
      const mockDecoded = { userId: 'user-123' };
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isActive: false,
      };

      jwt.verify.mockReturnValue(mockDecoded);
      AuthUser.findById.mockReturnValue({
        select: jest.fn().mockReturnValue({
          populate: jest.fn().mockResolvedValue(mockUser),
        }),
      });

      // Act
      await verifyJWT(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 401,
          message: 'User account is deactivated',
        })
      );
    });

    it('should handle JWT verification errors', async () => {
      // Arrange
      mockReq.headers.authorization = 'Bearer expired-token';
      jwt.verify.mockImplementation(() => {
        const error = new Error('TokenExpiredError');
        error.name = 'TokenExpiredError';
        throw error;
      });

      // Act
      await verifyJWT(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 401,
          message: 'Invalid or expired token',
        })
      );
    });

    it('should handle database errors gracefully', async () => {
      // Arrange
      mockReq.headers.authorization = 'Bearer valid-token';
      const mockDecoded = { userId: 'user-123' };

      jwt.verify.mockReturnValue(mockDecoded);
      AuthUser.findById.mockReturnValue({
        select: jest.fn().mockReturnValue({
          populate: jest.fn().mockRejectedValue(new Error('Database error')),
        }),
      });

      // Act
      await verifyJWT(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 401,
          message: 'Invalid or expired token',
        })
      );
    });
  });

  describe('requireRole', () => {
    it('should allow access for user with required role', () => {
      // Arrange
      mockReq.user = { role: { name: 'admin' } };

      // Act
      requireRole('admin', 'user')(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should allow access for user with multiple required roles', () => {
      // Arrange
      mockReq.user = { role: { name: 'admin' } };

      // Act
      requireRole('admin', 'super_admin')(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should deny access for user without required role', () => {
      // Arrange
      mockReq.user = { role: { name: 'user' } };

      // Act
      requireRole('admin')(mockReq, mockRes, mockNext);

      // Assert
      expect(safeLogger.warn).toHaveBeenCalledWith('Role access denied', {
        userId: undefined,
        userRole: 'user',
        requiredRoles: ['admin'],
        path: '/api/test',
        correlationId: 'test-correlation-id',
      });
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 403,
          message: 'Insufficient permissions',
        })
      );
    });

    it('should deny access if no user authenticated', () => {
      // Arrange
      mockReq.user = undefined;

      // Act
      requireRole('admin')(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 401,
          message: 'Authentication required',
        })
      );
    });

    it('should deny access if user has no role', () => {
      // Arrange
      mockReq.user = { role: null };

      // Act
      requireRole('admin')(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 403,
          message: 'Insufficient permissions',
        })
      );
    });

    it('should deny access if user role is undefined', () => {
      // Arrange
      mockReq.user = { role: undefined };

      // Act
      requireRole('admin')(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 403,
          message: 'Insufficient permissions',
        })
      );
    });

    it('should handle empty roles array', () => {
      // Arrange
      mockReq.user = { role: { name: 'user' } };

      // Act
      requireRole()(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 403,
          message: 'Insufficient permissions',
        })
      );
    });
  });

  describe('requirePermission', () => {
    it('should allow access for user with required permission', () => {
      // Arrange
      mockReq.user = {
        permissions: [{ name: 'read', scope: 'user' }],
        role: { permissions: ['read'] },
      };

      // Act
      requirePermission('read', 'user')(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should allow access for user with role permission', () => {
      // Arrange
      mockReq.user = {
        permissions: [],
        role: { permissions: ['write', 'read'] },
      };

      // Act
      requirePermission('write', 'user')(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should deny access for user without required permission', () => {
      // Arrange
      mockReq.user = {
        permissions: [{ name: 'read', scope: 'user' }],
        role: { permissions: ['read'] },
      };

      // Act
      requirePermission('write', 'user')(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 403,
          message: 'Insufficient permissions',
        })
      );
    });

    it('should deny access if no user authenticated', () => {
      // Arrange
      mockReq.user = undefined;

      // Act
      requirePermission('read', 'user')(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 401,
          message: 'Authentication required',
        })
      );
    });

    it('should deny access if user has no permissions', () => {
      // Arrange
      mockReq.user = {
        permissions: [],
        role: { permissions: [] },
      };

      // Act
      requirePermission('read', 'user')(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 403,
          message: 'Insufficient permissions',
        })
      );
    });

    it('should handle permission with specific scope', () => {
      // Arrange
      mockReq.user = {
        permissions: [{ name: 'read', scope: 'user' }],
        role: { permissions: ['read'] },
      };

      // Act
      requirePermission('read', 'admin')(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 403,
          message: 'Insufficient permissions',
        })
      );
    });
  });

  describe('extractToken', () => {
    it('should extract token from Authorization header', () => {
      // Arrange
      mockReq.headers.authorization = 'Bearer valid-token';

      // Act
      const token = extractToken(mockReq);

      // Assert
      expect(token).toBe('valid-token');
    });

    it('should return null for malformed header', () => {
      // Arrange
      mockReq.headers.authorization = 'InvalidFormat token';

      // Act
      const token = extractToken(mockReq);

      // Assert
      expect(token).toBeNull();
    });

    it('should return null for missing header', () => {
      // Arrange
      mockReq.headers.authorization = undefined;

      // Act
      const token = extractToken(mockReq);

      // Assert
      expect(token).toBeNull();
    });

    it('should handle empty Authorization header', () => {
      // Arrange
      mockReq.headers.authorization = '';

      // Act
      const token = extractToken(mockReq);

      // Assert
      expect(token).toBeNull();
    });
  });

  describe('verifyToken', () => {
    it('should verify valid JWT token', () => {
      // Arrange
      const token = 'valid-token';
      const mockDecoded = { userId: 'user-123' };

      jwt.verify.mockReturnValue(mockDecoded);

      // Act
      const result = verifyToken(token);

      // Assert
      expect(jwt.verify).toHaveBeenCalledWith(token, env.JWT_SECRET);
      expect(result).toEqual(mockDecoded);
    });

    it('should throw error for invalid token', () => {
      // Arrange
      const token = 'invalid-token';
      jwt.verify.mockImplementation(() => {
        throw new Error('Invalid token');
      });

      // Act & Assert
      expect(() => verifyToken(token)).toThrow(ApiError);
    });

    it('should handle JWT verification errors', () => {
      // Arrange
      const token = 'expired-token';
      jwt.verify.mockImplementation(() => {
        const error = new Error('TokenExpiredError');
        error.name = 'TokenExpiredError';
        throw error;
      });

      // Act & Assert
      expect(() => verifyToken(token)).toThrow(ApiError);
    });
  });

  describe('Error Handling', () => {
    it('should handle ApiError instances correctly', async () => {
      // Arrange
      mockReq.headers.authorization = 'Bearer valid-token';
      const apiError = new ApiError(401, 'Custom error');

      jwt.verify.mockReturnValue({ userId: 'user-123' });
      AuthUser.findById.mockReturnValue({
        select: jest.fn().mockReturnValue({
          populate: jest.fn().mockRejectedValue(apiError),
        }),
      });

      // Act
      await verifyJWT(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(apiError);
    });

    it('should handle generic errors correctly', async () => {
      // Arrange
      mockReq.headers.authorization = 'Bearer valid-token';
      const genericError = new Error('Generic error');

      jwt.verify.mockReturnValue({ userId: 'user-123' });
      AuthUser.findById.mockReturnValue({
        select: jest.fn().mockReturnValue({
          populate: jest.fn().mockRejectedValue(genericError),
        }),
      });

      // Act
      await verifyJWT(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 401,
          message: 'Invalid or expired token',
        })
      );
    });
  });

  describe('Performance and Edge Cases', () => {
    it('should handle large tokens efficiently', async () => {
      // Arrange
      const largeToken = 'a'.repeat(10000);
      mockReq.headers.authorization = `Bearer ${largeToken}`;

      jwt.verify.mockReturnValue({ userId: 'user-123' });
      AuthUser.findById.mockReturnValue({
        select: jest.fn().mockReturnValue({
          populate: jest
            .fn()
            .mockResolvedValue({ id: 'user-123', isActive: true }),
        }),
      });

      // Act
      const startTime = Date.now();
      await verifyJWT(mockReq, mockRes, mockNext);
      const endTime = Date.now();

      // Assert
      expect(endTime - startTime).toBeLessThan(100); // Should complete quickly
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should handle concurrent requests', async () => {
      // Arrange
      const requests = [];
      const mockUser = { id: 'user-123', isActive: true };

      jwt.verify.mockReturnValue({ userId: 'user-123' });
      AuthUser.findById.mockReturnValue({
        select: jest.fn().mockReturnValue({
          populate: jest.fn().mockResolvedValue(mockUser),
        }),
      });

      // Act
      for (let i = 0; i < 10; i++) {
        const req = {
          ...mockReq,
          headers: { authorization: `Bearer token-${i}` },
        };
        const res = {};
        const next = jest.fn();
        requests.push(verifyJWT(req, res, next));
      }

      await Promise.all(requests);

      // Assert
      expect(jwt.verify).toHaveBeenCalledTimes(10);
      expect(AuthUser.findById).toHaveBeenCalledTimes(10);
    });
  });
});
