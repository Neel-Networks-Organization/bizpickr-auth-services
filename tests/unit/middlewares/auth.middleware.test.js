import { jest } from '@jest/globals';
import jwt from 'jsonwebtoken';
import { verifyJWT } from '../../../src/middlewares/auth.middleware.js';
import { ApiError } from '../../../src/utils/ApiError.js';

// Mock jwt
jest.mock('jsonwebtoken');

describe('Auth Middleware Unit Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('verifyJWT', () => {
    it('should successfully verify valid JWT token', async () => {
      // Arrange
      const mockUser = {
        id: 1,
        email: 'test@example.com',
        type: 'customer'
      };

      const req = {
        cookies: {
          accessToken: 'valid-token'
        },
        headers: {
          authorization: 'Bearer valid-token'
        }
      };

      const res = {};
      const next = jest.fn();

      jwt.verify.mockReturnValue(mockUser);

      // Act
      await verifyJWT(req, res, next);

      // Assert
      expect(jwt.verify).toHaveBeenCalledWith('valid-token', process.env.ACCESS_TOKEN_SECRET);
      expect(req.user).toEqual(mockUser);
      expect(next).toHaveBeenCalled();
    });

    it('should verify token from Authorization header', async () => {
      // Arrange
      const mockUser = {
        id: 1,
        email: 'test@example.com',
        type: 'customer'
      };

      const req = {
        cookies: {},
        headers: {
          authorization: 'Bearer valid-token'
        }
      };

      const res = {};
      const next = jest.fn();

      jwt.verify.mockReturnValue(mockUser);

      // Act
      await verifyJWT(req, res, next);

      // Assert
      expect(jwt.verify).toHaveBeenCalledWith('valid-token', process.env.ACCESS_TOKEN_SECRET);
      expect(req.user).toEqual(mockUser);
      expect(next).toHaveBeenCalled();
    });

    it('should throw error when no token provided', async () => {
      // Arrange
      const req = {
        cookies: {},
        headers: {}
      };

      const res = {};
      const next = jest.fn();

      // Act
      await verifyJWT(req, res, next);

      // Assert
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 401,
          message: 'Unauthorized request'
        })
      );
    });

    it('should throw error for invalid token', async () => {
      // Arrange
      const req = {
        cookies: {
          accessToken: 'invalid-token'
        },
        headers: {}
      };

      const res = {};
      const next = jest.fn();

      jwt.verify.mockImplementation(() => {
        throw new Error('Invalid token');
      });

      // Act
      await verifyJWT(req, res, next);

      // Assert
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 401,
          message: 'Invalid access token'
        })
      );
    });

    it('should throw error for expired token', async () => {
      // Arrange
      const req = {
        cookies: {
          accessToken: 'expired-token'
        },
        headers: {}
      };

      const res = {};
      const next = jest.fn();

      jwt.verify.mockImplementation(() => {
        const error = new Error('TokenExpiredError');
        error.name = 'TokenExpiredError';
        throw error;
      });

      // Act
      await verifyJWT(req, res, next);

      // Assert
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 401,
          message: 'Access token expired'
        })
      );
    });

    it('should handle malformed authorization header', async () => {
      // Arrange
      const req = {
        cookies: {},
        headers: {
          authorization: 'InvalidFormat token'
        }
      };

      const res = {};
      const next = jest.fn();

      // Act
      await verifyJWT(req, res, next);

      // Assert
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 401,
          message: 'Unauthorized request'
        })
      );
    });
  });
}); 