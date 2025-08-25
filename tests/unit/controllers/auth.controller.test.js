import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from '@jest/globals';
import { ApiError } from '../../../src/utils/index.js';
import {
  signupUser,
  loginUser,
  logoutUser,
  verifyToken,
  refreshAccessToken,
  getCurrentUser,
} from '../../../src/controllers/auth.controller.js';

// Mock dependencies
jest.mock('../../../src/services/index.js');
jest.mock('../../../src/cache/auth.cache.js');
jest.mock('../../../src/config/logger.js');

import { authService } from '../../../src/services/index.js';
import { authCache } from '../../../src/cache/auth.cache.js';
import { safeLogger } from '../../../src/config/logger.js';

// Import test utilities
import {
  TEST_DATA,
  createMockRequest,
  createMockResponse,
  createMockNext,
  validateApiResponse,
  validateApiError,
} from '../../utils/testUtils.js';

describe('Auth Controller Unit Tests', () => {
  let mockReq, mockRes, mockNext;

  beforeEach(() => {
    jest.clearAllMocks();

    mockReq = createMockRequest();
    mockRes = createMockResponse();
    mockNext = createMockNext();
  });

  describe('signupUser', () => {
    const validUserData = {
      email: 'test@example.com',
      password: 'Password123',
      fullName: 'Test User',
      type: 'customer',
      role: 'user',
      phone: '+1234567890',
      acceptTerms: true,
    };

    it('should successfully register a new user', async () => {
      // Arrange
      mockReq.body = validUserData;
      mockReq.ip = '192.168.1.1';
      mockReq.get = jest.fn().mockReturnValue('Mozilla/5.0');

      const mockUser = {
        id: 1,
        email: validUserData.email,
        type: validUserData.type,
        role: validUserData.role,
        status: 'pending',
        emailVerified: false,
      };

      authService.registerUser.mockResolvedValue(mockUser);
      safeLogger.info.mockReturnValue();

      // Act
      await signupUser(mockReq, mockRes, mockNext);

      // Assert
      expect(authService.registerUser).toHaveBeenCalledWith({
        ...validUserData,
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
      });
      expect(mockRes.status).toHaveBeenCalledWith(201);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 201,
          success: true,
          data: expect.objectContaining({
            id: mockUser.id,
            email: mockUser.email,
          }),
        })
      );
      expect(safeLogger.info).toHaveBeenCalledWith(
        'User registered successfully',
        {
          userId: mockUser.id,
          email: mockUser.email,
          type: validUserData.type,
          role: mockUser.role,
        }
      );
    });

    it('should handle registration errors', async () => {
      // Arrange
      mockReq.body = validUserData;
      const error = new Error('User already exists');
      authService.registerUser.mockRejectedValue(error);

      // Act
      await signupUser(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(error);
    });

    it('should use default role when not provided', async () => {
      // Arrange
      const userDataWithoutRole = { ...validUserData };
      delete userDataWithoutRole.role;
      mockReq.body = userDataWithoutRole;
      mockReq.ip = '192.168.1.1';
      mockReq.get = jest.fn().mockReturnValue('Mozilla/5.0');

      const mockUser = {
        id: 1,
        email: userDataWithoutRole.email,
        type: userDataWithoutRole.type,
        role: 'user', // Default role
        status: 'pending',
        emailVerified: false,
      };

      authService.registerUser.mockResolvedValue(mockUser);

      // Act
      await signupUser(mockReq, mockRes, mockNext);

      // Assert
      expect(authService.registerUser).toHaveBeenCalledWith({
        ...userDataWithoutRole,
        role: 'user', // Should use default
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
      });
    });
  });

  describe('loginUser', () => {
    const validLoginData = {
      email: 'test@example.com',
      password: 'Password123',
      type: 'customer',
    };

    it('should successfully login user', async () => {
      // Arrange
      mockReq.body = validLoginData;
      mockReq.ip = '192.168.1.1';
      mockReq.get = jest.fn().mockReturnValue('Mozilla/5.0');

      const mockResult = {
        user: { id: 1, email: validLoginData.email },
        tokens: {
          accessToken: 'access-token',
          refreshToken: 'refresh-token',
          expiresIn: 3600,
        },
        session: { sessionId: 'session-123' },
      };

      authService.loginUser.mockResolvedValue(mockResult);

      // Act
      await loginUser(mockReq, mockRes, mockNext);

      // Assert
      expect(authService.loginUser).toHaveBeenCalledWith({
        ...validLoginData,
        deviceInfo: 'Mozilla/5.0',
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
      });
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'accessToken',
        'access-token',
        expect.objectContaining({
          maxAge: 60 * 60 * 1000, // 1 hour
        })
      );
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'refreshToken',
        'refresh-token',
        expect.objectContaining({
          maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        })
      );
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(safeLogger.info).toHaveBeenCalledWith(
        'User logged in successfully',
        {
          userId: mockResult.user.id,
          email: mockResult.user.email,
          loginMethod: 'email',
        }
      );
    });

    it('should handle login errors', async () => {
      // Arrange
      mockReq.body = validLoginData;
      const error = new ApiError(401, 'Invalid credentials');
      authService.loginUser.mockRejectedValue(error);

      // Act
      await loginUser(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(error);
    });
  });

  describe('logoutUser', () => {
    it('should successfully logout user', async () => {
      // Arrange
      mockReq.user = { id: 1, email: 'test@example.com' };
      mockReq.sessionId = 'session-123';
      authCache.blacklistToken.mockResolvedValue();
      safeLogger.info.mockReturnValue();

      // Act
      await logoutUser(mockReq, mockRes, mockNext);

      // Assert
      expect(authCache.blacklistToken).toHaveBeenCalledWith('session-123', {
        userId: 1,
        logoutReason: 'user_logout',
        timestamp: expect.any(Date),
      });
      expect(mockRes.clearCookie).toHaveBeenCalledWith(
        'accessToken',
        expect.any(Object)
      );
      expect(mockRes.clearCookie).toHaveBeenCalledWith(
        'refreshToken',
        expect.any(Object)
      );
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(safeLogger.info).toHaveBeenCalledWith(
        'User logged out successfully',
        {
          userId: 1,
          sessionId: 'session-123',
        }
      );
    });

    it('should throw error if user not authenticated', async () => {
      // Arrange
      mockReq.user = undefined;

      // Act
      await logoutUser(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'User not authenticated',
        })
      );
    });

    it('should continue logout even if blacklisting fails', async () => {
      // Arrange
      mockReq.user = { id: 1, email: 'test@example.com' };
      mockReq.sessionId = 'session-123';
      authCache.blacklistToken.mockRejectedValue(new Error('Blacklist failed'));
      safeLogger.warn.mockReturnValue();
      safeLogger.info.mockReturnValue();

      // Act
      await logoutUser(mockReq, mockRes, mockNext);

      // Assert
      expect(safeLogger.warn).toHaveBeenCalledWith(
        'Failed to blacklist token during logout',
        {
          userId: 1,
          sessionId: 'session-123',
          error: 'Blacklist failed',
        }
      );
      expect(mockRes.clearCookie).toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(200);
    });
  });

  describe('verifyToken', () => {
    it('should verify valid token', async () => {
      // Arrange
      mockReq.body = { token: 'valid-token' };
      const mockDecoded = {
        userId: 'user-123',
        email: 'test@example.com',
        role: 'user',
        exp: new Date(Date.now() + 3600000).getTime(),
      };
      authService.verifyToken.mockResolvedValue(mockDecoded);

      // Act
      await verifyToken(mockReq, mockRes, mockNext);

      // Assert
      expect(authService.verifyToken).toHaveBeenCalledWith('valid-token');
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 200,
          success: true,
          data: expect.objectContaining({
            valid: true,
            user: {
              userId: mockDecoded.userId,
              email: mockDecoded.email,
              role: mockDecoded.role,
            },
            expiresAt: mockDecoded.exp,
          }),
        })
      );
      expect(safeLogger.info).toHaveBeenCalledWith(
        'Token verified successfully',
        {
          userId: mockDecoded.userId,
        }
      );
    });

    it('should throw error if token missing', async () => {
      // Arrange
      mockReq.body = {};

      // Act
      await verifyToken(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Token is required',
        })
      );
    });
  });

  describe('refreshAccessToken', () => {
    it('should refresh access token', async () => {
      // Arrange
      mockReq.body = { refreshToken: 'refresh-token' };
      const mockResult = {
        accessToken: 'new-access-token',
        expiresIn: 3600,
      };
      authService.refreshToken.mockResolvedValue(mockResult);

      // Act
      await refreshAccessToken(mockReq, mockRes, mockNext);

      // Assert
      expect(authService.refreshToken).toHaveBeenCalledWith('refresh-token');
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'accessToken',
        'new-access-token',
        expect.objectContaining({
          maxAge: 60 * 60 * 1000, // 1 hour
        })
      );
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(safeLogger.info).toHaveBeenCalledWith(
        'Access token refreshed successfully'
      );
    });

    it('should throw error if refresh token missing', async () => {
      // Arrange
      mockReq.body = {};

      // Act
      await refreshAccessToken(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Refresh token is required',
        })
      );
    });
  });

  describe('getCurrentUser', () => {
    it('should get current user profile', async () => {
      // Arrange
      mockReq.user = { id: 1, email: 'test@example.com' };
      const mockUser = {
        id: 1,
        email: 'test@example.com',
        fullName: 'Test User',
        type: 'customer',
        role: 'user',
      };
      authService.getUserById.mockResolvedValue(mockUser);

      // Act
      await getCurrentUser(mockReq, mockRes, mockNext);

      // Assert
      expect(authService.getUserById).toHaveBeenCalledWith(1);
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 200,
          success: true,
          data: { user: mockUser },
        })
      );
    });

    it('should throw error if user not authenticated', async () => {
      // Arrange
      mockReq.user = undefined;

      // Act
      await getCurrentUser(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 401,
          message: 'User not authenticated',
        })
      );
    });
  });
});
