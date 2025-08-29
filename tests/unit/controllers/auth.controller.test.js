import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from '@jest/globals';
import request from 'supertest';
import express from 'express';

// Import the controller functions
import {
  signupUser,
  loginUser,
  logoutUser,
  verifyToken,
  refreshAccessToken,
} from '../../../src/controllers/auth.controller.js';

// Import models and utilities
import AuthUser from '../../../src/models/authUser.model.js';
import { ApiError } from '../../../src/utils/index.js';
import {
  createUserProfile,
  getUserById,
} from '../../../src/grpc/client/user.client.js';
import {
  generateAccessToken,
  generateRefreshToken,
} from '../../../src/crypto/tokenService.js';

// Import test utilities
import {
  TEST_DATA,
  createMockRequest,
  createMockResponse,
  createMockNext,
  validateApiResponse,
  validateApiError,
  setupTestEnvironment,
  cleanupTestEnvironment,
} from '../../utils/testUtils.js';

// Mock all external dependencies
jest.mock('../../../src/models/authUser.model.js');
jest.mock('../../../src/grpc/client/user.client.js');
jest.mock('../../../src/crypto/tokenService.js');
jest.mock('../../../src/cache/auth.cache.js');
jest.mock('../../../src/config/logger.js');

// Create Express app for integration-style tests
const app = express();
app.use(express.json());

/**
 * Auth Controller Unit Tests
 *
 * Test Coverage:
 * - User registration (signup)
 * - User authentication (login)
 * - User logout
 * - Token verification
 * - Token refresh
 * - Error handling
 * - Input validation
 * - Security measures
 */

describe('Auth Controller Unit Tests', () => {
  let mockAuthUser;
  let mockUserData;

  beforeEach(() => {
    // Setup test environment
    setupTestEnvironment();

    // Clear all mocks
    jest.clearAllMocks();

    // Setup mock data
    mockUserData = { ...TEST_DATA.users.customer };
    mockAuthUser = {
      id: 1,
      fullName: mockUserData.fullName,
      email: mockUserData.email,
      type: mockUserData.type,
      role: mockUserData.role,
      userId: mockUserData.userId,
      isValidPassword: jest.fn(),
      save: jest.fn(),
    };
  });

  afterEach(() => {
    cleanupTestEnvironment();
  });

  describe('User Registration (signupUser)', () => {
    describe('Success Scenarios', () => {
      it('should successfully register a new customer user', async () => {
        // Arrange
        const req = createMockRequest({
          body: {
            fullName: 'New Customer',
            email: 'newcustomer@test.com',
            password: 'securePassword123',
            type: 'customer',
            role: 'user',
          },
        });
        const res = createMockResponse();
        const next = createMockNext();

        // Mock dependencies
        AuthUser.findOne.mockResolvedValue(null);
        createUserProfile.mockResolvedValue({ userId: 201 });
        AuthUser.create.mockResolvedValue({
          id: 3,
          ...req.body,
          userId: 201,
        });

        // Act
        await signupUser(req, res, next);

        // Assert
        expect(AuthUser.findOne).toHaveBeenCalledWith({
          where: { email: req.body.email, type: req.body.type },
        });
        expect(createUserProfile).toHaveBeenCalledWith({
          fullName: req.body.fullName,
          email: req.body.email,
          type: req.body.type,
          role: req.body.role,
        });
        expect(AuthUser.create).toHaveBeenCalledWith(
          expect.objectContaining({
            fullName: req.body.fullName,
            email: req.body.email,
            type: req.body.type,
            role: req.body.role,
            userId: 201,
          })
        );
        validateApiResponse(res, 201);
      });

      it('should successfully register a new vendor user', async () => {
        // Arrange
        const req = createMockRequest({
          body: {
            fullName: 'New Vendor',
            email: 'newvendor@test.com',
            password: 'securePassword123',
            type: 'vendor',
            role: 'manager',
          },
        });
        const res = createMockResponse();
        const next = createMockNext();

        // Mock dependencies
        AuthUser.findOne.mockResolvedValue(null);
        createUserProfile.mockResolvedValue({ userId: 202 });
        AuthUser.create.mockResolvedValue({
          id: 4,
          ...req.body,
          userId: 202,
        });

        // Act
        await signupUser(req, res, next);

        // Assert
        expect(createUserProfile).toHaveBeenCalledWith({
          fullName: req.body.fullName,
          email: req.body.email,
          type: req.body.type,
          role: req.body.role,
        });
        validateApiResponse(res, 201);
      });
    });

    describe('Error Scenarios', () => {
      it('should throw error if user already exists', async () => {
        // Arrange
        const req = createMockRequest({
          body: mockUserData,
        });
        const res = createMockResponse();
        const next = createMockNext();

        AuthUser.findOne.mockResolvedValue(mockAuthUser);

        // Act
        await signupUser(req, res, next);

        // Assert
        validateApiError(next, {
          statusCode: 400,
          message: 'customer already exists with this email',
        });
      });

      it('should handle validation errors for invalid email', async () => {
        // Arrange
        const req = createMockRequest({
          body: {
            email: 'invalid-email',
            password: '123',
            type: 'customer',
          },
        });
        const res = createMockResponse();
        const next = createMockNext();

        // Act
        await signupUser(req, res, next);

        // Assert
        validateApiError(next, {
          statusCode: 400,
          message: 'Validation error',
        });
      });

      it('should handle validation errors for weak password', async () => {
        // Arrange
        const req = createMockRequest({
          body: {
            email: 'test@example.com',
            password: '123', // too short
            type: 'customer',
          },
        });
        const res = createMockResponse();
        const next = createMockNext();

        // Act
        await signupUser(req, res, next);

        // Assert
        validateApiError(next, {
          statusCode: 400,
          message: 'Validation error',
        });
      });

      it('should handle gRPC service errors', async () => {
        // Arrange
        const req = createMockRequest({
          body: mockUserData,
        });
        const res = createMockResponse();
        const next = createMockNext();

        AuthUser.findOne.mockResolvedValue(null);
        createUserProfile.mockRejectedValue(
          new Error('gRPC service unavailable')
        );

        // Act
        await signupUser(req, res, next);

        // Assert
        validateApiError(next, {
          statusCode: 500,
          message: 'Internal server error',
        });
      });
    });

    describe('Security Tests', () => {
      it('should not expose password in response', async () => {
        // Arrange
        const req = createMockRequest({
          body: mockUserData,
        });
        const res = createMockResponse();
        const next = createMockNext();

        AuthUser.findOne.mockResolvedValue(null);
        createUserProfile.mockResolvedValue({ userId: 123 });
        AuthUser.create.mockResolvedValue({
          id: 1,
          ...mockUserData,
          userId: 123,
        });

        // Act
        await signupUser(req, res, next);

        // Assert
        expect(res.json).toHaveBeenCalledWith(
          expect.not.objectContaining({
            data: expect.objectContaining({
              password: expect.any(String),
            }),
          })
        );
      });

      it('should hash password before saving', async () => {
        // Arrange
        const req = createMockRequest({
          body: mockUserData,
        });
        const res = createMockResponse();
        const next = createMockNext();

        AuthUser.findOne.mockResolvedValue(null);
        createUserProfile.mockResolvedValue({ userId: 123 });
        AuthUser.create.mockResolvedValue({
          id: 1,
          ...mockUserData,
          userId: 123,
        });

        // Act
        await signupUser(req, res, next);

        // Assert
        expect(AuthUser.create).toHaveBeenCalledWith(
          expect.objectContaining({
            password: expect.not.toBe(mockUserData.password),
          })
        );
      });
    });
  });

  describe('User Authentication (loginUser)', () => {
    describe('Success Scenarios', () => {
      it('should successfully login user with valid credentials', async () => {
        // Arrange
        const req = createMockRequest({
          body: {
            email: mockUserData.email,
            password: mockUserData.password,
            type: mockUserData.type,
          },
        });
        const res = createMockResponse();
        const next = createMockNext();

        // Mock dependencies
        mockAuthUser.isValidPassword.mockResolvedValue(true);
        AuthUser.findOne.mockResolvedValue(mockAuthUser);
        getUserById.mockResolvedValue({
          name: mockUserData.fullName,
          userId: mockUserData.userId,
        });
        generateAccessToken.mockResolvedValue(TEST_DATA.tokens.accessToken);
        generateRefreshToken.mockResolvedValue(TEST_DATA.tokens.refreshToken);

        // Act
        await loginUser(req, res, next);

        // Assert
        expect(AuthUser.findOne).toHaveBeenCalledWith({
          where: { email: req.body.email, type: req.body.type },
        });
        expect(mockAuthUser.isValidPassword).toHaveBeenCalledWith(
          req.body.password
        );
        expect(generateAccessToken).toHaveBeenCalledWith(mockAuthUser);
        expect(generateRefreshToken).toHaveBeenCalledWith(mockAuthUser);
        expect(res.cookie).toHaveBeenCalledTimes(2); // access and refresh tokens
        validateApiResponse(res, 200);
      });
    });

    describe('Error Scenarios', () => {
      it('should throw error for invalid credentials', async () => {
        // Arrange
        const req = createMockRequest({
          body: {
            email: mockUserData.email,
            password: 'wrongpassword',
            type: mockUserData.type,
          },
        });
        const res = createMockResponse();
        const next = createMockNext();

        mockAuthUser.isValidPassword.mockResolvedValue(false);
        AuthUser.findOne.mockResolvedValue(mockAuthUser);

        // Act
        await loginUser(req, res, next);

        // Assert
        validateApiError(next, {
          statusCode: 401,
          message: 'Invalid email or password',
        });
      });

      it('should throw error for non-existent user', async () => {
        // Arrange
        const req = createMockRequest({
          body: {
            email: 'nonexistent@test.com',
            password: mockUserData.password,
            type: mockUserData.type,
          },
        });
        const res = createMockResponse();
        const next = createMockNext();

        AuthUser.findOne.mockResolvedValue(null);

        // Act
        await loginUser(req, res, next);

        // Assert
        validateApiError(next, {
          statusCode: 401,
          message: 'Invalid email or password',
        });
      });

      it('should handle token generation errors', async () => {
        // Arrange
        const req = createMockRequest({
          body: {
            email: mockUserData.email,
            password: mockUserData.password,
            type: mockUserData.type,
          },
        });
        const res = createMockResponse();
        const next = createMockNext();

        mockAuthUser.isValidPassword.mockResolvedValue(true);
        AuthUser.findOne.mockResolvedValue(mockAuthUser);
        getUserById.mockResolvedValue({
          name: mockUserData.fullName,
          userId: mockUserData.userId,
        });
        generateAccessToken.mockRejectedValue(
          new Error('Token generation failed')
        );

        // Act
        await loginUser(req, res, next);

        // Assert
        validateApiError(next, {
          statusCode: 500,
          message: 'Internal server error',
        });
      });
    });

    describe('Security Tests', () => {
      it('should set secure cookie options', async () => {
        // Arrange
        const req = createMockRequest({
          body: {
            email: mockUserData.email,
            password: mockUserData.password,
            type: mockUserData.type,
          },
        });
        const res = createMockResponse();
        const next = createMockNext();

        mockAuthUser.isValidPassword.mockResolvedValue(true);
        AuthUser.findOne.mockResolvedValue(mockAuthUser);
        getUserById.mockResolvedValue({
          name: mockUserData.fullName,
          userId: mockUserData.userId,
        });
        generateAccessToken.mockResolvedValue(TEST_DATA.tokens.accessToken);
        generateRefreshToken.mockResolvedValue(TEST_DATA.tokens.refreshToken);

        // Act
        await loginUser(req, res, next);

        // Assert
        expect(res.cookie).toHaveBeenCalledWith(
          'accessToken',
          TEST_DATA.tokens.accessToken,
          expect.objectContaining({
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
          })
        );
      });

      it('should not expose password in logs or responses', async () => {
        // Arrange
        const req = createMockRequest({
          body: {
            email: mockUserData.email,
            password: mockUserData.password,
            type: mockUserData.type,
          },
        });
        const res = createMockResponse();
        const next = createMockNext();

        mockAuthUser.isValidPassword.mockResolvedValue(true);
        AuthUser.findOne.mockResolvedValue(mockAuthUser);
        getUserById.mockResolvedValue({
          name: mockUserData.fullName,
          userId: mockUserData.userId,
        });
        generateAccessToken.mockResolvedValue(TEST_DATA.tokens.accessToken);
        generateRefreshToken.mockResolvedValue(TEST_DATA.tokens.refreshToken);

        // Act
        await loginUser(req, res, next);

        // Assert
        expect(res.json).toHaveBeenCalledWith(
          expect.not.objectContaining({
            password: expect.any(String),
          })
        );
      });
    });
  });

  describe('User Logout (logoutUser)', () => {
    it('should successfully logout user and clear cookies', async () => {
      // Arrange
      const req = createMockRequest();
      const res = createMockResponse();
      const next = createMockNext();

      // Act
      await logoutUser(req, res, next);

      // Assert
      expect(res.clearCookie).toHaveBeenCalledWith('accessToken');
      expect(res.clearCookie).toHaveBeenCalledWith('refreshToken');
      validateApiResponse(res, 200);
    });
  });

  describe('Token Verification (verifyToken)', () => {
    it('should verify valid token and return user data', async () => {
      // Arrange
      const req = createMockRequest({
        headers: {
          authorization: `Bearer ${TEST_DATA.tokens.accessToken}`,
        },
      });
      const res = createMockResponse();
      const next = createMockNext();

      // Mock token verification
      jest.mock('../../../src/crypto/tokenService.js', () => ({
        verifyToken: jest.fn().mockResolvedValue({
          id: mockAuthUser.id,
          email: mockAuthUser.email,
          type: mockAuthUser.type,
        }),
      }));

      // Act
      await verifyToken(req, res, next);

      // Assert
      expect(req.user).toBeDefined();
      expect(req.user.id).toBe(mockAuthUser.id);
      expect(next).toHaveBeenCalled();
    });

    it('should handle invalid token', async () => {
      // Arrange
      const req = createMockRequest({
        headers: {
          authorization: 'Bearer invalid-token',
        },
      });
      const res = createMockResponse();
      const next = createMockNext();

      // Act
      await verifyToken(req, res, next);

      // Assert
      validateApiError(next, {
        statusCode: 401,
        message: 'Invalid token',
      });
    });
  });

  describe('Token Refresh (refreshAccessToken)', () => {
    it('should refresh access token with valid refresh token', async () => {
      // Arrange
      const req = createMockRequest({
        cookies: {
          refreshToken: TEST_DATA.tokens.refreshToken,
        },
      });
      const res = createMockResponse();
      const next = createMockNext();

      // Mock token refresh
      generateAccessToken.mockResolvedValue('new-access-token');

      // Act
      await refreshAccessToken(req, res, next);

      // Assert
      expect(generateAccessToken).toHaveBeenCalled();
      expect(res.cookie).toHaveBeenCalledWith(
        'accessToken',
        'new-access-token',
        expect.any(Object)
      );
      validateApiResponse(res, 200);
    });

    it('should handle invalid refresh token', async () => {
      // Arrange
      const req = createMockRequest({
        cookies: {
          refreshToken: TEST_DATA.tokens.invalidToken,
        },
      });
      const res = createMockResponse();
      const next = createMockNext();

      // Act
      await refreshAccessToken(req, res, next);

      // Assert
      validateApiError(next, {
        statusCode: 401,
        message: 'Invalid refresh token',
      });
    });
  });
});
