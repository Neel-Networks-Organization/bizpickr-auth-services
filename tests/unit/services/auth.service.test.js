import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from '@jest/globals';
import { ApiError } from '../../../src/utils/index.js';
import { authService } from '../../../src/services/index.js';

// Mock dependencies
jest.mock('../../../src/models/index.model.js');
jest.mock('../../../src/events/emitters/index.js');
jest.mock('../../../src/middlewares/audit.middleware.js');
jest.mock('../../../src/services/session.service.js');
jest.mock('../../../src/services/password.service.js');
jest.mock('../../../src/services/oauth.service.js');
jest.mock('../../../src/services/twoFactor.service.js');
jest.mock('../../../src/cache/auth.cache.js');

import {
  AuthUser,
  AuditLog,
  EmailVerification,
  PasswordReset,
} from '../../../src/models/index.model.js';
import {
  emitUserRegistered,
  emitUserLoggedIn,
  emitUserLoggedOut,
  emitEmailVerification,
} from '../../../src/events/emitters/index.js';
import { logAuditEvent } from '../../../src/middlewares/audit.middleware.js';
import sessionService from '../../../src/services/session.service.js';
import passwordService from '../../../src/services/password.service.js';
import oauthService from '../../../src/services/oauth.service.js';
import twoFactorService from '../../../src/services/twoFactor.service.js';
import authCache from '../../../src/cache/auth.cache.js';

describe('Auth Service Unit Tests', () => {
  let mockUserData;

  beforeEach(() => {
    jest.clearAllMocks();

    mockUserData = {
      email: 'test@example.com',
      password: 'Password123',
      fullName: 'Test User',
      type: 'customer',
      role: 'user',
      phone: '+1234567890',
      acceptTerms: true,
      ipAddress: '192.168.1.1',
      userAgent: 'Mozilla/5.0',
    };
  });

  describe('registerUser', () => {
    it('should successfully register a new user', async () => {
      // Arrange
      AuthUser.findOne.mockResolvedValue(null);
      passwordService.validatePassword.mockReturnValue({ isValid: true });

      const mockUser = {
        id: 1,
        email: mockUserData.email,
        type: mockUserData.type,
        role: mockUserData.role,
        status: 'pending',
        emailVerified: false,
        createdAt: new Date(),
      };

      AuthUser.create.mockResolvedValue(mockUser);
      logAuditEvent.mockResolvedValue();
      emitUserRegistered.mockResolvedValue();

      // Act
      const result = await authService.registerUser(mockUserData);

      // Assert
      expect(AuthUser.findOne).toHaveBeenCalledWith({
        where: { email: mockUserData.email },
      });
      expect(passwordService.validatePassword).toHaveBeenCalledWith(
        mockUserData.password
      );
      expect(AuthUser.create).toHaveBeenCalledWith({
        email: mockUserData.email,
        password: mockUserData.password,
        type: 'customer',
        role: 'customer',
        status: 'pending',
        emailVerified: false,
        ipAddress: mockUserData.ipAddress,
        deviceInfo: { userAgent: mockUserData.userAgent },
      });
      expect(logAuditEvent).toHaveBeenCalledWith({
        type: 'USER_REGISTERED',
        user: {
          userId: mockUser.id,
          username: mockUser.email,
          roles: [mockUser.role],
          permissions: [],
          ip: mockUserData.ipAddress,
          userAgent: mockUserData.userAgent,
        },
        resourceType: 'USER',
        resourceId: mockUser.id,
        details: {
          email: mockUserData.email,
          type: 'customer',
          role: 'customer',
        },
        ipAddress: mockUserData.ipAddress,
        userAgent: mockUserData.userAgent,
        status: 'success',
        severity: 'low',
        category: 'authentication',
        description: 'User registration completed successfully',
        timestamp: expect.any(Date),
      });
      expect(emitUserRegistered).toHaveBeenCalledWith(mockUser, {
        emailType: 'welcome',
        template: 'welcome-email',
      });
      expect(result).toEqual({
        id: mockUser.id,
        email: mockUser.email,
        type: mockUser.type,
        role: mockUser.role,
        status: mockUser.status,
        emailVerified: mockUser.emailVerified,
        createdAt: mockUser.createdAt,
      });
    });

    it('should throw error if user already exists', async () => {
      // Arrange
      const existingUser = { id: 1, email: mockUserData.email };
      AuthUser.findOne.mockResolvedValue(existingUser);

      // Act & Assert
      await expect(authService.registerUser(mockUserData)).rejects.toThrow(
        'User with this email already exists'
      );
    });

    it('should throw error if email or password missing', async () => {
      // Arrange
      const invalidData = { ...mockUserData, email: '', password: '' };

      // Act & Assert
      await expect(authService.registerUser(invalidData)).rejects.toThrow(
        'Email and password are required'
      );
    });

    it('should throw error if password validation fails', async () => {
      // Arrange
      AuthUser.findOne.mockResolvedValue(null);
      passwordService.validatePassword.mockReturnValue({
        isValid: false,
        errors: ['Password too weak'],
      });

      // Act & Assert
      await expect(authService.registerUser(mockUserData)).rejects.toThrow(
        'Password too weak'
      );
    });

    it('should use default type and role when not provided', async () => {
      // Arrange
      const userDataWithoutDefaults = { ...mockUserData };
      delete userDataWithoutDefaults.type;
      delete userDataWithoutDefaults.role;

      AuthUser.findOne.mockResolvedValue(null);
      passwordService.validatePassword.mockReturnValue({ isValid: true });

      const mockUser = {
        id: 1,
        email: userDataWithoutDefaults.email,
        type: 'customer', // Default type
        role: 'customer', // Default role
        status: 'pending',
        emailVerified: false,
        createdAt: new Date(),
      };

      AuthUser.create.mockResolvedValue(mockUser);
      logAuditEvent.mockResolvedValue();
      emitUserRegistered.mockResolvedValue();

      // Act
      await authService.registerUser(userDataWithoutDefaults);

      // Assert
      expect(AuthUser.create).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'customer',
          role: 'customer',
        })
      );
    });
  });

  describe('loginUser', () => {
    const loginData = {
      email: 'test@example.com',
      password: 'Password123',
      type: 'customer',
      deviceInfo: 'Mozilla/5.0',
      ipAddress: '192.168.1.1',
      userAgent: 'Mozilla/5.0',
    };

    it('should successfully login user with valid credentials', async () => {
      // Arrange
      const mockUser = {
        id: 1,
        email: loginData.email,
        type: loginData.type,
        role: 'user',
        status: 'active',
        emailVerified: true,
        isValidPassword: jest.fn().mockResolvedValue(true),
      };

      AuthUser.findOne.mockResolvedValue(mockUser);
      sessionService.createSession.mockResolvedValue({ id: 'session-1' });
      logAuditEvent.mockResolvedValue();
      emitUserLoggedIn.mockResolvedValue();

      // Act
      const result = await authService.loginUser(loginData);

      // Assert
      expect(AuthUser.findOne).toHaveBeenCalledWith({
        where: { email: loginData.email, type: loginData.type },
      });
      expect(mockUser.isValidPassword).toHaveBeenCalledWith(loginData.password);
      expect(sessionService.createSession).toHaveBeenCalled();
      expect(logAuditEvent).toHaveBeenCalled();
      expect(emitUserLoggedIn).toHaveBeenCalled();
      expect(result).toHaveProperty('user');
      expect(result).toHaveProperty('tokens');
    });

    it('should throw error if user not found', async () => {
      // Arrange
      AuthUser.findOne.mockResolvedValue(null);

      // Act & Assert
      await expect(authService.loginUser(loginData)).rejects.toThrow(
        'User not found'
      );
    });

    it('should throw error if password is invalid', async () => {
      // Arrange
      const mockUser = {
        id: 1,
        email: loginData.email,
        isValidPassword: jest.fn().mockResolvedValue(false),
      };

      AuthUser.findOne.mockResolvedValue(mockUser);

      // Act & Assert
      await expect(authService.loginUser(loginData)).rejects.toThrow(
        'Invalid credentials'
      );
    });

    it('should throw error if user account is inactive', async () => {
      // Arrange
      const mockUser = {
        id: 1,
        email: loginData.email,
        status: 'inactive',
        isValidPassword: jest.fn().mockResolvedValue(true),
      };

      AuthUser.findOne.mockResolvedValue(mockUser);

      // Act & Assert
      await expect(authService.loginUser(loginData)).rejects.toThrow(
        'Account is inactive'
      );
    });

    it('should throw error if email or password missing', async () => {
      // Arrange
      const invalidData = { ...loginData, email: '', password: '' };

      // Act & Assert
      await expect(authService.loginUser(invalidData)).rejects.toThrow(
        'Email and password are required'
      );
    });
  });

  describe('logoutUser', () => {
    it('should successfully logout user', async () => {
      // Arrange
      const logoutData = {
        userId: 1,
        token: 'access-token',
      };

      sessionService.invalidateSession.mockResolvedValue();
      logAuditEvent.mockResolvedValue();
      emitUserLoggedOut.mockResolvedValue();

      // Act
      await authService.logoutUser(logoutData);

      // Assert
      expect(sessionService.invalidateSession).toHaveBeenCalledWith(
        logoutData.token
      );
      expect(logAuditEvent).toHaveBeenCalled();
      expect(emitUserLoggedOut).toHaveBeenCalledWith(logoutData.userId);
    });
  });

  describe('verifyToken', () => {
    it('should verify valid token', async () => {
      // Arrange
      const token = 'valid-token';
      const mockUser = { id: 1, email: 'test@example.com' };
      sessionService.verifySession.mockResolvedValue(mockUser);

      // Act
      const result = await authService.verifyToken(token);

      // Assert
      expect(sessionService.verifySession).toHaveBeenCalledWith(token);
      expect(result).toEqual(mockUser);
    });

    it('should throw error for invalid token', async () => {
      // Arrange
      const token = 'invalid-token';
      sessionService.verifySession.mockRejectedValue(
        new Error('Invalid token')
      );

      // Act & Assert
      await expect(authService.verifyToken(token)).rejects.toThrow(
        'Invalid token'
      );
    });
  });

  describe('refreshToken', () => {
    it('should refresh access token', async () => {
      // Arrange
      const refreshToken = 'refresh-token';
      const mockResult = {
        accessToken: 'new-access-token',
        user: { id: 1, email: 'test@example.com' },
      };

      sessionService.refreshSession.mockResolvedValue(mockResult);

      // Act
      const result = await authService.refreshToken(refreshToken);

      // Assert
      expect(sessionService.refreshSession).toHaveBeenCalledWith(refreshToken);
      expect(result).toEqual(mockResult);
    });
  });

  describe('getUserById', () => {
    it('should get user by ID', async () => {
      // Arrange
      const userId = 1;
      const mockUser = {
        id: userId,
        email: 'test@example.com',
        fullName: 'Test User',
        type: 'customer',
        role: 'user',
      };

      AuthUser.findByPk.mockResolvedValue(mockUser);

      // Act
      const result = await authService.getUserById(userId);

      // Assert
      expect(AuthUser.findByPk).toHaveBeenCalledWith(userId, {
        attributes: { exclude: ['password', 'refreshToken'] },
      });
      expect(result).toEqual(mockUser);
    });

    it('should throw error if user not found', async () => {
      // Arrange
      const userId = 999;
      AuthUser.findByPk.mockResolvedValue(null);

      // Act & Assert
      await expect(authService.getUserById(userId)).rejects.toThrow(
        'User not found'
      );
    });
  });

  describe('updateUserProfile', () => {
    it('should update user profile', async () => {
      // Arrange
      const userId = 1;
      const updateData = {
        fullName: 'Updated Name',
        phone: '+9876543210',
      };

      const mockUser = {
        id: userId,
        ...updateData,
        update: jest.fn().mockResolvedValue(true),
      };

      AuthUser.findByPk.mockResolvedValue(mockUser);
      logAuditEvent.mockResolvedValue();

      // Act
      await authService.updateUserProfile(userId, updateData);

      // Assert
      expect(AuthUser.findByPk).toHaveBeenCalledWith(userId);
      expect(mockUser.update).toHaveBeenCalledWith(updateData);
      expect(logAuditEvent).toHaveBeenCalled();
    });

    it('should throw error if user not found', async () => {
      // Arrange
      const userId = 999;
      AuthUser.findByPk.mockResolvedValue(null);

      // Act & Assert
      await expect(authService.updateUserProfile(userId, {})).rejects.toThrow(
        'User not found'
      );
    });
  });

  describe('deleteUser', () => {
    it('should delete user account', async () => {
      // Arrange
      const userId = 1;
      const mockUser = {
        id: userId,
        email: 'test@example.com',
        destroy: jest.fn().mockResolvedValue(true),
      };

      AuthUser.findByPk.mockResolvedValue(mockUser);
      logAuditEvent.mockResolvedValue();
      emitUserLoggedOut.mockResolvedValue();

      // Act
      await authService.deleteUser(userId);

      // Assert
      expect(AuthUser.findByPk).toHaveBeenCalledWith(userId);
      expect(mockUser.destroy).toHaveBeenCalled();
      expect(logAuditEvent).toHaveBeenCalled();
      expect(emitUserLoggedOut).toHaveBeenCalledWith(userId);
    });

    it('should throw error if user not found', async () => {
      // Arrange
      const userId = 999;
      AuthUser.findByPk.mockResolvedValue(null);

      // Act & Assert
      await expect(authService.deleteUser(userId)).rejects.toThrow(
        'User not found'
      );
    });
  });
});
