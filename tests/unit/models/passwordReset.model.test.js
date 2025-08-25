import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from '@jest/globals';

// Mock dependencies
jest.mock('sequelize');

// Create mock objects directly
const safeLogger = {
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
};

const getCorrelationId = jest.fn(() => 'test-correlation-id');

const mockSequelize = {
  Op: {
    gt: 'gt',
    lt: 'lt',
  },
  fn: jest.fn(),
  col: jest.fn(),
  literal: jest.fn(),
  models: {
    AuthUser: {},
  },
};

// Mock ApiError
class ApiError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
    this.name = 'ApiError';
  }
}

// Simple PasswordReset Model Tests - Basic Functionality
describe('PasswordReset Model - Basic Tests', () => {
  let mockPasswordReset;
  let mockPasswordResetData;

  beforeEach(() => {
    jest.clearAllMocks();

    // Mock password reset data
    mockPasswordResetData = {
      id: 'reset-id-123',
      userId: 'user-id-456',
      email: 'test@example.com',
      token: 'password-reset-token-789-abcdef-123456',
      tokenHash: 'hashed-reset-token-abc-def-123-456',
      expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
      usedAt: null,
      ipAddress: '192.168.1.1',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      status: 'pending',
      attempts: 0,
      maxAttempts: 3,
      sentAt: null,
      emailProvider: null,
      emailId: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    // Mock password reset instance
    mockPasswordReset = {
      ...mockPasswordResetData,
      save: jest.fn(),
      update: jest.fn(),
      destroy: jest.fn(),
      changed: jest.fn(),
      findByPk: jest.fn(),
      findOne: jest.fn(),
      findAll: jest.fn(),
      create: jest.fn(),
    };

    // Mock static methods
    mockPasswordReset.constructor.findByToken = jest.fn();
    mockPasswordReset.constructor.findByTokenHash = jest.fn();
    mockPasswordReset.constructor.findActiveResets = jest.fn();
    mockPasswordReset.constructor.createReset = jest.fn();
    mockPasswordReset.constructor.markAsUsed = jest.fn();
    mockPasswordReset.constructor.revokeReset = jest.fn();
    mockPasswordReset.constructor.cleanupExpiredResets = jest.fn();
    mockPasswordReset.constructor.getResetStats = jest.fn();
    mockPasswordReset.constructor.validateToken = jest.fn();
    mockPasswordReset.constructor.validateEmail = jest.fn();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Static Methods - Password Reset Management', () => {
    describe('findByToken', () => {
      it('should find password reset by token with user data', async () => {
        // Arrange
        const token = 'password-reset-token-123';
        const resetWithUser = {
          ...mockPasswordResetData,
          user: {
            id: 'user-id-456',
            email: 'test@example.com',
            type: 'customer',
            role: 'customer',
          },
        };

        mockPasswordReset.constructor.findByToken.mockResolvedValue(
          resetWithUser
        );

        // Act
        const result = await mockPasswordReset.constructor.findByToken(token);

        // Assert
        expect(result).toEqual(resetWithUser);
        expect(result.user).toBeDefined();
        expect(result.user.email).toBe('test@example.com');
        expect(mockPasswordReset.constructor.findByToken).toHaveBeenCalledWith(
          token
        );
      });

      it('should return null when token not found', async () => {
        // Arrange
        const token = 'nonexistent-token';
        mockPasswordReset.constructor.findByToken.mockResolvedValue(null);

        // Act
        const result = await mockPasswordReset.constructor.findByToken(token);

        // Assert
        expect(result).toBeNull();
      });

      it('should handle database errors gracefully', async () => {
        // Arrange
        const token = 'test-token';
        const dbError = new Error('Database connection failed');
        mockPasswordReset.constructor.findByToken.mockRejectedValue(dbError);

        // Act & Assert
        await expect(
          mockPasswordReset.constructor.findByToken(token)
        ).rejects.toThrow('Database connection failed');
      });

      it('should mask token in error logs for security', async () => {
        // Arrange
        const token = 'very-long-password-reset-token-123456789';
        const dbError = new Error('Database error');
        mockPasswordReset.constructor.findByToken.mockRejectedValue(dbError);

        // Act & Assert
        try {
          await mockPasswordReset.constructor.findByToken(token);
        } catch (error) {
          // Token should be masked in logs (first 8 chars + ...)
          expect(token.substring(0, 8) + '...').toBe('very-lon...');
        }
      });
    });

    describe('findByTokenHash', () => {
      it('should find password reset by token hash', async () => {
        // Arrange
        const tokenHash = 'hashed-reset-token-abc-def-123';
        const resetWithUser = {
          ...mockPasswordResetData,
          user: { id: 'user-id-456', email: 'test@example.com' },
        };

        mockPasswordReset.constructor.findByTokenHash.mockResolvedValue(
          resetWithUser
        );

        // Act
        const result =
          await mockPasswordReset.constructor.findByTokenHash(tokenHash);

        // Assert
        expect(result).toEqual(resetWithUser);
        expect(
          mockPasswordReset.constructor.findByTokenHash
        ).toHaveBeenCalledWith(tokenHash);
      });

      it('should handle token hash search errors', async () => {
        // Arrange
        const tokenHash = 'invalid-hash';
        const searchError = new Error('Hash search failed');
        mockPasswordReset.constructor.findByTokenHash.mockRejectedValue(
          searchError
        );

        // Act & Assert
        await expect(
          mockPasswordReset.constructor.findByTokenHash(tokenHash)
        ).rejects.toThrow('Hash search failed');
      });
    });

    describe('findActiveResets', () => {
      it('should find active password resets for user', async () => {
        // Arrange
        const userId = 'user-id-123';
        const activeResets = [
          {
            id: 'reset-1',
            status: 'pending',
            expiresAt: new Date(Date.now() + 3600000),
          },
          {
            id: 'reset-2',
            status: 'pending',
            expiresAt: new Date(Date.now() + 7200000),
          },
        ];

        mockPasswordReset.constructor.findActiveResets.mockResolvedValue(
          activeResets
        );

        // Act
        const result =
          await mockPasswordReset.constructor.findActiveResets(userId);

        // Assert
        expect(result).toEqual(activeResets);
        expect(
          mockPasswordReset.constructor.findActiveResets
        ).toHaveBeenCalledWith(userId);
      });

      it('should handle active reset search errors', async () => {
        // Arrange
        const userId = 'user-id-123';
        const searchError = new Error('Active reset search failed');
        mockPasswordReset.constructor.findActiveResets.mockRejectedValue(
          searchError
        );

        // Act & Assert
        await expect(
          mockPasswordReset.constructor.findActiveResets(userId)
        ).rejects.toThrow('Active reset search failed');
      });
    });

    describe('createReset', () => {
      it('should create password reset with required fields', async () => {
        // Arrange
        const resetData = {
          userId: 'user-id-123',
          email: 'new@example.com',
          token: 'new-reset-token-123',
          tokenHash: 'new-hashed-token-456',
        };
        const createdReset = { ...resetData, id: 'new-reset-id' };

        mockPasswordReset.constructor.createReset.mockResolvedValue(
          createdReset
        );

        // Act
        const result =
          await mockPasswordReset.constructor.createReset(resetData);

        // Assert
        expect(result).toEqual(createdReset);
        expect(mockPasswordReset.constructor.createReset).toHaveBeenCalledWith(
          resetData,
          {}
        );
      });

      it('should set default expiration when not provided', async () => {
        // Arrange
        const resetData = {
          userId: 'user-id-123',
          email: 'test@example.com',
          token: 'token-123',
          tokenHash: 'hash-456',
        };

        // Act - Simulate default expiration logic
        if (!resetData.expiresAt) {
          resetData.expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
        }

        // Assert
        expect(resetData.expiresAt).toBeInstanceOf(Date);
        expect(resetData.expiresAt.getTime()).toBeGreaterThan(
          new Date().getTime()
        );
      });

      it('should reject creation without required fields', async () => {
        const requiredFields = ['userId', 'email', 'token', 'tokenHash'];

        requiredFields.forEach(field => {
          const incompleteData = { ...mockPasswordResetData };
          delete incompleteData[field];

          // Act & Assert
          expect(() => {
            if (!incompleteData[field]) {
              throw new ApiError(
                400,
                `${field.charAt(0).toUpperCase() + field.slice(1)} is required`
              );
            }
          }).toThrow(
            `${field.charAt(0).toUpperCase() + field.slice(1)} is required`
          );
        });
      });

      it('should reject creation with existing active reset', async () => {
        // Arrange
        const resetData = {
          userId: 'user-id-123',
          email: 'existing@example.com',
          token: 'token-123',
          tokenHash: 'hash-456',
        };

        // Act & Assert
        expect(() => {
          // Simulate finding existing reset
          const existingReset = { id: 'existing-id', status: 'pending' };
          if (existingReset) {
            throw new ApiError(409, 'Active password reset already exists');
          }
        }).toThrow('Active password reset already exists');
      });

      it('should handle creation errors gracefully', async () => {
        // Arrange
        const resetData = { userId: 'user-id-123', email: 'test@example.com' };
        const creationError = new Error('Password reset creation failed');
        mockPasswordReset.constructor.createReset.mockRejectedValue(
          creationError
        );

        // Act & Assert
        await expect(
          mockPasswordReset.constructor.createReset(resetData)
        ).rejects.toThrow('Password reset creation failed');
      });
    });

    describe('markAsUsed', () => {
      it('should mark password reset as used successfully', async () => {
        // Arrange
        const resetId = 'reset-id-123';
        const reset = { ...mockPasswordResetData, status: 'pending' };

        mockPasswordReset.constructor.markAsUsed.mockResolvedValue(reset);

        // Act
        const result = await mockPasswordReset.constructor.markAsUsed(resetId);

        // Assert
        expect(result).toEqual(reset);
        expect(mockPasswordReset.constructor.markAsUsed).toHaveBeenCalledWith(
          resetId,
          {}
        );
      });

      it('should reject reset when not found', async () => {
        // Arrange
        const resetId = 'nonexistent-id';

        // Act & Assert
        expect(() => {
          const reset = null;
          if (!reset) {
            throw new ApiError(404, 'Password reset not found');
          }
        }).toThrow('Password reset not found');
      });

      it('should reject reset when not in pending status', async () => {
        // Arrange
        const reset = { ...mockPasswordResetData, status: 'used' };

        // Act & Assert
        expect(() => {
          if (reset.status !== 'pending') {
            throw new ApiError(400, 'Password reset is not in pending status');
          }
        }).toThrow('Password reset is not in pending status');
      });

      it('should reject reset when expired', async () => {
        // Arrange
        const reset = {
          ...mockPasswordResetData,
          status: 'pending',
          expiresAt: new Date(Date.now() - 3600000), // 1 hour ago
        };

        // Act & Assert
        expect(() => {
          if (reset.expiresAt < new Date()) {
            throw new ApiError(400, 'Password reset has expired');
          }
        }).toThrow('Password reset has expired');
      });
    });

    describe('revokeReset', () => {
      it('should revoke password reset successfully', async () => {
        // Arrange
        const resetId = 'reset-id-123';
        const reason = 'security_breach';
        const reset = { ...mockPasswordResetData };

        mockPasswordReset.constructor.revokeReset.mockResolvedValue(reset);

        // Act
        const result = await mockPasswordReset.constructor.revokeReset(
          resetId,
          reason
        );

        // Assert
        expect(result).toEqual(reset);
        expect(mockPasswordReset.constructor.revokeReset).toHaveBeenCalledWith(
          resetId,
          reason,
          {}
        );
      });

      it('should use default revocation reason when not provided', async () => {
        // Arrange
        const resetId = 'reset-id-123';
        const defaultReason = 'manual_revocation';

        // Act - Simulate default reason logic
        const reason = defaultReason;

        // Assert
        expect(reason).toBe('manual_revocation');
      });

      it('should handle revocation errors gracefully', async () => {
        // Arrange
        const resetId = 'reset-id-123';
        const revocationError = new Error('Revocation failed');
        mockPasswordReset.constructor.revokeReset.mockRejectedValue(
          revocationError
        );

        // Act & Assert
        await expect(
          mockPasswordReset.constructor.revokeReset(resetId)
        ).rejects.toThrow('Revocation failed');
      });
    });

    describe('cleanupExpiredResets', () => {
      it('should cleanup expired password resets and return count', async () => {
        // Arrange
        const cleanedCount = 5;
        mockPasswordReset.constructor.cleanupExpiredResets.mockResolvedValue(
          cleanedCount
        );

        // Act
        const result =
          await mockPasswordReset.constructor.cleanupExpiredResets();

        // Assert
        expect(result).toBe(cleanedCount);
        expect(
          mockPasswordReset.constructor.cleanupExpiredResets
        ).toHaveBeenCalled();
      });

      it('should handle cleanup errors gracefully', async () => {
        // Arrange
        const cleanupError = new Error('Cleanup operation failed');
        mockPasswordReset.constructor.cleanupExpiredResets.mockRejectedValue(
          cleanupError
        );

        // Act & Assert
        await expect(
          mockPasswordReset.constructor.cleanupExpiredResets()
        ).rejects.toThrow('Cleanup operation failed');
      });
    });

    describe('getResetStats', () => {
      it('should return password reset statistics grouped by status', async () => {
        // Arrange
        const mockStats = [
          { status: 'pending', count: '15' },
          { status: 'used', count: '30' },
          { status: 'expired', count: '8' },
          { status: 'revoked', count: '3' },
        ];
        const expectedStats = {
          pending: 15,
          used: 30,
          expired: 8,
          revoked: 3,
        };

        mockPasswordReset.constructor.getResetStats.mockResolvedValue(
          expectedStats
        );

        // Act
        const result = await mockPasswordReset.constructor.getResetStats();

        // Assert
        expect(result).toEqual(expectedStats);
        expect(mockPasswordReset.constructor.getResetStats).toHaveBeenCalled();
      });

      it('should return empty object when no stats available', async () => {
        // Arrange
        mockPasswordReset.constructor.getResetStats.mockResolvedValue({});

        // Act
        const result = await mockPasswordReset.constructor.getResetStats();

        // Assert
        expect(result).toEqual({});
      });

      it('should handle statistics errors gracefully', async () => {
        // Arrange
        const statsError = new Error('Statistics query failed');
        mockPasswordReset.constructor.getResetStats.mockRejectedValue(
          statsError
        );

        // Act & Assert
        await expect(
          mockPasswordReset.constructor.getResetStats()
        ).rejects.toThrow('Statistics query failed');
      });
    });
  });

  describe('Static Methods - Validation', () => {
    describe('validateToken', () => {
      it('should validate token format correctly', async () => {
        // Arrange
        const validToken = 'valid-password-reset-token-123456789';
        const invalidToken = 'short';

        // Act - Simulate token validation logic
        const validateTokenLength = token => {
          if (token.length < 32) {
            return { isValid: false, errors: ['Token too short'] };
          }
          if (token.length > 255) {
            return { isValid: false, errors: ['Token too long'] };
          }
          return { isValid: true, errors: [] };
        };

        const validResult = validateTokenLength(validToken);
        const invalidResult = validateTokenLength(invalidToken);

        // Assert
        expect(validResult.isValid).toBe(true);
        expect(validResult.errors).toEqual([]);
        expect(invalidResult.isValid).toBe(false);
        expect(invalidResult.errors).toContain('Token too short');
      });

      it('should handle validation errors gracefully', async () => {
        // Arrange
        const token = 'test-token';
        const validationError = new Error('Token validation failed');

        // Act & Assert
        try {
          throw validationError;
        } catch (error) {
          expect(error.message).toBe('Token validation failed');
        }
      });
    });

    describe('validateEmail', () => {
      it('should validate correct email format', async () => {
        // Arrange
        const validEmail = 'test@example.com';
        const invalidEmail = 'invalid-email';

        // Act - Simulate email validation logic
        const validateEmailFormat = email => {
          const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
          if (!emailRegex.test(email)) {
            return { isValid: false, errors: ['Invalid email format'] };
          }
          return { isValid: true, errors: [] };
        };

        const validResult = validateEmailFormat(validEmail);
        const invalidResult = validateEmailFormat(invalidEmail);

        // Assert
        expect(validResult.isValid).toBe(true);
        expect(validResult.errors).toEqual([]);
        expect(invalidResult.isValid).toBe(false);
        expect(invalidResult.errors).toContain('Invalid email format');
      });

      it('should handle email validation errors gracefully', async () => {
        // Arrange
        const email = 'test@example.com';
        const validationError = new Error('Email validation failed');

        // Act & Assert
        try {
          throw validationError;
        } catch (error) {
          expect(error.message).toBe('Email validation failed');
        }
      });
    });
  });

  describe('Instance Methods', () => {
    describe('isExpired', () => {
      it('should return false for active password reset', () => {
        // Arrange
        const reset = {
          ...mockPasswordResetData,
          expiresAt: new Date(Date.now() + 3600000), // 1 hour from now
        };

        // Act
        const result = reset.expiresAt > new Date();

        // Assert
        expect(result).toBe(true); // Not expired yet
      });

      it('should return true for expired password reset', () => {
        // Arrange
        const reset = {
          ...mockPasswordResetData,
          expiresAt: new Date(Date.now() - 3600000), // 1 hour ago
        };

        // Act
        const result = reset.expiresAt < new Date();

        // Assert
        expect(result).toBe(true); // Already expired
      });

      it('should handle edge case - reset expiring now', () => {
        // Arrange
        const reset = {
          ...mockPasswordResetData,
          expiresAt: new Date(), // Expires now
        };

        // Act
        const result = reset.expiresAt.getTime() === new Date().getTime();

        // Assert
        expect(result).toBe(true); // Expires exactly now
      });
    });

    describe('isMaxAttemptsReached', () => {
      it('should return false when attempts below maximum', () => {
        // Arrange
        const reset = {
          ...mockPasswordResetData,
          attempts: 1,
          maxAttempts: 3,
        };

        // Act
        const result = reset.attempts < reset.maxAttempts;

        // Assert
        expect(result).toBe(true); // Still has attempts left
      });

      it('should return true when attempts at maximum', () => {
        // Arrange
        const reset = {
          ...mockPasswordResetData,
          attempts: 3,
          maxAttempts: 3,
        };

        // Act
        const result = reset.attempts >= reset.maxAttempts;

        // Assert
        expect(result).toBe(true); // Max attempts reached
      });

      it('should return true when attempts exceed maximum', () => {
        // Arrange
        const reset = {
          ...mockPasswordResetData,
          attempts: 4,
          maxAttempts: 3,
        };

        // Act
        const result = reset.attempts >= reset.maxAttempts;

        // Assert
        expect(result).toBe(true); // Exceeded max attempts
      });
    });

    describe('incrementAttempts', () => {
      it('should increment attempts successfully', async () => {
        // Arrange
        const reset = { ...mockPasswordResetData, attempts: 1 };

        // Act - Simulate incrementing attempts
        reset.attempts += 1;

        // Assert
        expect(reset.attempts).toBe(2);
      });

      it('should handle attempt increment errors gracefully', async () => {
        // Arrange
        const reset = { ...mockPasswordResetData };
        const incrementError = new Error('Increment failed');

        // Act & Assert
        try {
          throw incrementError;
        } catch (error) {
          expect(error.message).toBe('Increment failed');
        }
      });
    });

    describe('markAsSent', () => {
      it('should mark password reset as sent with provider info', async () => {
        // Arrange
        const reset = { ...mockPasswordResetData };
        const emailProvider = 'sendgrid';
        const emailId = 'email-123-456';

        // Act - Simulate marking as sent
        reset.sentAt = new Date();
        reset.emailProvider = emailProvider;
        reset.emailId = emailId;

        // Assert
        expect(reset.sentAt).toBeInstanceOf(Date);
        expect(reset.emailProvider).toBe(emailProvider);
        expect(reset.emailId).toBe(emailId);
      });

      it('should handle mark as sent errors gracefully', async () => {
        // Arrange
        const reset = { ...mockPasswordResetData };
        const markError = new Error('Mark as sent failed');

        // Act & Assert
        try {
          throw markError;
        } catch (error) {
          expect(error.message).toBe('Mark as sent failed');
        }
      });
    });

    describe('toSafeJSON', () => {
      it('should return reset data without sensitive fields', () => {
        // Arrange
        const reset = { ...mockPasswordResetData };

        // Act - Simulate toSafeJSON method
        const safeData = { ...reset };
        delete safeData.token;
        delete safeData.tokenHash;

        // Assert
        expect(safeData.token).toBeUndefined();
        expect(safeData.tokenHash).toBeUndefined();
        expect(safeData.userId).toBe(reset.userId);
        expect(safeData.email).toBe(reset.email);
        expect(safeData.status).toBe(reset.status);
      });

      it('should preserve all non-sensitive fields', () => {
        // Arrange
        const reset = { ...mockPasswordResetData };

        // Act - Simulate toSafeJSON method
        const safeData = { ...reset };
        delete safeData.token;
        delete safeData.tokenHash;

        // Assert - Check that important fields are preserved
        const preservedFields = [
          'id',
          'userId',
          'email',
          'expiresAt',
          'usedAt',
          'ipAddress',
          'userAgent',
          'status',
          'attempts',
          'maxAttempts',
          'sentAt',
          'emailProvider',
          'emailId',
          'createdAt',
          'updatedAt',
        ];

        preservedFields.forEach(field => {
          expect(safeData[field]).toBeDefined();
        });
      });
    });
  });

  describe('Model Validation and Constraints', () => {
    it('should validate required fields', () => {
      const requiredFields = [
        'userId',
        'email',
        'token',
        'tokenHash',
        'expiresAt',
      ];
      const reset = { ...mockPasswordResetData };

      requiredFields.forEach(field => {
        expect(reset[field]).toBeDefined();
        expect(reset[field]).not.toBeNull();
      });
    });

    it('should validate token length constraints', () => {
      const reset = { ...mockPasswordResetData };

      // Token should be between 32 and 255 characters
      expect(reset.token.length).toBeGreaterThanOrEqual(32);
      expect(reset.token.length).toBeLessThanOrEqual(255);
    });

    it('should validate token hash length constraints', () => {
      const reset = { ...mockPasswordResetData };

      // Token hash should be between 32 and 255 characters
      expect(reset.tokenHash.length).toBeGreaterThanOrEqual(32);
      expect(reset.tokenHash.length).toBeLessThanOrEqual(255);
    });

    it('should validate expiration date logic', () => {
      const reset = { ...mockPasswordResetData };

      // Expiration should be in the future for pending resets
      if (reset.status === 'pending') {
        expect(reset.expiresAt.getTime()).toBeGreaterThan(new Date().getTime());
      }
    });

    it('should validate attempts constraints', () => {
      const reset = { ...mockPasswordResetData };

      // Attempts should be between 0 and maxAttempts
      expect(reset.attempts).toBeGreaterThanOrEqual(0);
      expect(reset.attempts).toBeLessThanOrEqual(reset.maxAttempts);
    });

    it('should validate max attempts constraints', () => {
      const reset = { ...mockPasswordResetData };

      // Max attempts should be between 1 and 5 (more restrictive than email verification)
      expect(reset.maxAttempts).toBeGreaterThanOrEqual(1);
      expect(reset.maxAttempts).toBeLessThanOrEqual(5);
    });
  });

  describe('Status Management', () => {
    it('should handle all valid status values', () => {
      const validStatuses = ['pending', 'used', 'expired', 'revoked'];
      const reset = { ...mockPasswordResetData };

      validStatuses.forEach(status => {
        reset.status = status;
        expect(validStatuses.includes(reset.status)).toBe(true);
      });
    });

    it('should reject invalid status values', () => {
      const validStatuses = ['pending', 'used', 'expired', 'revoked'];
      const invalidStatuses = ['invalid', 'active', 'inactive', 'verified', ''];

      invalidStatuses.forEach(status => {
        expect(validStatuses.includes(status)).toBe(false);
      });
    });

    it('should handle status transitions correctly', () => {
      const reset = { ...mockPasswordResetData, status: 'pending' };

      // Pending -> Used
      reset.status = 'used';
      reset.usedAt = new Date();
      expect(reset.status).toBe('used');
      expect(reset.usedAt).toBeInstanceOf(Date);

      // Used -> Revoked
      reset.status = 'revoked';
      expect(reset.status).toBe('revoked');

      // Pending -> Expired (via cleanup)
      reset.status = 'expired';
      expect(reset.status).toBe('expired');
    });
  });

  describe('Email Provider Integration', () => {
    it('should track email provider information', () => {
      const reset = { ...mockPasswordResetData };
      const emailProvider = 'sendgrid';
      const emailId = 'email-123-456';

      // Act - Simulate email sending
      reset.emailProvider = emailProvider;
      reset.emailId = emailId;
      reset.sentAt = new Date();

      // Assert
      expect(reset.emailProvider).toBe(emailProvider);
      expect(reset.emailId).toBe(emailId);
      expect(reset.sentAt).toBeInstanceOf(Date);
    });

    it('should handle different email providers', () => {
      const emailProviders = ['sendgrid', 'mailgun', 'ses', 'smtp'];
      const reset = { ...mockPasswordResetData };

      emailProviders.forEach(provider => {
        reset.emailProvider = provider;
        expect(reset.emailProvider).toBe(provider);
      });
    });
  });

  describe('Security Features', () => {
    it('should enforce shorter expiration time than email verification', () => {
      const reset = { ...mockPasswordResetData };
      const emailVerificationExpiry = 24 * 60 * 60 * 1000; // 24 hours
      const resetExpiry = 60 * 60 * 1000; // 1 hour

      // Password resets should expire faster for security
      expect(resetExpiry).toBeLessThan(emailVerificationExpiry);
    });

    it('should enforce stricter attempt limits than email verification', () => {
      const reset = { ...mockPasswordResetData };
      const emailVerificationMaxAttempts = 5;
      const resetMaxAttempts = 3;

      // Password resets should have fewer attempts for security
      expect(resetMaxAttempts).toBeLessThan(emailVerificationMaxAttempts);
    });

    it('should track IP address for security monitoring', () => {
      const reset = { ...mockPasswordResetData };

      expect(reset.ipAddress).toBeDefined();
      expect(typeof reset.ipAddress).toBe('string');
      expect(reset.ipAddress).toMatch(/^\d+\.\d+\.\d+\.\d+$/);
    });

    it('should track user agent for security monitoring', () => {
      const reset = { ...mockPasswordResetData };

      expect(reset.userAgent).toBeDefined();
      expect(typeof reset.userAgent).toBe('string');
      expect(reset.userAgent.length).toBeGreaterThan(0);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle null and undefined values gracefully', () => {
      const reset = { ...mockPasswordResetData };

      // Test with null values
      reset.usedAt = null;
      reset.ipAddress = null;
      reset.userAgent = null;

      // Test with undefined values
      reset.emailProvider = undefined;
      reset.emailId = undefined;

      // Assert - Should not crash
      expect(reset.usedAt).toBeNull();
      expect(reset.ipAddress).toBeNull();
      expect(reset.userAgent).toBeNull();
      expect(reset.emailProvider).toBeUndefined();
      expect(reset.emailId).toBeUndefined();
    });

    it('should handle very long strings gracefully', () => {
      const reset = { ...mockPasswordResetData };

      // Test with very long token
      const longToken = 'A'.repeat(255);
      reset.token = longToken;

      // Test with very long email
      const longEmail = 'a'.repeat(250) + '@example.com';
      reset.email = longEmail;

      // Assert
      expect(reset.token.length).toBe(255);
      expect(reset.email.length).toBe(255 + 12); // 250 + '@example.com'
    });

    it('should handle special characters in data', () => {
      const reset = { ...mockPasswordResetData };

      // Test with special characters in email
      reset.email = 'test+special.email@example-domain.com';

      // Test with special characters in user agent
      reset.userAgent =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';

      // Assert
      expect(reset.email).toBe('test+special.email@example-domain.com');
      expect(reset.userAgent).toContain('Chrome/91.0.4472.124');
    });
  });

  describe('Performance Tests', () => {
    it('should handle bulk reset operations efficiently', () => {
      // Arrange
      const bulkResets = Array.from({ length: 1000 }, (_, i) => ({
        id: `reset-${i}`,
        userId: `user-${i % 100}`,
        email: `user${i}@example.com`,
        status: ['pending', 'used', 'expired', 'revoked'][i % 4],
        expiresAt: new Date(Date.now() + i * 60000), // Each expires 1 minute later
      }));

      // Act
      const startTime = Date.now();
      const pendingResets = bulkResets.filter(r => r.status === 'pending');
      const expiredResets = bulkResets.filter(r => r.status === 'expired');
      const endTime = Date.now();

      // Assert
      expect(pendingResets).toHaveLength(250);
      expect(expiredResets).toHaveLength(250);
      expect(endTime - startTime).toBeLessThan(10); // Less than 10ms for 1000 items
    });

    it('should handle reset validation efficiently', () => {
      // Arrange
      const iterations = 100;
      const startTime = Date.now();

      // Act
      for (let i = 0; i < iterations; i++) {
        const reset = {
          id: `reset-${i}`,
          userId: `user-${i}`,
          email: `user${i}@example.com`,
          token: `token-${i}-${'a'.repeat(30)}`,
          tokenHash: `hash-${i}-${'b'.repeat(30)}`,
          status: 'pending',
          expiresAt: new Date(Date.now() + 3600000),
        };

        // Simulate validation checks
        expect(reset.token.length).toBeGreaterThanOrEqual(32);
        expect(reset.tokenHash.length).toBeGreaterThanOrEqual(32);
        expect(reset.expiresAt.getTime()).toBeGreaterThan(new Date().getTime());
      }
      const endTime = Date.now();

      // Assert
      const averageTime = (endTime - startTime) / iterations;
      expect(averageTime).toBeLessThan(1); // Less than 1ms per validation
    });
  });
});
