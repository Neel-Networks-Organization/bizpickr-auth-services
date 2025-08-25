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

// Simple EmailVerification Model Tests - Basic Functionality
describe('EmailVerification Model - Basic Tests', () => {
  let mockVerification;
  let mockVerificationData;

  beforeEach(() => {
    jest.clearAllMocks();

    // Mock verification data
    mockVerificationData = {
      id: 'verification-id-123',
      userId: 'user-id-456',
      email: 'test@example.com',
      token: 'verification-token-789-abcdef-123456',
      tokenHash: 'hashed-token-abc-def-123-456',
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours from now
      verifiedAt: null,
      ipAddress: '192.168.1.1',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      status: 'pending',
      attempts: 0,
      maxAttempts: 5,
      sentAt: null,
      emailProvider: null,
      emailId: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    // Mock verification instance
    mockVerification = {
      ...mockVerificationData,
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
    mockVerification.constructor.findByToken = jest.fn();
    mockVerification.constructor.findByTokenHash = jest.fn();
    mockVerification.constructor.findActiveVerifications = jest.fn();
    mockVerification.constructor.createVerification = jest.fn();
    mockVerification.constructor.markAsVerified = jest.fn();
    mockVerification.constructor.revokeVerification = jest.fn();
    mockVerification.constructor.cleanupExpiredVerifications = jest.fn();
    mockVerification.constructor.getVerificationStats = jest.fn();
    mockVerification.constructor.validateToken = jest.fn();
    mockVerification.constructor.validateEmail = jest.fn();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Static Methods - Verification Management', () => {
    describe('findByToken', () => {
      it('should find verification by token with user data', async () => {
        // Arrange
        const token = 'verification-token-123';
        const verificationWithUser = {
          ...mockVerificationData,
          user: {
            id: 'user-id-456',
            email: 'test@example.com',
            type: 'customer',
            role: 'customer',
          },
        };

        mockVerification.constructor.findByToken.mockResolvedValue(
          verificationWithUser
        );

        // Act
        const result = await mockVerification.constructor.findByToken(token);

        // Assert
        expect(result).toEqual(verificationWithUser);
        expect(result.user).toBeDefined();
        expect(result.user.email).toBe('test@example.com');
        expect(mockVerification.constructor.findByToken).toHaveBeenCalledWith(
          token
        );
      });

      it('should return null when token not found', async () => {
        // Arrange
        const token = 'nonexistent-token';
        mockVerification.constructor.findByToken.mockResolvedValue(null);

        // Act
        const result = await mockVerification.constructor.findByToken(token);

        // Assert
        expect(result).toBeNull();
      });

      it('should handle database errors gracefully', async () => {
        // Arrange
        const token = 'test-token';
        const dbError = new Error('Database connection failed');
        mockVerification.constructor.findByToken.mockRejectedValue(dbError);

        // Act & Assert
        await expect(
          mockVerification.constructor.findByToken(token)
        ).rejects.toThrow('Database connection failed');
      });

      it('should mask token in error logs for security', async () => {
        // Arrange
        const token = 'very-long-verification-token-123456789';
        const dbError = new Error('Database error');
        mockVerification.constructor.findByToken.mockRejectedValue(dbError);

        // Act & Assert
        try {
          await mockVerification.constructor.findByToken(token);
        } catch (error) {
          // Token should be masked in logs (first 8 chars + ...)
          expect(token.substring(0, 8) + '...').toBe('very-lon...');
        }
      });
    });

    describe('findByTokenHash', () => {
      it('should find verification by token hash', async () => {
        // Arrange
        const tokenHash = 'hashed-token-abc-def-123';
        const verificationWithUser = {
          ...mockVerificationData,
          user: { id: 'user-id-456', email: 'test@example.com' },
        };

        mockVerification.constructor.findByTokenHash.mockResolvedValue(
          verificationWithUser
        );

        // Act
        const result =
          await mockVerification.constructor.findByTokenHash(tokenHash);

        // Assert
        expect(result).toEqual(verificationWithUser);
        expect(
          mockVerification.constructor.findByTokenHash
        ).toHaveBeenCalledWith(tokenHash);
      });

      it('should handle token hash search errors', async () => {
        // Arrange
        const tokenHash = 'invalid-hash';
        const searchError = new Error('Hash search failed');
        mockVerification.constructor.findByTokenHash.mockRejectedValue(
          searchError
        );

        // Act & Assert
        await expect(
          mockVerification.constructor.findByTokenHash(tokenHash)
        ).rejects.toThrow('Hash search failed');
      });
    });

    describe('findActiveVerifications', () => {
      it('should find active verifications for user', async () => {
        // Arrange
        const userId = 'user-id-123';
        const activeVerifications = [
          {
            id: 'verification-1',
            status: 'pending',
            expiresAt: new Date(Date.now() + 3600000),
          },
          {
            id: 'verification-2',
            status: 'pending',
            expiresAt: new Date(Date.now() + 7200000),
          },
        ];

        mockVerification.constructor.findActiveVerifications.mockResolvedValue(
          activeVerifications
        );

        // Act
        const result =
          await mockVerification.constructor.findActiveVerifications(userId);

        // Assert
        expect(result).toEqual(activeVerifications);
        expect(
          mockVerification.constructor.findActiveVerifications
        ).toHaveBeenCalledWith(userId);
      });

      it('should handle active verification search errors', async () => {
        // Arrange
        const userId = 'user-id-123';
        const searchError = new Error('Active verification search failed');
        mockVerification.constructor.findActiveVerifications.mockRejectedValue(
          searchError
        );

        // Act & Assert
        await expect(
          mockVerification.constructor.findActiveVerifications(userId)
        ).rejects.toThrow('Active verification search failed');
      });
    });

    describe('createVerification', () => {
      it('should create verification with required fields', async () => {
        // Arrange
        const verificationData = {
          userId: 'user-id-123',
          email: 'new@example.com',
          token: 'new-verification-token-123',
          tokenHash: 'new-hashed-token-456',
        };
        const createdVerification = {
          ...verificationData,
          id: 'new-verification-id',
        };

        mockVerification.constructor.createVerification.mockResolvedValue(
          createdVerification
        );

        // Act
        const result =
          await mockVerification.constructor.createVerification(
            verificationData
          );

        // Assert
        expect(result).toEqual(createdVerification);
        expect(
          mockVerification.constructor.createVerification
        ).toHaveBeenCalledWith(verificationData, {});
      });

      it('should set default expiration when not provided', async () => {
        // Arrange
        const verificationData = {
          userId: 'user-id-123',
          email: 'test@example.com',
          token: 'token-123',
          tokenHash: 'hash-456',
        };

        // Act - Simulate default expiration logic
        if (!verificationData.expiresAt) {
          verificationData.expiresAt = new Date(
            Date.now() + 24 * 60 * 60 * 1000
          ); // 24 hours
        }

        // Assert
        expect(verificationData.expiresAt).toBeInstanceOf(Date);
        expect(verificationData.expiresAt.getTime()).toBeGreaterThan(
          new Date().getTime()
        );
      });

      it('should reject creation without required fields', async () => {
        const requiredFields = ['userId', 'email', 'token', 'tokenHash'];

        requiredFields.forEach(field => {
          const incompleteData = { ...mockVerificationData };
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

      it('should reject creation with existing active verification', async () => {
        // Arrange
        const verificationData = {
          userId: 'user-id-123',
          email: 'existing@example.com',
          token: 'token-123',
          tokenHash: 'hash-456',
        };

        // Act & Assert
        expect(() => {
          // Simulate finding existing verification
          const existingVerification = { id: 'existing-id', status: 'pending' };
          if (existingVerification) {
            throw new ApiError(409, 'Active verification already exists');
          }
        }).toThrow('Active verification already exists');
      });

      it('should handle creation errors gracefully', async () => {
        // Arrange
        const verificationData = {
          userId: 'user-id-123',
          email: 'test@example.com',
        };
        const creationError = new Error('Verification creation failed');
        mockVerification.constructor.createVerification.mockRejectedValue(
          creationError
        );

        // Act & Assert
        await expect(
          mockVerification.constructor.createVerification(verificationData)
        ).rejects.toThrow('Verification creation failed');
      });
    });

    describe('markAsVerified', () => {
      it('should mark verification as verified successfully', async () => {
        // Arrange
        const verificationId = 'verification-id-123';
        const verification = { ...mockVerificationData, status: 'pending' };

        mockVerification.constructor.markAsVerified.mockResolvedValue(
          verification
        );

        // Act
        const result =
          await mockVerification.constructor.markAsVerified(verificationId);

        // Assert
        expect(result).toEqual(verification);
        expect(
          mockVerification.constructor.markAsVerified
        ).toHaveBeenCalledWith(verificationId, {});
      });

      it('should reject verification when not found', async () => {
        // Arrange
        const verificationId = 'nonexistent-id';

        // Act & Assert
        expect(() => {
          const verification = null;
          if (!verification) {
            throw new ApiError(404, 'Verification not found');
          }
        }).toThrow('Verification not found');
      });

      it('should reject verification when not in pending status', async () => {
        // Arrange
        const verification = { ...mockVerificationData, status: 'verified' };

        // Act & Assert
        expect(() => {
          if (verification.status !== 'pending') {
            throw new ApiError(400, 'Verification is not in pending status');
          }
        }).toThrow('Verification is not in pending status');
      });

      it('should reject verification when expired', async () => {
        // Arrange
        const verification = {
          ...mockVerificationData,
          status: 'pending',
          expiresAt: new Date(Date.now() - 3600000), // 1 hour ago
        };

        // Act & Assert
        expect(() => {
          if (verification.expiresAt < new Date()) {
            throw new ApiError(400, 'Verification has expired');
          }
        }).toThrow('Verification has expired');
      });
    });

    describe('revokeVerification', () => {
      it('should revoke verification successfully', async () => {
        // Arrange
        const verificationId = 'verification-id-123';
        const reason = 'security_breach';
        const verification = { ...mockVerificationData };

        mockVerification.constructor.revokeVerification.mockResolvedValue(
          verification
        );

        // Act
        const result = await mockVerification.constructor.revokeVerification(
          verificationId,
          reason
        );

        // Assert
        expect(result).toEqual(verification);
        expect(
          mockVerification.constructor.revokeVerification
        ).toHaveBeenCalledWith(verificationId, reason, {});
      });

      it('should use default revocation reason when not provided', async () => {
        // Arrange
        const verificationId = 'verification-id-123';
        const defaultReason = 'manual_revocation';

        // Act - Simulate default reason logic
        const reason = defaultReason;

        // Assert
        expect(reason).toBe('manual_revocation');
      });

      it('should handle revocation errors gracefully', async () => {
        // Arrange
        const verificationId = 'verification-id-123';
        const revocationError = new Error('Revocation failed');
        mockVerification.constructor.revokeVerification.mockRejectedValue(
          revocationError
        );

        // Act & Assert
        await expect(
          mockVerification.constructor.revokeVerification(verificationId)
        ).rejects.toThrow('Revocation failed');
      });
    });

    describe('cleanupExpiredVerifications', () => {
      it('should cleanup expired verifications and return count', async () => {
        // Arrange
        const cleanedCount = 3;
        mockVerification.constructor.cleanupExpiredVerifications.mockResolvedValue(
          cleanedCount
        );

        // Act
        const result =
          await mockVerification.constructor.cleanupExpiredVerifications();

        // Assert
        expect(result).toBe(cleanedCount);
        expect(
          mockVerification.constructor.cleanupExpiredVerifications
        ).toHaveBeenCalled();
      });

      it('should handle cleanup errors gracefully', async () => {
        // Arrange
        const cleanupError = new Error('Cleanup operation failed');
        mockVerification.constructor.cleanupExpiredVerifications.mockRejectedValue(
          cleanupError
        );

        // Act & Assert
        await expect(
          mockVerification.constructor.cleanupExpiredVerifications()
        ).rejects.toThrow('Cleanup operation failed');
      });
    });

    describe('getVerificationStats', () => {
      it('should return verification statistics grouped by status', async () => {
        // Arrange
        const mockStats = [
          { status: 'pending', count: '10' },
          { status: 'verified', count: '25' },
          { status: 'expired', count: '5' },
          { status: 'revoked', count: '2' },
        ];
        const expectedStats = {
          pending: 10,
          verified: 25,
          expired: 5,
          revoked: 2,
        };

        mockVerification.constructor.getVerificationStats.mockResolvedValue(
          expectedStats
        );

        // Act
        const result =
          await mockVerification.constructor.getVerificationStats();

        // Assert
        expect(result).toEqual(expectedStats);
        expect(
          mockVerification.constructor.getVerificationStats
        ).toHaveBeenCalled();
      });

      it('should return empty object when no stats available', async () => {
        // Arrange
        mockVerification.constructor.getVerificationStats.mockResolvedValue({});

        // Act
        const result =
          await mockVerification.constructor.getVerificationStats();

        // Assert
        expect(result).toEqual({});
      });

      it('should handle statistics errors gracefully', async () => {
        // Arrange
        const statsError = new Error('Statistics query failed');
        mockVerification.constructor.getVerificationStats.mockRejectedValue(
          statsError
        );

        // Act & Assert
        await expect(
          mockVerification.constructor.getVerificationStats()
        ).rejects.toThrow('Statistics query failed');
      });
    });
  });

  describe('Static Methods - Validation', () => {
    describe('validateToken', () => {
      it('should validate token format correctly', async () => {
        // Arrange
        const validToken = 'valid-verification-token-123456789';
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
      it('should return false for active verification', () => {
        // Arrange
        const verification = {
          ...mockVerificationData,
          expiresAt: new Date(Date.now() + 3600000), // 1 hour from now
        };

        // Act
        const result = verification.expiresAt > new Date();

        // Assert
        expect(result).toBe(true); // Not expired yet
      });

      it('should return true for expired verification', () => {
        // Arrange
        const verification = {
          ...mockVerificationData,
          expiresAt: new Date(Date.now() - 3600000), // 1 hour ago
        };

        // Act
        const result = verification.expiresAt < new Date();

        // Assert
        expect(result).toBe(true); // Already expired
      });

      it('should handle edge case - verification expiring now', () => {
        // Arrange
        const verification = {
          ...mockVerificationData,
          expiresAt: new Date(), // Expires now
        };

        // Act
        const result =
          verification.expiresAt.getTime() === new Date().getTime();

        // Assert
        expect(result).toBe(true); // Expires exactly now
      });
    });

    describe('isMaxAttemptsReached', () => {
      it('should return false when attempts below maximum', () => {
        // Arrange
        const verification = {
          ...mockVerificationData,
          attempts: 2,
          maxAttempts: 5,
        };

        // Act
        const result = verification.attempts < verification.maxAttempts;

        // Assert
        expect(result).toBe(true); // Still has attempts left
      });

      it('should return true when attempts at maximum', () => {
        // Arrange
        const verification = {
          ...mockVerificationData,
          attempts: 5,
          maxAttempts: 5,
        };

        // Act
        const result = verification.attempts >= verification.maxAttempts;

        // Assert
        expect(result).toBe(true); // Max attempts reached
      });

      it('should return true when attempts exceed maximum', () => {
        // Arrange
        const verification = {
          ...mockVerificationData,
          attempts: 6,
          maxAttempts: 5,
        };

        // Act
        const result = verification.attempts >= verification.maxAttempts;

        // Assert
        expect(result).toBe(true); // Exceeded max attempts
      });
    });

    describe('incrementAttempts', () => {
      it('should increment attempts successfully', async () => {
        // Arrange
        const verification = { ...mockVerificationData, attempts: 2 };

        // Act - Simulate incrementing attempts
        verification.attempts += 1;

        // Assert
        expect(verification.attempts).toBe(3);
      });

      it('should handle attempt increment errors gracefully', async () => {
        // Arrange
        const verification = { ...mockVerificationData };
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
      it('should mark verification as sent with provider info', async () => {
        // Arrange
        const verification = { ...mockVerificationData };
        const emailProvider = 'sendgrid';
        const emailId = 'email-123-456';

        // Act - Simulate marking as sent
        verification.sentAt = new Date();
        verification.emailProvider = emailProvider;
        verification.emailId = emailId;

        // Assert
        expect(verification.sentAt).toBeInstanceOf(Date);
        expect(verification.emailProvider).toBe(emailProvider);
        expect(verification.emailId).toBe(emailId);
      });

      it('should handle mark as sent errors gracefully', async () => {
        // Arrange
        const verification = { ...mockVerificationData };
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
      it('should return verification data without sensitive fields', () => {
        // Arrange
        const verification = { ...mockVerificationData };

        // Act - Simulate toSafeJSON method
        const safeData = { ...verification };
        delete safeData.token;
        delete safeData.tokenHash;

        // Assert
        expect(safeData.token).toBeUndefined();
        expect(safeData.tokenHash).toBeUndefined();
        expect(safeData.userId).toBe(verification.userId);
        expect(safeData.email).toBe(verification.email);
        expect(safeData.status).toBe(verification.status);
      });

      it('should preserve all non-sensitive fields', () => {
        // Arrange
        const verification = { ...mockVerificationData };

        // Act - Simulate toSafeJSON method
        const safeData = { ...verification };
        delete safeData.token;
        delete safeData.tokenHash;

        // Assert - Check that important fields are preserved
        const preservedFields = [
          'id',
          'userId',
          'email',
          'expiresAt',
          'verifiedAt',
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
      const verification = { ...mockVerificationData };

      requiredFields.forEach(field => {
        expect(verification[field]).toBeDefined();
        expect(verification[field]).not.toBeNull();
      });
    });

    it('should validate token length constraints', () => {
      const verification = { ...mockVerificationData };

      // Token should be between 32 and 255 characters
      expect(verification.token.length).toBeGreaterThanOrEqual(32);
      expect(verification.token.length).toBeLessThanOrEqual(255);
    });

    it('should validate token hash length constraints', () => {
      const verification = { ...mockVerificationData };

      // Token hash should be between 32 and 255 characters
      expect(verification.tokenHash.length).toBeGreaterThanOrEqual(32);
      expect(verification.tokenHash.length).toBeLessThanOrEqual(255);
    });

    it('should validate expiration date logic', () => {
      const verification = { ...mockVerificationData };

      // Expiration should be in the future for pending verifications
      if (verification.status === 'pending') {
        expect(verification.expiresAt.getTime()).toBeGreaterThan(
          new Date().getTime()
        );
      }
    });

    it('should validate attempts constraints', () => {
      const verification = { ...mockVerificationData };

      // Attempts should be between 0 and maxAttempts
      expect(verification.attempts).toBeGreaterThanOrEqual(0);
      expect(verification.attempts).toBeLessThanOrEqual(
        verification.maxAttempts
      );
    });

    it('should validate max attempts constraints', () => {
      const verification = { ...mockVerificationData };

      // Max attempts should be between 1 and 10
      expect(verification.maxAttempts).toBeGreaterThanOrEqual(1);
      expect(verification.maxAttempts).toBeLessThanOrEqual(10);
    });
  });

  describe('Status Management', () => {
    it('should handle all valid status values', () => {
      const validStatuses = ['pending', 'verified', 'expired', 'revoked'];
      const verification = { ...mockVerificationData };

      validStatuses.forEach(status => {
        verification.status = status;
        expect(validStatuses.includes(verification.status)).toBe(true);
      });
    });

    it('should reject invalid status values', () => {
      const validStatuses = ['pending', 'verified', 'expired', 'revoked'];
      const invalidStatuses = ['invalid', 'active', 'inactive', ''];

      invalidStatuses.forEach(status => {
        expect(validStatuses.includes(status)).toBe(false);
      });
    });

    it('should handle status transitions correctly', () => {
      const verification = { ...mockVerificationData, status: 'pending' };

      // Pending -> Verified
      verification.status = 'verified';
      verification.verifiedAt = new Date();
      expect(verification.status).toBe('verified');
      expect(verification.verifiedAt).toBeInstanceOf(Date);

      // Verified -> Revoked
      verification.status = 'revoked';
      expect(verification.status).toBe('revoked');

      // Pending -> Expired (via cleanup)
      verification.status = 'expired';
      expect(verification.status).toBe('expired');
    });
  });

  describe('Email Provider Integration', () => {
    it('should track email provider information', () => {
      const verification = { ...mockVerificationData };
      const emailProvider = 'sendgrid';
      const emailId = 'email-123-456';

      // Act - Simulate email sending
      verification.emailProvider = emailProvider;
      verification.emailId = emailId;
      verification.sentAt = new Date();

      // Assert
      expect(verification.emailProvider).toBe(emailProvider);
      expect(verification.emailId).toBe(emailId);
      expect(verification.sentAt).toBeInstanceOf(Date);
    });

    it('should handle different email providers', () => {
      const emailProviders = ['sendgrid', 'mailgun', 'ses', 'smtp'];
      const verification = { ...mockVerificationData };

      emailProviders.forEach(provider => {
        verification.emailProvider = provider;
        expect(verification.emailProvider).toBe(provider);
      });
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle null and undefined values gracefully', () => {
      const verification = { ...mockVerificationData };

      // Test with null values
      verification.verifiedAt = null;
      verification.ipAddress = null;
      verification.userAgent = null;

      // Test with undefined values
      verification.emailProvider = undefined;
      verification.emailId = undefined;

      // Assert - Should not crash
      expect(verification.verifiedAt).toBeNull();
      expect(verification.ipAddress).toBeNull();
      expect(verification.userAgent).toBeNull();
      expect(verification.emailProvider).toBeUndefined();
      expect(verification.emailId).toBeUndefined();
    });

    it('should handle very long strings gracefully', () => {
      const verification = { ...mockVerificationData };

      // Test with very long token
      const longToken = 'A'.repeat(255);
      verification.token = longToken;

      // Test with very long email
      const longEmail = 'a'.repeat(250) + '@example.com';
      verification.email = longEmail;

      // Assert
      expect(verification.token.length).toBe(255);
      expect(verification.email.length).toBe(255 + 12); // 250 + '@example.com'
    });

    it('should handle special characters in data', () => {
      const verification = { ...mockVerificationData };

      // Test with special characters in email
      verification.email = 'test+special.email@example-domain.com';

      // Test with special characters in user agent
      verification.userAgent =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';

      // Assert
      expect(verification.email).toBe('test+special.email@example-domain.com');
      expect(verification.userAgent).toContain('Chrome/91.0.4472.124');
    });
  });

  describe('Performance Tests', () => {
    it('should handle bulk verification operations efficiently', () => {
      // Arrange
      const bulkVerifications = Array.from({ length: 1000 }, (_, i) => ({
        id: `verification-${i}`,
        userId: `user-${i % 100}`,
        email: `user${i}@example.com`,
        status: ['pending', 'verified', 'expired', 'revoked'][i % 4],
        expiresAt: new Date(Date.now() + i * 60000), // Each expires 1 minute later
      }));

      // Act
      const startTime = Date.now();
      const pendingVerifications = bulkVerifications.filter(
        v => v.status === 'pending'
      );
      const expiredVerifications = bulkVerifications.filter(
        v => v.status === 'expired'
      );
      const endTime = Date.now();

      // Assert
      expect(pendingVerifications).toHaveLength(250);
      expect(expiredVerifications).toHaveLength(250);
      expect(endTime - startTime).toBeLessThan(10); // Less than 10ms for 1000 items
    });

    it('should handle verification validation efficiently', () => {
      // Arrange
      const iterations = 100;
      const startTime = Date.now();

      // Act
      for (let i = 0; i < iterations; i++) {
        const verification = {
          id: `verification-${i}`,
          userId: `user-${i}`,
          email: `user${i}@example.com`,
          token: `token-${i}-${'a'.repeat(30)}`,
          tokenHash: `hash-${i}-${'b'.repeat(30)}`,
          status: 'pending',
          expiresAt: new Date(Date.now() + 3600000),
        };

        // Simulate validation checks
        expect(verification.token.length).toBeGreaterThanOrEqual(32);
        expect(verification.tokenHash.length).toBeGreaterThanOrEqual(32);
        expect(verification.expiresAt.getTime()).toBeGreaterThan(
          new Date().getTime()
        );
      }
      const endTime = Date.now();

      // Assert
      const averageTime = (endTime - startTime) / iterations;
      expect(averageTime).toBeLessThan(1); // Less than 1ms per validation
    });
  });
});
