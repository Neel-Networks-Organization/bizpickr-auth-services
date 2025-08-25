import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from '@jest/globals';
import bcrypt from 'bcryptjs';
import { passwordService } from '../../../src/services/password.service.js';

// Mock bcrypt
jest.mock('bcryptjs');

describe('Password Service Unit Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('validatePassword', () => {
    it('should validate strong password', () => {
      // Arrange
      const strongPassword = 'StrongPass123';

      // Act
      const result = passwordService.validatePassword(strongPassword);

      // Assert
      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject weak password without uppercase', () => {
      // Arrange
      const weakPassword = 'weakpass123';

      // Act
      const result = passwordService.validatePassword(weakPassword);

      // Assert
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain(
        'Password must contain at least one uppercase letter'
      );
    });

    it('should reject weak password without lowercase', () => {
      // Arrange
      const weakPassword = 'WEAKPASS123';

      // Act
      const result = passwordService.validatePassword(weakPassword);

      // Assert
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain(
        'Password must contain at least one lowercase letter'
      );
    });

    it('should reject weak password without number', () => {
      // Arrange
      const weakPassword = 'WeakPass';

      // Act
      const result = passwordService.validatePassword(weakPassword);

      // Assert
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain(
        'Password must contain at least one number'
      );
    });

    it('should reject password shorter than 8 characters', () => {
      // Arrange
      const shortPassword = 'Weak1';

      // Act
      const result = passwordService.validatePassword(shortPassword);

      // Assert
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain(
        'Password must be at least 8 characters long'
      );
    });

    it('should reject password longer than 128 characters', () => {
      // Arrange
      const longPassword = 'a'.repeat(129);

      // Act
      const result = passwordService.validatePassword(longPassword);

      // Assert
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain(
        'Password must not exceed 128 characters'
      );
    });

    it('should reject empty password', () => {
      // Arrange
      const emptyPassword = '';

      // Act
      const result = passwordService.validatePassword(emptyPassword);

      // Assert
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain(
        'Password must be at least 8 characters long'
      );
    });

    it('should reject null password', () => {
      // Arrange
      const nullPassword = null;

      // Act
      const result = passwordService.validatePassword(nullPassword);

      // Assert
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain(
        'Password must be at least 8 characters long'
      );
    });

    it('should handle multiple validation errors', () => {
      // Arrange
      const invalidPassword = 'weak';

      // Act
      const result = passwordService.validatePassword(invalidPassword);

      // Assert
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain(
        'Password must be at least 8 characters long'
      );
      expect(result.errors).toContain(
        'Password must contain at least one uppercase letter'
      );
      expect(result.errors).toContain(
        'Password must contain at least one number'
      );
    });
  });

  describe('hashPassword', () => {
    it('should hash password with default salt rounds', async () => {
      // Arrange
      const password = 'password123';
      const salt = 'salt123';
      const hashedPassword = 'hashedPassword123';

      bcrypt.genSalt.mockResolvedValue(salt);
      bcrypt.hash.mockResolvedValue(hashedPassword);

      // Act
      const result = await passwordService.hashPassword(password);

      // Assert
      expect(bcrypt.genSalt).toHaveBeenCalledWith(12);
      expect(bcrypt.hash).toHaveBeenCalledWith(password, salt);
      expect(result).toBe(hashedPassword);
    });

    it('should hash password with custom salt rounds', async () => {
      // Arrange
      const password = 'password123';
      const saltRounds = 10;
      const salt = 'salt123';
      const hashedPassword = 'hashedPassword123';

      bcrypt.genSalt.mockResolvedValue(salt);
      bcrypt.hash.mockResolvedValue(hashedPassword);

      // Act
      const result = await passwordService.hashPassword(password, saltRounds);

      // Assert
      expect(bcrypt.genSalt).toHaveBeenCalledWith(saltRounds);
      expect(bcrypt.hash).toHaveBeenCalledWith(password, salt);
      expect(result).toBe(hashedPassword);
    });

    it('should handle bcrypt errors gracefully', async () => {
      // Arrange
      const password = 'password123';
      const error = new Error('Bcrypt error');

      bcrypt.genSalt.mockRejectedValue(error);

      // Act & Assert
      await expect(passwordService.hashPassword(password)).rejects.toThrow(
        'Bcrypt error'
      );
    });
  });

  describe('comparePassword', () => {
    it('should compare password correctly', async () => {
      // Arrange
      const password = 'password123';
      const hashedPassword = 'hashedPassword123';

      bcrypt.compare.mockResolvedValue(true);

      // Act
      const result = await passwordService.comparePassword(
        password,
        hashedPassword
      );

      // Assert
      expect(bcrypt.compare).toHaveBeenCalledWith(password, hashedPassword);
      expect(result).toBe(true);
    });

    it('should return false for incorrect password', async () => {
      // Arrange
      const password = 'wrongpassword';
      const hashedPassword = 'hashedPassword123';

      bcrypt.compare.mockResolvedValue(false);

      // Act
      const result = await passwordService.comparePassword(
        password,
        hashedPassword
      );

      // Assert
      expect(bcrypt.compare).toHaveBeenCalledWith(password, hashedPassword);
      expect(result).toBe(false);
    });

    it('should handle bcrypt compare errors gracefully', async () => {
      // Arrange
      const password = 'password123';
      const hashedPassword = 'hashedPassword123';
      const error = new Error('Bcrypt compare error');

      bcrypt.compare.mockRejectedValue(error);

      // Act & Assert
      await expect(
        passwordService.comparePassword(password, hashedPassword)
      ).rejects.toThrow('Bcrypt compare error');
    });
  });

  describe('generatePassword', () => {
    it('should generate password with default length', () => {
      // Arrange
      const defaultLength = 12;

      // Act
      const result = passwordService.generatePassword();

      // Assert
      expect(result).toHaveLength(defaultLength);
      expect(result).toMatch(/[A-Z]/); // Contains uppercase
      expect(result).toMatch(/[a-z]/); // Contains lowercase
      expect(result).toMatch(/\d/); // Contains number
      expect(result).toMatch(/[!@#$%^&*]/); // Contains special char
    });

    it('should generate password with custom length', () => {
      // Arrange
      const customLength = 16;

      // Act
      const result = passwordService.generatePassword(customLength);

      // Assert
      expect(result).toHaveLength(customLength);
      expect(result).toMatch(/[A-Z]/);
      expect(result).toMatch(/[a-z]/);
      expect(result).toMatch(/\d/);
      expect(result).toMatch(/[!@#$%^&*]/);
    });

    it('should generate unique passwords', () => {
      // Arrange
      const passwords = new Set();

      // Act
      for (let i = 0; i < 100; i++) {
        passwords.add(passwordService.generatePassword());
      }

      // Assert
      expect(passwords.size).toBe(100); // All passwords are unique
    });

    it('should generate password with minimum length 8', () => {
      // Arrange
      const shortLength = 5;

      // Act
      const result = passwordService.generatePassword(shortLength);

      // Assert
      expect(result).toHaveLength(8); // Minimum length enforced
    });
  });

  describe('validatePasswordStrength', () => {
    it('should return strong for strong password', () => {
      // Arrange
      const strongPassword = 'StrongPass123!';

      // Act
      const result = passwordService.validatePasswordStrength(strongPassword);

      // Assert
      expect(result.strength).toBe('strong');
      expect(result.score).toBeGreaterThanOrEqual(80);
    });

    it('should return medium for medium password', () => {
      // Arrange
      const mediumPassword = 'MediumPass123';

      // Act
      const result = passwordService.validatePasswordStrength(mediumPassword);

      // Assert
      expect(result.strength).toBe('medium');
      expect(result.score).toBeGreaterThanOrEqual(60);
      expect(result.score).toBeLessThan(80);
    });

    it('should return weak for weak password', () => {
      // Arrange
      const weakPassword = 'weakpass';

      // Act
      const result = passwordService.validatePasswordStrength(weakPassword);

      // Assert
      expect(result.strength).toBe('weak');
      expect(result.score).toBeLessThan(60);
    });

    it('should calculate score based on criteria', () => {
      // Arrange
      const password = 'TestPass123!';

      // Act
      const result = passwordService.validatePasswordStrength(password);

      // Assert
      expect(result.score).toBeGreaterThan(0);
      expect(result.score).toBeLessThanOrEqual(100);
      expect(result.criteria).toBeDefined();
    });
  });

  describe('checkPasswordHistory', () => {
    it('should return true for new password', async () => {
      // Arrange
      const userId = 1;
      const newPassword = 'NewPassword123';
      const passwordHistory = [];

      // Mock password history service
      passwordService.getPasswordHistory = jest
        .fn()
        .mockResolvedValue(passwordHistory);

      // Act
      const result = await passwordService.checkPasswordHistory(
        userId,
        newPassword
      );

      // Assert
      expect(result).toBe(true);
    });

    it('should return false for reused password', async () => {
      // Arrange
      const userId = 1;
      const reusedPassword = 'OldPassword123';
      const passwordHistory = ['OldPassword123', 'AnotherPassword123'];

      // Mock password history service
      passwordService.getPasswordHistory = jest
        .fn()
        .mockResolvedValue(passwordHistory);

      // Act
      const result = await passwordService.checkPasswordHistory(
        userId,
        reusedPassword
      );

      // Assert
      expect(result).toBe(false);
    });

    it('should handle password history errors gracefully', async () => {
      // Arrange
      const userId = 1;
      const newPassword = 'NewPassword123';
      const error = new Error('Database error');

      // Mock password history service
      passwordService.getPasswordHistory = jest.fn().mockRejectedValue(error);

      // Act & Assert
      await expect(
        passwordService.checkPasswordHistory(userId, newPassword)
      ).rejects.toThrow('Database error');
    });
  });

  describe('updatePasswordHistory', () => {
    it('should add password to history', async () => {
      // Arrange
      const userId = 1;
      const newPassword = 'NewPassword123';

      // Mock password history service
      passwordService.addToPasswordHistory = jest.fn().mockResolvedValue(true);

      // Act
      await passwordService.updatePasswordHistory(userId, newPassword);

      // Assert
      expect(passwordService.addToPasswordHistory).toHaveBeenCalledWith(
        userId,
        newPassword
      );
    });

    it('should maintain password history limit', async () => {
      // Arrange
      const userId = 1;
      const newPassword = 'NewPassword123';
      const maxHistorySize = 5;

      // Mock password history service
      passwordService.addToPasswordHistory = jest.fn().mockResolvedValue(true);
      passwordService.trimPasswordHistory = jest.fn().mockResolvedValue(true);

      // Act
      await passwordService.updatePasswordHistory(
        userId,
        newPassword,
        maxHistorySize
      );

      // Assert
      expect(passwordService.addToPasswordHistory).toHaveBeenCalledWith(
        userId,
        newPassword
      );
      expect(passwordService.trimPasswordHistory).toHaveBeenCalledWith(
        userId,
        maxHistorySize
      );
    });
  });

  describe('Edge Cases', () => {
    it('should handle very long passwords', () => {
      // Arrange
      const longPassword = 'a'.repeat(1000);

      // Act
      const result = passwordService.validatePassword(longPassword);

      // Assert
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain(
        'Password must not exceed 128 characters'
      );
    });

    it('should handle passwords with special characters', () => {
      // Arrange
      const specialPassword = 'Pass!@#$%^&*()123';

      // Act
      const result = passwordService.validatePassword(specialPassword);

      // Assert
      expect(result.isValid).toBe(true);
    });

    it('should handle passwords with unicode characters', () => {
      // Arrange
      const unicodePassword = 'Pass🚀测试123';

      // Act
      const result = passwordService.validatePassword(unicodePassword);

      // Assert
      expect(result.isValid).toBe(true);
    });

    it('should handle null and undefined inputs gracefully', () => {
      // Arrange
      const nullPassword = null;
      const undefinedPassword = undefined;

      // Act & Assert
      expect(() =>
        passwordService.validatePassword(nullPassword)
      ).not.toThrow();
      expect(() =>
        passwordService.validatePassword(undefinedPassword)
      ).not.toThrow();
    });
  });

  describe('Performance Tests', () => {
    it('should hash passwords quickly', async () => {
      // Arrange
      const password = 'TestPassword123';
      const iterations = 10;
      const startTime = Date.now();

      bcrypt.genSalt.mockResolvedValue('salt');
      bcrypt.hash.mockResolvedValue('hashed');

      // Act
      for (let i = 0; i < iterations; i++) {
        await passwordService.hashPassword(password);
      }
      const endTime = Date.now();

      // Assert
      const averageTime = (endTime - startTime) / iterations;
      expect(averageTime).toBeLessThan(100); // Less than 100ms per hash
    });

    it('should validate passwords efficiently', () => {
      // Arrange
      const password = 'TestPassword123';
      const iterations = 1000;
      const startTime = Date.now();

      // Act
      for (let i = 0; i < iterations; i++) {
        passwordService.validatePassword(password);
      }
      const endTime = Date.now();

      // Assert
      const averageTime = (endTime - startTime) / iterations;
      expect(averageTime).toBeLessThan(1); // Less than 1ms per validation
    });
  });
});
