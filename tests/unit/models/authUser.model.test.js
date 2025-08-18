import { jest } from '@jest/globals';
import bcrypt from 'bcryptjs';
import AuthUser from '../../../src/models/authUser.model.js';

// Mock bcrypt
jest.mock('bcryptjs');

describe('AuthUser Model Unit Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Password Hashing', () => {
    it('should hash password before creating user', async () => {
      // Arrange
      const userData = {
        fullName: 'Test User',
        email: 'test@example.com',
        password: 'password123',
        type: 'customer',
        role: 'requirement_coordinator',
      };

      bcrypt.genSalt.mockResolvedValue('salt123');
      bcrypt.hash.mockResolvedValue('hashedPassword123');

      // Act
      const user = await AuthUser.create(userData);

      // Assert
      expect(bcrypt.genSalt).toHaveBeenCalledWith(10);
      expect(bcrypt.hash).toHaveBeenCalledWith('password123', 'salt123');
    });

    it('should hash password before updating user', async () => {
      // Arrange
      const user = await AuthUser.create({
        fullName: 'Test User',
        email: 'test@example.com',
        password: 'oldpassword',
        type: 'customer',
      });

      bcrypt.genSalt.mockResolvedValue('salt123');
      bcrypt.hash.mockResolvedValue('newHashedPassword123');

      // Act
      await user.update({ password: 'newpassword' });

      // Assert
      expect(bcrypt.genSalt).toHaveBeenCalledWith(10);
      expect(bcrypt.hash).toHaveBeenCalledWith('newpassword', 'salt123');
    });

    it('should not hash password if password is null', async () => {
      // Arrange
      const userData = {
        fullName: 'Test User',
        email: 'test@example.com',
        password: null,
        type: 'customer',
      };

      // Act
      await AuthUser.create(userData);

      // Assert
      expect(bcrypt.genSalt).not.toHaveBeenCalled();
      expect(bcrypt.hash).not.toHaveBeenCalled();
    });
  });

  describe('Password Validation', () => {
    it('should validate correct password', async () => {
      // Arrange
      const user = await AuthUser.create({
        fullName: 'Test User',
        email: 'test@example.com',
        password: 'password123',
        type: 'customer',
      });

      bcrypt.compare.mockResolvedValue(true);

      // Act
      const isValid = await user.isValidPassword('password123');

      // Assert
      expect(bcrypt.compare).toHaveBeenCalledWith('password123', user.password);
      expect(isValid).toBe(true);
    });

    it('should reject incorrect password', async () => {
      // Arrange
      const user = await AuthUser.create({
        fullName: 'Test User',
        email: 'test@example.com',
        password: 'password123',
        type: 'customer',
      });

      bcrypt.compare.mockResolvedValue(false);

      // Act
      const isValid = await user.isValidPassword('wrongpassword');

      // Assert
      expect(bcrypt.compare).toHaveBeenCalledWith(
        'wrongpassword',
        user.password
      );
      expect(isValid).toBe(false);
    });
  });

  describe('Model Validation', () => {
    it('should validate email format', async () => {
      // Arrange
      const userData = {
        fullName: 'Test User',
        email: 'invalid-email',
        password: 'password123',
        type: 'customer',
      };

      // Act & Assert
      await expect(AuthUser.create(userData)).rejects.toThrow();
    });

    it('should require email field', async () => {
      // Arrange
      const userData = {
        fullName: 'Test User',
        password: 'password123',
        type: 'customer',
      };

      // Act & Assert
      await expect(AuthUser.create(userData)).rejects.toThrow();
    });

    it('should validate user type enum', async () => {
      // Arrange
      const userData = {
        fullName: 'Test User',
        email: 'test@example.com',
        password: 'password123',
        type: 'invalid-type',
      };

      // Act & Assert
      await expect(AuthUser.create(userData)).rejects.toThrow();
    });

    it('should validate role enum', async () => {
      // Arrange
      const userData = {
        fullName: 'Test User',
        email: 'test@example.com',
        password: 'password123',
        type: 'customer',
        role: 'invalid-role',
      };

      // Act & Assert
      await expect(AuthUser.create(userData)).rejects.toThrow();
    });
  });

  describe('Unique Constraints', () => {
    it('should enforce unique email constraint', async () => {
      // Arrange
      const userData = {
        fullName: 'Test User',
        email: 'test@example.com',
        password: 'password123',
        type: 'customer',
      };

      // Create first user
      await AuthUser.create(userData);

      // Act & Assert - Creating second user with same email should fail
      await expect(AuthUser.create(userData)).rejects.toThrow();
    });

    it('should enforce unique provider + providerId constraint', async () => {
      // Arrange
      const userData1 = {
        fullName: 'Test User 1',
        email: 'test1@example.com',
        password: 'password123',
        type: 'customer',
        provider: 'google',
        providerId: 'google123',
      };

      const userData2 = {
        fullName: 'Test User 2',
        email: 'test2@example.com',
        password: 'password123',
        type: 'customer',
        provider: 'google',
        providerId: 'google123',
      };

      // Create first user
      await AuthUser.create(userData1);

      // Act & Assert - Creating second user with same provider + providerId should fail
      await expect(AuthUser.create(userData2)).rejects.toThrow();
    });
  });
});
