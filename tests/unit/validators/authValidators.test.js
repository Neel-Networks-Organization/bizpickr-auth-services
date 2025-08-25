import { describe, it, expect, beforeEach } from '@jest/globals';
import Joi from 'joi';
import { authSchemas } from '../../../src/validators/authValidators.js';

describe('Auth Validators Unit Tests', () => {
  describe('Signup Schema', () => {
    const validSignupData = {
      body: {
        email: 'test@example.com',
        password: 'Password123',
        fullName: 'Test User',
        type: 'customer',
        role: 'user',
        phone: '+1234567890',
        acceptTerms: true,
      },
    };

    it('should validate correct signup data', () => {
      // Act
      const result = authSchemas.signup.validate(validSignupData);

      // Assert
      expect(result.error).toBeUndefined();
      expect(result.value).toEqual(validSignupData);
    });

    it('should reject invalid email format', () => {
      // Arrange
      const invalidData = {
        ...validSignupData,
        body: { ...validSignupData.body, email: 'invalid-email' },
      };

      // Act
      const result = authSchemas.signup.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe(
        'Please provide a valid email address'
      );
    });

    it('should reject weak password', () => {
      // Arrange
      const invalidData = {
        ...validSignupData,
        body: { ...validSignupData.body, password: 'weak' },
      };

      // Act
      const result = authSchemas.signup.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe(
        'Password must be at least 8 characters long'
      );
    });

    it('should reject password without uppercase', () => {
      // Arrange
      const invalidData = {
        ...validSignupData,
        body: { ...validSignupData.body, password: 'password123' },
      };

      // Act
      const result = authSchemas.signup.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe(
        'Password must contain at least one uppercase letter, one lowercase letter, and one number'
      );
    });

    it('should reject password without lowercase', () => {
      // Arrange
      const invalidData = {
        ...validSignupData,
        body: { ...validSignupData.body, password: 'PASSWORD123' },
      };

      // Act
      const result = authSchemas.signup.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe(
        'Password must contain at least one uppercase letter, one lowercase letter, and one number'
      );
    });

    it('should reject password without number', () => {
      // Arrange
      const invalidData = {
        ...validSignupData,
        body: { ...validSignupData.body, password: 'PasswordABC' },
      };

      // Act
      const result = authSchemas.signup.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe(
        'Password must contain at least one uppercase letter, one lowercase letter, and one number'
      );
    });

    it('should reject password shorter than 8 characters', () => {
      // Arrange
      const invalidData = {
        ...validSignupData,
        body: { ...validSignupData.body, password: 'Pass1' },
      };

      // Act
      const result = authSchemas.signup.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe(
        'Password must be at least 8 characters long'
      );
    });

    it('should reject password longer than 128 characters', () => {
      // Arrange
      const longPassword = 'A'.repeat(129);
      const invalidData = {
        ...validSignupData,
        body: { ...validSignupData.body, password: longPassword },
      };

      // Act
      const result = authSchemas.signup.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe(
        'Password must not exceed 128 characters'
      );
    });

    it('should reject invalid user type', () => {
      // Arrange
      const invalidData = {
        ...validSignupData,
        body: { ...validSignupData.body, type: 'invalid' },
      };

      // Act
      const result = authSchemas.signup.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe(
        'User type must be one of: individual, company, customer, vendor, staff, admin'
      );
    });

    it('should reject invalid user role', () => {
      // Arrange
      const invalidData = {
        ...validSignupData,
        body: { ...validSignupData.body, role: 'invalid' },
      };

      // Act
      const result = authSchemas.signup.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe(
        'User role must be one of: customer, vendor, staff, admin, super_admin'
      );
    });

    it('should reject invalid phone format', () => {
      // Arrange
      const invalidData = {
        ...validSignupData,
        body: { ...validSignupData.body, phone: 'invalid-phone' },
      };

      // Act
      const result = authSchemas.signup.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe(
        'Please provide a valid phone number'
      );
    });

    it('should reject when terms not accepted', () => {
      // Arrange
      const invalidData = {
        ...validSignupData,
        body: { ...validSignupData.body, acceptTerms: false },
      };

      // Act
      const result = authSchemas.signup.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe(
        'You must accept the terms and conditions'
      );
    });

    it('should use default role when not provided', () => {
      // Arrange
      const dataWithoutRole = {
        ...validSignupData,
        body: { ...validSignupData.body },
      };
      delete dataWithoutRole.body.role;

      // Act
      const result = authSchemas.signup.validate(dataWithoutRole);

      // Assert
      expect(result.error).toBeUndefined();
      expect(result.value.body.role).toBe('customer');
    });

    it('should validate all valid user types', () => {
      const validTypes = [
        'individual',
        'company',
        'customer',
        'vendor',
        'staff',
        'admin',
      ];

      validTypes.forEach(type => {
        const testData = {
          ...validSignupData,
          body: { ...validSignupData.body, type },
        };

        const result = authSchemas.signup.validate(testData);
        expect(result.error).toBeUndefined();
      });
    });

    it('should validate all valid user roles', () => {
      const validRoles = [
        'customer',
        'vendor',
        'staff',
        'admin',
        'super_admin',
      ];

      validRoles.forEach(role => {
        const testData = {
          ...validSignupData,
          body: { ...validSignupData.body, role },
        };

        const result = authSchemas.signup.validate(testData);
        expect(result.error).toBeUndefined();
      });
    });

    it('should validate valid phone formats', () => {
      const validPhones = [
        '+1234567890',
        '123-456-7890',
        '(123) 456-7890',
        '123 456 7890',
        '+1 234 567 8900',
      ];

      validPhones.forEach(phone => {
        const testData = {
          ...validSignupData,
          body: { ...validSignupData.body, phone },
        };

        const result = authSchemas.signup.validate(testData);
        expect(result.error).toBeUndefined();
      });
    });
  });

  describe('Login Schema', () => {
    const validLoginData = {
      body: {
        email: 'test@example.com',
        password: 'Password123',
        type: 'customer',
      },
    };

    it('should validate correct login data', () => {
      // Act
      const result = authSchemas.login.validate(validLoginData);

      // Assert
      expect(result.error).toBeUndefined();
      expect(result.value).toEqual(validLoginData);
    });

    it('should reject missing email', () => {
      // Arrange
      const invalidData = {
        ...validLoginData,
        body: { ...validLoginData.body },
      };
      delete invalidData.body.email;

      // Act
      const result = authSchemas.login.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe('Email is required');
    });

    it('should reject missing password', () => {
      // Arrange
      const invalidData = {
        ...validLoginData,
        body: { ...validLoginData.body },
      };
      delete invalidData.body.password;

      // Act
      const result = authSchemas.login.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe('Password is required');
    });

    it('should reject invalid email format in login', () => {
      // Arrange
      const invalidData = {
        ...validLoginData,
        body: { ...validLoginData.body, email: 'invalid-email' },
      };

      // Act
      const result = authSchemas.login.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe(
        'Please provide a valid email address'
      );
    });

    it('should accept login without type', () => {
      // Arrange
      const dataWithoutType = {
        ...validLoginData,
        body: { ...validLoginData.body },
      };
      delete dataWithoutType.body.type;

      // Act
      const result = authSchemas.login.validate(dataWithoutType);

      // Assert
      expect(result.error).toBeUndefined();
    });

    it('should validate all valid user types for login', () => {
      const validTypes = [
        'individual',
        'company',
        'customer',
        'vendor',
        'staff',
        'admin',
      ];

      validTypes.forEach(type => {
        const testData = {
          ...validLoginData,
          body: { ...validLoginData.body, type },
        };

        const result = authSchemas.login.validate(testData);
        expect(result.error).toBeUndefined();
      });
    });
  });

  describe('Email Verification Schema', () => {
    const validVerificationData = {
      body: {
        token: 'verification-token-123',
        email: 'test@example.com',
      },
    };

    it('should validate correct verification data', () => {
      // Act
      const result = authSchemas.verifyEmail.validate(validVerificationData);

      // Assert
      expect(result.error).toBeUndefined();
      expect(result.value).toEqual(validVerificationData);
    });

    it('should reject missing token', () => {
      // Arrange
      const invalidData = {
        ...validVerificationData,
        body: { ...validVerificationData.body },
      };
      delete invalidData.body.token;

      // Act
      const result = authSchemas.verifyEmail.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe(
        'Verification token is required'
      );
    });

    it('should accept verification without email', () => {
      // Arrange
      const dataWithoutEmail = {
        ...validVerificationData,
        body: { ...validVerificationData.body },
      };
      delete dataWithoutEmail.body.email;

      // Act
      const result = authSchemas.verifyEmail.validate(dataWithoutEmail);

      // Assert
      expect(result.error).toBeUndefined();
    });

    it('should reject invalid email format in verification', () => {
      // Arrange
      const invalidData = {
        ...validVerificationData,
        body: { ...validVerificationData.body, email: 'invalid-email' },
      };

      // Act
      const result = authSchemas.verifyEmail.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe(
        'Please provide a valid email address'
      );
    });

    it('should validate long verification tokens', () => {
      // Arrange
      const longToken = 'a'.repeat(1000);
      const testData = {
        ...validVerificationData,
        body: { ...validVerificationData.body, token: longToken },
      };

      // Act
      const result = authSchemas.verifyEmail.validate(testData);

      // Assert
      expect(result.error).toBeUndefined();
    });
  });

  describe('Password Reset Schema', () => {
    const validResetData = {
      body: {
        email: 'test@example.com',
      },
    };

    it('should validate correct password reset data', () => {
      // Act
      const result = authSchemas.forgotPassword.validate(validResetData);

      // Assert
      expect(result.error).toBeUndefined();
      expect(result.value).toEqual(validResetData);
    });

    it('should reject missing email in password reset', () => {
      // Arrange
      const invalidData = {
        ...validResetData,
        body: {},
      };

      // Act
      const result = authSchemas.forgotPassword.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe('Email is required');
    });

    it('should reject invalid email format in password reset', () => {
      // Arrange
      const invalidData = {
        ...validResetData,
        body: { email: 'invalid-email' },
      };

      // Act
      const result = authSchemas.forgotPassword.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe(
        'Please provide a valid email address'
      );
    });
  });

  describe('Password Reset Confirm Schema', () => {
    const validResetConfirmData = {
      body: {
        token: 'reset-token-123',
        password: 'NewPassword123',
        confirmPassword: 'NewPassword123',
      },
    };

    it('should validate correct password reset confirmation data', () => {
      // Act
      const result = authSchemas.resetPassword.validate(validResetConfirmData);

      // Assert
      expect(result.error).toBeUndefined();
      expect(result.value).toEqual(validResetConfirmData);
    });

    it('should reject missing token in password reset confirmation', () => {
      // Arrange
      const invalidData = {
        ...validResetConfirmData,
        body: { ...validResetConfirmData.body },
      };
      delete invalidData.body.token;

      // Act
      const result = authSchemas.resetPassword.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe('Reset token is required');
    });

    it('should reject missing password in password reset confirmation', () => {
      // Arrange
      const invalidData = {
        ...validResetConfirmData,
        body: { ...validResetConfirmData.body },
      };
      delete invalidData.body.password;

      // Act
      const result = authSchemas.resetPassword.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe('New password is required');
    });

    it('should reject missing confirm password in password reset confirmation', () => {
      // Arrange
      const invalidData = {
        ...validResetConfirmData,
        body: { ...validResetConfirmData.body },
      };
      delete invalidData.body.confirmPassword;

      // Act
      const result = authSchemas.resetPassword.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe(
        'Password confirmation is required'
      );
    });

    it('should reject when passwords do not match', () => {
      // Arrange
      const invalidData = {
        ...validResetConfirmData,
        body: {
          ...validResetConfirmData.body,
          confirmPassword: 'DifferentPassword123',
        },
      };

      // Act
      const result = authSchemas.resetPassword.validate(invalidData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe('Passwords do not match');
    });

    it('should validate strong password in reset confirmation', () => {
      // Arrange
      const testData = {
        ...validResetConfirmData,
        body: {
          ...validResetConfirmData.body,
          password: 'StrongPass123',
          confirmPassword: 'StrongPass123',
        },
      };

      // Act
      const result = authSchemas.resetPassword.validate(testData);

      // Assert
      expect(result.error).toBeUndefined();
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle empty body gracefully', () => {
      // Arrange
      const emptyData = { body: {} };

      // Act
      const result = authSchemas.signup.validate(emptyData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details.length).toBeGreaterThan(0);
    });

    it('should handle null values gracefully', () => {
      // Arrange
      const nullData = {
        body: {
          email: null,
          password: null,
          fullName: null,
          type: null,
          acceptTerms: null,
        },
      };

      // Act
      const result = authSchemas.signup.validate(nullData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details.length).toBeGreaterThan(0);
    });

    it('should handle undefined values gracefully', () => {
      // Arrange
      const undefinedData = {
        body: {
          email: undefined,
          password: undefined,
          fullName: undefined,
          type: undefined,
          acceptTerms: undefined,
        },
      };

      // Act
      const result = authSchemas.signup.validate(undefinedData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details.length).toBeGreaterThan(0);
    });

    it('should handle very long strings gracefully', () => {
      // Arrange
      const longString = 'a'.repeat(1000);
      const longData = {
        body: {
          email: 'test@example.com',
          password: 'Password123',
          fullName: longString,
          type: 'customer',
          acceptTerms: true,
        },
      };

      // Act
      const result = authSchemas.signup.validate(longData);

      // Assert
      expect(result.error).toBeDefined();
      expect(result.error.details[0].message).toBe(
        'Full name must not exceed 100 characters'
      );
    });

    it('should handle special characters in strings', () => {
      // Arrange
      const specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';
      const specialData = {
        body: {
          email: 'test@example.com',
          password: 'Password123',
          fullName: `Test User ${specialChars}`,
          type: 'customer',
          acceptTerms: true,
        },
      };

      // Act
      const result = authSchemas.signup.validate(specialData);

      // Assert
      expect(result.error).toBeUndefined();
    });

    it('should handle unicode characters in strings', () => {
      // Arrange
      const unicodeString = 'Test User 🚀 测试 テスト';
      const unicodeData = {
        body: {
          email: 'test@example.com',
          password: 'Password123',
          fullName: unicodeString,
          type: 'customer',
          acceptTerms: true,
        },
      };

      // Act
      const result = authSchemas.signup.validate(unicodeData);

      // Assert
      expect(result.error).toBeUndefined();
    });
  });

  describe('Schema Structure Validation', () => {
    it('should have correct schema structure for signup', () => {
      // Assert
      expect(authSchemas.signup).toBeDefined();
      expect(authSchemas.signup.describe().keys).toHaveProperty('body');
      expect(authSchemas.signup.describe().keys).toHaveProperty('query');
      expect(authSchemas.signup.describe().keys).toHaveProperty('params');
    });

    it('should have correct schema structure for login', () => {
      // Assert
      expect(authSchemas.login).toBeDefined();
      expect(authSchemas.login.describe().keys).toHaveProperty('body');
      expect(authSchemas.login.describe().keys).toHaveProperty('query');
      expect(authSchemas.login.describe().keys).toHaveProperty('params');
    });

    it('should have correct schema structure for email verification', () => {
      // Assert
      expect(authSchemas.verifyEmail).toBeDefined();
      expect(authSchemas.verifyEmail.describe().keys).toHaveProperty('body');
      expect(authSchemas.verifyEmail.describe().keys).toHaveProperty('query');
      expect(authSchemas.verifyEmail.describe().keys).toHaveProperty('params');
    });

    it('should have correct schema structure for password reset', () => {
      // Assert
      expect(authSchemas.forgotPassword).toBeDefined();
      expect(authSchemas.forgotPassword.describe().keys).toHaveProperty('body');
      expect(authSchemas.forgotPassword.describe().keys).toHaveProperty(
        'query'
      );
      expect(authSchemas.forgotPassword.describe().keys).toHaveProperty(
        'params'
      );
    });

    it('should have correct schema structure for password reset confirmation', () => {
      // Assert
      expect(authSchemas.resetPassword).toBeDefined();
      expect(authSchemas.resetPassword.describe().keys).toHaveProperty('body');
      expect(authSchemas.resetPassword.describe().keys).toHaveProperty('query');
      expect(authSchemas.resetPassword.describe().keys).toHaveProperty(
        'params'
      );
    });
  });
});
