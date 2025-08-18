/**
 * Centralized Validation Utilities
 *
 * This file consolidates all validation functions to eliminate duplicates
 * across models, services, and validators.
 */

import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';

// Import existing validators from validation.js
import {
  emailVerificationSchema,
  passwordResetSchema,
} from '../validators/validation.js';

/**
 * Centralized Email Validation
 * Comprehensive email validation with security checks
 */
export const validateEmail = async email => {
  try {
    if (!email) {
      return { isValid: false, errors: ['Email is required'] };
    }

    // Basic email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return { isValid: false, errors: ['Invalid email format'] };
    }

    // Check for disposable email domains
    const disposableDomains = [
      'tempmail.org',
      'guerrillamail.com',
      '10minutemail.com',
      'mailinator.com',
      'yopmail.com',
      'throwaway.email',
    ];
    const domain = email.split('@')[1];
    if (disposableDomains.includes(domain)) {
      return {
        isValid: false,
        errors: ['Disposable email addresses are not allowed'],
      };
    }

    return { isValid: true, errors: [] };
  } catch (error) {
    safeLogger.error('Email validation error', {
      error: error.message,
      correlationId: getCorrelationId(),
    });
    return { isValid: false, errors: [error.message] };
  }
};

/**
 * Centralized Password Validation
 * Comprehensive password strength validation
 */
export const validatePassword = async password => {
  try {
    if (!password) {
      return { isValid: false, errors: ['Password is required'] };
    }

    const errors = [];

    // Length validation
    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }
    if (password.length > 128) {
      errors.push('Password must not exceed 128 characters');
    }

    // Complexity requirements
    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }
    if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    // Check for common weak passwords
    const weakPasswords = [
      'password',
      '123456',
      '123456789',
      'qwerty',
      'abc123',
      'password123',
      'admin',
      'letmein',
      'welcome',
      'monkey',
    ];
    if (weakPasswords.some(weak => password.toLowerCase().includes(weak))) {
      errors.push('Password contains common patterns and is not secure');
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  } catch (error) {
    safeLogger.error('Password validation error', {
      error: error.message,
      correlationId: getCorrelationId(),
    });
    return { isValid: false, errors: [error.message] };
  }
};

/**
 * Centralized Token Validation
 * Basic JWT token format validation
 */
export const validateToken = async token => {
  try {
    if (!token) {
      return { isValid: false, errors: ['Token is required'] };
    }

    // Basic JWT token format validation (3 parts separated by dots)
    const jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/;
    if (!jwtRegex.test(token)) {
      return { isValid: false, errors: ['Invalid JWT token format'] };
    }

    // Check token length
    if (token.length < 50 || token.length > 2000) {
      return { isValid: false, errors: ['JWT token length is invalid'] };
    }

    return { isValid: true, errors: [] };
  } catch (error) {
    safeLogger.error('Token validation error', {
      error: error.message,
      correlationId: getCorrelationId(),
    });
    return { isValid: false, errors: [error.message] };
  }
};

/**
 * Centralized Email Verification Token Validation
 * Uses the emailVerificationSchema from validation.js
 */
export const validateEmailVerificationToken = async token => {
  try {
    const schema = emailVerificationSchema({ token });
    const { error } = schema.validate({ token });
    return {
      isValid: !error,
      errors: error ? error.details.map(d => d.message) : [],
    };
  } catch (error) {
    safeLogger.error('Email verification token validation error', {
      error: error.message,
      correlationId: getCorrelationId(),
    });
    return { isValid: false, errors: [error.message] };
  }
};

/**
 * Centralized Password Reset Token Validation
 * Uses the passwordResetSchema from validation.js
 */
export const validatePasswordResetToken = async token => {
  try {
    const schema = passwordResetSchema({ token });
    const { error } = schema.validate({ token });
    return {
      isValid: !error,
      errors: error ? error.details.map(d => d.message) : [],
    };
  } catch (error) {
    safeLogger.error('Password reset token validation error', {
      error: error.message,
      correlationId: getCorrelationId(),
    });
    return { isValid: false, errors: [error.message] };
  }
};

/**
 * Centralized Phone Number Validation
 * Comprehensive phone number validation
 */
export const validatePhoneNumber = async phone => {
  try {
    if (!phone) {
      return { isValid: false, errors: ['Phone number is required'] };
    }

    // Remove all non-digit characters
    const digitsOnly = phone.replace(/\D/g, '');

    // Check for minimum and maximum length
    if (digitsOnly.length < 10 || digitsOnly.length > 15) {
      return {
        isValid: false,
        errors: ['Phone number must be between 10 and 15 digits'],
      };
    }

    // Check for valid country codes
    const validCountryCodes = [
      '1',
      '44',
      '33',
      '49',
      '81',
      '86',
      '91',
      '61',
      '55',
      '7',
      '34',
      '39',
      '31',
      '32',
      '46',
      '47',
      '45',
      '358',
      '351',
    ];
    if (!validCountryCodes.some(code => digitsOnly.startsWith(code))) {
      return { isValid: false, errors: ['Invalid country code'] };
    }

    return { isValid: true, errors: [] };
  } catch (error) {
    safeLogger.error('Phone number validation error', {
      error: error.message,
      correlationId: getCorrelationId(),
    });
    return { isValid: false, errors: [error.message] };
  }
};

/**
 * Centralized Username Validation
 * Basic username validation
 */
export const validateUsername = async username => {
  try {
    if (!username) {
      return { isValid: false, errors: ['Username is required'] };
    }

    // Length validation
    if (username.length < 3) {
      return {
        isValid: false,
        errors: ['Username must be at least 3 characters long'],
      };
    }
    if (username.length > 30) {
      return {
        isValid: false,
        errors: ['Username must not exceed 30 characters'],
      };
    }

    // Character validation (alphanumeric, underscore, hyphen)
    const usernameRegex = /^[a-zA-Z0-9_-]+$/;
    if (!usernameRegex.test(username)) {
      return {
        isValid: false,
        errors: [
          'Username can only contain letters, numbers, underscores, and hyphens',
        ],
      };
    }

    return { isValid: true, errors: [] };
  } catch (error) {
    safeLogger.error('Username validation error', {
      error: error.message,
      correlationId: getCorrelationId(),
    });
    return { isValid: false, errors: [error.message] };
  }
};

/**
 * Centralized API Key Validation
 * Basic API key format validation
 */
export const validateApiKey = async apiKey => {
  try {
    if (!apiKey) {
      return { isValid: false, errors: ['API key is required'] };
    }

    // API key format validation (alphanumeric, 32-64 characters)
    const apiKeyRegex = /^[A-Za-z0-9]{32,64}$/;
    if (!apiKeyRegex.test(apiKey)) {
      return { isValid: false, errors: ['Invalid API key format'] };
    }

    return { isValid: true, errors: [] };
  } catch (error) {
    safeLogger.error('API key validation error', {
      error: error.message,
      correlationId: getCorrelationId(),
    });
    return { isValid: false, errors: [error.message] };
  }
};

/**
 * Centralized IP Address Validation
 * Uses the existing ipAddressValidator from securityValidators
 */
export const validateIpAddress = async ipAddress => {
  try {
    const { ipAddressValidator } = await import(
      '../validators/securityValidators.js'
    );
    const result = ipAddressValidator(ipAddress, {
      error: msg => ({ message: msg }),
    });
    return {
      isValid: !result,
      errors: result ? [result.message] : [],
    };
  } catch (error) {
    safeLogger.error('IP address validation error', {
      error: error.message,
      correlationId: getCorrelationId(),
    });
    return { isValid: false, errors: [error.message] };
  }
};

/**
 * Validation Result Helper
 */
export const createValidationResult = (isValid, errors = []) => ({
  isValid,
  errors: Array.isArray(errors) ? errors : [errors],
});

/**
 * Batch Validation Helper
 */
export const validateMultiple = async validations => {
  const results = {};
  const errors = [];

  for (const [key, validation] of Object.entries(validations)) {
    const result = await validation();
    results[key] = result;

    if (!result.isValid) {
      errors.push(...result.errors);
    }
  }

  return {
    isValid: errors.length === 0,
    errors,
    results,
  };
};

// All validation functions are now centralized and exported individually above
