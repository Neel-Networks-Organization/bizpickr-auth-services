import Joi from 'joi';
import { safeLogger } from '../config/logger.js';
/**
 * Enhanced Validation Service
 *
 * Features:
 * - Comprehensive Joi schemas with security validation
 * - Custom validators for business logic
 * - Input sanitization and normalization
 * - Password strength validation
 * - Phone number validation
 * - Address validation
 * - File upload validation
 * - Rate limiting validation
 * - Security threat detection
 * - Validation metrics and logging
 * - Schema versioning and migration
 * - Enterprise-grade validation rules
 */
// ✅ Validation Configuration
const VALIDATION_CONFIG = {
  // Password settings
  passwordMinLength: 8,
  passwordMaxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  // Phone settings
  phoneRegex: /^\+?[1-9]\d{1,14}$/,
  allowInternational: true,
  // Name settings
  nameMinLength: 2,
  nameMaxLength: 100,
  allowSpecialChars: false,
  // Rate limiting
  maxLoginAttempts: 5,
  maxSignupAttempts: 3,
  // File upload
  maxFileSize: 5 * 1024 * 1024, // 5MB
  allowedFileTypes: ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'],
  // Security
  enableThreatDetection: true,
  enableSanitization: true,
  enableNormalization: true,
};
// ✅ Validation Metrics
const validationMetrics = {
  totalValidations: 0,
  successfulValidations: 0,
  failedValidations: 0,
  securityThreats: 0,
  passwordViolations: 0,
  emailViolations: 0,
  phoneViolations: 0,
  schemaErrors: {},
};
/**
 * Custom password strength validator
 */
const passwordStrengthValidator = (value, helpers) => {
  const errors = [];
  if (value.length < VALIDATION_CONFIG.passwordMinLength) {
    errors.push(
      `Password must be at least ${VALIDATION_CONFIG.passwordMinLength} characters long`
    );
  }
  if (value.length > VALIDATION_CONFIG.passwordMaxLength) {
    errors.push(
      `Password must not exceed ${VALIDATION_CONFIG.passwordMaxLength} characters`
    );
  }
  if (VALIDATION_CONFIG.requireUppercase && !/[A-Z]/.test(value)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  if (VALIDATION_CONFIG.requireLowercase && !/[a-z]/.test(value)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  if (VALIDATION_CONFIG.requireNumbers && !/\d/.test(value)) {
    errors.push('Password must contain at least one number');
  }
  if (
    VALIDATION_CONFIG.requireSpecialChars &&
    !/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(value)
  ) {
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
  if (weakPasswords.includes(value.toLowerCase())) {
    errors.push('Password is too common, please choose a stronger password');
  }
  // Check for sequential characters
  if (/(.)\1{2,}/.test(value)) {
    errors.push(
      'Password cannot contain more than 2 consecutive identical characters'
    );
  }
  // Check for keyboard patterns
  const keyboardPatterns = ['qwerty', 'asdfgh', 'zxcvbn', '123456', '654321'];
  for (const pattern of keyboardPatterns) {
    if (value.toLowerCase().includes(pattern)) {
      errors.push('Password cannot contain keyboard patterns');
      break;
    }
  }
  if (errors.length > 0) {
    validationMetrics.passwordViolations++;
    return helpers.error('any.invalid', { message: errors.join('; ') });
  }
  return value;
};
/**
 * Custom email validator with basic validation
 */
const emailValidator = (value, helpers) => {
  try {
    // Basic email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(value)) {
      validationMetrics.emailViolations++;
      return helpers.error('any.invalid', {
        message: 'Invalid email format',
      });
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
    const domain = value.split('@')[1];
    if (disposableDomains.includes(domain)) {
      validationMetrics.emailViolations++;
      return helpers.error('any.invalid', {
        message: 'Disposable email addresses are not allowed',
      });
    }

    return value;
  } catch (error) {
    safeLogger.error('Email validation error', {
      email: value,
      error: error.message,
    });
    return helpers.error('any.invalid', { message: 'Email validation failed' });
  }
};
/**
 * Custom phone number validator
 */
const phoneValidator = (value, helpers) => {
  if (!VALIDATION_CONFIG.phoneRegex.test(value)) {
    validationMetrics.phoneViolations++;
    return helpers.error('any.invalid', {
      message: 'Invalid phone number format',
    });
  }
  // Remove all non-digit characters for length check
  const digitsOnly = value.replace(/\D/g, '');
  if (digitsOnly.length < 10 || digitsOnly.length > 15) {
    validationMetrics.phoneViolations++;
    return helpers.error('any.invalid', {
      message: 'Phone number must be between 10 and 15 digits',
    });
  }
  return value;
};
/**
 * Custom name validator
 */
const nameValidator = (value, helpers) => {
  if (value.length < VALIDATION_CONFIG.nameMinLength) {
    return helpers.error('any.invalid', {
      message: `Name must be at least ${VALIDATION_CONFIG.nameMinLength} characters long`,
    });
  }
  if (value.length > VALIDATION_CONFIG.nameMaxLength) {
    return helpers.error('any.invalid', {
      message: `Name must not exceed ${VALIDATION_CONFIG.nameMaxLength} characters`,
    });
  }
  if (
    !VALIDATION_CONFIG.allowSpecialChars &&
    /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(value)
  ) {
    return helpers.error('any.invalid', {
      message: 'Name cannot contain special characters',
    });
  }
  // Check for suspicious patterns
  if (VALIDATION_CONFIG.enableThreatDetection) {
    const suspiciousPatterns = [
      /\b(union|select|insert|update|delete|drop|create|alter)\b/i,
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/gi,
    ];
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(value)) {
        validationMetrics.securityThreats++;
        return helpers.error('any.invalid', {
          message: 'Name contains invalid characters',
        });
      }
    }
  }
  return value;
};
/**
 * Input sanitization function
 */
function sanitizeInput(data) {
  if (!VALIDATION_CONFIG.enableSanitization) return data;
  const sanitized = {};
  for (const [key, value] of Object.entries(data)) {
    if (typeof value === 'string') {
      // Remove null bytes and control characters
      // eslint-disable-next-line no-control-regex
      let sanitizedValue = value.replace(/[\u0000-\u001F\u007F]/g, '');
      // Trim whitespace
      sanitizedValue = sanitizedValue.trim();
      // Normalize unicode
      sanitizedValue = sanitizedValue.normalize('NFC');
      sanitized[key] = sanitizedValue;
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}
/**
 * Enhanced signup validation schema - AUTHENTICATION ONLY
 */
export const signupSchemas = data => {
  validationMetrics.totalValidations++;
  try {
    // Sanitize input
    const sanitizedData = sanitizeInput(data);
    const schema = Joi.object({
      email: Joi.string()
        .email({ tlds: { allow: false } })
        .custom(emailValidator, 'email validation')
        .required()
        .messages({
          'string.email': 'Please provide a valid email address',
          'string.empty': 'Email is required',
          'any.required': 'Email is required',
        }),
      password: Joi.string()
        .custom(passwordStrengthValidator, 'password strength validation')
        .required()
        .messages({
          'string.empty': 'Password is required',
          'any.required': 'Password is required',
        }),
      confirmPassword: Joi.string()
        .valid(Joi.ref('password'))
        .required()
        .messages({
          'any.only': 'Passwords do not match',
          'any.required': 'Password confirmation is required',
        }),
      type: Joi.string()
        .valid('customer', 'vendor', 'staff', 'admin')
        .required()
        .messages({
          'any.only': 'Type must be customer, vendor, staff, or admin',
          'any.required': 'Type is required',
        }),
      role: Joi.string()
        .valid(
          'customer',
          'vendor',
          'requirement_coordinator',
          'hr_admin',
          'admin',
          'super_admin'
        )
        .allow('', null)
        .default('customer')
        .messages({
          'any.only': 'Invalid role specified',
        }),
      termsAccepted: Joi.boolean().valid(true).required().messages({
        'any.only': 'You must accept the terms and conditions',
        'any.required': 'Terms acceptance is required',
      }),
      privacyAccepted: Joi.boolean().valid(true).required().messages({
        'any.only': 'You must accept the privacy policy',
        'any.required': 'Privacy policy acceptance is required',
      }),
      marketingConsent: Joi.boolean().default(false).messages({
        'boolean.base': 'Marketing consent must be a boolean value',
      }),
    });
    const result = schema.validate(sanitizedData, {
      abortEarly: false,
      stripUnknown: true,
      allowUnknown: false,
    });
    if (result.error) {
      validationMetrics.failedValidations++;
      validationMetrics.schemaErrors[result.error.name] =
        (validationMetrics.schemaErrors[result.error.name] || 0) + 1;
      safeLogger.warn('Signup validation failed', {
        errors: result.error.details,
        data: sanitizedData,
      });
      return result;
    }
    validationMetrics.successfulValidations++;
    safeLogger.debug('Signup validation successful', {
      email: sanitizedData.email,
      type: sanitizedData.type,
    });
    return result;
  } catch (error) {
    validationMetrics.failedValidations++;
    safeLogger.error('Signup validation error', {
      error: error.message,
      stack: error.stack,
      data,
    });
    return {
      error: {
        name: 'ValidationError',
        message: 'Validation processing error',
        details: [{ message: 'Internal validation error' }],
      },
    };
  }
};
/**
 * Enhanced login validation schema
 */
export const commonLoginSchema = data => {
  validationMetrics.totalValidations++;
  try {
    // Sanitize input
    const sanitizedData = sanitizeInput(data);
    const schema = Joi.object({
      email: Joi.string()
        .email({ tlds: { allow: false } })
        .custom(emailValidator, 'email validation')
        .required()
        .messages({
          'string.email': 'Please provide a valid email address',
          'string.empty': 'Email is required',
          'any.required': 'Email is required',
        }),
      password: Joi.string().required().messages({
        'string.empty': 'Password is required',
        'any.required': 'Password is required',
      }),
      type: Joi.string()
        .valid('customer', 'vendor', 'staff', 'admin')
        .optional()
        .messages({
          'any.only': 'Type must be customer, vendor, staff, or admin',
        }),
      rememberMe: Joi.boolean().default(false).messages({
        'boolean.base': 'Remember me must be a boolean value',
      }),
      deviceInfo: Joi.object({
        userAgent: Joi.string().optional(),
        ip: Joi.string().ip().optional(),
        deviceId: Joi.string().optional(),
      }).optional(),
      captchaToken: Joi.string()
        .when('loginAttempts', {
          is: Joi.number().min(VALIDATION_CONFIG.maxLoginAttempts),
          then: Joi.required(),
          otherwise: Joi.optional(),
        })
        .messages({
          'any.required':
            'Captcha verification required after multiple failed attempts',
        }),
      loginAttempts: Joi.number().default(0).messages({
        'number.base': 'Login attempts must be a number',
      }),
    });
    const result = schema.validate(sanitizedData, {
      abortEarly: false,
      stripUnknown: true,
      allowUnknown: false,
    });
    if (result.error) {
      validationMetrics.failedValidations++;
      validationMetrics.schemaErrors[result.error.name] =
        (validationMetrics.schemaErrors[result.error.name] || 0) + 1;
      safeLogger.warn('Login validation failed', {
        errors: result.error.details,
        email: sanitizedData.email,
      });
      return result;
    }
    validationMetrics.successfulValidations++;
    safeLogger.debug('Login validation successful', {
      email: sanitizedData.email,
      type: sanitizedData.type,
    });
    return result;
  } catch (error) {
    validationMetrics.failedValidations++;
    safeLogger.error('Login validation error', {
      error: error.message,
      stack: error.stack,
      data,
    });
    return {
      error: {
        name: 'ValidationError',
        message: 'Validation processing error',
        details: [{ message: 'Internal validation error' }],
      },
    };
  }
};
/**
 * Password reset validation schema
 */
export const passwordResetSchema = data => {
  validationMetrics.totalValidations++;
  try {
    const sanitizedData = sanitizeInput(data);
    const schema = Joi.object({
      email: Joi.string()
        .email({ tlds: { allow: false } })
        .custom(emailValidator, 'email validation')
        .required()
        .messages({
          'string.email': 'Please provide a valid email address',
          'string.empty': 'Email is required',
          'any.required': 'Email is required',
        }),
      resetToken: Joi.string()
        .min(32)
        .max(256)
        .when('action', {
          is: 'reset',
          then: Joi.required(),
          otherwise: Joi.optional(),
        })
        .messages({
          'string.min': 'Invalid reset token',
          'string.max': 'Invalid reset token',
          'any.required': 'Reset token is required',
        }),
      newPassword: Joi.string()
        .custom(passwordStrengthValidator, 'password strength validation')
        .when('action', {
          is: 'reset',
          then: Joi.required(),
          otherwise: Joi.optional(),
        })
        .messages({
          'any.required': 'New password is required',
        }),
      confirmPassword: Joi.string()
        .valid(Joi.ref('newPassword'))
        .when('action', {
          is: 'reset',
          then: Joi.required(),
          otherwise: Joi.optional(),
        })
        .messages({
          'any.only': 'Passwords do not match',
          'any.required': 'Password confirmation is required',
        }),
      action: Joi.string().valid('request', 'reset').required().messages({
        'any.only': 'Action must be request or reset',
        'any.required': 'Action is required',
      }),
    });
    const result = schema.validate(sanitizedData, {
      abortEarly: false,
      stripUnknown: true,
      allowUnknown: false,
    });
    if (result.error) {
      validationMetrics.failedValidations++;
      return result;
    }
    validationMetrics.successfulValidations++;
    return result;
  } catch (error) {
    validationMetrics.failedValidations++;
    safeLogger.error('Password reset validation error', {
      error: error.message,
    });
    return {
      error: {
        name: 'ValidationError',
        message: 'Validation processing error',
        details: [{ message: 'Internal validation error' }],
      },
    };
  }
};
/**
 * Profile update validation schema
 */
export const profileUpdateSchema = data => {
  validationMetrics.totalValidations++;
  try {
    const sanitizedData = sanitizeInput(data);
    const schema = Joi.object({
      fullName: Joi.string()
        .custom(nameValidator, 'name validation')
        .min(VALIDATION_CONFIG.nameMinLength)
        .max(VALIDATION_CONFIG.nameMaxLength)
        .optional()
        .messages({
          'string.min': `Full name must be at least ${VALIDATION_CONFIG.nameMinLength} characters long`,
          'string.max': `Full name must not exceed ${VALIDATION_CONFIG.nameMaxLength} characters`,
        }),
      phone: Joi.string()
        .custom(phoneValidator, 'phone validation')
        .optional()
        .messages({
          'any.invalid': 'Please provide a valid phone number',
        }),
      dateOfBirth: Joi.date().max('now').optional().messages({
        'date.max': 'Date of birth cannot be in the future',
      }),
      address: Joi.object({
        street: Joi.string().min(5).max(200).optional(),
        city: Joi.string().min(2).max(100).optional(),
        state: Joi.string().min(2).max(100).optional(),
        zipCode: Joi.string()
          .pattern(/^\d{5}(-\d{4})?$/)
          .optional(),
        country: Joi.string().min(2).max(100).optional(),
      }).optional(),
      preferences: Joi.object({
        language: Joi.string().valid('en', 'es', 'fr', 'de').optional(),
        timezone: Joi.string().optional(),
        currency: Joi.string().valid('USD', 'EUR', 'GBP', 'CAD').optional(),
        notifications: Joi.object({
          email: Joi.boolean().default(true),
          sms: Joi.boolean().default(false),
          push: Joi.boolean().default(true),
        }).optional(),
      }).optional(),
      avatar: Joi.object({
        file: Joi.binary().max(VALIDATION_CONFIG.maxFileSize).optional(),
        mimeType: Joi.string()
          .valid(...VALIDATION_CONFIG.allowedFileTypes)
          .optional(),
      }).optional(),
    });
    const result = schema.validate(sanitizedData, {
      abortEarly: false,
      stripUnknown: true,
      allowUnknown: false,
    });
    if (result.error) {
      validationMetrics.failedValidations++;
      return result;
    }
    validationMetrics.successfulValidations++;
    return result;
  } catch (error) {
    validationMetrics.failedValidations++;
    safeLogger.error('Profile update validation error', {
      error: error.message,
    });
    return {
      error: {
        name: 'ValidationError',
        message: 'Validation processing error',
        details: [{ message: 'Internal validation error' }],
      },
    };
  }
};
/**
 * Get validation metrics
 */
export function getValidationMetrics() {
  return {
    ...validationMetrics,
    successRate:
      validationMetrics.totalValidations > 0
        ? (validationMetrics.successfulValidations /
            validationMetrics.totalValidations) *
          100
        : 0,
    failureRate:
      validationMetrics.totalValidations > 0
        ? (validationMetrics.failedValidations /
            validationMetrics.totalValidations) *
          100
        : 0,
    threatRate:
      validationMetrics.totalValidations > 0
        ? (validationMetrics.securityThreats /
            validationMetrics.totalValidations) *
          100
        : 0,
  };
}
/**
 * Reset validation metrics
 */
export function resetValidationMetrics() {
  Object.assign(validationMetrics, {
    totalValidations: 0,
    successfulValidations: 0,
    failedValidations: 0,
    securityThreats: 0,
    passwordViolations: 0,
    emailViolations: 0,
    phoneViolations: 0,
    schemaErrors: {},
  });
}
/**
 * Update validation configuration
 */
export function updateValidationConfig(newConfig) {
  Object.assign(VALIDATION_CONFIG, newConfig);
  safeLogger.info('Validation configuration updated', { newConfig });
}
// Email verification schema
export const emailVerificationSchema = data => {
  const sanitizedData = sanitizeInput(data);
  const schema = Joi.object({
    token: Joi.string().required().min(32).max(255),
  });

  const result = schema.validate(sanitizedData, {
    abortEarly: false,
    stripUnknown: true,
    allowUnknown: false,
  });

  if (result.error) {
    validationMetrics.failedValidations++;
    return result;
  }
  validationMetrics.successfulValidations++;
  return result;
};

// 2FA verification schema
export const twoFactorVerificationSchema = data => {
  const sanitizedData = sanitizeInput(data);
  const schema = Joi.object({
    code: Joi.string()
      .required()
      .length(6)
      .pattern(/^\d{6}$/),
    sessionId: Joi.string().required().uuid(),
  });

  const result = schema.validate(sanitizedData, {
    abortEarly: false,
    stripUnknown: true,
    allowUnknown: false,
  });

  if (result.error) {
    validationMetrics.failedValidations++;
    return result;
  }
  validationMetrics.successfulValidations++;
  return result;
};

// 2FA disable schema
export const twoFactorDisableSchema = data => {
  const sanitizedData = sanitizeInput(data);
  const schema = Joi.object({
    code: Joi.string()
      .required()
      .length(6)
      .pattern(/^\d{6}$/),
  });

  const result = schema.validate(sanitizedData, {
    abortEarly: false,
    stripUnknown: true,
    allowUnknown: false,
  });

  if (result.error) {
    validationMetrics.failedValidations++;
    return result;
  }
  validationMetrics.successfulValidations++;
  return result;
};

export default {
  signupSchemas,
  commonLoginSchema,
  passwordResetSchema,
  profileUpdateSchema,
  emailVerificationSchema,
  twoFactorVerificationSchema,
  twoFactorDisableSchema,
  getValidationMetrics,
  resetValidationMetrics,
  updateValidationConfig,
};
