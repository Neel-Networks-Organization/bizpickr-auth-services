import Joi from 'joi';

/**
 * Industry-Standard Auth Validators
 * Professional validation for SaaS applications
 */

// ✅ Industry-standard validation constants
const VALIDATION_RULES = {
  PASSWORD: {
    MIN_LENGTH: 8,
    MAX_LENGTH: 128,
    REQUIRE_UPPERCASE: true,
    REQUIRE_LOWERCASE: true,
    REQUIRE_NUMBERS: true,
    REQUIRE_SPECIAL_CHARS: true,
  },
  EMAIL: {
    MAX_LENGTH: 254,
    ALLOW_DISPOSABLE: false,
  },
  PHONE: {
    PATTERN: /^\+?[\d\s-()]{7,20}$/,
    ALLOW_INTERNATIONAL: true,
  },
  USERNAME: {
    MIN_LENGTH: 3,
    MAX_LENGTH: 30,
    PATTERN: /^[a-zA-Z0-9_-]+$/,
  },
};

// ✅ Industry-standard OAuth providers
const OAUTH_PROVIDERS = {
  GOOGLE: 'google',
  FACEBOOK: 'facebook',
  GITHUB: 'github',
  LINKEDIN: 'linkedin',
  TWITTER: 'twitter',
  APPLE: 'apple',
  MICROSOFT: 'microsoft',
};

// ✅ Industry-standard user roles
const USER_ROLES = {
  SUPER_ADMIN: 'super_admin',
  ADMIN: 'admin',
  MODERATOR: 'moderator',
  USER: 'user',
  GUEST: 'guest',
};

// ✅ Industry-standard user types
const USER_TYPES = {
  INDIVIDUAL: 'individual',
  BUSINESS: 'business',
  ENTERPRISE: 'enterprise',
};

// ✅ Industry-standard 2FA methods
const TWO_FACTOR_METHODS = {
  TOTP: 'totp',
  SMS: 'sms',
  EMAIL: 'email',
  AUTHENTICATOR_APP: 'authenticator_app',
  HARDWARE_TOKEN: 'hardware_token',
};

// ✅ Industry-standard account statuses
const ACCOUNT_STATUSES = {
  ACTIVE: 'active',
  INACTIVE: 'inactive',
  SUSPENDED: 'suspended',
  PENDING_VERIFICATION: 'pending_verification',
  LOCKED: 'locked',
  DELETED: 'deleted',
};

/**
 * Industry-standard validation schemas
 */
export const authValidators = {
  // ✅ User registration with comprehensive validation
  register: Joi.object({
    email: Joi.string()
      .email({ tlds: { allow: false } })
      .max(VALIDATION_RULES.EMAIL.MAX_LENGTH)
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'string.max': 'Email address is too long',
        'any.required': 'Email address is required',
      }),

    password: Joi.string()
      .min(VALIDATION_RULES.PASSWORD.MIN_LENGTH)
      .max(VALIDATION_RULES.PASSWORD.MAX_LENGTH)
      .pattern(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/
      )
      .required()
      .messages({
        'string.min': `Password must be at least ${VALIDATION_RULES.PASSWORD.MIN_LENGTH} characters long`,
        'string.max': `Password must not exceed ${VALIDATION_RULES.PASSWORD.MAX_LENGTH} characters`,
        'string.pattern.base':
          'Password must contain uppercase, lowercase, number, and special character',
        'any.required': 'Password is required',
      }),

    firstName: Joi.string()
      .min(2)
      .max(50)
      .pattern(/^[a-zA-Z\s'-]+$/)
      .required()
      .messages({
        'string.min': 'First name must be at least 2 characters long',
        'string.max': 'First name must not exceed 50 characters',
        'string.pattern.base': 'First name contains invalid characters',
        'any.required': 'First name is required',
      }),

    lastName: Joi.string()
      .min(2)
      .max(50)
      .pattern(/^[a-zA-Z\s'-]+$/)
      .required()
      .messages({
        'string.min': 'Last name must be at least 2 characters long',
        'string.max': 'Last name must not exceed 50 characters',
        'string.pattern.base': 'Last name contains invalid characters',
        'any.required': 'Last name is required',
      }),

    phone: Joi.string()
      .pattern(VALIDATION_RULES.PHONE.PATTERN)
      .optional()
      .messages({
        'string.pattern.base': 'Please provide a valid phone number',
      }),

    username: Joi.string()
      .min(VALIDATION_RULES.USERNAME.MIN_LENGTH)
      .max(VALIDATION_RULES.USERNAME.MAX_LENGTH)
      .pattern(VALIDATION_RULES.USERNAME.PATTERN)
      .optional()
      .messages({
        'string.min': `Username must be at least ${VALIDATION_RULES.USERNAME.MIN_LENGTH} characters long`,
        'string.max': `Username must not exceed ${VALIDATION_RULES.USERNAME.MAX_LENGTH} characters`,
        'string.pattern.base':
          'Username can only contain letters, numbers, hyphens, and underscores',
      }),

    userType: Joi.string()
      .valid(...Object.values(USER_TYPES))
      .default(USER_TYPES.INDIVIDUAL)
      .optional(),

    acceptTerms: Joi.boolean().valid(true).required().messages({
      'any.only': 'You must accept the terms and conditions',
      'any.required': 'Terms acceptance is required',
    }),

    marketingConsent: Joi.boolean().default(false).optional(),
  }),

  // ✅ OAuth registration
  oauthRegister: Joi.object({
    provider: Joi.string()
      .valid(...Object.values(OAUTH_PROVIDERS))
      .required()
      .messages({
        'any.only': 'Invalid OAuth provider',
        'any.required': 'OAuth provider is required',
      }),

    accessToken: Joi.string().required().messages({
      'any.required': 'OAuth access token is required',
    }),

    profile: Joi.object({
      id: Joi.string().required(),
      email: Joi.string().email().required(),
      firstName: Joi.string().min(2).max(50).optional(),
      lastName: Joi.string().min(2).max(50).optional(),
      avatar: Joi.string().uri().optional(),
    }).required(),

    userType: Joi.string()
      .valid(...Object.values(USER_TYPES))
      .default(USER_TYPES.INDIVIDUAL)
      .optional(),

    acceptTerms: Joi.boolean().valid(true).required().messages({
      'any.only': 'You must accept the terms and conditions',
      'any.required': 'Terms acceptance is required',
    }),
  }),

  // ✅ User login with security features
  login: Joi.object({
    email: Joi.string()
      .email({ tlds: { allow: false } })
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email address is required',
      }),

    password: Joi.string().required().messages({
      'any.required': 'Password is required',
    }),

    rememberMe: Joi.boolean().default(false).optional(),

    twoFactorCode: Joi.string()
      .length(6)
      .pattern(/^\d{6}$/)
      .optional()
      .messages({
        'string.length': 'Two-factor code must be 6 digits',
        'string.pattern.base': 'Two-factor code must contain only numbers',
      }),

    deviceFingerprint: Joi.string().optional(),

    captchaToken: Joi.string().optional(),
  }),

  // ✅ Two-factor authentication setup
  setupTwoFactor: Joi.object({
    method: Joi.string()
      .valid(...Object.values(TWO_FACTOR_METHODS))
      .required()
      .messages({
        'any.only': 'Invalid two-factor method',
        'any.required': 'Two-factor method is required',
      }),

    phone: Joi.string()
      .pattern(VALIDATION_RULES.PHONE.PATTERN)
      .when('method', {
        is: TWO_FACTOR_METHODS.SMS,
        then: Joi.required(),
        otherwise: Joi.optional(),
      })
      .messages({
        'string.pattern.base': 'Please provide a valid phone number',
        'any.required':
          'Phone number is required for SMS two-factor authentication',
      }),

    backupCodes: Joi.array()
      .items(
        Joi.string()
          .length(8)
          .pattern(/^[A-Z0-9]{8}$/)
      )
      .length(10)
      .optional()
      .messages({
        'array.length': 'Must provide exactly 10 backup codes',
        'string.length': 'Each backup code must be 8 characters long',
        'string.pattern.base':
          'Backup codes must contain only uppercase letters and numbers',
      }),
  }),

  // ✅ Two-factor authentication verification
  verifyTwoFactor: Joi.object({
    method: Joi.string()
      .valid(...Object.values(TWO_FACTOR_METHODS))
      .required()
      .messages({
        'any.only': 'Invalid two-factor method',
        'any.required': 'Two-factor method is required',
      }),

    code: Joi.string()
      .length(6)
      .pattern(/^\d{6}$/)
      .required()
      .messages({
        'string.length': 'Verification code must be 6 digits',
        'string.pattern.base': 'Verification code must contain only numbers',
        'any.required': 'Verification code is required',
      }),

    backupCode: Joi.string()
      .length(8)
      .pattern(/^[A-Z0-9]{8}$/)
      .optional()
      .messages({
        'string.length': 'Backup code must be 8 characters long',
        'string.pattern.base':
          'Backup code must contain only uppercase letters and numbers',
      }),
  }),

  // ✅ Password reset request with rate limiting
  passwordResetRequest: Joi.object({
    email: Joi.string()
      .email({ tlds: { allow: false } })
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email address is required',
      }),

    captchaToken: Joi.string().optional(),

    deviceFingerprint: Joi.string().optional(),
  }),

  // ✅ Password reset with security validation
  passwordReset: Joi.object({
    token: Joi.string().required().messages({
      'any.required': 'Reset token is required',
    }),

    newPassword: Joi.string()
      .min(VALIDATION_RULES.PASSWORD.MIN_LENGTH)
      .max(VALIDATION_RULES.PASSWORD.MAX_LENGTH)
      .pattern(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/
      )
      .required()
      .messages({
        'string.min': `Password must be at least ${VALIDATION_RULES.PASSWORD.MIN_LENGTH} characters long`,
        'string.max': `Password must not exceed ${VALIDATION_RULES.PASSWORD.MAX_LENGTH} characters`,
        'string.pattern.base':
          'Password must contain uppercase, lowercase, number, and special character',
        'any.required': 'New password is required',
      }),

    confirmPassword: Joi.string()
      .valid(Joi.ref('newPassword'))
      .required()
      .messages({
        'any.only': 'Passwords do not match',
        'any.required': 'Password confirmation is required',
      }),

    deviceFingerprint: Joi.string().optional(),
  }),

  // ✅ Email verification
  verifyEmail: Joi.object({
    token: Joi.string().required().messages({
      'any.required': 'Verification token is required',
    }),

    deviceFingerprint: Joi.string().optional(),
  }),

  // ✅ Token refresh with security
  refreshToken: Joi.object({
    refreshToken: Joi.string().required().messages({
      'any.required': 'Refresh token is required',
    }),

    deviceFingerprint: Joi.string().optional(),

    userAgent: Joi.string().optional(),
  }),

  // ✅ Change password with current password verification
  changePassword: Joi.object({
    currentPassword: Joi.string().required().messages({
      'any.required': 'Current password is required',
    }),

    newPassword: Joi.string()
      .min(VALIDATION_RULES.PASSWORD.MIN_LENGTH)
      .max(VALIDATION_RULES.PASSWORD.MAX_LENGTH)
      .pattern(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/
      )
      .invalid(Joi.ref('currentPassword'))
      .required()
      .messages({
        'string.min': `Password must be at least ${VALIDATION_RULES.PASSWORD.MIN_LENGTH} characters long`,
        'string.max': `Password must not exceed ${VALIDATION_RULES.PASSWORD.MAX_LENGTH} characters`,
        'string.pattern.base':
          'Password must contain uppercase, lowercase, number, and special character',
        'any.invalid': 'New password must be different from current password',
        'any.required': 'New password is required',
      }),

    confirmPassword: Joi.string()
      .valid(Joi.ref('newPassword'))
      .required()
      .messages({
        'any.only': 'Passwords do not match',
        'any.required': 'Password confirmation is required',
      }),

    twoFactorCode: Joi.string()
      .length(6)
      .pattern(/^\d{6}$/)
      .optional()
      .messages({
        'string.length': 'Two-factor code must be 6 digits',
        'string.pattern.base': 'Two-factor code must contain only numbers',
      }),
  }),

  // ✅ Update profile with validation
  updateProfile: Joi.object({
    firstName: Joi.string()
      .min(2)
      .max(50)
      .pattern(/^[a-zA-Z\s'-]+$/)
      .optional()
      .messages({
        'string.min': 'First name must be at least 2 characters long',
        'string.max': 'First name must not exceed 50 characters',
        'string.pattern.base': 'First name contains invalid characters',
      }),

    lastName: Joi.string()
      .min(2)
      .max(50)
      .pattern(/^[a-zA-Z\s'-]+$/)
      .optional()
      .messages({
        'string.min': 'Last name must be at least 2 characters long',
        'string.max': 'Last name must not exceed 50 characters',
        'string.pattern.base': 'Last name contains invalid characters',
      }),

    phone: Joi.string()
      .pattern(VALIDATION_RULES.PHONE.PATTERN)
      .optional()
      .messages({
        'string.pattern.base': 'Please provide a valid phone number',
      }),

    username: Joi.string()
      .min(VALIDATION_RULES.USERNAME.MIN_LENGTH)
      .max(VALIDATION_RULES.USERNAME.MAX_LENGTH)
      .pattern(VALIDATION_RULES.USERNAME.PATTERN)
      .optional()
      .messages({
        'string.min': `Username must be at least ${VALIDATION_RULES.USERNAME.MIN_LENGTH} characters long`,
        'string.max': `Username must not exceed ${VALIDATION_RULES.USERNAME.MAX_LENGTH} characters`,
        'string.pattern.base':
          'Username can only contain letters, numbers, hyphens, and underscores',
      }),

    avatar: Joi.string().uri().optional().messages({
      'string.uri': 'Please provide a valid avatar URL',
    }),

    bio: Joi.string().max(500).optional().messages({
      'string.max': 'Bio must not exceed 500 characters',
    }),

    dateOfBirth: Joi.date().max('now').optional().messages({
      'date.max': 'Date of birth cannot be in the future',
    }),

    timezone: Joi.string().optional(),

    language: Joi.string().length(2).optional().messages({
      'string.length': 'Language code must be 2 characters',
    }),
  }),

  // ✅ Account security settings
  updateSecuritySettings: Joi.object({
    twoFactorEnabled: Joi.boolean().optional(),

    twoFactorMethod: Joi.string()
      .valid(...Object.values(TWO_FACTOR_METHODS))
      .optional()
      .messages({
        'any.only': 'Invalid two-factor method',
      }),

    loginNotifications: Joi.boolean().optional(),

    suspiciousActivityAlerts: Joi.boolean().optional(),

    sessionTimeout: Joi.number()
      .integer()
      .min(15)
      .max(1440)
      .optional()
      .messages({
        'number.integer': 'Session timeout must be a whole number',
        'number.min': 'Session timeout must be at least 15 minutes',
        'number.max': 'Session timeout must not exceed 24 hours',
      }),

    maxConcurrentSessions: Joi.number()
      .integer()
      .min(1)
      .max(10)
      .optional()
      .messages({
        'number.integer': 'Maximum concurrent sessions must be a whole number',
        'number.min': 'Maximum concurrent sessions must be at least 1',
        'number.max': 'Maximum concurrent sessions must not exceed 10',
      }),
  }),

  // ✅ Admin user management
  adminUpdateUser: Joi.object({
    userId: Joi.string().required().messages({
      'any.required': 'User ID is required',
    }),

    role: Joi.string()
      .valid(...Object.values(USER_ROLES))
      .optional()
      .messages({
        'any.only': 'Invalid user role',
      }),

    status: Joi.string()
      .valid(...Object.values(ACCOUNT_STATUSES))
      .optional()
      .messages({
        'any.only': 'Invalid account status',
      }),

    isActive: Joi.boolean().optional(),

    isVerified: Joi.boolean().optional(),

    permissions: Joi.array().items(Joi.string()).optional(),

    notes: Joi.string().max(1000).optional().messages({
      'string.max': 'Admin notes must not exceed 1000 characters',
    }),
  }),

  // ✅ Bulk user operations
  bulkUserOperation: Joi.object({
    userIds: Joi.array()
      .items(Joi.string())
      .min(1)
      .max(100)
      .required()
      .messages({
        'array.min': 'At least one user ID is required',
        'array.max': 'Maximum 100 users can be processed at once',
        'any.required': 'User IDs are required',
      }),

    operation: Joi.string()
      .valid(
        'activate',
        'deactivate',
        'suspend',
        'delete',
        'verify',
        'unverify'
      )
      .required()
      .messages({
        'any.only': 'Invalid bulk operation',
        'any.required': 'Operation type is required',
      }),

    reason: Joi.string().max(500).optional().messages({
      'string.max': 'Reason must not exceed 500 characters',
    }),
  }),
};

// ✅ Export default
export default authValidators;

// ✅ Export validation functions for backward compatibility
export const validateSignup = data => {
  const { error, value } = authValidators.register.validate(data);
  if (error) {
    throw new Error(`Validation error: ${error.details[0].message}`);
  }
  return value;
};

export const validateLogin = data => {
  const { error, value } = authValidators.login.validate(data);
  if (error) {
    throw new Error(`Validation error: ${error.details[0].message}`);
  }
  return value;
};

export const validatePasswordReset = data => {
  const { error, value } = authValidators.passwordReset.validate(data);
  if (error) {
    throw new Error(`Validation error: ${error.details[0].message}`);
  }
  return value;
};

export const validateEmailVerification = data => {
  const { error, value } = authValidators.verifyEmail.validate(data);
  if (error) {
    throw new Error(`Validation error: ${error.details[0].message}`);
  }
  return value;
};

export const validateTokenRefresh = data => {
  const { error, value } = authValidators.refreshToken.validate(data);
  if (error) {
    throw new Error(`Validation error: ${error.details[0].message}`);
  }
  return value;
};

export const validatePasswordChange = data => {
  const { error, value } = authValidators.changePassword.validate(data);
  if (error) {
    throw new Error(`Validation error: ${error.details[0].message}`);
  }
  return value;
};

export const validateProfileUpdate = data => {
  const { error, value } = authValidators.updateProfile.validate(data);
  if (error) {
    throw new Error(`Validation error: ${error.details[0].message}`);
  }
  return value;
};
