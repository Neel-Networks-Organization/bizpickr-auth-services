import Joi from 'joi';

/**
 * Auth Service Validation Schemas
 * Comprehensive Joi validation for all authentication endpoints
 */

export const authSchemas = {
  // User Registration
  signup: Joi.object({
    body: Joi.object({
      email: Joi.string().email().required().messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required',
      }),
      password: Joi.string()
        .min(8)
        .max(128)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
        .required()
        .messages({
          'string.min': 'Password must be at least 8 characters long',
          'string.max': 'Password must not exceed 128 characters',
          'string.pattern.base':
            'Password must contain at least one uppercase letter, one lowercase letter, and one number',
          'any.required': 'Password is required',
        }),
      fullName: Joi.string().min(2).max(100).required().messages({
        'string.min': 'Full name must be at least 2 characters long',
        'string.max': 'Full name must not exceed 100 characters',
        'any.required': 'Full name is required',
      }),
      type: Joi.string()
        .valid('individual', 'company', 'customer', 'vendor', 'staff', 'admin')
        .required()
        .messages({
          'any.only':
            'User type must be one of: individual, company, customer, vendor, staff, admin',
          'any.required': 'User type is required',
        }),
      role: Joi.string()
        .valid('customer', 'vendor', 'staff', 'admin', 'super_admin')
        .optional()
        .default('customer')
        .messages({
          'any.only':
            'User role must be one of: customer, vendor, staff, admin, super_admin',
        }),
      phone: Joi.string()
        .pattern(/^\+?[\d\s\-\(\)]+$/)
        .optional()
        .messages({
          'string.pattern.base': 'Please provide a valid phone number',
        }),
      acceptTerms: Joi.boolean().valid(true).required().messages({
        'any.only': 'You must accept the terms and conditions',
        'any.required': 'Terms acceptance is required',
      }),
    }).required(),
    query: Joi.object({}).optional(),
    params: Joi.object({}).optional(),
  }),

  // User Login
  login: Joi.object({
    body: Joi.object({
      email: Joi.string().email().required().messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required',
      }),
      password: Joi.string().required().messages({
        'any.required': 'Password is required',
      }),
      type: Joi.string()
        .valid('individual', 'company', 'customer', 'vendor', 'staff', 'admin')
        .optional()
        .messages({
          'any.only':
            'User type must be one of: individual, company, customer, vendor, staff, admin',
        }),
    }).required(),
    query: Joi.object({}).optional(),
    params: Joi.object({}).optional(),
  }),

  // Email Verification
  verifyEmail: Joi.object({
    body: Joi.object({
      token: Joi.string().required().messages({
        'any.required': 'Verification token is required',
      }),
      email: Joi.string().email().optional().messages({
        'string.email': 'Please provide a valid email address',
      }),
    }).required(),
    query: Joi.object({}).optional(),
    params: Joi.object({}).optional(),
  }),

  // Resend Verification Email
  resendVerification: Joi.object({
    body: Joi.object({
      email: Joi.string().email().optional().messages({
        'string.email': 'Please provide a valid email address',
      }),
    }).optional(),
    query: Joi.object({}).optional(),
    params: Joi.object({}).optional(),
  }),

  // Two-Factor Authentication
  enableTwoFactor: Joi.object({
    body: Joi.object({
      method: Joi.string().valid('totp', 'sms', 'email').required().messages({
        'any.only': '2FA method must be one of: totp, sms, email',
        'any.required': '2FA method is required',
      }),
    }).required(),
    query: Joi.object({}).optional(),
    params: Joi.object({}).optional(),
  }),

  verifyTwoFactor: Joi.object({
    body: Joi.object({
      code: Joi.string()
        .length(6)
        .pattern(/^\d{6}$/)
        .required()
        .messages({
          'string.length': '2FA code must be exactly 6 digits',
          'string.pattern.base': '2FA code must contain only digits',
          'any.required': '2FA code is required',
        }),
      method: Joi.string().valid('totp', 'sms', 'email').required().messages({
        'any.only': '2FA method must be one of: totp, sms, email',
        'any.required': '2FA method is required',
      }),
    }).required(),
    query: Joi.object({}).optional(),
    params: Joi.object({}).optional(),
  }),

  // Password Reset
  forgotPassword: Joi.object({
    body: Joi.object({
      email: Joi.string().email().required().messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required',
      }),
    }).required(),
    query: Joi.object({}).optional(),
    params: Joi.object({}).optional(),
  }),

  // Email Verification and Activation
  verifyEmailActivate: Joi.object({
    body: Joi.object({
      token: Joi.string().required().messages({
        'any.required': 'Activation token is required',
      }),
      email: Joi.string().email().optional().messages({
        'string.email': 'Please provide a valid email address',
      }),
    }).required(),
    query: Joi.object({}).optional(),
    params: Joi.object({}).optional(),
  }),

  // Token Verification
  verifyToken: Joi.object({
    body: Joi.object({
      token: Joi.string().required().messages({
        'any.required': 'Token is required',
      }),
    }).required(),
    query: Joi.object({}).optional(),
    params: Joi.object({}).optional(),
  }),

  // Refresh Token
  refreshToken: Joi.object({
    body: Joi.object({
      refreshToken: Joi.string().required().messages({
        'any.required': 'Refresh token is required',
      }),
    }).required(),
    query: Joi.object({}).optional(),
    params: Joi.object({}).optional(),
  }),
};

// Export individual schemas for easy use
export const {
  signup,
  login,
  verifyEmail,
  resendVerification,
  enableTwoFactor,
  verifyTwoFactor,
  forgotPassword,
  verifyEmailActivate,
  verifyToken,
  refreshToken,
} = authSchemas;

export default authSchemas;
