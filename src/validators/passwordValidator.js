import Joi from 'joi';

export const passwordSchemas = {
  changePassword: Joi.object({
    body: Joi.object({
      currentPassword: Joi.string().required().messages({
        'any.required': 'Current password is required',
      }),
      newPassword: Joi.string().required().messages({
        'any.required': 'New password is required',
      }),
    }).required(),
    params: Joi.object({}).optional(),
    query: Joi.object({}).optional(),
  }),

  forgotPassword: Joi.object({
    body: Joi.object({
      email: Joi.string().email().required().messages({
        'any.required': 'Email is required',
        'string.email': 'Please provide a valid email address',
      }),
    }).required(),
    params: Joi.object({}).optional(),
    query: Joi.object({}).optional(),
  }),

  resetPassword: Joi.object({
    body: Joi.object({
      email: Joi.string().email().required().messages({
        'any.required': 'Email is required',
        'string.email': 'Please provide a valid email address',
      }),
      otp: Joi.number().required().messages({
        'any.required': 'OTP is required',
      }),
      newPassword: Joi.string().required().messages({
        'any.required': 'New password is required',
      }),
    }).required(),
    params: Joi.object({}).optional(),
    query: Joi.object({}).optional(),
  }),

  getPasswordResetStatsByEmail: Joi.object({
    params: Joi.object({
      email: Joi.string().email().required().messages({
        'any.required': 'Email is required',
        'string.email': 'Please provide a valid email address',
      }),
    }).required(),
  }),
};

export const {
  changePassword,
  forgotPassword,
  resetPassword,
  getPasswordResetStatsByEmail,
} = passwordSchemas;

export default passwordSchemas;
