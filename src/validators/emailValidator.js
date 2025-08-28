import Joi from 'joi';

export const emailSchemas = {
  sendVerificationEmail: Joi.object({
    body: Joi.object({
      email: Joi.string().email().required().messages({
        'any.required': 'Email is required',
        'string.email': 'Please provide a valid email address',
      }),
    }).required(),
    query: Joi.object({}).optional(),
    params: Joi.object({}).optional(),
  }),
  verifyEmail: Joi.object({
    body: Joi.object({
      email: Joi.string().email().required().messages({
        'any.required': 'Email is required',
        'string.email': 'Please provide a valid email address',
      }),
      otp: Joi.number().required().messages({
        'any.required': 'OTP is required',
      }),
    }).required(),
    query: Joi.object({}).optional(),
    params: Joi.object({}).optional(),
  }),
  getVerificationStatsByEmail: Joi.object({
    params: Joi.object({
      email: Joi.string().email().required().messages({
        'any.required': 'Email is required',
        'string.email': 'Please provide a valid email address',
      }),
    }).required(),
  }),
  getVerificationStats: Joi.object({
    query: Joi.object({}).optional(),
    params: Joi.object({}).optional(),
  }),
};

export const {
  sendVerificationEmail,
  verifyEmail,
  getVerificationStatsByEmail,
  getVerificationStats,
} = emailSchemas;

export default emailSchemas;
