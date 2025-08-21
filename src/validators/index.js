/**
 * Validators Index
 * Central export for all validation schemas and functions
 */

// Joi-based validation schemas
export { authSchemas, default as authValidators } from './authValidators.js';
export { jwkValidators, default as jwkValidators } from './jwkValidators.js';

// Basic validation functions (legacy support)
export { default as basicValidators } from './basicValidators.js';

// Re-export individual schemas for convenience
export {
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
} from './authValidators.js';

export {
  createJwk,
  updateJwk,
  jwkId,
  listJwks,
  validateJWKRequest,
} from './jwkValidators.js';
