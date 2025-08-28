/**
 * Validators Index
 * Central export for all validation schemas and functions
 */

// Joi-based validation schemas
export { authSchemas, default as authValidator } from './authValidator.js';
export { jwkSchemas, default as jwkValidator } from './jwkValidator.js';
export {
  passwordSchemas,
  default as passwordValidator,
} from './passwordValidator.js';
export { emailSchemas, default as emailValidator } from './emailValidator.js';

// Re-export individual schemas for convenience
export {
  signup,
  login,
  enableTwoFactor,
  verifyTwoFactor,
  forgotPassword,
  refreshToken,
} from './authValidator.js';

export { getJWKByKid } from './jwkValidator.js';

export {
  changePassword,
  getPasswordResetStatsByEmail,
} from './passwordValidator.js';

export {
  sendVerificationEmail,
  verifyEmail,
  getVerificationStatsByEmail,
} from './emailValidator.js';
