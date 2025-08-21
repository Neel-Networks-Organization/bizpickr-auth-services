/**
 * Password Routes - Password Management Endpoints
 *
 * Handles all password-related routes:
 * - Password reset
 * - Password change
 * - Password validation
 * - Password statistics
 */
import { Router } from 'express';
import {
  changePassword,
  forgotPassword,
  resetPassword,
  validatePassword,
  getPasswordStats,
  cleanExpiredTokens,
} from '../controllers/password.controller.js';
import {
  verifyJWT,
  requireRole,
  rateLimiter,
  auditLog,
} from '../middlewares/auth.middleware.js';
import { validateRequest } from '../middlewares/validation.middleware.js';
import { asyncHandler } from '../utils/index.js';
import {
  validatePasswordChange,
  validatePasswordReset,
} from '../validators/basicValidators.js';

const router = Router();

// Password Change
router
  .route('/change')
  .post(
    verifyJWT,
    validateRequest(validatePasswordChange),
    auditLog('password_change'),
    asyncHandler(changePassword),
  );

// Password Reset
router
  .route('/forgot')
  .post(
    rateLimiter('forgot-password', { windowMs: 15 * 60 * 1000, max: 3 }),
    auditLog('forgot_password'),
    asyncHandler(forgotPassword),
  );

router
  .route('/reset')
  .post(
    rateLimiter('reset-password', { windowMs: 15 * 60 * 1000, max: 3 }),
    validateRequest(validatePasswordReset),
    auditLog('password_reset'),
    asyncHandler(resetPassword),
  );

// Password Validation with rate limiting
router
  .route('/validate')
  .post(
    rateLimiter('password_validate', { windowMs: 60 * 1000, max: 20 }),
    auditLog('password_validation'),
    asyncHandler(validatePassword),
  );

// Password Statistics
router.route('/stats').get(verifyJWT, asyncHandler(getPasswordStats));

// Password Cleanup (Admin only)
router
  .route('/cleanup')
  .post(
    verifyJWT,
    requireRole('admin'),
    auditLog('password_cleanup'),
    asyncHandler(cleanExpiredTokens),
  );

export default router;
