import { Router } from 'express';
import {
  changePassword,
  forgotPassword,
  resetPassword,
  validatePassword,
  getPasswordStats,
  cleanExpiredTokens,
} from '../controllers/password.controller.js';
import { verifyJWT, requireRole } from '../middlewares/auth.middleware.js';
import ipRateLimit from '../middlewares/rateLimiter.middleware.js';
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
    asyncHandler(changePassword)
  );

// Password Reset
router
  .route('/forgot')
  .post(
    ipRateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 3 }),
    asyncHandler(forgotPassword)
  );

router
  .route('/reset')
  .post(
    ipRateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 3 }),
    validateRequest(validatePasswordReset),
    asyncHandler(resetPassword)
  );

// Password Validation with rate limiting
router
  .route('/validate')
  .post(
    ipRateLimit({ windowMs: 60 * 1000, maxRequests: 20 }),
    asyncHandler(validatePassword)
  );

// Password Statistics
router.route('/stats').get(verifyJWT, asyncHandler(getPasswordStats));

// Password Cleanup (Admin only)
router
  .route('/cleanup')
  .post(verifyJWT, requireRole('admin'), asyncHandler(cleanExpiredTokens));

export default router;
