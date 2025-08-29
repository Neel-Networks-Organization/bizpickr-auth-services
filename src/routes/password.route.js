import { Router } from 'express';
import {
  changePassword,
  forgotPassword,
  resetPassword,
  getPasswordStats,
  cleanExpiredTokens,
  getPasswordResetStatsByEmail,
} from '../controllers/password.controller.js';
import { verifyJWT, requireRole } from '../middlewares/auth.middleware.js';
import ipRateLimit from '../middlewares/rateLimiter.middleware.js';
import { validateRequest } from '../middlewares/validation.middleware.js';
import { asyncHandler } from '../utils/index.js';
import { passwordSchemas } from '../validators/index.js';
import { env } from '../config/env.js';

const router = Router();

// Password Change
router
  .route('/change')
  .post(
    verifyJWT,
    validateRequest(passwordSchemas.changePassword),
    asyncHandler(changePassword)
  );

// Password Reset
router
  .route('/forgot')
  .post(
    ipRateLimit(env.services.rateLimit.routes.password.forgot),
    validateRequest(passwordSchemas.forgotPassword),
    asyncHandler(forgotPassword)
  );

router
  .route('/reset')
  .post(
    ipRateLimit(env.services.rateLimit.routes.password.reset),
    validateRequest(passwordSchemas.resetPassword),
    asyncHandler(resetPassword)
  );

// Password Statistics
router
  .route('/stats')
  .get(verifyJWT, requireRole('admin'), asyncHandler(getPasswordStats));

// Password Cleanup (Admin only)
router
  .route('/cleanup')
  .post(verifyJWT, requireRole('admin'), asyncHandler(cleanExpiredTokens));

// Password Reset Statistics by Email
router
  .route('/stats/:email')
  .get(
    validateRequest(passwordSchemas.getPasswordResetStatsByEmail),
    requireRole('admin'),
    asyncHandler(getPasswordResetStatsByEmail)
  );
export default router;
