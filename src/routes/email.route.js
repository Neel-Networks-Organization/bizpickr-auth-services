import { Router } from 'express';
import {
  sendVerificationEmail,
  verifyEmail,
  getVerificationStats,
  getVerificationStatsByEmail,
} from '../controllers/email.controller.js';
import { validateRequest } from '../middlewares/validation.middleware.js';
import { asyncHandler } from '../utils/index.js';
import { emailSchemas } from '../validators/index.js';
import ipRateLimit from '../middlewares/rateLimiter.middleware.js';
import { requireRole } from '../middlewares/auth.middleware.js';
import { env } from '../config/env.js';

const router = Router();

// Email Verification
router
  .route('/send-verification-email')
  .post(
    ipRateLimit(env.services.rateLimit.routes.email.verify),
    validateRequest(emailSchemas.sendVerificationEmail),
    asyncHandler(sendVerificationEmail)
  );

router
  .route('/verify-email')
  .post(
    ipRateLimit(env.services.rateLimit.routes.email.verify),
    validateRequest(emailSchemas.verifyEmail),
    asyncHandler(verifyEmail)
  );

router
  .route('/stats')
  .get(requireRole('admin'), asyncHandler(getVerificationStats));

router
  .route('/stats/:email')
  .get(
    validateRequest(emailSchemas.getVerificationStatsByEmail),
    requireRole('admin'),
    asyncHandler(getVerificationStatsByEmail)
  );

export default router;
