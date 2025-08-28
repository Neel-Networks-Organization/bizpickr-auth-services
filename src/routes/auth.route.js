import { Router } from 'express';
import {
  signupUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  getCurrentUser,
  loginWithGoogle,
  googleCallback,
  enableTwoFactor,
  disableTwoFactor,
  verifyTwoFactor,
} from '../controllers/auth.controller.js';
import { verifyJWT } from '../middlewares/auth.middleware.js';
import ipRateLimit from '../middlewares/rateLimiter.middleware.js';
import { validateRequest } from '../middlewares/validation.middleware.js';
import { authSchemas } from '../validators/index.js';
import { asyncHandler } from '../utils/index.js';

const router = Router();

// User Registration & Authentication
router
  .route('/signup')
  .post(
    ipRateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 5 }),
    validateRequest(authSchemas.signup),
    asyncHandler(signupUser)
  );

router
  .route('/login')
  .post(
    ipRateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 10 }),
    validateRequest(authSchemas.login),
    asyncHandler(loginUser)
  );

router.route('/logout').post(verifyJWT, asyncHandler(logoutUser));

router
  .route('/refresh-token')
  .post(
    ipRateLimit({ windowMs: 60 * 1000, maxRequests: 20 }),
    validateRequest(authSchemas.refreshToken),
    asyncHandler(refreshAccessToken)
  );

// Current User
router.route('/me').get(verifyJWT, getCurrentUser);

// Two-Factor Authentication Routes
router
  .route('/2fa/enable')
  .post(
    verifyJWT,
    ipRateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 5 }),
    validateRequest(authSchemas.enableTwoFactor),
    asyncHandler(enableTwoFactor)
  );

router
  .route('/2fa/disable')
  .post(
    verifyJWT,
    ipRateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 5 }),
    asyncHandler(disableTwoFactor)
  );

router
  .route('/2fa/verify')
  .post(
    ipRateLimit({ windowMs: 5 * 60 * 1000, maxRequests: 10 }),
    validateRequest(authSchemas.verifyTwoFactor),
    asyncHandler(verifyTwoFactor)
  );

// OAuth Integration
router
  .route('/google')
  .get(
    ipRateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 10 }),
    asyncHandler(loginWithGoogle)
  );

router
  .route('/google/callback')
  .get(
    ipRateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 10 }),
    asyncHandler(googleCallback)
  );

export default router;
