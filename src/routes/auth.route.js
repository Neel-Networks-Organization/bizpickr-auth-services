/**
 * Auth Routes - Core Authentication Endpoints
 *
 * Handles core authentication routes:
 * - User registration and login
 * - JWT token management
 * - OAuth integration
 * - Core authentication flows
 */
import { Router } from 'express';
import {
  signupUser,
  loginUser,
  logoutUser,
  verifyToken,
  refreshAccessToken,
  getCurrentUser,
  loginWithGoogle,
  googleCallback,
  verifyEmail,
  resendVerificationEmail,
  enableTwoFactor,
  disableTwoFactor,
  verifyTwoFactor,
  forgotPassword,
  verifyEmailAndActivate,
} from '../controllers/auth.controller.js';
import {
  verifyJWT,
  rateLimiter,
  auditLog,
} from '../middlewares/auth.middleware.js';

import { asyncHandler } from '../utils/index.js';

const router = Router();

// User Registration & Authentication
router.route('/signup').post(
  rateLimiter('signup', { windowMs: 15 * 60 * 1000, max: 5 }),
  auditLog('user_signup'),
  asyncHandler(signupUser, {
    enableTiming: true,
    enableLogging: true,
    timeout: 30000,
    retryAttempts: 1,
  })
);

router.route('/login').post(
  rateLimiter('login', { windowMs: 15 * 60 * 1000, max: 10 }),
  auditLog('user_login'),
  asyncHandler(loginUser, {
    enableTiming: true,
    enableLogging: true,
    timeout: 30000,
    retryAttempts: 1,
  })
);

router.route('/logout').post(
  verifyJWT,
  auditLog('user_logout'),
  asyncHandler(logoutUser, {
    enableTiming: true,
    enableLogging: true,
    timeout: 10000,
    retryAttempts: 1,
  })
);

// Token Management
router.route('/verify-token').post(
  rateLimiter('verify', { windowMs: 60 * 1000, max: 30 }),
  asyncHandler(verifyToken, {
    enableTiming: true,
    enableLogging: true,
    timeout: 10000,
    retryAttempts: 1,
  })
);

router.route('/refresh-token').post(
  rateLimiter('refresh', { windowMs: 60 * 1000, max: 20 }),
  asyncHandler(refreshAccessToken, {
    enableTiming: true,
    enableLogging: true,
    timeout: 15000,
    retryAttempts: 1,
  })
);

// Current User
router.route('/me').get(
  verifyJWT,
  asyncHandler(getCurrentUser, {
    enableTiming: true,
    enableLogging: true,
    timeout: 10000,
    retryAttempts: 1,
  })
);

// Email Verification Routes
router.route('/verify-email').post(
  rateLimiter('email_verify', { windowMs: 15 * 60 * 1000, max: 5 }),
  auditLog('email_verification'),
  asyncHandler(verifyEmail, {
    enableTiming: true,
    enableLogging: true,
    timeout: 15000,
    retryAttempts: 1,
  })
);

router.route('/resend-verification').post(
  verifyJWT,
  rateLimiter('resend_verification', { windowMs: 15 * 60 * 1000, max: 3 }),
  auditLog('resend_verification_email'),
  asyncHandler(resendVerificationEmail, {
    enableTiming: true,
    enableLogging: true,
    timeout: 15000,
    retryAttempts: 1,
  })
);

// Two-Factor Authentication Routes
router.route('/2fa/enable').post(
  verifyJWT,
  rateLimiter('2fa', { windowMs: 15 * 60 * 1000, max: 5 }),
  auditLog('2fa_enable'),
  asyncHandler(enableTwoFactor, {
    enableTiming: true,
    enableLogging: true,
    timeout: 20000,
    retryAttempts: 1,
  })
);

router.route('/2fa/disable').post(
  verifyJWT,
  rateLimiter('2fa', { windowMs: 15 * 60 * 1000, max: 5 }),
  auditLog('2fa_disable'),
  asyncHandler(disableTwoFactor, {
    enableTiming: true,
    enableLogging: true,
    timeout: 20000,
    retryAttempts: 1,
  })
);

router.route('/2fa/verify').post(
  rateLimiter('2fa_verify', { windowMs: 5 * 60 * 1000, max: 10 }),
  auditLog('2fa_verification'),
  asyncHandler(verifyTwoFactor, {
    enableTiming: true,
    enableLogging: true,
    timeout: 15000,
    retryAttempts: 1,
  })
);

// Password Reset Routes
router.route('/forgot-password').post(
  rateLimiter('forgot_password', { windowMs: 15 * 60 * 1000, max: 3 }),
  auditLog('forgot_password'),
  asyncHandler(forgotPassword, {
    enableTiming: true,
    enableLogging: true,
    timeout: 15000,
    retryAttempts: 1,
  })
);

// Email Verification and Activation Routes
router.route('/verify-email-activate').post(
  rateLimiter('email_verify_activate', { windowMs: 15 * 60 * 1000, max: 5 }),
  auditLog('email_verify_activate'),
  asyncHandler(verifyEmailAndActivate, {
    enableTiming: true,
    enableLogging: true,
    timeout: 15000,
    retryAttempts: 1,
  })
);

// OAuth Integration
router.route('/google').get(
  rateLimiter('oauth', { windowMs: 15 * 60 * 1000, max: 10 }),
  auditLog('oauth_google_initiate'),
  asyncHandler(loginWithGoogle, {
    enableTiming: true,
    enableLogging: true,
    timeout: 5000,
    retryAttempts: 1,
  })
);

router.route('/google/callback').get(
  rateLimiter('oauth', { windowMs: 15 * 60 * 1000, max: 10 }),
  auditLog('oauth_google_callback'),
  asyncHandler(googleCallback, {
    enableTiming: true,
    enableLogging: true,
    timeout: 30000,
    retryAttempts: 1,
  })
);

export default router;
