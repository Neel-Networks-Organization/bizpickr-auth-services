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
import { validateRequest } from '../middlewares/validation.middleware.js';
import { authSchemas } from '../validators/authValidators.js';
import { asyncHandler } from '../utils/index.js';

const router = Router();

// User Registration & Authentication
router
  .route('/signup')
  .post(
    rateLimiter('signup', { windowMs: 15 * 60 * 1000, max: 5 }),
    validateRequest(authSchemas.signup),
    auditLog('user_signup'),
    asyncHandler(signupUser)
  );

router
  .route('/login')
  .post(
    rateLimiter('login', { windowMs: 15 * 60 * 1000, max: 10 }),
    validateRequest(authSchemas.login),
    auditLog('user_login'),
    asyncHandler(loginUser)
  );

router
  .route('/logout')
  .post(verifyJWT, auditLog('user_logout'), asyncHandler(logoutUser));

// Token Management
router
  .route('/verify-token')
  .post(
    rateLimiter('verify', { windowMs: 60 * 1000, max: 30 }),
    validateRequest(authSchemas.verifyToken),
    asyncHandler(verifyToken)
  );

router
  .route('/refresh-token')
  .post(
    rateLimiter('refresh', { windowMs: 60 * 1000, max: 20 }),
    validateRequest(authSchemas.refreshToken),
    asyncHandler(refreshAccessToken)
  );

// Current User
router.route('/me').get(verifyJWT, asyncHandler(getCurrentUser));

// Email Verification Routes
router
  .route('/verify-email')
  .post(
    rateLimiter('email_verify', { windowMs: 15 * 60 * 1000, max: 5 }),
    validateRequest(authSchemas.verifyEmail),
    auditLog('email_verification'),
    asyncHandler(verifyEmail)
  );

router
  .route('/resend-verification')
  .post(
    verifyJWT,
    rateLimiter('resend_verification', { windowMs: 15 * 60 * 1000, max: 3 }),
    validateRequest(authSchemas.resendVerification),
    auditLog('resend_verification_email'),
    asyncHandler(resendVerificationEmail)
  );

// Two-Factor Authentication Routes
router
  .route('/2fa/enable')
  .post(
    verifyJWT,
    rateLimiter('2fa', { windowMs: 15 * 60 * 1000, max: 5 }),
    validateRequest(authSchemas.enableTwoFactor),
    auditLog('2fa_enable'),
    asyncHandler(enableTwoFactor)
  );

router
  .route('/2fa/disable')
  .post(
    verifyJWT,
    rateLimiter('2fa', { windowMs: 15 * 60 * 1000, max: 5 }),
    auditLog('2fa_disable'),
    asyncHandler(disableTwoFactor)
  );

router
  .route('/2fa/verify')
  .post(
    rateLimiter('2fa_verify', { windowMs: 5 * 60 * 1000, max: 10 }),
    validateRequest(authSchemas.verifyTwoFactor),
    auditLog('2fa_verification'),
    asyncHandler(verifyTwoFactor)
  );

// Password Reset Routes
router
  .route('/forgot-password')
  .post(
    rateLimiter('forgot_password', { windowMs: 15 * 60 * 1000, max: 3 }),
    validateRequest(authSchemas.forgotPassword),
    auditLog('forgot_password'),
    asyncHandler(forgotPassword)
  );

// Email Verification and Activation Routes
router
  .route('/verify-email-activate')
  .post(
    rateLimiter('email_verify_activate', { windowMs: 15 * 60 * 1000, max: 5 }),
    validateRequest(authSchemas.verifyEmailActivate),
    auditLog('email_verify_activate'),
    asyncHandler(verifyEmailAndActivate)
  );

// OAuth Integration
router
  .route('/google')
  .get(
    rateLimiter('oauth', { windowMs: 15 * 60 * 1000, max: 10 }),
    auditLog('oauth_google_initiate'),
    asyncHandler(loginWithGoogle)
  );

router
  .route('/google/callback')
  .get(
    rateLimiter('oauth', { windowMs: 15 * 60 * 1000, max: 10 }),
    auditLog('oauth_google_callback'),
    asyncHandler(googleCallback)
  );

export default router;
