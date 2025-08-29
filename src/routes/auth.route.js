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
  // Admin endpoints
  unlockAccount,
  getAccountStatus,
  suspendAccount,
  activateAccount,
  getLockedAccounts,
  clearUserCache,
  activatePendingAccount,
} from '../controllers/auth.controller.js';
import { verifyJWT, requireRole } from '../middlewares/auth.middleware.js';
import ipRateLimit from '../middlewares/rateLimiter.middleware.js';
import { validateRequest } from '../middlewares/validation.middleware.js';
import { authSchemas } from '../validators/index.js';
import { asyncHandler } from '../utils/index.js';
import { rateLimitConfig } from '../config/rateLimit.config.js';

const router = Router();

// User Registration & Authentication
router
  .route('/signup')
  .post(
    ipRateLimit(rateLimitConfig.routes.auth.signup),
    validateRequest(authSchemas.signup),
    asyncHandler(signupUser)
  );

router
  .route('/login')
  .post(
    ipRateLimit(rateLimitConfig.routes.auth.login),
    validateRequest(authSchemas.login),
    asyncHandler(loginUser)
  );

router
  .route('/logout')
  .post(
    ipRateLimit(rateLimitConfig.routes.auth.logout),
    verifyJWT,
    asyncHandler(logoutUser)
  );

router
  .route('/refresh-token')
  .post(
    ipRateLimit(rateLimitConfig.routes.auth.refreshToken),
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
    ipRateLimit(rateLimitConfig.routes.auth.twoFactor.enable),
    validateRequest(authSchemas.enableTwoFactor),
    asyncHandler(enableTwoFactor)
  );

router
  .route('/2fa/disable')
  .post(
    verifyJWT,
    ipRateLimit(rateLimitConfig.routes.auth.twoFactor.disable),
    asyncHandler(disableTwoFactor)
  );

router
  .route('/2fa/verify')
  .post(
    ipRateLimit(rateLimitConfig.routes.auth.twoFactor.verify),
    validateRequest(authSchemas.verifyTwoFactor),
    asyncHandler(verifyTwoFactor)
  );

// OAuth Integration
router
  .route('/google')
  .get(
    ipRateLimit(rateLimitConfig.routes.auth.oauth.google),
    asyncHandler(loginWithGoogle)
  );

router
  .route('/google/callback')
  .get(
    ipRateLimit(rateLimitConfig.routes.auth.oauth.googleCallback),
    asyncHandler(googleCallback)
  );

// ========================================
// ADMIN ROUTES - Account Management
// ========================================

// Account Unlock (Admin only)
router
  .route('/admin/unlock')
  .post(
    verifyJWT,
    requireRole('admin', 'super_admin'),
    ipRateLimit(rateLimitConfig.routes.auth.admin.unlock),
    validateRequest(authSchemas.unlockAccount),
    asyncHandler(unlockAccount)
  );

// Get Account Status (Admin only)
router
  .route('/admin/status/:email')
  .get(
    verifyJWT,
    requireRole('admin', 'super_admin'),
    ipRateLimit(rateLimitConfig.routes.auth.admin.status),
    asyncHandler(getAccountStatus)
  );

// Suspend Account (Admin only)
router
  .route('/admin/suspend')
  .post(
    verifyJWT,
    requireRole('admin', 'super_admin'),
    ipRateLimit(rateLimitConfig.routes.auth.admin.suspend),
    validateRequest(authSchemas.suspendAccount),
    asyncHandler(suspendAccount)
  );

// Activate Account (Admin only)
router
  .route('/admin/activate')
  .post(
    verifyJWT,
    requireRole('admin', 'super_admin'),
    ipRateLimit(rateLimitConfig.routes.auth.admin.activate),
    validateRequest(authSchemas.activateAccount),
    asyncHandler(activateAccount)
  );

// Get Locked Accounts (Admin only)
router
  .route('/admin/locked-accounts')
  .get(
    verifyJWT,
    requireRole('admin', 'super_admin'),
    ipRateLimit(rateLimitConfig.routes.auth.admin.lockedAccounts),
    asyncHandler(getLockedAccounts)
  );

// Clear User Cache (Admin only)
router
  .route('/admin/clear-cache')
  .post(
    verifyJWT,
    requireRole('admin', 'super_admin'),
    ipRateLimit(rateLimitConfig.routes.auth.admin.clearCache),
    validateRequest(authSchemas.clearUserCache),
    asyncHandler(clearUserCache)
  );

// ========================================
// DEVELOPMENT ROUTES - Testing Only
// ========================================

// Activate Pending Account (Development only)
router
  .route('/dev/activate-account')
  .post(
    ipRateLimit(rateLimitConfig.routes.auth.dev.activateAccount),
    asyncHandler(activatePendingAccount)
  );

export default router;
