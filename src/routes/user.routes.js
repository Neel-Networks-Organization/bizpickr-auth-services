/**
 * User Routes - User Management Endpoints
 *
 * Handles all user-related routes:
 * - Profile management
 * - Account operations
 * - Activity tracking
 * - User statistics
 */
import { Router } from 'express';
import {
  getUserProfile,
  updateUserProfile,
  getUserActivity,
  getUserStats,
  deleteUserAccount,
  createUserActivity,
} from '../controllers/user.controller.js';
import {
  verifyJWT,
  validateRequest,
  auditLog,
} from '../middlewares/auth.middleware.js';
import { validateProfileUpdate } from '../validators/authValidators.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const router = Router();

// User Profile Management
router
  .route('/profile')
  .get(verifyJWT, asyncHandler(getUserProfile))
  .put(
    verifyJWT,
    validateRequest(validateProfileUpdate),
    auditLog('profile_update'),
    asyncHandler(updateUserProfile)
  );

// User Activity & Statistics
router
  .route('/activity')
  .get(verifyJWT, asyncHandler(getUserActivity))
  .post(
    verifyJWT,
    auditLog('activity_created'),
    asyncHandler(createUserActivity)
  );

router.route('/stats').get(verifyJWT, asyncHandler(getUserStats));

// Account Management
router
  .route('/account')
  .delete(
    verifyJWT,
    auditLog('account_deletion'),
    asyncHandler(deleteUserAccount)
  );

export default router;
