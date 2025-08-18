/**
 * Session Routes - Session Management Endpoints
 *
 * Handles all session-related routes:
 * - Session management
 * - Session validation
 * - Session analytics
 * - Session cleanup
 */
import { Router } from 'express';
import {
  getUserSessions,
  revokeSession,
  revokeAllSessions,
  getSessionStats,
  validateSession,
  cleanExpiredSessions,
} from '../controllers/session.controller.js';
import {
  verifyJWT,
  requireRole,
  auditLog,
} from '../middlewares/auth.middleware.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const router = Router();

// Session Management
router
  .route('/')
  .get(verifyJWT, asyncHandler(getUserSessions))
  .delete(
    verifyJWT,
    auditLog('revoke_all_sessions'),
    asyncHandler(revokeAllSessions),
  );

router
  .route('/:sessionId')
  .delete(verifyJWT, auditLog('revoke_session'), asyncHandler(revokeSession));

// Session Analytics
router.route('/stats').get(verifyJWT, asyncHandler(getSessionStats));

// Session Validation
router.route('/validate').post(asyncHandler(validateSession));

// Session Cleanup (Admin only)
router
  .route('/cleanup')
  .post(
    verifyJWT,
    requireRole('admin'),
    auditLog('session_cleanup'),
    asyncHandler(cleanExpiredSessions),
  );

export default router;
