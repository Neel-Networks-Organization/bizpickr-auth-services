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
  rateLimiter,
} from '../middlewares/auth.middleware.js';
import { asyncHandler } from '../utils/index.js';

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

// Session Validation with rate limiting
router
  .route('/validate')
  .post(
    rateLimiter('session_validate', { windowMs: 60 * 1000, max: 30 }),
    auditLog('session_validation'),
    asyncHandler(validateSession),
  );

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
