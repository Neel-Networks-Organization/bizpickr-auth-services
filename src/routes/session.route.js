import { Router } from 'express';
import {
  getUserSessions,
  revokeSession,
  revokeAllSessions,
  getSessionStats,
  validateSession,
  cleanExpiredSessions,
} from '../controllers/session.controller.js';
import { verifyJWT, requireRole } from '../middlewares/auth.middleware.js';
import ipRateLimit from '../middlewares/rateLimiter.middleware.js';
import { asyncHandler } from '../utils/index.js';

const router = Router();

// Session Management
router
  .route('/')
  .get(verifyJWT, asyncHandler(getUserSessions))
  .delete(verifyJWT, asyncHandler(revokeAllSessions));

router.route('/:sessionId').delete(verifyJWT, asyncHandler(revokeSession));

// Session Analytics
router.route('/stats').get(verifyJWT, asyncHandler(getSessionStats));

// Session Validation with rate limiting
router
  .route('/validate')
  .post(
    ipRateLimit({ windowMs: 60 * 1000, maxRequests: 30 }),
    asyncHandler(validateSession)
  );

// Session Cleanup (Admin only)
router
  .route('/cleanup')
  .post(verifyJWT, requireRole('admin'), asyncHandler(cleanExpiredSessions));

export default router;
