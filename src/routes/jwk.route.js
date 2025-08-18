import { Router } from 'express';
import {
  getJWKs,
  getJWKByKid,
  rotateJWKs,
  getJWKStats,
  validateAndRotateKeys,
} from '../controllers/jwk.controller.js';
import {
  rateLimiter,
  cacheMiddleware,
  securityHeaders,
  validateRequest,
  auditLog,
} from '../middlewares/auth.middleware.js';
import { validateJWKRequest } from '../validators/jwkValidators.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const router = Router();

// JWK Set Management
router.route('/.well-known/jwks.json').get(
  rateLimiter('jwks', { windowMs: 60 * 1000, max: 100 }),
  cacheMiddleware('jwks', 300),
  securityHeaders({
    'Cache-Control': 'public, max-age=300, s-maxage=300',
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
  }),
  auditLog('jwks_request'),
  asyncHandler(getJWKs),
);

router.route('/keys/:kid').get(
  rateLimiter('jwk-specific', { windowMs: 60 * 1000, max: 50 }),
  cacheMiddleware('jwk-specific', 600),
  securityHeaders({
    'Cache-Control': 'public, max-age=600, s-maxage=600',
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
  }),
  auditLog('jwk_specific_request'),
  asyncHandler(getJWKByKid),
);

// JWK Operations
router
  .route('/refresh')
  .post(
    rateLimiter('jwk-refresh', { windowMs: 60 * 60 * 1000, max: 10 }),
    validateRequest(validateJWKRequest),
    auditLog('jwks_refresh'),
    asyncHandler(rotateJWKs),
  );

router
  .route('/validate')
  .post(
    rateLimiter('jwk-validate', { windowMs: 60 * 1000, max: 30 }),
    validateRequest(validateJWKRequest),
    auditLog('jwk_validation'),
    asyncHandler(validateAndRotateKeys),
  );

// JWK Statistics
router
  .route('/stats')
  .get(
    rateLimiter('jwk-stats', { windowMs: 60 * 1000, max: 20 }),
    auditLog('jwk_stats'),
    asyncHandler(getJWKStats),
  );

export default router;
