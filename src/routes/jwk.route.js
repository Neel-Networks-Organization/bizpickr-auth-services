import { Router } from 'express';
import {
  getJWKs,
  getJWKByKid,
  rotateJWKs,
  getJWKStats,
  validateAndRotateKeys,
  getHealthStatus,
} from '../controllers/jwk.controller.js';
import ipRateLimit from '../middlewares/rateLimiter.middleware.js';
import { jwkSchemas } from '../validators/index.js';
import validateRequest from '../middlewares/validation.middleware.js';
import { asyncHandler } from '../utils/index.js';

const router = Router();

// JWK Set Management
router
  .route('/.well-known/jwks.json')
  .get(
    ipRateLimit({ windowMs: 60 * 1000, maxRequests: 100 }),
    asyncHandler(getJWKs)
  );

router
  .route('/keys/:kid')
  .get(
    ipRateLimit({ windowMs: 60 * 1000, maxRequests: 50 }),
    validateRequest(jwkSchemas.getJWKByKid),
    asyncHandler(getJWKByKid)
  );

// JWK Operations
router
  .route('/refresh')
  .post(
    ipRateLimit({ windowMs: 60 * 60 * 1000, maxRequests: 10 }),
    asyncHandler(rotateJWKs)
  );

router
  .route('/validate')
  .post(
    ipRateLimit({ windowMs: 60 * 1000, maxRequests: 30 }),
    asyncHandler(validateAndRotateKeys)
  );

// JWK Statistics
router
  .route('/stats')
  .get(
    ipRateLimit({ windowMs: 60 * 1000, maxRequests: 20 }),
    asyncHandler(getJWKStats)
  );

// JWK Health Status
router
  .route('/health')
  .get(
    ipRateLimit({ windowMs: 60 * 1000, maxRequests: 20 }),
    asyncHandler(getHealthStatus)
  );

export default router;
