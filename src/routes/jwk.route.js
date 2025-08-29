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
import { env } from '../config/env.js';

const router = Router();

// JWK Set Management
router
  .route('/.well-known/jwks.json')
  .get(
    ipRateLimit(env.services.rateLimit.routes.jwk.jwks),
    asyncHandler(getJWKs)
  );

router
  .route('/keys/:kid')
  .get(
    ipRateLimit(env.services.rateLimit.routes.jwk.jwks),
    validateRequest(jwkSchemas.getJWKByKid),
    asyncHandler(getJWKByKid)
  );

// JWK Operations
router
  .route('/refresh')
  .post(
    ipRateLimit(env.services.rateLimit.routes.jwk.rotate),
    asyncHandler(rotateJWKs)
  );

router
  .route('/validate')
  .post(
    ipRateLimit(env.services.rateLimit.routes.jwk.jwks),
    asyncHandler(validateAndRotateKeys)
  );

// JWK Statistics
router
  .route('/stats')
  .get(
    ipRateLimit(env.services.rateLimit.routes.jwk.jwks),
    asyncHandler(getJWKStats)
  );

// JWK Health Status
router
  .route('/health')
  .get(
    ipRateLimit(env.services.rateLimit.routes.jwk.jwks),
    asyncHandler(getHealthStatus)
  );

export default router;
