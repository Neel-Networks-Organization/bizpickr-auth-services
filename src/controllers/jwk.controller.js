import { asyncHandler, ApiError, ApiResponse } from '../utils/index.js';
import { safeLogger } from '../config/logger.js';
import { jwkService } from '../services/index.js';
/**
 * Get JWK Set
 * GET /api/v1/jwk/.well-known/jwks.json
 */
export const getJWKs = asyncHandler(
  async (req, res) => {
    // Call JWK service to get JWK set
    const jwkSet = await jwkService.getJWKSet();
    safeLogger.info('JWKs retrieved successfully', {
      keyCount: jwkSet.keys.length,
      requestId: req.correlationId,
    });
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'public, max-age=3600'); // Cache for 1 hour
    return res.status(200).json(
      ApiResponse.success(jwkSet, 'JWKs retrieved successfully', {
        keyCount: jwkSet.keys.length,
        algorithm: 'RS256',
        keyUse: 'sig',
        cacheable: true,
        cacheDuration: '1 hour',
      })
    );
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 10000,
    retryAttempts: 1,
  }
);
/**
 * Get specific JWK by key ID
 * GET /api/v1/jwk/:kid
 */
export const getJWKByKid = asyncHandler(
  async (req, res) => {
    const { kid } = req.params;
    if (!kid) {
      throw new ApiError(400, 'Key ID is required', [
        'Please provide a valid key ID',
      ]);
    }
    // Call JWK service to get specific JWK
    const jwk = await jwkService.getJWKByKid(kid);
    safeLogger.info('JWK retrieved by kid', {
      kid,
      requestId: req.correlationId,
    });
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'public, max-age=3600'); // Cache for 1 hour
    return res.status(200).json(
      ApiResponse.success(jwk, 'JWK retrieved successfully', {
        kid,
        algorithm: 'RS256',
        keyUse: 'sig',
        cacheable: true,
        cacheDuration: '1 hour',
      })
    );
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 10000,
    retryAttempts: 1,
  }
);
/**
 * Rotate JWK keys
 * POST /api/v1/jwk/rotate
 */
export const rotateJWKs = asyncHandler(
  async (req, res) => {
    const { force = false } = req.body;
    const correlationId = req.correlationId;
    safeLogger.info('JWK rotation requested', {
      force,
      correlationId,
      userId: req.user?.id || 'system',
    });
    // Call JWK service to rotate keys
    const result = await jwkService.rotateKeys();
    safeLogger.info('JWK rotation completed', {
      newKid: result.newKid,
      totalKeys: result.totalKeys,
      correlationId,
      userId: req.user?.id || 'system',
    });
    return res.status(200).json(
      ApiResponse.success(
        {
          newKid: result.newKid,
          totalKeys: result.totalKeys,
          rotatedAt: result.rotatedAt,
        },
        'JWK keys rotated successfully',
        {
          force,
          rotationTime: new Date().toISOString(),
          nextRotation: new Date(
            Date.now() + 24 * 60 * 60 * 1000
          ).toISOString(), // 24 hours
        }
      )
    );
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 30000,
    retryAttempts: 1,
  }
);
/**
 * Get JWK statistics
 * GET /api/v1/jwk/stats
 */
export const getJWKStats = asyncHandler(
  async (req, res) => {
    // Call JWK service to get statistics
    const stats = await jwkService.getKeyStats();
    return res.status(200).json(
      ApiResponse.success(
        {
          stats,
        },
        'JWK statistics retrieved successfully'
      )
    );
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 10000,
    retryAttempts: 1,
  }
);
/**
 * Generate new key pair
 * POST /api/v1/jwk/generate
 */
export const generateKeyPair = asyncHandler(
  async (req, res) => {
    const { kid } = req.body;
    safeLogger.info('Key pair generation requested', {
      kid,
      userId: req.user?.id || 'system',
    });
    // Call JWK service to generate key pair
    const keyPair = await jwkService.generateKeyPair(kid);
    safeLogger.info('Key pair generated successfully', {
      kid: keyPair.kid,
      userId: req.user?.id || 'system',
    });
    return res.status(201).json(
      ApiResponse.created(
        {
          kid: keyPair.kid,
          algorithm: 'RS256',
          keySize: 2048,
          createdAt: keyPair.createdAt,
          expiresAt: keyPair.expiresAt,
        },
        'Key pair generated successfully',
        {
          algorithm: 'RS256',
          keySize: 2048,
        }
      )
    );
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 30000,
    retryAttempts: 1,
  }
);
/**
 * Validate and rotate keys if needed
 * POST /api/v1/jwk/validate
 */
export const validateAndRotateKeys = asyncHandler(
  async (req, res) => {
    const correlationId = req.correlationId;
    safeLogger.info('JWK validation requested', {
      correlationId,
      userId: req.user?.id || 'system',
    });
    // Call JWK service to validate and rotate keys
    const wasRotated = await jwkService.validateAndRotateKeys();
    safeLogger.info('JWK validation completed', {
      wasRotated,
      correlationId,
      userId: req.user?.id || 'system',
    });
    return res.status(200).json(
      ApiResponse.success(
        {
          wasRotated,
          validatedAt: new Date().toISOString(),
        },
        wasRotated
          ? 'Keys validated and rotated'
          : 'Keys validated successfully'
      )
    );
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 15000,
    retryAttempts: 1,
  }
);
/**
 * Clean up expired keys
 * POST /api/v1/jwk/cleanup
 */
export const cleanupExpiredKeys = asyncHandler(
  async (req, res) => {
    const correlationId = req.correlationId;
    safeLogger.info('JWK cleanup requested', {
      correlationId,
      userId: req.user?.id || 'system',
    });
    // Call JWK service to cleanup expired keys
    const removedCount = await jwkService.cleanupExpiredKeys();
    safeLogger.info('JWK cleanup completed', {
      removedCount,
      correlationId,
      userId: req.user?.id || 'system',
    });
    return res.status(200).json(
      ApiResponse.success(
        {
          removedCount,
          cleanedAt: new Date().toISOString(),
        },
        'Expired keys cleaned up successfully',
        {
          removedCount,
        }
      )
    );
  },
  {
    enableTiming: true,
    enableLogging: true,
    timeout: 15000,
    retryAttempts: 1,
  }
);
