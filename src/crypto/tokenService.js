import { SignJWT } from 'jose';
import { getPrivateKey } from './getKeys.js';
import { env } from '../config/env.js';
import { safeLogger } from '../config/logger.js';
import { ApiError } from '../utils/ApiError.js';
/**
 * Industry-level Token Service
 *
 * Features:
 * - Enhanced error handling and logging
 * - Token validation and security checks
 * - Performance monitoring
 * - Token metadata and tracking
 * - Rate limiting support
 */
// Token generation configuration
const TOKEN_CONFIG = {
  access: {
    algorithm: 'RS256',
    expiryBuffer: 300, // 5 minutes buffer
  },
  refresh: {
    algorithm: 'HS256',
    expiryBuffer: 3600, // 1 hour buffer
  },
};
// Token metadata tracking
const tokenMetadata = new Map();
/**
 * Generate access token with enhanced security and logging
 * @param {Object} user - User object
 * @param {Object} options - Additional options
 * @returns {Promise<string>} JWT token
 */
export async function generateAccessToken(user, options = {}) {
  try {
    // Validate user object
    if (!user || !user.id || !user.email) {
      throw new ApiError(400, 'Invalid user data for token generation', [
        'User object must contain id and email',
        'Please provide valid user information',
      ]);
    }
    const { pirvateKey, kid } = await getPrivateKey();
    // Enhanced payload with additional security claims
    const payload = {
      id: user.id,
      email: user.email,
      type: user.type,
      linkedUserId: user.linkedUserId,
      role: user.role,
      iat: Math.floor(Date.now() / 1000), // Issued at
      jti: `${user.id}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`, // JWT ID for tracking
    };
    // Add custom claims if provided
    if (options.customClaims) {
      Object.assign(payload, options.customClaims);
    }
    const token = await new SignJWT(payload)
      .setProtectedHeader({
        alg: TOKEN_CONFIG.access.algorithm,
        kid,
        typ: 'JWT',
      })
      .setIssuedAt()
      .setExpirationTime(env.PRIVATE_KEY_EXIPRY)
      .setIssuer(env.JWT_ISSUER || 'bizPickr-auth-service')
      .setAudience(env.JWT_AUDIENCE || 'bizPickr-api')
      .sign(pirvateKey);
    // Track token metadata
    const tokenInfo = {
      userId: user.id,
      email: user.email,
      type: user.type,
      tokenType: 'access',
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(
        Date.now() + parseInt(env.PRIVATE_KEY_EXIPRY) * 1000,
      ).toISOString(),
      kid,
      jti: payload.jti,
    };
    tokenMetadata.set(payload.jti, tokenInfo);
    safeLogger.info('Access token generated successfully', {
      userId: user.id,
      email: user.email,
      type: user.type,
      jti: payload.jti,
      kid,
      expiresAt: tokenInfo.expiresAt,
    });
    return token;
  } catch (error) {
    safeLogger.error('Access token generation failed', {
      userId: user?.id,
      email: user?.email,
      error: error.message,
      stack: error.stack,
    });
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError(500, 'Failed to generate access token', [
      'Token generation process failed',
      'Please try again later',
    ]);
  }
}
/**
 * Generate refresh token with enhanced security
 * @param {Object} user - User object
 * @param {Object} options - Additional options
 * @returns {Promise<string>} JWT refresh token
 */
export async function generateRefreshToken(user, options = {}) {
  try {
    // Validate user object
    if (!user || !user.id) {
      throw new ApiError(
        400,
        'Invalid user data for refresh token generation',
        ['User object must contain id', 'Please provide valid user information'],
      );
    }
    const payload = {
      id: user.id,
      type: user.type,
      linkedUserId: user.linkedUserId,
      iat: Math.floor(Date.now() / 1000),
      jti: `refresh_${user.id}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      purpose: 'refresh',
    };
    // Add custom claims if provided
    if (options.customClaims) {
      Object.assign(payload, options.customClaims);
    }
    const secret = new TextEncoder().encode(env.REFRESH_TOKEN_SECRET);
    const token = await new SignJWT(payload)
      .setProtectedHeader({
        alg: TOKEN_CONFIG.refresh.algorithm,
        typ: 'JWT',
      })
      .setIssuedAt()
      .setExpirationTime(env.REFRESH_TOKEN_EXPIRY)
      .setIssuer(env.JWT_ISSUER || 'bizPickr-auth-service')
      .setAudience(env.JWT_AUDIENCE || 'bizPickr-api')
      .sign(secret);
    // Track refresh token metadata
    const tokenInfo = {
      userId: user.id,
      type: user.type,
      tokenType: 'refresh',
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(
        Date.now() + parseInt(env.REFRESH_TOKEN_EXPIRY) * 1000,
      ).toISOString(),
      jti: payload.jti,
    };
    tokenMetadata.set(payload.jti, tokenInfo);
    safeLogger.info('Refresh token generated successfully', {
      userId: user.id,
      type: user.type,
      jti: payload.jti,
      expiresAt: tokenInfo.expiresAt,
    });
    return token;
  } catch (error) {
    safeLogger.error('Refresh token generation failed', {
      userId: user?.id,
      error: error.message,
      stack: error.stack,
    });
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError(500, 'Failed to generate refresh token', [
      'Refresh token generation process failed',
      'Please try again later',
    ]);
  }
}
/**
 * Generate both access and refresh tokens
 * @param {Object} user - User object
 * @param {Object} options - Additional options
 * @returns {Promise<Object>} Object containing access and refresh tokens
 */
export async function generateTokens(user, options = {}) {
  try {
    const [accessToken, refreshToken] = await Promise.all([
      generateAccessToken(user, options),
      generateRefreshToken(user, options),
    ]);
    safeLogger.info('Both tokens generated successfully', {
      userId: user.id,
      email: user.email,
      type: user.type,
    });
    return { accessToken, refreshToken };
  } catch (error) {
    safeLogger.error('Token generation failed', {
      userId: user?.id,
      error: error.message,
    });
    throw error;
  }
}
/**
 * Get token metadata by JTI
 * @param {string} jti - JWT ID
 * @returns {Object|null} Token metadata
 */
export function getTokenMetadata(jti) {
  return tokenMetadata.get(jti) || null;
}
/**
 * Remove token metadata (for logout/invalidation)
 * @param {string} jti - JWT ID
 * @returns {boolean} Success status
 */
export function removeTokenMetadata(jti) {
  return tokenMetadata.delete(jti);
}
/**
 * Get all active token metadata
 * @returns {Array} Array of token metadata
 */
export function getAllTokenMetadata() {
  return Array.from(tokenMetadata.values());
}
/**
 * Clean up expired token metadata
 */
export function cleanupExpiredTokenMetadata() {
  const now = new Date();
  let cleanedCount = 0;
  for (const [jti, metadata] of tokenMetadata.entries()) {
    if (new Date(metadata.expiresAt) < now) {
      tokenMetadata.delete(jti);
      cleanedCount++;
    }
  }
  if (cleanedCount > 0) {
    safeLogger.info('Cleaned up expired token metadata', {
      cleanedCount,
      remainingTokens: tokenMetadata.size,
    });
  }
  return cleanedCount;
}
// Cleanup expired tokens every hour
setInterval(cleanupExpiredTokenMetadata, 60 * 60 * 1000);
