import * as jose from 'jose';
import { v4 as uuidv4 } from 'uuid';
import { safeLogger } from '../config/logger.js';
import { ApiError } from '../utils/index.js';
import { jwkService } from './index.js';
import { env } from '../config/env.js';

class CryptoService {
  constructor() {
    const config = env.jwt;

    // Convert string secret to Uint8Array for HS256 algorithm
    this.refreshSecret = new TextEncoder().encode(
      config.refreshSecret ||
        'default-jwt-refresh-secretfdsfsdfsdfsfsfsfsfsfdsfsfdsfsfsdfdsfsds'
    );
    this.refreshTokenTTL = config.refreshTTL;
    this.accessTokenTTL = config.expiresIn;
    this.refreshAlgorithm = config.refreshAlgorithm;
    this.accessAlgorithm = config.accessAlgorithm;
    this.issuer = config.issuer;
    this.audience = config.audience;

    // Validate refresh secret format
    this.validateRefreshSecret();

    safeLogger.info('CryptoService initialized with config', { config });
  }

  async generateAccessToken(user, options = {}) {
    try {
      if (!user?.id || !user?.email) {
        throw new ApiError(400, 'Invalid user data for token generation');
      }

      const signingKey = await jwkService.getCurrentSigningKey();

      const payload = {
        userId: user.id,
        email: user.email,
        role: user.role,
        type: user.type,
        jti: uuidv4(),
      };

      if (options.customClaims) {
        Object.assign(payload, options.customClaims);
      }

      const token = await new jose.SignJWT(payload)
        .setProtectedHeader({
          alg: this.accessAlgorithm,
          kid: signingKey.kid,
          typ: 'JWT',
        })
        .setIssuedAt()
        .setExpirationTime(this.accessTokenTTL)
        .setIssuer(this.issuer)
        .setAudience(this.audience)
        .sign(signingKey.privateKey);

      safeLogger.info('Access token generated', {
        userId: user.id,
        kid: signingKey.kid,
        jti: payload.jti,
      });

      return token;
    } catch (error) {
      safeLogger.error('Access token generation failed', {
        error: error.message,
        userId: user?.id,
      });
      throw error;
    }
  }

  async generateRefreshToken(user) {
    try {
      if (!user?.id) {
        throw new ApiError(400, 'Invalid user data for refresh token');
      }

      const payload = {
        userId: user.id,
        type: 'refresh',
        jti: uuidv4(),
      };

      const token = await new jose.SignJWT(payload)
        .setProtectedHeader({
          alg: this.refreshAlgorithm,
          typ: 'JWT',
        })
        .setIssuedAt()
        .setExpirationTime(this.refreshTokenTTL)
        .setIssuer(this.issuer)
        .setAudience(this.audience)
        .sign(this.refreshSecret);

      return token;
    } catch (error) {
      safeLogger.error('Refresh token generation failed', {
        error: error.message,
        userId: user?.id,
        refreshAlgorithm: this.refreshAlgorithm,
        secretType: typeof this.refreshSecret,
        secretLength: this.refreshSecret?.length,
      });
      throw error;
    }
  }

  //generate tokens
  async generateTokens(user, options = {}) {
    const [accessToken, refreshToken] = await Promise.all([
      this.generateAccessToken(user, options),
      this.generateRefreshToken(user),
    ]);

    return { accessToken, refreshToken };
  }

  //revoke tokens
  async revokeToken(jti) {
    // TODO: Implement token blacklisting
    // This could use Redis or database to store revoked JTIs
    safeLogger.info('Token revoked', { jti });
  }

  //verify tokens
  async verifyRefreshToken(refreshToken) {
    if (!refreshToken) {
      throw new ApiError(400, 'Refresh token is required');
    }

    try {
      const { payload } = await jose.jwtVerify(
        refreshToken,
        this.refreshSecret,
        {
          algorithms: [this.refreshAlgorithm],
        }
      );

      return payload;
    } catch (error) {
      safeLogger.error('Refresh token verification failed', {
        error: error.message,
        refreshAlgorithm: this.refreshAlgorithm,
        secretType: typeof this.refreshSecret,
        secretLength: this.refreshSecret?.length,
      });
      throw error;
    }
  }

  async verifyAccessToken(accessToken) {
    if (!accessToken) {
      throw new ApiError(400, 'Access token is required');
    }

    try {
      const signingKey = await jwkService.getCurrentSigningKey();

      const { payload } = await jose.jwtVerify(
        accessToken,
        signingKey.publicKey,
        {
          algorithms: [this.accessAlgorithm],
        }
      );

      return payload;
    } catch (error) {
      safeLogger.error('Access token verification failed', {
        error: error.message,
        accessAlgorithm: this.accessAlgorithm,
      });
      throw error;
    }
  }

  validateRefreshSecret() {
    if (!this.refreshSecret || this.refreshSecret.length === 0) {
      throw new Error('Refresh secret cannot be empty');
    }

    // For HS256, ensure minimum key length (at least 32 bytes recommended)
    if (this.refreshSecret.length < 32) {
      safeLogger.warn('Refresh secret is shorter than recommended 32 bytes', {
        currentLength: this.refreshSecret.length,
        recommendedLength: 32,
      });
    }
  }

  // Check if the service is properly initialized
  isServiceHealthy() {
    return {
      refreshSecret: {
        configured: !!this.refreshSecret,
        type: typeof this.refreshSecret,
        length: this.refreshSecret?.length || 0,
      },
      algorithms: {
        access: this.accessAlgorithm,
        refresh: this.refreshAlgorithm,
      },
      ttl: {
        access: this.accessTokenTTL,
        refresh: this.refreshTokenTTL,
      },
    };
  }
}

export default new CryptoService();
