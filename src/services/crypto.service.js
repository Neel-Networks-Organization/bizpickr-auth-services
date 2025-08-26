import * as jose from 'jose';
import { v4 as uuidv4 } from 'uuid';
import { safeLogger } from '../config/logger.js';
import { env } from '../config/env.js';
import { ApiError } from '../utils/index.js';
import { jwkService } from './index.js';

class CryptoService {
  constructor() {
    this.refreshSecret = env.jwt.refreshSecret;
    this.refreshTokenTTL = env.jwt.refreshTTL;
    this.accessTokenTTL = env.jwt.accessTTL;
    this.refreshAlgorithm = env.jwt.refreshAlgorithm;
    this.accessAlgorithm = env.jwt.accessAlgorithm;
    this.issuer = env.jwt.issuer;
    this.audience = env.jwt.audience;
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

      const token = await new SignJWT(payload)
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

      const token = await new SignJWT(payload)
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
      });
      throw error;
    }
  }

  async verifyAccessToken(accessToken) {
    if (!accessToken) {
      throw new ApiError(400, 'Access token is required');
    }

    try {
      const { payload } = await jose.jwtVerify(accessToken, this.accessSecret, {
        algorithms: [this.accessAlgorithm],
      });

      return payload;
    } catch (error) {
      safeLogger.error('Access token verification failed', {
        error: error.message,
      });
      throw error;
    }
  }
}

export default new CryptoService();
