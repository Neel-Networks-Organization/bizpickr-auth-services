import { User } from '../models/index.model.js';
import { safeLogger } from '../config/logger.js';
import { ApiError } from '../utils/index.js';
import { logAuditEvent } from './audit.service.js';
import { passwordService, cryptoService, oauthService } from './index.js';
import authCache from '../cache/auth.cache.js';

class AuthService {
  constructor() {
    // TODO: Add constructor logic here
  }

  async registerUser(userData) {
    try {
      const { email, password, type, role } = userData;
      const existingUser = await User.findOne({ where: { email } });
      if (existingUser) {
        throw new Error('User with this email already exists');
      }

      // Create user
      const user = await User.create({
        email,
        password,
        type,
        role,
        status: 'pending',
        emailVerified: false,
      });

      await logAuditEvent('USER_REGISTERED', {
        userId: user.id,
        email: user.email,
        type,
        role,
        createdAt: user.createdAt,
      });

      safeLogger.info('User registered successfully', {
        userId: user.id,
        email: user.email,
      });

      return {
        id: user.id,
        email: user.email,
        type: user.type,
        role: user.role,
        status: user.status,
        emailVerified: user.emailVerified,
        createdAt: user.createdAt,
      };
    } catch (error) {
      safeLogger.error('User registration failed', {
        error: error.message,
        email: userData.email,
      });
      throw error;
    }
  }

  async loginUser(loginData) {
    try {
      const { email, password } = loginData;

      const user = await User.findOne({ where: { email } });
      if (!user) {
        throw new ApiError('Invalid email or password');
      }

      if (user.isLocked()) {
        throw new ApiError('Account is locked');
      }

      const isPasswordCorrect = await user.isPasswordCorrect(password);

      if (!isPasswordCorrect) {
        throw new ApiError('Invalid or password');
      }

      const { accessToken, refreshToken } =
        await cryptoService.generateTokens(user);

      await authCache.storeUserSession(user.id, {
        userId: user.id,
        email: user.email,
        role: user.role,
        type: user.type,
        status: user.status,
        emailVerified: user.emailVerified,
        createdAt: new Date().toISOString(),
      });

      await logAuditEvent('USER_LOGGED_IN', {
        userId: user.id,
        email: user.email,
        role: user.role,
        type: user.type,
        status: user.status,
        emailVerified: user.emailVerified,
      });

      safeLogger.info('User logged in successfully', {
        userId: user.id,
        email: user.email,
      });

      return {
        user: {
          id: user.id,
          email: user.email,
          type: user.type,
          role: user.role,
          status: user.status,
          emailVerified: user.emailVerified,
        },
        tokens: {
          accessToken,
          refreshToken,
        },
      };
    } catch (error) {
      safeLogger.error('User login failed', {
        error: error.message,
        email: loginData.email,
      });
      throw error;
    }
  }

  async refreshToken(refreshToken) {
    try {
      const userPayload = await cryptoService.verifyRefreshToken(refreshToken);

      // find from cache then db
      const user = await authCache.getUserSession(userPayload.userId);
      if (!user) {
        const user = await User.findByPk(userPayload.userId);
        await authCache.storeUserSession(user.id, user);
      }

      if (!user || user.status !== 'active') {
        throw new ApiError('User inactive');
      }

      const tokens = await cryptoService.generateTokens(user);
      return tokens;
    } catch (error) {
      safeLogger.error('Refresh token verification failed', {
        error: error.message,
        refreshToken,
      });
      throw error;
    }
  }

  async logoutUser(userPayload) {
    const { jti, userId } = userPayload;
    try {
      await cryptoService.revokeToken(jti);
      await authCache.removeUserSession(userId);

      await logAuditEvent('USER_LOGGED_OUT', {
        userId,
      });

      safeLogger.info('User logged out successfully', {
        userId,
      });

      return true;
    } catch (error) {
      safeLogger.error('User logout failed', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  async googleOAuthLogin(code, deviceInfo) {
    try {
      return await oauthService.completeGoogleLogin(code, deviceInfo);
    } catch (error) {
      safeLogger.error('Google OAuth login failed', { error: error.message });
      throw error;
    }
  }
}

export default new AuthService();
