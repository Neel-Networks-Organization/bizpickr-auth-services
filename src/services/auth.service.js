import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import {
  AuthUser,
  AuditLog,
  AuthUser as User,
  EmailVerification,
  PasswordReset,
} from '../models/index.model.js';
import { safeLogger } from '../config/logger.js';
import { ApiError } from '../utils/index.js';
import {
  emitUserRegistered,
  emitUserLoggedIn,
  emitUserLoggedOut,
  emitEmailVerified,
  emitEmailVerification,
  emitPasswordResetInitiated,
  emitAccountActivated,
} from '../events/emitters/index.js';
import { logAuditEvent } from './audit.service.js';
import { env } from '../config/env.js';

import sessionService from './session.service.js';
import passwordService from './password.service.js';
import oauthService from './oauth.service.js';
import twoFactorService from './twoFactor.service.js';
import authCache from '../cache/auth.cache.js';

class AuthService {
  constructor() {
    this.saltRounds = 12;
    this.sessionTTL = 24 * 60 * 60; // 24 hours
    this.refreshTokenTTL = 7 * 24 * 60 * 60; // 7 days
  }

  /**
   * Register a new user
   * @param {Object} userData - User registration data
   * @returns {Promise<Object>} Created user object
   */
  async registerUser(userData) {
    try {
      const { email, password, type, role } = userData;
      const existingUser = await AuthUser.findOne({ where: { email } });
      if (existingUser) {
        throw new Error('User with this email already exists');
      }

      // Validate password
      passwordService.validatePassword(password);

      // Set defaults for type and role if not provided
      const userType = type || 'customer';
      const userRole = role || 'customer';

      // Create user
      const user = await AuthUser.create({
        email,
        password, // Raw password - will be hashed by model hook
        type: userType,
        role: userRole,
        status: 'pending',
        emailVerified: false,
      });

      // Create audit log using the proper audit middleware
      await logAuditEvent('USER_REGISTERED', {
        userId: user.id,
        email: user.email,
        type: userType,
        role: userRole,
        createdAt: user.createdAt,
      });

      // Publish welcome email event

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
      const { email, password, deviceInfo, ipAddress, userAgent } = loginData;

      const user = await AuthUser.findOne({ where: { email } });
      if (!user) {
        throw new ApiError('Invalid email or password');
      }

      if (user.isLocked()) {
        throw new ApiError('Account is locked');
      }

      // Verify password
      const isPasswordCorrect = await user.isPasswordCorrect(password);

      if (!isPasswordCorrect) {
        throw new ApiError('Invalid or password');
      }

      const accessToken = this.generateAccessToken(user); // Use the same sessionId
      const refreshToken = this.generateRefreshToken(user);

      // const session = await sessionService.createSession({
      //   userId: user.id,
      //   deviceInfo,
      //   ipAddress,
      //   userAgent,
      // });

      // Store user session in cache
      await authCache.storeUserSession(user.id, {
        userId: user.id,
        email: user.email,
        role: user.role,
        type: user.type,
        status: user.status,
        emailVerified: user.emailVerified,
        createdAt: new Date().toISOString(),
      });

      // Check if this is user's first login (no previous sessions)
      // const previousSessions = await sessionService.getUserSessions(user.id);
      // const isFirstLogin = previousSessions.length === 0;

      // // If first login, create user profile and related data
      // if (isFirstLogin) {
      //   await emitUserRegistered(user, {
      //     emailType: 'welcome',
      //     template: 'welcome-email',
      //   });
      // }

      // Publish login event
      // await emitUserLoggedIn({
      //   userId: user.id,
      //   email: user.email,
      //   ipAddress: loginData.ipAddress,
      //   userAgent: loginData.userAgent,
      // });

      // Create audit log
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

  /**
   * Refresh access token
   * @param {string} refreshToken - Refresh token
   * @returns {Promise<Object>} New access token
   */
  async refreshToken(refreshToken) {
    try {
      // Get refresh token data from SessionService
      const refreshData =
        await sessionService.getRefreshTokenData(refreshToken);
      if (!refreshData) {
        throw new ApiError('Invalid refresh token');
      }

      const { userId } = refreshData;

      if (!sessionData) {
        throw new ApiError('Session expired');
      }

      // Get user
      const user = await AuthUser.findByPk(userId);
      if (!user || !['active', 'pending'].includes(user.status)) {
        throw new ApiError('User not found or inactive');
      }

      // Generate new access token
      const newAccessToken = this.generateAccessToken(user); // Pass existing sessionId

      safeLogger.info('Token refreshed successfully', {
        userId: user.id,
      });

      return {
        accessToken: newAccessToken,
        expiresIn: env.jwtExpiry,
      };
    } catch (error) {
      safeLogger.error('Token refresh failed', {
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Logout user
   * @param {string} sessionId - Session ID
   * @param {string} userId - User ID
   * @returns {Promise<boolean>} Logout success
   */
  async logoutUser(sessionId, userId) {
    try {
      // Revoke session using SessionService
      await sessionService.revokeSession(sessionId, userId);

      // Remove user session from cache
      await authCache.removeUserSession(userId);

      // Publish logout event
      await emitUserLoggedOut({
        userId: userId,
        email: user?.email,
        sessionId: sessionId,
      });

      // Create audit log
      await AuditLog.create({
        userId,
        action: 'USER_LOGOUT',
        resourceType: 'SESSION',
        resourceId: sessionId,
        details: { sessionId },
      });

      safeLogger.info('User logged out successfully', {
        userId,
        sessionId,
      });

      return true;
    } catch (error) {
      safeLogger.error('User logout failed', {
        error: error.message,
        userId,
        sessionId,
      });
      throw error;
    }
  }

  /**
   * Verify JWT token
   * @param {string} token - JWT token
   * @returns {Promise<Object>} Decoded token payload
   */
  async verifyToken(token) {
    try {
      const decoded = jwt.verify(token, env.jwtSecret);

      // Check if user still exists and has valid status
      const user = await AuthUser.findByPk(decoded.userId);
      if (!user || !['active', 'pending'].includes(user.status)) {
        throw new ApiError('User not found or inactive');
      }

      return {
        userId: decoded.userId,
        email: decoded.email,
        role: decoded.role,
        iat: decoded.iat,
        exp: decoded.exp,
      };
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new ApiError('Token expired');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new ApiError('Invalid token');
      }
      throw error;
    }
  }

  /**
   * Get user sessions (delegate to SessionService)
   * @param {number} userId - User ID
   * @returns {Promise<Array>} User sessions
   */
  async getUserSessions(userId) {
    return await sessionService.getUserSessions(userId);
  }

  /**
   * Revoke user session (delegate to SessionService)
   * @param {string} sessionId - Session ID
   * @param {number} userId - User ID
   * @returns {Promise<boolean>} Revoke success
   */
  async revokeSession(sessionId, userId) {
    return await sessionService.revokeSession(sessionId, userId);
  }

  /**
   * Revoke all user sessions (delegate to SessionService)
   * @param {number} userId - User ID
   * @returns {Promise<boolean>} Revoke success
   */
  async revokeAllSessions(userId) {
    return await sessionService.revokeAllSessions(userId);
  }

  /**
   * Change user password (delegate to PasswordService)
   * @param {number} userId - User ID
   * @param {string} currentPassword - Current password
   * @param {string} newPassword - New password
   * @returns {Promise<boolean>} Password change success
   */
  async changePassword(userId, currentPassword, newPassword) {
    return await passwordService.changePassword(
      userId,
      currentPassword,
      newPassword
    );
  }

  /**
   * Generate access token
   * @param {Object} user - User object
   * @returns {string} JWT access token
   */
  generateAccessToken(user) {
    return jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
      },
      env.jwtSecret,
      {
        expiresIn: env.jwtExpiry,
        issuer: 'auth-service',
        audience: 'api-gateway',
      }
    );
  }

  /**
   * Generate refresh token
   * @param {Object} user - User object
   * @returns {string} JWT refresh token
   */
  generateRefreshToken(user) {
    return jwt.sign(
      {
        userId: user.id,
        type: 'refresh',
      },
      env.refreshTokenSecret,
      {
        expiresIn: this.refreshTokenTTL,
        issuer: 'auth-service',
        audience: 'auth-service',
      }
    );
  }

  /**
   * Google OAuth login
   * @param {string} code - Authorization code from Google
   * @param {Object} deviceInfo - Device information
   * @returns {Promise<Object>} User and tokens
   */
  async googleOAuthLogin(code, deviceInfo) {
    try {
      return await oauthService.completeGoogleLogin(code, deviceInfo);
    } catch (error) {
      safeLogger.error('Google OAuth login failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Verify email with token
   * @param {string} token - Email verification token
   * @returns {Promise<Object>} Verification result
   */
  async verifyEmail(token) {
    try {
      return await EmailVerification.verifyEmailToken(token);
    } catch (error) {
      safeLogger.error('Email verification failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Resend verification email
   * @param {string} userId - User ID
   * @param {Object} deviceInfo - Device information
   * @returns {Promise<Object>} Resend result
   */
  async resendVerificationEmail(userId, deviceInfo) {
    try {
      return await EmailVerification.resendVerificationEmail(
        userId,
        deviceInfo
      );
    } catch (error) {
      safeLogger.error('Resend verification failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Enable two-factor authentication
   * @param {string} userId - User ID
   * @returns {Promise<Object>} 2FA setup data
   */
  async enableTwoFactor(userId) {
    try {
      return await twoFactorService.enableTwoFactor(userId);
    } catch (error) {
      safeLogger.error('Enable 2FA failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Disable two-factor authentication
   * @param {string} userId - User ID
   * @param {string} code - 2FA code
   * @returns {Promise<Object>} Disable result
   */
  async disableTwoFactor(userId, code) {
    try {
      return await twoFactorService.disableTwoFactor(userId, code);
    } catch (error) {
      safeLogger.error('Disable 2FA failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Verify two-factor authentication
   * @param {string} code - 2FA code
   * @param {string} sessionId - Session ID
   * @returns {Promise<Object>} Verification result
   */
  async verifyTwoFactor(code, sessionId) {
    try {
      return await twoFactorService.completeTwoFactorLogin(code, sessionId);
    } catch (error) {
      safeLogger.error('2FA verification failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Send password reset email
   * @param {string} email - User email
   * @returns {Promise<Object>} Reset result
   */
  async sendPasswordResetEmail(email) {
    try {
      const user = await AuthUser.findOne({ where: { email } });
      if (!user) {
        throw new ApiError('User not found');
      }

      // Generate reset token
      const resetToken = await passwordService.generateResetToken(user.id);

      // Publish password reset email event
      await emitPasswordResetInitiated({
        userId: user.id,
        email: user.email,
        resetToken: resetToken,
      });

      safeLogger.info('Password reset email sent', {
        userId: user.id,
        email: user.email,
      });

      return {
        success: true,
        message: 'Password reset email sent successfully',
        email: user.email,
      };
    } catch (error) {
      safeLogger.error('Failed to send password reset email', {
        error: error.message,
        email,
      });
      throw error;
    }
  }

  /**
   * Verify email and activate account
   * @param {string} token - Verification token
   * @returns {Promise<Object>} Verification result
   */
  async verifyEmailAndActivate(token) {
    try {
      const user = await AuthUser.findByPk(token);
      if (!user) {
        throw new ApiError('Invalid verification token');
      }

      if (user.emailVerified) {
        throw new ApiError('Email already verified');
      }

      // Update user to verified
      await user.update({
        emailVerified: true,
        status: 'active',
      });

      // Publish account activation event
      await emitAccountActivated(user, {
        emailType: 'activation',
        template: 'account-activated',
      });

      // Publish user verified event
      await emitEmailVerified({
        userId: user.id,
        email: user.email,
        method: 'email_verification',
      });

      safeLogger.info('Email verified and account activated', {
        userId: user.id,
        email: user.email,
      });

      return {
        success: true,
        message: 'Email verified successfully',
        user: {
          id: user.id,
          email: user.email,
          type: user.type,
          status: user.status,
        },
      };
    } catch (error) {
      safeLogger.error('Email verification failed', {
        error: error.message,
        token,
      });
      throw error;
    }
  }
}

export default new AuthService();
