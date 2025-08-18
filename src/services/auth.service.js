/**
 * Auth Service - Core Authentication Layer
 *
 * Handles core authentication and authorization business logic:
 * - User registration and login
 * - JWT token management
 * - Core authentication flows
 * - Service orchestration
 */
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { safeLogger } from '../config/logger.js';
import { env } from '../config/env.js';
import { publishEvent } from '../events/index.js';
import { AuthUser as User, AuditLog } from '../models/index.model.js';
import { authCache } from '../cache/auth.cache.js';
import userService from './user.service.js';
import sessionService from './session.service.js';
import passwordService from './password.service.js';
import { logAuditEvent } from '../middlewares/audit.middleware.js';
import oauthService from './oauth.service.js';
import emailVerificationService from './emailVerification.service.js';
import twoFactorService from './twoFactor.service.js';
import permissionService from './permission.service.js';

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
      // Validate input - AUTHENTICATION ONLY
      if (!email || !password) {
        throw new Error('Email and password are required');
      }
      // Check if user already exists
      const existingUser = await User.findOne({ where: { email } });
      if (existingUser) {
        throw new Error('User with this email already exists');
      }

      // Validate password
      passwordService.validatePassword(password);

      // Password will be hashed by the model hook
      // const hashedPassword = await passwordService.hashPassword(password);

      // Set defaults for type and role if not provided
      const userType = type || 'customer';
      const userRole = role || 'customer';

      // Create user (only model-valid fields)
      const user = await User.create({
        email,
        password, // Raw password - will be hashed by model hook
        type: userType,
        role: userRole,
        status: 'pending', // Start with pending status
        emailVerified: false,
        ipAddress: userData.ipAddress,
        deviceInfo: userData.userAgent
          ? { userAgent: userData.userAgent }
          : null,
      });

      // Create audit log using the proper audit middleware
      await logAuditEvent({
        type: 'USER_REGISTERED',
        user: {
          userId: user.id,
          username: user.email,
          roles: [user.role],
          permissions: [],
          ip: userData.ipAddress,
          userAgent: userData.userAgent,
        },
        resourceType: 'USER',
        resourceId: user.id,
        details: { email, type: userType, role: userRole },
        ipAddress: userData.ipAddress,
        userAgent: userData.userAgent,
        status: 'success',
        severity: 'low',
        category: 'authentication',
        description: 'User registration completed successfully',
        timestamp: new Date(),
      });

      // Publish welcome email event
      await publishEvent('welcome.email', {
        userId: user.id,
        email: user.email,
        type: user.type,
        role: user.role,
        template: 'welcome',
        data: {
          userName: user.email.split('@')[0], // Use email prefix as username
          email: user.email,
          accountType: user.type,
          activationLink: `${env.frontendUrl}/verify-email?token=${user.id}`,
        },
        timestamp: new Date(),
      });

      // Publish email verification event
      // await publishEvent('email.verification', {
      //   userId: user.id,
      //   email: user.email,
      //   fullName: user.fullName,
      //   verificationToken: user.id, // Using user ID as token for simplicity
      //   template: 'email_verification',
      //   data: {
      //     userName: user.fullName,
      //     email: user.email,
      //     verificationLink: `${env.frontendUrl}/verify-email?token=${user.id}`,
      //   },
      //   timestamp: new Date(),
      // });

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

  /**
   * Authenticate user login
   * @param {Object} loginData - Login credentials
   * @returns {Promise<Object>} Authentication result with tokens
   */
  async loginUser(loginData) {
    try {
      const { email, password, deviceInfo, ipAddress, userAgent } = loginData;

      // Validate input
      if (!email || !password) {
        throw new Error('Email and password are required');
      }

      // Find user
      const user = await User.findOne({ where: { email } });
      if (!user) {
        throw new Error('Invalid email or password');
      }

      // Check user status - Allow pending users to login
      if (user.status === 'suspended' || user.status === 'inactive') {
        throw new Error('Account is not active');
      }

      // Verify password
      const isPasswordValid = await passwordService.verifyPassword(
        password,
        user.password
      );
      if (!isPasswordValid) {
        throw new Error('Invalid email or password');
      }

      // Generate tokens
      const sessionId = uuidv4();
      const accessToken = this.generateAccessToken(user, sessionId); // Use the same sessionId
      const refreshToken = this.generateRefreshToken(user);

      // Create session using SessionService
      const session = await sessionService.createSession({
        userId: user.id,
        sessionId,
        deviceInfo,
        ipAddress,
        userAgent,
      });

      // Store refresh token
      await sessionService.storeRefreshToken(refreshToken, {
        userId: user.id,
        sessionId,
      });

      // Store user session in cache
      await authCache.storeUserSession(user.id, {
        sessionId,
        deviceInfo,
        ipAddress,
        userAgent,
        lastActive: new Date().toISOString(),
        createdAt: new Date().toISOString(),
      });

      // Check if this is user's first login (no previous sessions)
      const previousSessions = await sessionService.getUserSessions(user.id);
      const isFirstLogin = previousSessions.length === 0;

      // If first login, create user profile and related data
      if (isFirstLogin) {
        await publishEvent('user.created', {
          userId: user.id,
          email: user.email,
          type: user.type,
          role: user.role,
          ipAddress,
          userAgent,
          timestamp: new Date(),
        });
      }

      // Publish login event
      await publishEvent('user.logged_in', {
        userId: user.id,
        email: user.email,
        sessionId,
        timestamp: new Date(),
      });

      // Create audit log
      await AuditLog.create({
        userId: user.id,
        action: 'USER_LOGIN',
        resourceType: 'SESSION',
        resourceId: sessionId,
        details: { deviceInfo, ipAddress },
        ipAddress,
        userAgent,
      });

      safeLogger.info('User logged in successfully', {
        userId: user.id,
        email: user.email,
        sessionId,
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
          expiresIn: env.jwtExpiry,
        },
        session: {
          sessionId,
          expiresAt: session.expiresAt,
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
        throw new Error('Invalid refresh token');
      }

      const { userId, sessionId } = refreshData;

      // Validate session
      const sessionData = await sessionService.validateSession(sessionId);
      if (!sessionData) {
        throw new Error('Session expired');
      }

      // Get user
      const user = await User.findByPk(userId);
      if (!user || !['active', 'pending'].includes(user.status)) {
        throw new Error('User not found or inactive');
      }

      // Generate new access token
      const newAccessToken = this.generateAccessToken(user, sessionId); // Pass existing sessionId

      safeLogger.info('Token refreshed successfully', {
        userId: user.id,
        sessionId,
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
      await publishEvent('user.logged_out', {
        userId,
        sessionId,
        timestamp: new Date(),
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
      const user = await User.findByPk(decoded.userId);
      if (!user || !['active', 'pending'].includes(user.status)) {
        throw new Error('User not found or inactive');
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
        throw new Error('Token expired');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid token');
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
   * Get user by ID (delegate to UserService)
   * @param {number} userId - User ID
   * @returns {Promise<Object>} User object
   */
  async getUserById(userId) {
    // Get user from cache first, then database
    const cachedUser = await authCache.getUserProfile(userId);
    if (cachedUser) {
      return cachedUser;
    }

    const user = await User.findByPk(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Cache user profile
    await authCache.storeUserProfile(userId, {
      id: user.id,
      email: user.email,
      type: user.type,
      role: user.role,
      status: user.status,
      emailVerified: user.emailVerified,
      createdAt: user.createdAt,
    });

    return user;
  }

  /**
   * Update user profile (delegate to UserService)
   * @param {number} userId - User ID
   * @param {Object} updateData - Update data
   * @returns {Promise<Object>} Updated user object
   */
  async updateUserProfile(userId, updateData) {
    return await userService.updateUserProfile(userId, updateData);
  }

  /**
   * Generate access token
   * @param {Object} user - User object
   * @returns {string} JWT access token
   */
  generateAccessToken(user, sessionId) {
    return jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
        sessionId: sessionId, // Include sessionId for logout tracking
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
      return await emailVerificationService.verifyEmailToken(token);
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
      return await emailVerificationService.resendVerificationEmail(
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
      const user = await User.findOne({ where: { email } });
      if (!user) {
        throw new Error('User not found');
      }

      // Generate reset token
      const resetToken = await passwordService.generateResetToken(user.id);

      // Publish password reset email event
      await publishEvent('password.reset', {
        userId: user.id,
        email: user.email,
        resetToken,
        template: 'password_reset',
        data: {
          userName: user.email.split('@')[0], // Use email prefix as username
          email: user.email,
          resetLink: `${env.frontendUrl}/reset-password?token=${resetToken}`,
          expiryTime: '30 minutes',
        },
        timestamp: new Date(),
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
      const user = await User.findByPk(token);
      if (!user) {
        throw new Error('Invalid verification token');
      }

      if (user.emailVerified) {
        throw new Error('Email already verified');
      }

      // Update user to verified
      await user.update({
        emailVerified: true,
        status: 'active',
      });

      // Publish account activation event
      await publishEvent('account.activation', {
        userId: user.id,
        email: user.email,
        type: user.type,
        role: user.role,
        template: 'account_activated',
        data: {
          userName: user.email.split('@')[0], // Use email prefix as username
          email: user.email,
          accountType: user.type,
          loginLink: `${env.frontendUrl}/login`,
        },
        timestamp: new Date(),
      });

      // Publish user verified event
      await publishEvent('user.verified', {
        userId: user.id,
        email: user.email,
        type: user.type,
        role: user.role,
        timestamp: new Date(),
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
