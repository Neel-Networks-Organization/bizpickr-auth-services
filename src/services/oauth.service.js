/**
 * OAuth Service - External Authentication Providers
 *
 * Handles OAuth authentication flows:
 * - Google OAuth
 * - Token exchange and validation
 * - User creation/login via OAuth
 */
import axios from 'axios';
import { safeLogger } from '../config/logger.js';
import { env } from '../config/env.js';
import { AuthUser as User } from '../models/index.model.js';
import { logAuditEvent } from '../middlewares/audit.middleware.js';
import sessionService from './session.service.js';

class OAuthService {
  constructor() {
    this.googleTokenUrl = 'https://oauth2.googleapis.com/token';
    this.googleUserInfoUrl = 'https://www.googleapis.com/oauth2/v2/userinfo';
  }

  /**
   * Exchange authorization code for Google tokens
   * @param {string} code - Authorization code from Google
   * @returns {Promise<Object>} Google tokens
   */
  async exchangeGoogleCode(code) {
    try {
      const response = await axios.post(this.googleTokenUrl, {
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: env.GOOGLE_REDIRECT_URI,
      });

      return {
        access_token: response.data.access_token,
        refresh_token: response.data.refresh_token,
        expires_in: response.data.expires_in,
      };
    } catch (error) {
      safeLogger.error('Google token exchange failed', {
        error: error.response?.data || error.message,
      });
      throw new Error('Failed to exchange Google authorization code');
    }
  }

  /**
   * Get user info from Google
   * @param {string} accessToken - Google access token
   * @returns {Promise<Object>} Google user info
   */
  async getGoogleUserInfo(accessToken) {
    try {
      const response = await axios.get(this.googleUserInfoUrl, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      return {
        id: response.data.id,
        email: response.data.email,
        name: response.data.name,
        given_name: response.data.given_name,
        family_name: response.data.family_name,
        picture: response.data.picture,
        verified_email: response.data.verified_email,
      };
    } catch (error) {
      safeLogger.error('Google user info fetch failed', {
        error: error.response?.data || error.message,
      });
      throw new Error('Failed to fetch Google user information');
    }
  }

  /**
   * Find or create user from Google OAuth
   * @param {Object} googleUser - Google user info
   * @returns {Promise<Object>} User object
   */
  async findOrCreateGoogleUser(googleUser) {
    try {
      // Check if user exists with this Google ID
      let user = await User.findOne({
        where: {
          provider: 'google',
          providerId: googleUser.id,
        },
      });

      if (!user) {
        // Check if user exists with this email
        user = await User.findOne({
          where: { email: googleUser.email },
        });

        if (user) {
          // Link existing user to Google account
          await user.update({
            provider: 'google',
            providerId: googleUser.id,
            emailVerified: googleUser.verified_email || user.emailVerified,
          });
        } else {
          // Create new user from Google data
          user = await User.create({
            email: googleUser.email,
            fullName: googleUser.name,
            provider: 'google',
            providerId: googleUser.id,
            type: 'customer',
            role: 'customer',
            status: 'active',
            emailVerified: googleUser.verified_email || false,
            metadata: {
              googleProfile: {
                picture: googleUser.picture,
                givenName: googleUser.given_name,
                familyName: googleUser.family_name,
              },
            },
          });
        }
      }

      return user;
    } catch (error) {
      safeLogger.error('Google user creation failed', {
        error: error.message,
        googleUser: { id: googleUser.id, email: googleUser.email },
      });
      throw new Error('Failed to create or link Google user');
    }
  }

  /**
   * Complete Google OAuth login
   * @param {string} code - Authorization code
   * @param {Object} deviceInfo - Device information
   * @returns {Promise<Object>} Login result with user and tokens
   */
  async completeGoogleLogin(code, deviceInfo) {
    try {
      // Exchange code for tokens
      const tokens = await this.exchangeGoogleCode(code);

      // Get user info from Google
      const googleUser = await this.getGoogleUserInfo(tokens.access_token);

      // Find or create user
      const user = await this.findOrCreateGoogleUser(googleUser);

      // Create session
      const session = await sessionService.createSession(user.id, {
        ...deviceInfo,
        loginMethod: 'oauth',
        oauthProvider: 'google',
      });

      // Generate JWT tokens
      const accessToken = this.generateAccessToken(user);
      const refreshToken = this.generateRefreshToken(user);

      // Log audit event
      await logAuditEvent({
        type: 'USER_LOGIN',
        user: {
          userId: user.id,
          username: user.email,
          roles: [user.role],
          permissions: [],
          ip: deviceInfo.ipAddress,
          userAgent: deviceInfo.userAgent,
        },
        resourceType: 'USER',
        resourceId: user.id,
        details: {
          loginMethod: 'oauth',
          oauthProvider: 'google',
          email: user.email,
        },
        ipAddress: deviceInfo.ipAddress,
        userAgent: deviceInfo.userAgent,
        status: 'success',
        severity: 'low',
        category: 'authentication',
        description: 'User logged in via Google OAuth',
        timestamp: new Date(),
      });

      safeLogger.info('Google OAuth login successful', {
        userId: user.id,
        email: user.email,
        oauthProvider: 'google',
      });

      return {
        user: {
          id: user.id,
          email: user.email,
          fullName: user.fullName,
          role: user.role,
          status: user.status,
          emailVerified: user.emailVerified,
        },
        tokens: {
          accessToken,
          refreshToken,
          expiresIn: env.JWT_EXPIRES_IN,
        },
        session: {
          sessionId: session.sessionId,
          expiresAt: session.expiresAt,
        },
      };
    } catch (error) {
      safeLogger.error('Google OAuth login failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Generate access token
   * @param {Object} user - User object
   * @returns {string} JWT access token
   */
  generateAccessToken(user) {
    const jwt = require('jsonwebtoken');
    return jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
      },
      env.JWT_SECRET,
      {
        expiresIn: env.JWT_EXPIRES_IN,
        issuer: 'auth-service',
        audience: 'api-gateway',
      },
    );
  }

  /**
   * Generate refresh token
   * @param {Object} user - User object
   * @returns {string} JWT refresh token
   */
  generateRefreshToken(user) {
    const jwt = require('jsonwebtoken');
    return jwt.sign(
      {
        userId: user.id,
        type: 'refresh',
      },
      env.REFRESH_TOKEN_SECRET,
      {
        expiresIn: 7 * 24 * 60 * 60, // 7 days
        issuer: 'auth-service',
        audience: 'auth-service',
      },
    );
  }
}

export default new OAuthService();
