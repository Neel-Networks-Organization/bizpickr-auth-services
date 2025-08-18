/**
 * Auth Controller - Core Authentication Layer
 *
 * Handles core authentication HTTP requests:
 * - User registration and login
 * - JWT token management
 * - OAuth integration
 * - Core authentication flows
 */
import { ApiError } from '../utils/ApiError.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import { signupSchemas, commonLoginSchema } from '../validators/validation.js';
import { safeLogger } from '../config/logger.js';
import { authService } from '../services/index.js';
import { authCache } from '../cache/auth.cache.js';

export const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
  path: '/',
  domain: process.env.COOKIE_DOMAIN || undefined,
};

/**
 * Register a new user
 * POST /api/v1/auth/signup
 */
export const signupUser = async (req, res, next) => {
  const { error, value } = signupSchemas(req.body);
  if (error) {
    const errorMessages = error.details.map(err =>
      err.message.replace(/["]/g, '')
    );
    throw new ApiError(400, 'Validation error', errorMessages);
  }
  const { email, password, type, role } = value;

  // Prepare user data for service - AUTHENTICATION ONLY
  const userData = {
    email,
    password,
    type,
    role,
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
  };

  // Call auth service to register user
  const user = await authService.registerUser(userData);

  safeLogger.info('User registered successfully', {
    userId: user.id,
    email: user.email,
    type,
    role,
  });

  return res.status(201).json(
    ApiResponse.created(
      {
        id: user.id,
        email: user.email,
        type: user.type,
        role: user.role,
        status: user.status,
        emailVerified: user.emailVerified,
      },
      `${type} registered successfully`,
      {
        registrationMethod: 'email',
        emailVerified: user.emailVerified,
        requiresEmailVerification: !user.emailVerified,
      }
    )
  );
};

/**
 * Login user
 * POST /api/v1/auth/login
 */
export const loginUser = async (req, res, next) => {
  const { error, value } = commonLoginSchema(req.body);
  if (error) {
    const errorMessages = error.details.map(err =>
      err.message.replace(/["]/g, '')
    );
    throw new ApiError(400, 'Login validation errors', errorMessages);
  }
  const { email, password, type } = value;

  // Prepare login data for service
  const loginData = {
    email,
    password,
    type,
    deviceInfo: req.get('User-Agent'),
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
  };

  // Call auth service to login user
  const result = await authService.loginUser(loginData);

  // Set cookies
  res.cookie('accessToken', result.tokens.accessToken, {
    ...cookieOptions,
    maxAge: 60 * 60 * 1000, // 1 hour
  });
  res.cookie('refreshToken', result.tokens.refreshToken, {
    ...cookieOptions,
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  });

  safeLogger.info('User logged in successfully', {
    userId: result.user.id,
    email: result.user.email,
    loginMethod: 'email',
  });

  return res.status(200).json(
    ApiResponse.success(
      {
        user: result.user,
        tokens: {
          accessToken: result.tokens.accessToken,
          refreshToken: result.tokens.refreshToken,
          expiresIn: result.tokens.expiresIn,
        },
        session: result.session,
      },
      'Login successful',
      {
        loginMethod: 'email',
        sessionId: result.session.sessionId,
      }
    )
  );
};

/**
 * Refresh access token
 * POST /api/v1/auth/refresh-token
 */
export const refreshAccessToken = async (req, res, next) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    throw new ApiError(400, 'Refresh token is required', [
      'Please provide a valid refresh token',
    ]);
  }

  // Call auth service to refresh token
  const result = await authService.refreshToken(refreshToken);

  // Set new access token cookie
  res.cookie('accessToken', result.accessToken, {
    ...cookieOptions,
    maxAge: 60 * 60 * 1000, // 1 hour
  });

  safeLogger.info('Access token refreshed successfully');

  return res.status(200).json(
    ApiResponse.success(
      {
        accessToken: result.accessToken,
        expiresIn: result.expiresIn,
      },
      'Token refreshed successfully'
    )
  );
};

/**
 * Logout user
 * POST /api/v1/auth/logout
 */
export const logoutUser = async (req, res, next) => {
  const sessionId = req.sessionId;
  const userId = req.user?.id;

  // Debug: Log what we received
  safeLogger.debug('Logout attempt', {
    sessionId: sessionId,
    userId: userId,
    hasSessionId: !!sessionId,
    hasUserId: !!userId,
    user: req.user,
  });

  if (!userId) {
    throw new ApiError(400, 'User not authenticated', [
      'User must be authenticated to logout',
    ]);
  }

  try {
    // Simplified logout: Just blacklist the token if we have one
    if (sessionId) {
      // Try to blacklist the token
      try {
        await authCache.blacklistToken(sessionId, {
          userId,
          logoutReason: 'user_logout',
          timestamp: new Date(),
        });
        safeLogger.info('Token blacklisted during logout', {
          userId,
          sessionId,
        });
      } catch (blacklistError) {
        safeLogger.warn('Failed to blacklist token during logout', {
          userId,
          sessionId,
          error: blacklistError.message,
        });
        // Continue with logout even if blacklisting fails
      }
    }

    // Clear cookies
    res.clearCookie('accessToken', cookieOptions);
    res.clearCookie('refreshToken', cookieOptions);

    safeLogger.info('User logged out successfully', {
      userId,
      sessionId: sessionId || 'none',
    });

    return res.status(200).json(ApiResponse.success({}, 'Logout successful'));
  } catch (error) {
    safeLogger.error('Logout failed', {
      userId,
      sessionId,
      error: error.message,
    });
    throw new ApiError(500, 'Logout failed', [
      'An error occurred during logout',
      'Please try again',
    ]);
  }
};

/**
 * Verify JWT token
 * POST /api/v1/auth/verify-token
 */
export const verifyToken = async (req, res, next) => {
  const { token } = req.body;
  if (!token) {
    throw new ApiError(400, 'Token is required', [
      'Please provide a valid JWT token',
    ]);
  }

  // Call auth service to verify token
  const decoded = await authService.verifyToken(token);

  safeLogger.info('Token verified successfully', {
    userId: decoded.userId,
  });

  return res.status(200).json(
    ApiResponse.success(
      {
        valid: true,
        user: {
          userId: decoded.userId,
          email: decoded.email,
          role: decoded.role,
        },
        expiresAt: decoded.exp,
      },
      'Token is valid'
    )
  );
};

/**
 * Get current user
 * GET /api/v1/auth/me
 */
export const getCurrentUser = async (req, res, next) => {
  const userId = req.user?.id;
  if (!userId) {
    throw new ApiError(401, 'User not authenticated', [
      'Please login to access your profile',
    ]);
  }

  // Call auth service to get user profile
  const user = await authService.getUserById(userId);

  return res.status(200).json(
    ApiResponse.success(
      {
        user,
      },
      'Current user retrieved successfully'
    )
  );
};

/**
 * Google OAuth login
 * GET /api/v1/auth/google
 */
export const loginWithGoogle = async (req, res, next) => {
  // Redirect to Google OAuth
  const googleAuthUrl = `https://accounts.google.com/oauth/authorize?client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=${process.env.GOOGLE_REDIRECT_URI}&scope=email profile&response_type=code`;
  return res.redirect(googleAuthUrl);
};

/**
 * Google OAuth callback
 * GET /api/v1/auth/google/callback
 */
export const googleCallback = async (req, res, next) => {
  const { code } = req.query;
  if (!code) {
    throw new ApiError(400, 'Authorization code is required', [
      'Please provide a valid authorization code',
    ]);
  }

  try {
    // Call auth service to handle Google OAuth
    const deviceInfo = {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    };
    const result = await authService.googleOAuthLogin(code, deviceInfo);

    // Set cookies for successful OAuth login
    res.cookie('accessToken', result.tokens.accessToken, {
      ...cookieOptions,
      maxAge: 60 * 60 * 1000, // 1 hour
    });
    res.cookie('refreshToken', result.tokens.refreshToken, {
      ...cookieOptions,
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    });

    safeLogger.info('Google OAuth login successful', {
      userId: result.user.id,
      email: result.user.email,
    });

    return res.status(200).json(
      ApiResponse.success(
        {
          user: result.user,
          tokens: result.tokens,
        },
        'Google OAuth login successful',
        {
          oauthProvider: 'google',
          loginMethod: 'oauth',
        }
      )
    );
  } catch (error) {
    safeLogger.error('Google OAuth callback failed', { error: error.message });
    throw new ApiError(400, 'OAuth login failed', [error.message]);
  }
};

/**
 * Verify email
 * POST /api/v1/auth/verify-email
 */
export const verifyEmail = async (req, res, next) => {
  const { token } = req.body;
  if (!token) {
    throw new ApiError(400, 'Verification token is required', [
      'Please provide a valid verification token',
    ]);
  }

  try {
    // Call auth service to verify email
    const result = await authService.verifyEmail(token);

    safeLogger.info('Email verification successful', { token });

    return res.status(200).json(
      ApiResponse.success(
        {
          emailVerified: true,
          message: 'Email verified successfully',
        },
        'Email verified successfully'
      )
    );
  } catch (error) {
    safeLogger.error('Email verification failed', { error: error.message });
    throw new ApiError(400, 'Email verification failed', [error.message]);
  }
};

/**
 * Resend verification email
 * POST /api/v1/auth/resend-verification
 */
export const resendVerificationEmail = async (req, res, next) => {
  const userId = req.user?.id;
  if (!userId) {
    throw new ApiError(401, 'User not authenticated', [
      'Please login to resend verification email',
    ]);
  }

  try {
    // Call auth service to resend verification email
    const deviceInfo = {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    };
    const result = await authService.resendVerificationEmail(
      userId,
      deviceInfo
    );

    safeLogger.info('Verification email resent successfully', { userId });

    return res.status(200).json(
      ApiResponse.success(
        {
          message: 'Verification email sent successfully',
        },
        'Verification email sent'
      )
    );
  } catch (error) {
    safeLogger.error('Resend verification failed', { error: error.message });
    throw new ApiError(400, 'Failed to resend verification email', [
      error.message,
    ]);
  }
};

/**
 * Enable two-factor authentication
 * POST /api/v1/auth/2fa/enable
 */
export const enableTwoFactor = async (req, res, next) => {
  const userId = req.user?.id;
  if (!userId) {
    throw new ApiError(401, 'User not authenticated', [
      'Please login to enable 2FA',
    ]);
  }

  try {
    // Call auth service to enable 2FA
    const result = await authService.enableTwoFactor(userId);

    safeLogger.info('2FA enabled successfully', { userId });

    return res.status(200).json(
      ApiResponse.success(
        {
          qrCode: result.qrCode,
          secret: result.secret,
          backupCodes: result.backupCodes,
        },
        '2FA enabled successfully'
      )
    );
  } catch (error) {
    safeLogger.error('Enable 2FA failed', { error: error.message });
    throw new ApiError(400, 'Failed to enable 2FA', [error.message]);
  }
};

/**
 * Disable two-factor authentication
 * POST /api/v1/auth/2fa/disable
 */
export const disableTwoFactor = async (req, res, next) => {
  const userId = req.user?.id;
  const { code } = req.body;
  if (!userId) {
    throw new ApiError(401, 'User not authenticated', [
      'Please login to disable 2FA',
    ]);
  }
  if (!code) {
    throw new ApiError(400, '2FA code is required', [
      'Please provide your 2FA code',
    ]);
  }

  try {
    // Call auth service to disable 2FA
    const result = await authService.disableTwoFactor(userId, code);

    safeLogger.info('2FA disabled successfully', { userId });

    return res.status(200).json(
      ApiResponse.success(
        {
          message: '2FA disabled successfully',
        },
        '2FA disabled successfully'
      )
    );
  } catch (error) {
    safeLogger.error('Disable 2FA failed', { error: error.message });
    throw new ApiError(400, 'Failed to disable 2FA', [error.message]);
  }
};
/**
 * Verify two-factor authentication
 * POST /api/v1/auth/2fa/verify
 */
export const verifyTwoFactor = async (req, res, next) => {
  const { code, sessionId } = req.body;
  if (!code || !sessionId) {
    throw new ApiError(400, '2FA code and session ID are required', [
      'Please provide both 2FA code and session ID',
    ]);
  }

  try {
    // Call auth service to verify 2FA
    const result = await authService.verifyTwoFactor(code, sessionId);

    // Set access token cookie for successful 2FA verification
    res.cookie('accessToken', result.accessToken, {
      ...cookieOptions,
      maxAge: result.expiresIn * 1000, // Convert to milliseconds
    });

    safeLogger.info('2FA verification successful', { sessionId });

    return res.status(200).json(
      ApiResponse.success(
        {
          accessToken: result.accessToken,
          expiresIn: result.expiresIn,
        },
        '2FA verification successful'
      )
    );
  } catch (error) {
    safeLogger.error('2FA verification failed', { error: error.message });
    throw new ApiError(400, '2FA verification failed', [error.message]);
  }
};

/**
 * Send password reset email
 * POST /api/v1/auth/forgot-password
 */
export const forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;

    if (!email) {
      throw new ApiError(400, 'Email is required');
    }

    const result = await authService.sendPasswordResetEmail(email);

    return res.status(200).json(
      ApiResponse.success(
        {
          message: result.message,
          email: result.email,
        },
        'Password reset email sent successfully'
      )
    );
  } catch (error) {
    safeLogger.error('Password reset email failed', {
      error: error.message,
      email: req.body.email,
    });
    next(error);
  }
};

/**
 * Verify email and activate account
 * POST /api/v1/auth/verify-email-activate
 */
export const verifyEmailAndActivate = async (req, res, next) => {
  try {
    const { token } = req.body;

    if (!token) {
      throw new ApiError(400, 'Verification token is required');
    }

    const result = await authService.verifyEmailAndActivate(token);

    return res.status(200).json(
      ApiResponse.success(
        {
          user: result.user,
          message: result.message,
        },
        'Email verified and account activated successfully'
      )
    );
  } catch (error) {
    safeLogger.error('Email verification and activation failed', {
      error: error.message,
      token: req.body.token,
    });
    next(error);
  }
};
