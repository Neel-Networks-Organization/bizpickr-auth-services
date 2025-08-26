import { ApiError, ApiResponse } from '../utils/index.js';
import { safeLogger } from '../config/logger.js';
import { authService } from '../services/index.js';

export const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
  path: '/',
  domain: process.env.COOKIE_DOMAIN || undefined,
};

export const signupUser = async (req, res) => {
  const { email, password, type, role } = req.body;

  const userData = {
    email,
    password,
    type,
    role: role || 'user',
  };

  const user = await authService.registerUser(userData);

  safeLogger.info('User registered successfully', {
    userId: user.id,
    email: user.email,
    type,
    role: user.role,
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

export const loginUser = async (req, res) => {
  const { email, password, type } = req.body;

  const loginData = {
    email,
    password,
    type,
  };

  const result = await authService.loginUser(loginData);

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
        },
      },
      'Login successful',
      { loginMethod: 'email' }
    )
  );
};

export const refreshAccessToken = async (req, res) => {
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

  res.cookie('refreshToken', result.refreshToken, {
    ...cookieOptions,
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  });

  safeLogger.info('Access token refreshed successfully');

  return res.status(200).json(
    ApiResponse.success(
      {
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
      },
      'Token refreshed successfully'
    )
  );
};

export const logoutUser = async (req, res) => {
  const userPayload = req.user;

  if (!userPayload) {
    throw new ApiError(400, 'User not authenticated', [
      'User must be authenticated to logout',
    ]);
  }

  await authService.logoutUser(userPayload);

  res.clearCookie('accessToken', {
    ...cookieOptions,
  });
  res.clearCookie('refreshToken', {
    ...cookieOptions,
  });

  return res
    .status(200)
    .json(
      ApiResponse.success(
        { message: 'User logged out successfully' },
        'User logged out successfully'
      )
    );
};

export const getCurrentUser = async (req, res) => {
  const userId = req.user?.id;
  if (!userId) {
    throw new ApiError(401, 'User not authenticated', [
      'Please login to access your profile',
    ]);
  }

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

// Google OAuth - future features

export const loginWithGoogle = async (req, res) => {
  // Redirect to Google OAuth
  const googleAuthUrl = `https://accounts.google.com/oauth/authorize?client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=${process.env.GOOGLE_REDIRECT_URI}&scope=email profile&response_type=code`;
  return res.redirect(googleAuthUrl);
};

export const googleCallback = async (req, res) => {
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

// 2FA - future features

export const enableTwoFactor = async (req, res) => {
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

export const disableTwoFactor = async (req, res) => {
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
    await authService.disableTwoFactor(userId, code);

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

export const verifyTwoFactor = async (req, res) => {
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
