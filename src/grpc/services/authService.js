import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { ApiError } from '../../utils/ApiError.js';
import { env } from '../../config/env.js';
import { safeLogger } from '../../config/logger.js';
import { getCorrelationId } from '../../config/requestContext.js';
/**
 * Industry-level Authentication Service
 *
 * Features:
 * - Enhanced security and validation
 * - Session management
 * - Token refresh and management
 * - Health monitoring
 * - Performance tracking
 * - Audit logging
 */
// In-memory storage (replace with database in production)
const users = new Map();
const sessions = new Map();
const refreshTokens = new Map();
// Service metrics
const serviceMetrics = {
  totalLogins: 0,
  successfulLogins: 0,
  failedLogins: 0,
  totalRegistrations: 0,
  successfulRegistrations: 0,
  failedRegistrations: 0,
  totalTokenValidations: 0,
  successfulValidations: 0,
  failedValidations: 0,
  uptime: Date.now(),
};
/**
 * Update service metrics
 * @param {string} type - Metric type
 * @param {Object} data - Additional data
 */
function updateMetrics(type, data = {}) {
  switch (type) {
    case 'login':
      serviceMetrics.totalLogins++;
      break;
    case 'loginSuccess':
      serviceMetrics.successfulLogins++;
      break;
    case 'loginFailure':
      serviceMetrics.failedLogins++;
      break;
    case 'registration':
      serviceMetrics.totalRegistrations++;
      break;
    case 'registrationSuccess':
      serviceMetrics.successfulRegistrations++;
      break;
    case 'registrationFailure':
      serviceMetrics.failedRegistrations++;
      break;
    case 'validation':
      serviceMetrics.totalTokenValidations++;
      break;
    case 'validationSuccess':
      serviceMetrics.successfulValidations++;
      break;
    case 'validationFailure':
      serviceMetrics.failedValidations++;
      break;
  }
  safeLogger.debug('Auth service metrics updated', {
    type,
    data,
    metrics: { ...serviceMetrics },
  });
}
/**
 * Validate email format
 * @param {string} email - Email to validate
 * @returns {boolean} Valid email
 */
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}
/**
 * Validate password strength
 * @param {string} password - Password to validate
 * @returns {Object} Validation result
 */
function validatePassword(password) {
  const errors = [];
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  if (!/(?=.*[a-z])/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  if (!/(?=.*[A-Z])/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  if (!/(?=.*\d)/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  if (!/(?=.*[@$!%*?&])/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  return {
    isValid: errors.length === 0,
    errors,
  };
}
/**
 * Generate session information
 * @param {string} userId - User ID
 * @param {Object} metadata - Session metadata
 * @returns {Object} Session information
 */
function generateSessionInfo(userId, metadata = {}) {
  const sessionId = `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours
  const sessionInfo = {
    sessionId,
    userId,
    deviceId: metadata.deviceId || 'unknown',
    ipAddress: metadata.ipAddress || 'unknown',
    userAgent: metadata.userAgent || 'unknown',
    createdAt: now,
    lastActivity: now,
    expiresAt,
    isActive: true,
    metadata: metadata || {},
  };
  sessions.set(sessionId, sessionInfo);
  return sessionInfo;
}
/**
 * Generate JWT token with enhanced security
 * @param {Object} payload - Token payload
 * @param {Object} options - Token options
 * @returns {Object} Token information
 */
function generateToken(payload, options = {}) {
  const now = Date.now();
  const expiresIn = options.expiresIn || '1h';
  const expiresAt = new Date(
    now + (expiresIn === '1h' ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000)
  );
  const tokenPayload = {
    ...payload,
    iat: Math.floor(now / 1000),
    exp: Math.floor(expiresAt.getTime() / 1000),
    jti: `jwt_${now}_${Math.random().toString(36).substr(2, 9)}`,
  };
  const token = jwt.sign(tokenPayload, env.JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn,
  });
  return {
    token,
    expiresAt,
    issuedAt: new Date(now),
    jti: tokenPayload.jti,
  };
}
/**
 * Generate refresh token
 * @param {string} userId - User ID
 * @param {Object} metadata - Token metadata
 * @returns {Object} Refresh token information
 */
function generateRefreshToken(userId, metadata = {}) {
  const refreshToken = `rt_${Date.now()}_${Math.random().toString(36).substr(2, 15)}`;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 days
  const refreshTokenInfo = {
    refreshToken,
    userId,
    createdAt: now,
    expiresAt,
    isActive: true,
    metadata: metadata || {},
  };
  refreshTokens.set(refreshToken, refreshTokenInfo);
  return refreshTokenInfo;
}
/**
 * Enhanced login with session management
 * @param {Object} loginData - Login data
 * @returns {Promise<Object>} Login result
 */
export const login = async loginData => {
  const { email, password, deviceId, ipAddress, userAgent, metadata } =
    loginData;
  const correlationId = getCorrelationId();
  try {
    updateMetrics('login');
    // Validate input
    if (!email || !password) {
      throw new ApiError(400, 'Validation Error', [
        'Email and password are required',
      ]);
    }
    if (!isValidEmail(email)) {
      throw new ApiError(400, 'Validation Error', ['Invalid email format']);
    }
    // Find user
    const user = users.get(email);
    if (!user) {
      updateMetrics('loginFailure');
      throw new ApiError(401, 'Authentication Failed', [
        'Invalid email or password',
      ]);
    }
    // Check if user is active
    if (user.status !== 'ACTIVE') {
      updateMetrics('loginFailure');
      throw new ApiError(401, 'Account Inactive', ['Account is not active']);
    }
    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      updateMetrics('loginFailure');
      throw new ApiError(401, 'Authentication Failed', [
        'Invalid email or password',
      ]);
    }
    // Generate tokens
    const accessTokenInfo = generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    });
    const refreshTokenInfo = generateRefreshToken(user.id, {
      deviceId,
      ipAddress,
      userAgent,
    });
    // Generate session
    const sessionInfo = generateSessionInfo(user.id, {
      deviceId,
      ipAddress,
      userAgent,
      ...metadata,
    });
    // Update user last login
    user.lastLogin = new Date();
    users.set(email, user);
    updateMetrics('loginSuccess');
    safeLogger.info('User login successful', {
      userId: user.id,
      email: user.email,
      correlationId,
      sessionId: sessionInfo.sessionId,
      deviceId,
      ipAddress,
    });
    return {
      token: accessTokenInfo.token,
      refreshToken: refreshTokenInfo.refreshToken,
      userId: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      status: user.status,
      expiresAt: accessTokenInfo.expiresAt,
      session: sessionInfo,
    };
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    updateMetrics('loginFailure');
    safeLogger.error('Login error', {
      error: error.message,
      email,
      correlationId,
    });
    throw new ApiError(500, 'Login failed', [
      'Internal server error during login',
    ]);
  }
};
/**
 * Enhanced registration with validation
 * @param {Object} registrationData - Registration data
 * @returns {Promise<Object>} Registration result
 */
export const register = async registrationData => {
  const { email, password, name, phoneNumber, role, metadata } =
    registrationData;
  const correlationId = getCorrelationId();
  try {
    updateMetrics('registration');
    // Validate input
    if (!email || !password || !name) {
      throw new ApiError(400, 'Validation Error', [
        'Email, password, and name are required',
      ]);
    }
    if (!isValidEmail(email)) {
      throw new ApiError(400, 'Validation Error', ['Invalid email format']);
    }
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      throw new ApiError(400, 'Validation Error', passwordValidation.errors);
    }
    // Check if user already exists
    if (users.has(email)) {
      updateMetrics('registrationFailure');
      throw new ApiError(409, 'Registration Failed', ['Email already exists']);
    }
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    // Create user
    const userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const now = new Date();
    const user = {
      id: userId,
      email,
      password: hashedPassword,
      name,
      phoneNumber,
      role: role || 'USER',
      status: 'PENDING_VERIFICATION',
      createdAt: now,
      updatedAt: now,
      metadata: metadata || {},
    };
    users.set(email, user);
    updateMetrics('registrationSuccess');
    safeLogger.info('User registration successful', {
      userId,
      email,
      name,
      correlationId,
    });
    return {
      userId,
      email,
      name,
      status: user.status,
      createdAt: user.createdAt,
    };
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    updateMetrics('registrationFailure');
    safeLogger.error('Registration error', {
      error: error.message,
      email,
      correlationId,
    });
    throw new ApiError(500, 'Registration failed', [
      'Internal server error during registration',
    ]);
  }
};
/**
 * Enhanced token validation with session checking
 * @param {string} token - JWT token
 * @param {Object} options - Validation options
 * @returns {Promise<Object>} Validation result
 */
export const validateToken = async (token, options = {}) => {
  const { deviceId, metadata } = options;
  const correlationId = getCorrelationId();
  try {
    updateMetrics('validation');
    if (!token) {
      throw new ApiError(400, 'Validation Error', ['Token is required']);
    }
    // Verify token
    const decoded = jwt.verify(token, env.JWT_SECRET);
    // Check if user exists
    const user = Array.from(users.values()).find(u => u.id === decoded.userId);
    if (!user) {
      updateMetrics('validationFailure');
      throw new ApiError(401, 'Invalid Token', ['User not found']);
    }
    // Check if user is active
    if (user.status !== 'ACTIVE') {
      updateMetrics('validationFailure');
      throw new ApiError(401, 'Invalid Token', ['User account is not active']);
    }
    updateMetrics('validationSuccess');
    safeLogger.debug('Token validation successful', {
      userId: decoded.userId,
      correlationId,
    });
    return {
      valid: true,
      userId: decoded.userId,
      email: decoded.email,
      role: decoded.role,
      status: user.status,
      issuedAt: new Date(decoded.iat * 1000),
      expiresAt: new Date(decoded.exp * 1000),
      claims: decoded,
    };
  } catch (error) {
    updateMetrics('validationFailure');
    if (error instanceof jwt.JsonWebTokenError) {
      throw new ApiError(401, 'Invalid Token', [error.message]);
    }
    if (error instanceof jwt.TokenExpiredError) {
      throw new ApiError(401, 'Token Expired', ['Token has expired']);
    }
    if (error instanceof ApiError) {
      throw error;
    }
    safeLogger.error('Token validation error', {
      error: error.message,
      correlationId,
    });
    throw new ApiError(500, 'Token validation failed', [
      'Internal server error during token validation',
    ]);
  }
};
/**
 * Refresh access token
 * @param {string} refreshToken - Refresh token
 * @param {Object} options - Refresh options
 * @returns {Promise<Object>} Refresh result
 */
export const refreshToken = async (refreshToken, options = {}) => {
  const { deviceId, metadata } = options;
  const correlationId = getCorrelationId();
  try {
    if (!refreshToken) {
      throw new ApiError(400, 'Validation Error', [
        'Refresh token is required',
      ]);
    }
    // Find refresh token
    const refreshTokenInfo = refreshTokens.get(refreshToken);
    if (!refreshTokenInfo || !refreshTokenInfo.isActive) {
      throw new ApiError(401, 'Invalid Refresh Token', [
        'Refresh token is invalid or expired',
      ]);
    }
    // Check if refresh token is expired
    if (new Date() > refreshTokenInfo.expiresAt) {
      refreshTokens.delete(refreshToken);
      throw new ApiError(401, 'Refresh Token Expired', [
        'Refresh token has expired',
      ]);
    }
    // Get user
    const user = Array.from(users.values()).find(
      u => u.id === refreshTokenInfo.userId
    );
    if (!user || user.status !== 'ACTIVE') {
      throw new ApiError(401, 'Invalid Refresh Token', [
        'User not found or inactive',
      ]);
    }
    // Generate new tokens
    const accessTokenInfo = generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    });
    const newRefreshTokenInfo = generateRefreshToken(user.id, {
      deviceId,
      ...metadata,
    });
    // Invalidate old refresh token
    refreshTokens.delete(refreshToken);
    safeLogger.info('Token refresh successful', {
      userId: user.id,
      correlationId,
    });
    return {
      accessToken: accessTokenInfo.token,
      refreshToken: newRefreshTokenInfo.refreshToken,
      expiresAt: accessTokenInfo.expiresAt,
    };
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    safeLogger.error('Token refresh error', {
      error: error.message,
      correlationId,
    });
    throw new ApiError(500, 'Token refresh failed', [
      'Internal server error during token refresh',
    ]);
  }
};
/**
 * Logout user and invalidate sessions
 * @param {string} token - Access token
 * @param {Object} options - Logout options
 * @returns {Promise<Object>} Logout result
 */
export const logout = async (token, options = {}) => {
  const { deviceId, allSessions, metadata } = options;
  const correlationId = getCorrelationId();
  try {
    if (!token) {
      throw new ApiError(400, 'Validation Error', ['Token is required']);
    }
    // Decode token to get user ID
    const decoded = jwt.verify(token, env.JWT_SECRET);
    const userId = decoded.userId;
    let sessionsTerminated = 0;
    if (allSessions) {
      // Terminate all sessions for the user
      for (const [sessionId, session] of sessions.entries()) {
        if (session.userId === userId) {
          session.isActive = false;
          sessionsTerminated++;
        }
      }
    } else {
      // Terminate specific session
      for (const [sessionId, session] of sessions.entries()) {
        if (session.userId === userId && session.deviceId === deviceId) {
          session.isActive = false;
          sessionsTerminated++;
          break;
        }
      }
    }
    // Invalidate refresh tokens
    for (const [refreshToken, refreshTokenInfo] of refreshTokens.entries()) {
      if (refreshTokenInfo.userId === userId) {
        if (allSessions || refreshTokenInfo.metadata.deviceId === deviceId) {
          refreshTokens.delete(refreshToken);
        }
      }
    }
    safeLogger.info('User logout successful', {
      userId,
      sessionsTerminated,
      allSessions,
      correlationId,
    });
    return {
      success: true,
      sessionsTerminated,
    };
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    safeLogger.error('Logout error', {
      error: error.message,
      correlationId,
    });
    throw new ApiError(500, 'Logout failed', [
      'Internal server error during logout',
    ]);
  }
};
/**
 * Get user sessions
 * @param {string} userId - User ID
 * @param {Object} options - Session options
 * @returns {Promise<Object>} Sessions result
 */
export const getSessions = async (userId, options = {}) => {
  const { deviceId, metadata } = options;
  const correlationId = getCorrelationId();
  try {
    if (!userId) {
      throw new ApiError(400, 'Validation Error', ['User ID is required']);
    }
    const userSessions = [];
    for (const [sessionId, session] of sessions.entries()) {
      if (session.userId === userId && session.isActive) {
        if (!deviceId || session.deviceId === deviceId) {
          userSessions.push(session);
        }
      }
    }
    safeLogger.debug('Retrieved user sessions', {
      userId,
      sessionCount: userSessions.length,
      correlationId,
    });
    return {
      sessions: userSessions,
      totalSessions: userSessions.length,
    };
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    safeLogger.error('Get sessions error', {
      error: error.message,
      userId,
      correlationId,
    });
    throw new ApiError(500, 'Get sessions failed', [
      'Internal server error while retrieving sessions',
    ]);
  }
};
/**
 * Health check for auth service
 * @param {Object} options - Health check options
 * @returns {Promise<Object>} Health check result
 */
export const healthCheck = async (options = {}) => {
  const { serviceName, metadata } = options;
  const correlationId = getCorrelationId();
  try {
    const uptime = Date.now() - serviceMetrics.uptime;
    const successRate =
      serviceMetrics.totalLogins > 0
        ? (serviceMetrics.successfulLogins / serviceMetrics.totalLogins) * 100
        : 0;
    const healthStatus = {
      status: 'OK',
      version: process.env.SERVICE_VERSION || '1.0.0',
      timestamp: new Date().toISOString(),
      details: {
        uptime: `${Math.round(uptime / 1000)}s`,
        totalUsers: users.size,
        totalSessions: sessions.size,
        totalRefreshTokens: refreshTokens.size,
        loginSuccessRate: `${successRate.toFixed(2)}%`,
        metrics: { ...serviceMetrics },
      },
    };
    safeLogger.debug('Health check completed', {
      serviceName: serviceName || 'auth-service',
      correlationId,
      status: healthStatus.status,
    });
    return healthStatus;
  } catch (error) {
    safeLogger.error('Health check error', {
      error: error.message,
      correlationId,
    });
    return {
      status: 'ERROR',
      version: process.env.SERVICE_VERSION || '1.0.0',
      timestamp: new Date().toISOString(),
      error: error.message,
    };
  }
};
/**
 * Get service metrics
 * @returns {Object} Service metrics
 */
export const getServiceMetrics = () => {
  return {
    ...serviceMetrics,
    currentTime: new Date().toISOString(),
    totalUsers: users.size,
    totalSessions: sessions.size,
    totalRefreshTokens: refreshTokens.size,
  };
};
/**
 * Reset service metrics
 */
export const resetServiceMetrics = () => {
  Object.assign(serviceMetrics, {
    totalLogins: 0,
    successfulLogins: 0,
    failedLogins: 0,
    totalRegistrations: 0,
    successfulRegistrations: 0,
    failedRegistrations: 0,
    totalTokenValidations: 0,
    successfulValidations: 0,
    failedValidations: 0,
    uptime: Date.now(),
  });
  safeLogger.info('Auth service metrics reset');
};
