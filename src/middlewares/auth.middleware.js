import { ApiError, asyncHandler } from '../utils/index.js';
import AuthUser from '../models/authUser.model.js';
import jwt from 'jsonwebtoken';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import authCache from '../cache/auth.cache.js';
import { env } from '../config/env.js';

/**
 * Smart Auth Middleware
 * Core JWT authentication with essential security
 */

/**
 * Extract token from request
 */
function extractToken(req) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  return null;
}

/**
 * Verify JWT token
 */
function verifyToken(token) {
  try {
    return jwt.verify(token, env.JWT_SECRET);
  } catch (error) {
    throw new ApiError(401, 'Invalid or expired token');
  }
}

/**
 * Main authentication middleware
 */
export const authenticate = asyncHandler(async (req, res, next) => {
  const startTime = Date.now();
  const correlationId = getCorrelationId();

  try {
    // Basic device fingerprint (simplified)
    const deviceFingerprint = req.headers['x-device-fingerprint'];
    if (deviceFingerprint) {
      req.deviceFingerprint = deviceFingerprint;
    }

    // Rate limiting check
    const clientIP = req.ip || req.connection?.remoteAddress;
    const rateLimitKey = `auth:${clientIP}`;
    const currentRate = await authCache.incrementRateLimit(rateLimitKey);

    if (currentRate > 10) {
      throw new ApiError(429, 'Too many authentication attempts');
    }

    const token = extractToken(req);

    if (!token) {
      throw new ApiError(401, 'Access token required');
    }

    // Check if token is blacklisted
    const isBlacklisted = await authCache.isTokenBlacklisted(token);
    if (isBlacklisted) {
      throw new ApiError(401, 'Token has been revoked');
    }

    // Verify token
    const decoded = verifyToken(token);

    // Get user from database
    const user = await AuthUser.findById(decoded.userId)
      .select('-password')
      .populate('permissions', 'name scope')
      .populate('role', 'name permissions');

    if (!user) {
      throw new ApiError(401, 'User not found');
    }

    // Basic security checks
    if (!user.isActive) {
      throw new ApiError(401, 'User account is deactivated');
    }

    if (user.isLocked) {
      throw new ApiError(423, 'User account is locked');
    }

    if (user.failedLoginAttempts >= 5) {
      throw new ApiError(
        423,
        'Account temporarily locked due to failed attempts'
      );
    }

    // Check account expiration
    if (user.accountExpiresAt && new Date() > user.accountExpiresAt) {
      throw new ApiError(401, 'User account has expired');
    }

    // Check last password change
    if (user.lastPasswordChange && user.passwordChangeRequired) {
      const daysSinceChange =
        (Date.now() - user.lastPasswordChange.getTime()) /
        (1000 * 60 * 60 * 24);
      if (daysSinceChange > 90) {
        throw new ApiError(401, 'Password change required');
      }
    }

    // Add user to request
    req.user = user;
    req.token = token;
    req.correlationId = correlationId;

    // Basic security context
    req.securityContext = {
      deviceFingerprint,
      clientIP,
      userAgent: req.headers['user-agent'],
      timestamp: Date.now(),
      sessionId: decoded.sessionId || null,
    };

    // Log successful authentication
    const responseTime = Date.now() - startTime;
    safeLogger.info('Authentication successful', {
      userId: user._id,
      email: user.email,
      correlationId,
      responseTime: `${responseTime}ms`,
      clientIP,
      deviceFingerprint,
      userAgent: req.headers['user-agent'],
      userRole: user.role?.name || 'user',
      permissions: user.permissions?.map(p => p.name) || [],
    });

    // Update user activity
    await AuthUser.findByIdAndUpdate(user._id, {
      $inc: { loginCount: 1 },
      $set: {
        lastLoginAt: new Date(),
        lastLoginIP: clientIP,
        lastLoginUserAgent: req.headers['user-agent'],
      },
      $push: {
        loginHistory: {
          timestamp: new Date(),
          ip: clientIP,
          userAgent: req.headers['user-agent'],
          deviceFingerprint,
          correlationId,
        },
      },
    });

    next();
  } catch (error) {
    const responseTime = Date.now() - startTime;

    // Log failed authentication
    safeLogger.error('Authentication failed', {
      error: error.message,
      correlationId,
      responseTime: `${responseTime}ms`,
      clientIP: req.ip || req.connection?.remoteAddress,
      deviceFingerprint: req.headers['x-device-fingerprint'],
      userAgent: req.headers['user-agent'],
      attemptedToken: extractToken(req) ? 'present' : 'missing',
    });

    // Increment failed login attempts if user exists
    if (error.statusCode === 401 && req.body.email) {
      try {
        const user = await AuthUser.findOne({ email: req.body.email });
        if (user) {
          await AuthUser.findByIdAndUpdate(user._id, {
            $inc: { failedLoginAttempts: 1 },
            $set: { lastFailedLoginAt: new Date() },
          });
        }
      } catch (updateError) {
        safeLogger.error('Failed to update login attempts', {
          error: updateError.message,
        });
      }
    }

    next(error);
  }
});

/**
 * Optional authentication middleware
 */
export const optionalAuth = asyncHandler(async (req, res, next) => {
  try {
    const token = extractToken(req);

    if (token) {
      const decoded = verifyToken(token);
      const user = await AuthUser.findById(decoded.userId)
        .select('-password')
        .populate('permissions', 'name scope')
        .populate('role', 'name permissions');

      if (user && user.isActive && !user.isLocked) {
        req.user = user;
        req.token = token;
        req.correlationId = getCorrelationId();
      }
    }

    next();
  } catch (error) {
    // Continue without authentication
    next();
  }
});

/**
 * Role-based access control middleware
 */
export const requireRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new ApiError(401, 'Authentication required'));
    }

    const userRole = req.user.role?.name;
    if (!userRole || !roles.includes(userRole)) {
      safeLogger.warn('Role access denied', {
        userId: req.user._id,
        userRole,
        requiredRoles: roles,
        path: req.path,
        correlationId: req.correlationId,
      });

      return next(new ApiError(403, 'Insufficient permissions'));
    }

    next();
  };
};

/**
 * Permission-based access control middleware
 */
export const requirePermission = (...permissions) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new ApiError(401, 'Authentication required'));
    }

    const userPermissions = req.user.permissions?.map(p => p.name) || [];
    const hasPermission = permissions.some(permission =>
      userPermissions.includes(permission)
    );

    if (!hasPermission) {
      safeLogger.warn('Permission access denied', {
        userId: req.user._id,
        userPermissions,
        requiredPermissions: permissions,
        path: req.path,
        correlationId: req.correlationId,
      });

      return next(new ApiError(403, 'Insufficient permissions'));
    }

    next();
  };
};

/**
 * Admin-only middleware
 */
export const requireAdmin = (req, res, next) => {
  return requireRole('admin', 'super_admin')(req, res, next);
};

/**
 * Staff-only middleware
 */
export const requireStaff = (req, res, next) => {
  return requireRole('staff', 'admin', 'super_admin')(req, res, next);
};

/**
 * Customer-only middleware
 */
export const requireCustomer = (req, res, next) => {
  return requireRole('customer')(req, res, next);
};

/**
 * Vendor-only middleware
 */
export const requireVendor = (req, res, next) => {
  return requireRole('vendor')(req, res, next);
};

export default {
  authenticate,
  optionalAuth,
  requireRole,
  requirePermission,
  requireAdmin,
  requireStaff,
  requireCustomer,
  requireVendor,
};
