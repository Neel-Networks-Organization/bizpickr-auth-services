import { ApiError, asyncHandler } from '../utils/index.js';
import AuthUser from '../models/authUser.model.js';
import jwt from 'jsonwebtoken';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
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
 * JWT Authentication Middleware
 */
export const verifyJWT = asyncHandler(async (req, res, next) => {
  const token = extractToken(req);

  if (!token) {
    throw new ApiError(401, 'Access token required');
  }

  try {
    const decoded = verifyToken(token);
    const user = await AuthUser.findById(decoded.userId)
      .select('-password')
      .populate('permissions', 'name scope')
      .populate('role', 'name permissions');

    if (!user) {
      throw new ApiError(401, 'User not found');
    }

    if (!user.isActive) {
      throw new ApiError(401, 'User account is deactivated');
    }

    req.user = user;
    req.token = token;
    req.correlationId = getCorrelationId();

    next();
  } catch (error) {
    if (error instanceof ApiError) {
      next(error);
    } else {
      next(new ApiError(401, 'Invalid or expired token'));
    }
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
 * Audit Logging Middleware
 */
export const auditLog = action => {
  return (req, res, next) => {
    const auditData = {
      action,
      userId: req.user?._id,
      email: req.user?.email,
      ip: req.ip || req.connection?.remoteAddress,
      userAgent: req.headers['user-agent'],
      path: req.path,
      method: req.method,
      correlationId: req.correlationId,
      timestamp: new Date(),
    };

    safeLogger.info('Audit Log', auditData);
    next();
  };
};

/**
 * Rate Limiting Middleware
 */
export const rateLimiter = (strategy, options = {}) => {
  const { windowMs = 15 * 60 * 1000, max = 100 } = options;

  return (req, res, next) => {
    // Simple in-memory rate limiting (for production, use Redis)
    const key = `${strategy}:${req.ip}`;
    const now = Date.now();

    if (!req.rateLimitStore) {
      req.rateLimitStore = new Map();
    }

    const userRequests = req.rateLimitStore.get(key) || [];
    const validRequests = userRequests.filter(time => now - time < windowMs);

    if (validRequests.length >= max) {
      return next(new ApiError(429, 'Too many requests'));
    }

    validRequests.push(now);
    req.rateLimitStore.set(key, validRequests);

    next();
  };
};

export default {
  verifyJWT,
  requireRole,
  auditLog,
  rateLimiter,
};
