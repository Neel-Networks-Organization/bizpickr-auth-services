import { ApiError, asyncHandler } from '../utils/index.js';
import AuthUser from '../models/authUser.model.js';
import jwt from 'jsonwebtoken';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import { env } from '../config/env.js';

function extractToken(req) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  return null;
}

function verifyToken(token) {
  try {
    return jwt.verify(token, env.jwtSecret);
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

    const userRole = req.user?.role;
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
