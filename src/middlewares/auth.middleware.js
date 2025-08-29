import { ApiError, asyncHandler } from '../utils/index.js';
import AuthUser from '../models/authUser.model.js';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import { cryptoService } from '../services/index.js';

function extractToken(req) {
  const authHeader = req.headers.authorization || req.cookies.accessToken;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }

  return authHeader;
}

async function verifyToken(token) {
  try {
    // Use the crypto service to verify the access token
    return await cryptoService.verifyAccessToken(token);
  } catch (error) {
    safeLogger.error('Token verification failed in middleware', {
      error: error.message,
      tokenLength: token?.length,
    });
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
    const decoded = await verifyToken(token);
    const user = await AuthUser.findByPk(decoded.userId, {
      attributes: { exclude: ['password'] },
    });

    if (!user) {
      throw new ApiError(401, 'User not found');
    }

    if (!user.isActive()) {
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
        userId: req.user.id,
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
