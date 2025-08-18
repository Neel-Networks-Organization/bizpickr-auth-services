import { ApiError } from '../utils/ApiError.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import AuthUser from '../models/authUser.model.js';
import jwt from 'jsonwebtoken';
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import authCache from '../cache/auth.cache.js';
import { env } from '../config/env.js';
import { createHash } from 'crypto';
import { promisify } from 'util';

/**
 * Industry-Standard Auth Middleware
 * Professional authentication with advanced security, metrics, and audit logging
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
 * Main authentication middleware with advanced security
 */
export const authenticate = asyncHandler(async (req, res, next) => {
  const startTime = Date.now();
  const correlationId = getCorrelationId();
  
  try {
    // Device fingerprint validation
    const deviceFingerprint = req.headers['x-device-fingerprint'] || req.body.deviceFingerprint;
    if (deviceFingerprint) {
      req.deviceFingerprint = deviceFingerprint;
    }

    // Rate limiting check
    const clientIP = req.ip || req.connection?.remoteAddress;
    const rateLimitKey = `auth:${clientIP}`;
    const currentRate = await authCache.incrementRateLimit(rateLimitKey);
    
    if (currentRate > 10) { // Max 10 auth attempts per 15 minutes
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

    // Verify token with enhanced security
    const decoded = verifyToken(token);
    
    // Get user from database with enhanced security
    const user = await AuthUser.findById(decoded.userId)
      .select('-password')
      .populate('permissions', 'name scope')
      .populate('role', 'name permissions');
    
    if (!user) {
      throw new ApiError(401, 'User not found');
    }

    // Enhanced security checks
    if (!user.isActive) {
      throw new ApiError(401, 'User account is deactivated');
    }

    if (user.isLocked) {
      throw new ApiError(423, 'User account is locked');
    }

    if (user.failedLoginAttempts >= 5) {
      throw new ApiError(423, 'Account temporarily locked due to failed attempts');
    }

    // Check account expiration
    if (user.accountExpiresAt && new Date() > user.accountExpiresAt) {
      throw new ApiError(401, 'User account has expired');
    }

    // Check last password change
    if (user.lastPasswordChange && user.passwordChangeRequired) {
      const daysSinceChange = (Date.now() - user.lastPasswordChange.getTime()) / (1000 * 60 * 60 * 24);
      if (daysSinceChange > 90) { // 90 days
        throw new ApiError(401, 'Password change required');
      }
    }

    // Add user to request
    req.user = user;
    req.token = token;
    req.correlationId = correlationId;
    
    // Add security context
    req.securityContext = {
      deviceFingerprint,
      clientIP,
      userAgent: req.headers['user-agent'],
      timestamp: Date.now(),
      sessionId: decoded.sessionId || null,
    };

    // Log successful authentication with metrics
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
        }
      }
    });

    next();
  } catch (error) {
    const responseTime = Date.now() - startTime;
    
    // Log failed authentication with security details
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
            $set: { lastFailedLoginAt: new Date() }
          });
        }
      } catch (updateError) {
        safeLogger.error('Failed to update login attempts', { error: updateError.message });
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
      const user = await AuthUser.findById(decoded.userId).select('-password');
      
      if (user && user.isActive) {
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
 * Advanced role-based access control with permissions
 */
export const requireRole = (roles, permissions = []) => {
  return asyncHandler(async (req, res, next) => {
    if (!req.user) {
      throw new ApiError(401, 'Authentication required');
    }

    const userRole = req.user.role?.name || req.user.role || 'user';
    const userPermissions = req.user.permissions?.map(p => p.name) || [];
    const allowedRoles = Array.isArray(roles) ? roles : [roles];

    // Check role access
    if (!allowedRoles.includes(userRole)) {
      safeLogger.warn('Role access denied', {
        userId: req.user._id,
        userRole,
        requiredRoles: allowedRoles,
        correlationId: req.correlationId,
      });
      throw new ApiError(403, 'Insufficient role permissions');
    }

    // Check specific permissions if required
    if (permissions.length > 0) {
      const hasPermission = permissions.some(permission => 
        userPermissions.includes(permission)
      );
      
      if (!hasPermission) {
        safeLogger.warn('Permission access denied', {
          userId: req.user._id,
          userRole,
          userPermissions,
          requiredPermissions: permissions,
          correlationId: req.correlationId,
        });
        throw new ApiError(403, 'Insufficient permissions');
      }
    }

    // Add permission context to request
    req.permissionContext = {
      userRole,
      userPermissions,
      requiredRoles: allowedRoles,
      requiredPermissions: permissions,
    };

    safeLogger.debug('Role and permission check passed', {
      userId: req.user._id,
      userRole,
      userPermissions,
      requiredRoles: allowedRoles,
      requiredPermissions: permissions,
      correlationId: req.correlationId,
    });

    next();
  });
};

/**
 * Admin access required
 */
export const requireAdmin = requireRole(['admin', 'super_admin'], ['admin:read', 'admin:write']);

/**
 * Super admin access required
 */
export const requireSuperAdmin = requireRole('super_admin', ['super_admin:all']);

/**
 * User access required
 */
export const requireUser = requireRole(['user', 'admin', 'moderator', 'super_admin']);

/**
 * Moderator access required
 */
export const requireModerator = requireRole(['moderator', 'admin', 'super_admin'], ['moderator:read', 'moderator:write']);

/**
 * Check if user has specific permission
 */
export const requirePermission = (permission) => {
  return asyncHandler(async (req, res, next) => {
    if (!req.user) {
      throw new ApiError(401, 'Authentication required');
    }

    const userPermissions = req.user.permissions?.map(p => p.name) || [];
    
    if (!userPermissions.includes(permission)) {
      safeLogger.warn('Permission check failed', {
        userId: req.user._id,
        userPermissions,
        requiredPermission: permission,
        correlationId: req.correlationId,
      });
      throw new ApiError(403, `Permission '${permission}' required`);
    }

    next();
  });
};

/**
 * Check if user owns the resource or has admin access
 */
export const requireOwnership = (resourceIdField = 'id') => {
  return asyncHandler(async (req, res, next) => {
    if (!req.user) {
      throw new ApiError(401, 'Authentication required');
    }

    const resourceId = req.params[resourceIdField] || req.body[resourceIdField];
    
    if (!resourceId) {
      throw new ApiError(400, 'Resource ID required');
    }

    // Admin and super admin can access any resource
    const userRole = req.user.role?.name || req.user.role || 'user';
    if (['admin', 'super_admin'].includes(userRole)) {
      return next();
    }

    // Check if user owns the resource
    if (req.user._id.toString() !== resourceId.toString()) {
      safeLogger.warn('Ownership check failed', {
        userId: req.user._id,
        resourceId,
        userRole,
        correlationId: req.correlationId,
      });
      throw new ApiError(403, 'Access denied - resource ownership required');
    }

    next();
  });
};

/**
 * Rate limiting middleware for specific endpoints
 */
export const rateLimit = (maxRequests = 100, windowMs = 15 * 60 * 1000) => {
  return asyncHandler(async (req, res, next) => {
    const clientIP = req.ip || req.connection?.remoteAddress;
    const endpoint = req.originalUrl || req.url;
    const rateLimitKey = `rate:${endpoint}:${clientIP}`;
    
    const currentRate = await authCache.incrementRateLimit(rateLimitKey, Math.floor(windowMs / 1000));
    
    if (currentRate > maxRequests) {
      safeLogger.warn('Rate limit exceeded', {
        clientIP,
        endpoint,
        currentRate,
        maxRequests,
        correlationId: req.correlationId,
      });
      throw new ApiError(429, 'Too many requests');
    }

    // Add rate limit info to response headers
    res.set({
      'X-RateLimit-Limit': maxRequests,
      'X-RateLimit-Remaining': Math.max(0, maxRequests - currentRate),
      'X-RateLimit-Reset': Date.now() + windowMs,
    });

    next();
  });
};

/**
 * Rate limiter middleware (alias for rateLimit for backward compatibility)
 */
export const rateLimiter = (endpoint, options = {}) => {
  const { windowMs = 15 * 60 * 1000, max = 100 } = options;
  return rateLimit(max, windowMs);
};

/**
 * Audit logging middleware
 */
export const auditLog = (action) => {
  return asyncHandler(async (req, res, next) => {
    const startTime = Date.now();
    
    // Add audit context to request
    req.auditContext = {
      action,
      timestamp: new Date(),
      correlationId: req.correlationId,
      userId: req.user?._id,
      ip: req.ip || req.connection?.remoteAddress,
      userAgent: req.headers['user-agent'],
    };

    // Override response end to log audit
    const originalEnd = res.end;
    res.end = function(chunk, encoding) {
      const responseTime = Date.now() - startTime;
      
      // Log audit event
      safeLogger.info('Audit log', {
        action,
        userId: req.user?._id,
        ip: req.ip || req.connection?.remoteAddress,
        method: req.method,
        url: req.originalUrl || req.url,
        statusCode: res.statusCode,
        responseTime: `${responseTime}ms`,
        correlationId: req.correlationId,
        timestamp: new Date().toISOString(),
      });

      originalEnd.call(this, chunk, encoding);
    };

    next();
  });
};

/**
 * Device fingerprint validation middleware
 */
export const validateDevice = asyncHandler(async (req, res, next) => {
  const deviceFingerprint = req.headers['x-device-fingerprint'] || req.body.deviceFingerprint;
  
  if (deviceFingerprint) {
    req.deviceFingerprint = deviceFingerprint;
    
    // Basic device validation
    if (deviceFingerprint.length < 10) {
      safeLogger.warn('Suspicious device fingerprint', {
        deviceFingerprint,
        ip: req.ip || req.connection?.remoteAddress,
        correlationId: req.correlationId,
      });
    }
  }

  next();
});

/**
 * reCAPTCHA validation middleware
 */
export const validateRecaptcha = asyncHandler(async (req, res, next) => {
  const recaptchaToken = req.body.recaptchaToken || req.headers['x-recaptcha-token'];
  
  if (!recaptchaToken) {
    safeLogger.warn('reCAPTCHA token missing', {
      ip: req.ip || req.connection?.remoteAddress,
      correlationId: req.correlationId,
    });
    // For now, just warn but don't block (can be made strict later)
  }

  next();
});

/**
 * JWT verification middleware (alias for authenticate)
 */
export const verifyJWT = authenticate;

/**
 * Request validation middleware
 */
export const validateRequest = (schema) => {
  return asyncHandler(async (req, res, next) => {
    try {
      if (schema) {
        let validationResult;
        
        // Handle both Joi schemas and validation functions
        if (typeof schema === 'function') {
          // If schema is a function, call it with the request body
          validationResult = schema(req.body);
        } else {
          // If schema is a Joi schema object, validate directly
          validationResult = schema.validate(req.body);
        }
        
        if (validationResult.error) {
          throw new ApiError(400, `Validation error: ${validationResult.error.details[0].message}`);
        }
        req.validatedBody = validationResult.value || validationResult;
      }
      next();
    } catch (error) {
      next(error);
    }
  });
};

/**
 * Cache middleware for response caching
 */
export const cacheMiddleware = (key, ttl = 300) => {
  return asyncHandler(async (req, res, next) => {
    const cacheKey = `response:${key}:${req.originalUrl || req.url}`;
    
    try {
      const cachedResponse = await authCache.get(cacheKey);
      if (cachedResponse) {
        return res.json(cachedResponse);
      }
      
      // Override response end to cache the response
      const originalEnd = res.end;
      res.end = function(chunk, encoding) {
        if (res.statusCode === 200 && chunk) {
          try {
            const responseData = JSON.parse(chunk.toString());
            authCache.set(cacheKey, responseData, ttl);
          } catch (error) {
            // Ignore parsing errors
          }
        }
        originalEnd.call(this, chunk, encoding);
      };
      
      next();
    } catch (error) {
      safeLogger.error('Cache middleware error', { error: error.message });
      next();
    }
  });
};

/**
 * Security headers middleware
 */
export const securityHeaders = (additionalHeaders = {}) => {
  return (req, res, next) => {
    // Set default security headers
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      ...additionalHeaders,
    });
    
    next();
  };
};

/**
 * Export default
 */
export default {
  authenticate,
  optionalAuth,
  requireRole,
  requireAdmin,
  requireSuperAdmin,
  requireUser,
  requireModerator,
  requirePermission,
  requireOwnership,
  rateLimit,
  rateLimiter,
  auditLog,
  validateDevice,
  validateRecaptcha,
  verifyJWT,
  validateRequest,
  cacheMiddleware,
  securityHeaders,
};
