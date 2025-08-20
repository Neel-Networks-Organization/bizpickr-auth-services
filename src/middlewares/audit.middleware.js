import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import { AuditLog, UserActivity } from '../models/index.model.js';

/**
 * Smart Audit Middleware
 * Essential audit logging for compliance and security
 */

/**
 * Audit configuration
 */
const AUDIT_CONFIG = {
  enabled: true,
  logLevel: 'info',
  maskSensitiveData: true,
  trackUserActivity: true,
  sensitiveFields: [
    'password',
    'token',
    'secret',
    'key',
    'authorization',
    'cookie',
  ],
  excludedPaths: ['/health', '/metrics', '/favicon.ico'],
  includeHeaders: [
    'user-agent',
    'x-forwarded-for',
    'x-real-ip',
    'authorization',
  ],
  includeBody: process.env.NODE_ENV === 'development',
};

/**
 * Mask sensitive data in objects
 */
function maskSensitiveData(
  data,
  sensitiveFields = AUDIT_CONFIG.sensitiveFields
) {
  if (!data || typeof data !== 'object') return data;

  const masked = { ...data };
  for (const field of sensitiveFields) {
    if (masked[field]) {
      masked[field] = '***MASKED***';
    }
  }
  return masked;
}

/**
 * Extract user information from request
 */
function extractUserInfo(req) {
  return {
    userId: req.user?.id || req.user?.userId || 'anonymous',
    username: req.user?.username || req.user?.email || 'anonymous',
    roles: req.user?.roles || [],
    permissions: req.user?.permissions || [],
    ip: req.ip || req.connection?.remoteAddress,
    userAgent: req.get('User-Agent'),
    sessionId: req.session?.id || req.cookies?.sessionId,
    correlationId: req.correlationId,
  };
}

/**
 * Determine if request contains sensitive data
 */
function isSensitiveRequest(req) {
  const sensitivePaths = [
    '/auth/login',
    '/auth/register',
    '/auth/password',
    '/admin',
    '/jwk',
  ];

  return sensitivePaths.some(path => req.path.startsWith(path));
}

/**
 * Main audit middleware
 */
export const auditMiddleware = (options = {}) => {
  const config = { ...AUDIT_CONFIG, ...options };

  return async (req, res, next) => {
    if (!config.enabled) {
      return next();
    }

    const correlationId = getCorrelationId();
    const startTime = Date.now();

    try {
      // Skip audit for excluded paths
      if (config.excludedPaths.some(path => req.path.startsWith(path))) {
        return next();
      }

      // Extract request information
      const requestInfo = {
        method: req.method,
        url: req.originalUrl || req.url,
        path: req.path,
        query: config.includeBody ? maskSensitiveData(req.query) : undefined,
        body: config.includeBody ? maskSensitiveData(req.body) : undefined,
        headers: config.includeHeaders.reduce((acc, header) => {
          if (req.headers[header]) {
            acc[header] = req.headers[header];
          }
          return acc;
        }, {}),
        ip: req.ip || req.connection?.remoteAddress,
        userAgent: req.get('User-Agent'),
        timestamp: new Date(),
        correlationId,
      };

      // Extract user information
      const userInfo = extractUserInfo(req);

      // Log request start
      safeLogger.info('Audit: Request started', {
        ...requestInfo,
        ...userInfo,
        event: 'request_start',
      });

      // Override response end to log completion
      const originalEnd = res.end;
      res.end = async function (...args) {
        const responseTime = Date.now() - startTime;

        try {
          // Create audit log entry
          const auditData = {
            userId: userInfo.userId,
            action: req.method,
            resourceType: 'http_request',
            resourceId: req.path,
            details: {
              method: req.method,
              path: req.path,
              statusCode: res.statusCode,
              responseTime: `${responseTime}ms`,
              userAgent: userInfo.userAgent,
              ip: userInfo.ip,
            },
            ipAddress: userInfo.ip,
            userAgent: userInfo.userAgent,
            status: res.statusCode < 400 ? 'success' : 'error',
            severity:
              res.statusCode >= 500
                ? 'high'
                : res.statusCode >= 400
                  ? 'medium'
                  : 'low',
            timestamp: new Date(),
            correlationId,
          };

          // Save audit log to database
          try {
            await AuditLog.create(auditData);
          } catch (dbError) {
            safeLogger.error('Failed to save audit log', {
              error: dbError.message,
              correlationId,
            });
          }

          // Log request completion
          safeLogger.info('Audit: Request completed', {
            ...requestInfo,
            ...userInfo,
            event: 'request_complete',
            statusCode: res.statusCode,
            responseTime: `${responseTime}ms`,
            auditId: auditData._id,
          });

          // Track user activity for sensitive operations
          if (
            config.trackUserActivity &&
            isSensitiveRequest(req) &&
            userInfo.userId !== 'anonymous'
          ) {
            try {
              const activityData = {
                userId: userInfo.userId,
                action: `${req.method} ${req.path}`,
                details: {
                  method: req.method,
                  path: req.path,
                  statusCode: res.statusCode,
                  responseTime: `${responseTime}ms`,
                  ip: userInfo.ip,
                  userAgent: userInfo.userAgent,
                },
                ipAddress: userInfo.ip,
                userAgent: userInfo.userAgent,
                timestamp: new Date(),
                correlationId,
              };

              await UserActivity.create(activityData);
            } catch (activityError) {
              safeLogger.error('Failed to save user activity', {
                error: activityError.message,
                correlationId,
              });
            }
          }
        } catch (error) {
          safeLogger.error('Audit logging error', {
            error: error.message,
            correlationId,
          });
        }

        originalEnd.apply(this, args);
      };

      next();
    } catch (error) {
      safeLogger.error('Audit middleware error', {
        error: error.message,
        correlationId,
      });
      next();
    }
  };
};

/**
 * Security event logging middleware
 */
export const securityEventLogger = (event, details = {}) => {
  return async (req, res, next) => {
    const correlationId = getCorrelationId();

    try {
      const userInfo = extractUserInfo(req);

      const securityData = {
        userId: userInfo.userId,
        action: event,
        resourceType: 'security_event',
        resourceId: req.path,
        details: {
          ...details,
          method: req.method,
          path: req.path,
          ip: userInfo.ip,
          userAgent: userInfo.userAgent,
        },
        ipAddress: userInfo.ip,
        userAgent: userInfo.userAgent,
        status: 'detected',
        severity: 'medium',
        timestamp: new Date(),
        correlationId,
      };

      // Save security event to audit log
      try {
        await AuditLog.create(securityData);

        safeLogger.warn('Security event logged', {
          event,
          userId: userInfo.userId,
          path: req.path,
          correlationId,
          auditId: securityData._id,
        });
      } catch (dbError) {
        safeLogger.error('Failed to save security event', {
          error: dbError.message,
          correlationId,
        });
      }

      next();
    } catch (error) {
      safeLogger.error('Security event logger error', {
        error: error.message,
        correlationId,
      });
      next();
    }
  };
};

/**
 * Data access logging middleware
 */
export const dataAccessLogger = (resourceType, resourceId) => {
  return async (req, res, next) => {
    const correlationId = getCorrelationId();

    try {
      const userInfo = extractUserInfo(req);

      const accessData = {
        userId: userInfo.userId,
        action: req.method,
        resourceType: resourceType || 'data',
        resourceId: resourceId || req.params.id || req.path,
        details: {
          method: req.method,
          path: req.path,
          ip: userInfo.ip,
          userAgent: userInfo.userAgent,
        },
        ipAddress: userInfo.ip,
        userAgent: userInfo.userAgent,
        status: 'accessed',
        severity: 'low',
        timestamp: new Date(),
        correlationId,
      };

      // Save data access log
      try {
        await AuditLog.create(accessData);
      } catch (dbError) {
        safeLogger.error('Failed to save data access log', {
          error: dbError.message,
          correlationId,
        });
      }

      next();
    } catch (error) {
      safeLogger.error('Data access logger error', {
        error: error.message,
        correlationId,
      });
      next();
    }
  };
};

/**
 * Get audit statistics
 */
export const getAuditStats = async () => {
  try {
    const totalLogs = await AuditLog.countDocuments();
    const totalActivities = await UserActivity.countDocuments();

    return {
      totalAuditLogs: totalLogs,
      totalUserActivities: totalActivities,
      config: AUDIT_CONFIG,
    };
  } catch (error) {
    safeLogger.error('Failed to get audit stats', { error: error.message });
    return { error: 'Failed to fetch audit statistics' };
  }
};

export default {
  auditMiddleware,
  securityEventLogger,
  dataAccessLogger,
  getAuditStats,
};
