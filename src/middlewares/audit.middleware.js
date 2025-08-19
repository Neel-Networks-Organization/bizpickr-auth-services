import { safeLogger } from '../config/logger.js';
import { AuditLog, UserActivity } from '../models/index.model.js';
import mongoose from 'mongoose';
/**
 * Audit Middleware
 *
 * Features:
 * - Comprehensive request/response logging
 * - Security event tracking
 * - Compliance logging (GDPR, SOX, etc.)
 * - User activity monitoring
 * - Sensitive data detection and masking
 * - Audit trail generation
 * - Security incident detection
 * - Performance impact tracking
 * - Data retention policies
 * - Audit report generation
 */
// ✅ Audit Configuration
const AUDIT_CONFIG = {
  enabled: true,
  logLevel: 'info',
  maskSensitiveData: true,
  trackUserActivity: true,
  complianceMode: process.env.COMPLIANCE_MODE || 'standard', // standard, gdpr, sox, pci
  retentionDays: 90,
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
  securityEvents: true,
  performanceTracking: true,
};
// ✅ Audit Event Types
const AUDIT_EVENTS = {
  REQUEST_START: 'request_start',
  REQUEST_COMPLETE: 'request_complete',
  AUTH_SUCCESS: 'auth_success',
  AUTH_FAILURE: 'auth_failure',
  PERMISSION_DENIED: 'permission_denied',
  SENSITIVE_ACCESS: 'sensitive_access',
  ERROR_OCCURRED: 'error_occurred',
  SECURITY_VIOLATION: 'security_violation',
  DATA_ACCESS: 'data_access',
  CONFIGURATION_CHANGE: 'configuration_change',
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
  return sensitivePaths.some(path => req.path.includes(path));
}
/**
 * Check for security violations
 */
function detectSecurityViolations(req) {
  const violations = [];
  // ✅ Check for suspicious headers
  const suspiciousHeaders = ['x-forwarded-for', 'x-real-ip'];
  for (const header of suspiciousHeaders) {
    if (req.headers[header] && req.headers[header] !== req.ip) {
      violations.push({
        type: 'suspicious_header',
        header,
        value: req.headers[header],
        expected: req.ip,
      });
    }
  }
  // ✅ Check for SQL injection patterns
  const sqlInjectionPatterns = [
    /(\b(union|select|insert|update|delete|drop|create|alter)\b)/i,
    /(\b(or|and)\b\s+\d+\s*=\s*\d+)/i,
    /(\b(union|select)\b.*\bfrom\b)/i,
  ];
  const requestString =
    JSON.stringify(req.body) + JSON.stringify(req.query) + req.path;
  for (const pattern of sqlInjectionPatterns) {
    if (pattern.test(requestString)) {
      violations.push({
        type: 'sql_injection_attempt',
        pattern: pattern.source,
        requestString: requestString.substring(0, 100) + '...',
      });
    }
  }
  // ✅ Check for XSS patterns
  const xssPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
  ];
  for (const pattern of xssPatterns) {
    if (pattern.test(requestString)) {
      violations.push({
        type: 'xss_attempt',
        pattern: pattern.source,
        requestString: requestString.substring(0, 100) + '...',
      });
    }
  }
  return violations;
}
/**
 * Create audit event
 */
function createAuditEvent(type, req, res, additionalData = {}) {
  const userInfo = extractUserInfo(req);
  const event = {
    id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    type,
    timestamp: new Date().toISOString(),
    user: userInfo,
    request: {
      method: req.method,
      url: req.url,
      path: req.path,
      query: AUDIT_CONFIG.includeBody
        ? maskSensitiveData(req.query)
        : undefined,
      body: AUDIT_CONFIG.includeBody ? maskSensitiveData(req.body) : undefined,
      headers: AUDIT_CONFIG.includeHeaders.reduce((acc, header) => {
        if (req.headers[header]) {
          acc[header] = maskSensitiveData({ [header]: req.headers[header] })[
            header
          ];
        }
        return acc;
      }, {}),
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      correlationId: req.correlationId,
    },
    response: res
      ? {
          statusCode: res.statusCode,
          statusMessage: res.statusMessage,
          headers: res.getHeaders ? res.getHeaders() : {},
          responseTime: req.performanceContext
            ? performance.now() - req.performanceContext.startTime
            : undefined,
        }
      : undefined,
    ...additionalData,
  };
  return event;
}
/**
 * Log audit event
 */
export async function logAuditEvent(event) {
  if (!AUDIT_CONFIG.enabled) return;
  try {
    // Set userId directly since we're using String type for MySQL UUID compatibility
    const auditUserId = event.user?.userId || null;

    await AuditLog.create({
      userId: auditUserId,
      action: event.type,
      resourceType: event.resourceType,
      resourceId: event.resourceId,
      details: event.details,
      ipAddress: event.ipAddress,
      userAgent: event.userAgent,
      status: event.status || 'success',
      severity: event.severity || 'low',
      metadata: event.metadata,
      createdAt: event.timestamp || new Date(),
    });

    // Optionally, also log to UserActivity if it's a user action
    if (
      event.user &&
      auditUserId &&
      event.type &&
      (event.type.startsWith('user_') ||
        event.type === 'USER_REGISTERED' ||
        event.type === 'USER_LOGIN' ||
        event.type === 'USER_LOGOUT' ||
        event.type === 'PASSWORD_CHANGE' ||
        event.type === 'EMAIL_VERIFICATION')
    ) {
      safeLogger.info('Creating UserActivity document', {
        userId: auditUserId,
        action: event.type,
        event: event,
      });

      await UserActivity.create({
        userId: auditUserId,
        action: event.type,
        description: event.description,
        severity: event.severity || 'low',
        category: event.category || 'system',
        ipAddress: event.ipAddress,
        userAgent: event.userAgent,
        metadata: event.metadata,
        status: event.status || 'success',
        createdAt: event.timestamp || new Date(),
      });
    } else {
      safeLogger.debug('UserActivity condition not met', {
        hasUser: !!event.user,
        auditUserId: auditUserId,
        eventType: event.type,
        condition:
          event.type &&
          (event.type.startsWith('user_') ||
            event.type === 'USER_REGISTERED' ||
            event.type === 'USER_LOGIN' ||
            event.type === 'USER_LOGOUT' ||
            event.type === 'PASSWORD_CHANGE' ||
            event.type === 'EMAIL_VERIFICATION'),
      });
    }

    // Only log to main logger if not production, or if critical event
    const isProduction = process.env.NODE_ENV === 'production';
    const isCritical =
      event.type &&
      (event.type.includes('violation') || event.type.includes('error'));
    if (!isProduction || isCritical) {
      const logLevel =
        event.type &&
        (event.type.includes('violation') || event.type.includes('error'))
          ? 'warn'
          : 'info';
      safeLogger[logLevel]('Audit event', event);
    }
  } catch (err) {
    safeLogger.error('Failed to persist audit event', {
      error: err.message,
      event,
    });
  }
}
/**
 * Main audit middleware
 */
export const auditMiddleware = (req, res, next) => {
  if (!AUDIT_CONFIG.enabled) return next();
  // ✅ Skip excluded paths
  if (AUDIT_CONFIG.excludedPaths.some(path => req.path.includes(path))) {
    return next();
  }
  const startTime = Date.now();
  // ✅ Log request start
  const startEvent = createAuditEvent(AUDIT_EVENTS.REQUEST_START, req);
  logAuditEvent(startEvent);
  // ✅ Detect security violations
  const violations = detectSecurityViolations(req);
  if (violations.length > 0) {
    const securityEvent = createAuditEvent(
      AUDIT_EVENTS.SECURITY_VIOLATION,
      req,
      null,
      {
        violations,
        severity: 'high',
      }
    );
    logAuditEvent(securityEvent);
  }
  // ✅ Track sensitive requests
  if (isSensitiveRequest(req)) {
    const sensitiveEvent = createAuditEvent(
      AUDIT_EVENTS.SENSITIVE_ACCESS,
      req,
      null,
      {
        sensitivity: 'high',
        dataType: 'authentication',
      }
    );
    logAuditEvent(sensitiveEvent);
  }
  // ✅ Override response methods to capture response data
  const originalSend = res.send;
  const originalJson = res.json;
  const originalEnd = res.end;
  res.send = function (data) {
    const responseTime = Date.now() - startTime;
    const completeEvent = createAuditEvent(
      AUDIT_EVENTS.REQUEST_COMPLETE,
      req,
      res,
      {
        responseTime,
        responseSize:
          typeof data === 'string' ? data.length : JSON.stringify(data).length,
      }
    );
    logAuditEvent(completeEvent);
    return originalSend.call(this, data);
  };
  res.json = function (data) {
    const responseTime = Date.now() - startTime;
    const completeEvent = createAuditEvent(
      AUDIT_EVENTS.REQUEST_COMPLETE,
      req,
      res,
      {
        responseTime,
        responseSize: JSON.stringify(data).length,
      }
    );
    logAuditEvent(completeEvent);
    return originalJson.call(this, data);
  };
  res.end = function (data) {
    const responseTime = Date.now() - startTime;
    const completeEvent = createAuditEvent(
      AUDIT_EVENTS.REQUEST_COMPLETE,
      req,
      res,
      {
        responseTime,
        responseSize: data ? data.length : 0,
      }
    );
    logAuditEvent(completeEvent);
    return originalEnd.call(this, data);
  };
  // ✅ Track errors
  const originalNext = next;
  next = function (err) {
    if (err) {
      const errorEvent = createAuditEvent(
        AUDIT_EVENTS.ERROR_OCCURRED,
        req,
        res,
        {
          error: {
            message: err.message,
            stack: err.stack,
            name: err.name,
          },
        }
      );
      logAuditEvent(errorEvent);
    }
    originalNext.call(this, err);
  };
  next();
};
/**
 * Authentication audit middleware
 */
export const authAuditMiddleware = (req, res, next) => {
  if (!AUDIT_CONFIG.enabled) return next();
  const originalNext = next;
  next = function (err) {
    if (req.user) {
      // ✅ Log successful authentication
      const authEvent = createAuditEvent(AUDIT_EVENTS.AUTH_SUCCESS, req, res, {
        authMethod: req.authMethod || 'jwt',
        sessionDuration: req.session?.duration,
        lastLogin: req.user.lastLogin,
      });
      logAuditEvent(authEvent);
    } else if (err && err.status === 401) {
      // ✅ Log authentication failure
      const authFailureEvent = createAuditEvent(
        AUDIT_EVENTS.AUTH_FAILURE,
        req,
        res,
        {
          error: err.message,
          authMethod: req.authMethod || 'jwt',
          attemptCount: req.authAttempts || 1,
        }
      );
      logAuditEvent(authFailureEvent);
    }
    originalNext.call(this, err);
  };
  next();
};
/**
 * Permission audit middleware
 */
export const permissionAuditMiddleware = (req, res, next) => {
  if (!AUDIT_CONFIG.enabled) return next();
  const originalNext = next;
  next = function (err) {
    if (err && err.status === 403) {
      const permissionEvent = createAuditEvent(
        AUDIT_EVENTS.PERMISSION_DENIED,
        req,
        res,
        {
          requiredPermissions: req.requiredPermissions || [],
          userPermissions: req.user?.permissions || [],
          resource: req.path,
          action: req.method,
        }
      );
      logAuditEvent(permissionEvent);
    }
    originalNext.call(this, err);
  };
  next();
};
/**
 * Get audit log
 */
export async function getAuditLog(options = {}) {
  const {
    type,
    userId,
    startDate,
    endDate,
    limit = 1000,
    status,
    severity,
  } = options;
  const query = {};
  if (type) query.action = type;
  if (userId) query.userId = userId;
  if (status) query.status = status;
  if (severity) query.severity = severity;
  if (startDate || endDate) {
    query.createdAt = {};
    if (startDate) query.createdAt.$gte = new Date(startDate);
    if (endDate) query.createdAt.$lte = new Date(endDate);
  }
  return AuditLog.find(query).sort({ createdAt: -1 }).limit(limit).lean();
}
/**
 * Get security events
 */
export async function getSecurityEvents(limit = 100) {
  return AuditLog.find({ action: { $regex: /security|violation/i } })
    .sort({ createdAt: -1 })
    .limit(limit)
    .lean();
}
/**
 * Get user activity
 */
export async function getUserActivity(userId, limit = 100) {
  return UserActivity.find({ userId })
    .sort({ createdAt: -1 })
    .limit(limit)
    .lean();
}
/**
 * Generate audit report
 */
export async function generateAuditReport(options = {}) {
  const { startDate, endDate, userId } = options;
  const query = {};
  if (startDate)
    query.createdAt = { ...query.createdAt, $gte: new Date(startDate) };
  if (endDate)
    query.createdAt = { ...query.createdAt, $lte: new Date(endDate) };
  if (userId) query.userId = userId;
  const events = await AuditLog.find(query).lean();
  const report = {
    period: { startDate, endDate },
    totalEvents: events.length,
    eventTypes: {},
    userActivity: {},
    securityEvents: events.filter(
      e => e.action.includes('security') || e.action.includes('violation')
    ).length,
    errors: events.filter(e => e.action.includes('error')).length,
    averageResponseTime:
      events.reduce((sum, e) => sum + (e.response?.responseTime || 0), 0) /
      (events.length || 1),
    topUsers: {},
    topEndpoints: {},
  };
  // Event type distribution
  events.forEach(event => {
    report.eventTypes[event.action] =
      (report.eventTypes[event.action] || 0) + 1;
  });
  // User activity
  events.forEach(event => {
    const uid = event.userId?.toString();
    if (uid) report.userActivity[uid] = (report.userActivity[uid] || 0) + 1;
  });
  // Top users
  Object.entries(report.userActivity)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 10)
    .forEach(([uid, count]) => {
      report.topUsers[uid] = count;
    });
  // Top endpoints (if available)
  const endpointCounts = {};
  events.forEach(event => {
    if (event.request && event.request.method && event.request.path) {
      const endpoint = `${event.request.method} ${event.request.path}`;
      endpointCounts[endpoint] = (endpointCounts[endpoint] || 0) + 1;
    }
  });
  Object.entries(endpointCounts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 10)
    .forEach(([endpoint, count]) => {
      report.topEndpoints[endpoint] = count;
    });
  return report;
}
/**
 * Clear audit log
 */
export async function clearAuditLog() {
  await AuditLog.deleteMany({});
  await UserActivity.deleteMany({});
}
export default auditMiddleware;
