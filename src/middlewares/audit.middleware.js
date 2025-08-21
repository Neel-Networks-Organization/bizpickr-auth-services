import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';

/**
 * Audit Middleware
 * Core audit logging functionality
 */

/**
 * Log audit event to database and logger
 */
export const logAuditEvent = async eventData => {
  const correlationId = getCorrelationId();

  try {
    const auditLog = {
      ...eventData,
      correlationId,
      timestamp: new Date(),
      ipAddress: eventData.ipAddress || 'unknown',
      userAgent: eventData.userAgent || 'unknown',
      status: eventData.status || 'info',
      severity: eventData.severity || 'low',
    };

    // Log to console/logger
    safeLogger.info('Audit Event', auditLog);

    // TODO: Save to database when AuditLog model is ready
    // await AuditLog.create(auditLog);

    return true;
  } catch (error) {
    safeLogger.error('Failed to log audit event', {
      error: error.message,
      eventData,
      correlationId,
    });
    return false;
  }
};

export default {
  logAuditEvent,
};
