import {
  getCorrelationId,
  getRequestMetadata,
} from '../config/requestContext.js';
import { safeLogger } from '../config/logger.js';

export const logAuditEvent = async (eventType, eventData) => {
  const correlationId = getCorrelationId();
  const requestMetadata = getRequestMetadata();

  try {
    const auditLog = {
      eventType,
      ...eventData,
      correlationId,
      timestamp: new Date(),
      ipAddress: requestMetadata.ipAddress,
      userAgent: requestMetadata.userAgent,
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
