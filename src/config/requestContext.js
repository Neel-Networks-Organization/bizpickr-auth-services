import { AsyncLocalStorage } from 'async_hooks';
import { v4 as uuidv4 } from 'uuid';
import { safeLogger } from './logger.js';

/**
 * Request Context Management
 *
 * Features:
 * - AsyncLocalStorage for request context
 * - Correlation ID generation and tracking
 * - Request metadata management
 * - Performance monitoring
 * - Security context
 * - Audit trail support
 */

// ✅ AsyncLocalStorage for request context
const asyncLocalStorage = new AsyncLocalStorage();

// ✅ Request context structure
const createRequestContext = (req = null) => ({
  // Core identifiers
  correlationId: req?.headers['x-correlation-id'] || uuidv4(),
  requestId: req?.headers['x-request-id'] || uuidv4(),
  sessionId: req?.headers['x-session-id'] || null,

  // User context
  userId: null,
  userRole: null,
  userPermissions: [],

  // Request metadata
  method: req?.method || null,
  url: req?.url || null,
  userAgent: req?.headers['user-agent'] || null,
  ipAddress: req?.ip || req?.connection?.remoteAddress || null,

  // Performance tracking
  startTime: Date.now(),
  timers: new Map(),

  // Security context
  isAuthenticated: false,
  authToken: req?.headers?.authorization || null,
  clientVersion: req?.headers['x-client-version'] || null,
  clientPlatform: req?.headers['x-client-platform'] || null,

  // Business context
  tenantId: req?.headers['x-tenant-id'] || null,
  organizationId: req?.headers['x-organization-id'] || null,

  // Audit trail
  auditEvents: [],

  // Error tracking
  errors: [],

  // Custom metadata
  metadata: new Map(),
});

// ✅ Get current request context
const getRequestContext = () => {
  const context = asyncLocalStorage.getStore();
  if (!context) {
    safeLogger.warn('No request context found, creating default context');
    return createRequestContext();
  }
  return context;
};

// ✅ Set request context
const setRequestContext = context => {
  asyncLocalStorage.enterWith(context);
};

// ✅ Get correlation ID
export const getCorrelationId = () => {
  const context = getRequestContext();
  return context.correlationId;
};

// ✅ Get request ID
export const getRequestId = () => {
  const context = getRequestContext();
  return context.requestId;
};

// ✅ Set user context
const setUserContext = (userId, userRole, permissions = []) => {
  const context = getRequestContext();
  context.userId = userId;
  context.userRole = userRole;
  context.userPermissions = permissions;
  context.isAuthenticated = true;
};

// ✅ Get user context
const getUserContext = () => {
  const context = getRequestContext();
  return {
    userId: context.userId,
    userRole: context.userRole,
    userPermissions: context.userPermissions,
    isAuthenticated: context.isAuthenticated,
  };
};

// ✅ Add audit event
const addAuditEvent = (event, details = {}) => {
  const context = getRequestContext();
  context.auditEvents.push({
    event,
    details,
    timestamp: new Date().toISOString(),
    correlationId: context.correlationId,
  });
};

// ✅ Add error to context
const addError = error => {
  const context = getRequestContext();
  context.errors.push({
    message: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString(),
    correlationId: context.correlationId,
  });
};

// ✅ Add metadata
const addMetadata = (key, value) => {
  const context = getRequestContext();
  context.metadata.set(key, value);
};

// ✅ Get metadata
const getMetadata = key => {
  const context = getRequestContext();
  return context.metadata.get(key);
};

// ✅ Start timer
const startTimer = name => {
  const context = getRequestContext();
  context.timers.set(name, Date.now());
};

// ✅ End timer
const endTimer = name => {
  const context = getRequestContext();
  const startTime = context.timers.get(name);
  if (startTime) {
    const duration = Date.now() - startTime;
    context.timers.delete(name);
    return duration;
  }
  return null;
};

// ✅ Get timer duration
const getTimerDuration = name => {
  const context = getRequestContext();
  const startTime = context.timers.get(name);
  if (startTime) {
    return Date.now() - startTime;
  }
  return null;
};

// ✅ Get context summary
const getContextSummary = () => {
  const context = getRequestContext();
  return {
    correlationId: context.correlationId,
    requestId: context.requestId,
    userId: context.userId,
    method: context.method,
    url: context.url,
    duration: Date.now() - context.startTime,
    errorCount: context.errors.length,
    auditEventCount: context.auditEvents.length,
    metadataCount: context.metadata.size,
  };
};

// ✅ Clear context
const clearContext = () => {
  asyncLocalStorage.disable();
};

// ✅ Middleware to set up request context
export const correlationIdMiddleware = (req, res, next) => {
  const context = createRequestContext(req);

  // Set correlation ID in response headers
  res.setHeader('x-correlation-id', context.correlationId);
  res.setHeader('x-request-id', context.requestId);

  // Add context to request
  req.correlationId = context.correlationId;
  req.requestId = context.requestId;

  // Run request in async context
  asyncLocalStorage.run(context, () => {
    next();
  });
};

// ✅ Export all functions
export {
  createRequestContext,
  setRequestContext,
  getUserContext,
  addAuditEvent,
  addError,
  addMetadata,
  getMetadata,
  startTimer,
  endTimer,
  getTimerDuration,
  getContextSummary,
  clearContext,
};
