import { AsyncLocalStorage } from 'async_hooks';
import { v4 as uuidv4 } from 'uuid';
import { safeLogger } from './logger.js';

/**
 * Request Context Management - Industry Standard
 *
 * Purpose: Request tracing and correlation for distributed systems
 * Features:
 * - AsyncLocalStorage for request context
 * - Correlation ID generation and tracking
 * - Request metadata for distributed tracing
 * - Header propagation for microservices
 * - Industry-standard tracing headers
 */

// ✅ AsyncLocalStorage for request context
const asyncLocalStorage = new AsyncLocalStorage();

// ✅ Industry-standard request context structure
const createRequestContext = (req = null) => ({
  // ✅ CORRECT - Request tracing identifiers
  correlationId: req?.headers['x-correlation-id'] || uuidv4(),
  requestId: req?.headers['x-request-id'] || uuidv4(),
  traceId: req?.headers['x-trace-id'] || uuidv4(),
  spanId: req?.headers['x-span-id'] || uuidv4(),

  // ✅ CORRECT - Basic request metadata
  method: req?.method || null,
  url: req?.url || null,
  userAgent: req?.headers['user-agent'] || null,
  ipAddress: req?.ip || req?.connection?.remoteAddress || null,

  // ✅ CORRECT - Request lifecycle timestamp
  startTime: Date.now(),

  // ✅ CORRECT - Headers for propagation
  headers: req?.headers || {},

  // ✅ CORRECT - Request path and query
  path: req?.path || null,
  query: req?.query || null,

  // ✅ CORRECT - Content type and length
  contentType: req?.headers['content-type'] || null,
  contentLength: req?.headers['content-length'] || null,
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

// ✅ Get trace ID
export const getTraceId = () => {
  const context = getRequestContext();
  return context.traceId;
};

// ✅ Get span ID
export const getSpanId = () => {
  const context = getRequestContext();
  return context.spanId;
};

// ✅ Get request metadata
export const getRequestMetadata = () => {
  const context = getRequestContext();
  return {
    method: context.method,
    url: context.url,
    path: context.path,
    ipAddress: context.ipAddress,
    userAgent: context.userAgent,
    contentType: context.contentType,
    contentLength: context.contentLength,
  };
};

// ✅ Get context summary for logging
export const getContextSummary = () => {
  const context = getRequestContext();
  return {
    correlationId: context.correlationId,
    requestId: context.requestId,
    traceId: context.traceId,
    spanId: context.spanId,
    method: context.method,
    url: context.url,
    path: context.path,
    duration: Date.now() - context.startTime,
  };
};

// ✅ Clear context
const clearContext = () => {
  asyncLocalStorage.disable();
};

// ✅ Middleware to set up request context
export const correlationIdMiddleware = (req, res, next) => {
  const context = createRequestContext(req);

  // ✅ Set industry-standard tracing headers in response
  res.setHeader('x-correlation-id', context.correlationId);
  res.setHeader('x-request-id', context.requestId);
  res.setHeader('x-trace-id', context.traceId);
  res.setHeader('x-span-id', context.spanId);

  // ✅ Add context to request for easy access
  req.correlationId = context.correlationId;
  req.requestId = context.requestId;
  req.traceId = context.traceId;
  req.spanId = context.spanId;

  // ✅ Run request in async context
  asyncLocalStorage.run(context, () => {
    next();
  });
};

// ✅ Export only industry-standard functions
export { createRequestContext, setRequestContext, clearContext };
