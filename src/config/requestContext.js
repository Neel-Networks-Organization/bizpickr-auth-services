import { AsyncLocalStorage } from 'async_hooks';
import { v4 as uuidv4 } from 'uuid';

const asyncLocalStorage = new AsyncLocalStorage();

const createRequestContext = (req = null) => ({
  correlationId: req?.headers['x-correlation-id'] || uuidv4(),
  requestId: req?.headers['x-request-id'] || uuidv4(),
  traceId: req?.headers['x-trace-id'] || uuidv4(),
  spanId: req?.headers['x-span-id'] || uuidv4(),

  method: req?.method || null,
  url: req?.url || null,
  userAgent: req?.headers['user-agent'] || null,
  ipAddress: req?.ip || req?.connection?.remoteAddress || null,

  startTime: Date.now(),

  headers: req?.headers || {},

  path: req?.path || null,
  query: req?.query || null,

  contentType: req?.headers['content-type'] || null,
  contentLength: req?.headers['content-length'] || null,
});

const getRequestContext = () => {
  const context = asyncLocalStorage.getStore();
  if (!context) {
    return createRequestContext();
  }
  return context;
};

const setRequestContext = context => {
  asyncLocalStorage.enterWith(context);
};

export const getCorrelationId = () => {
  const context = getRequestContext();
  return context.correlationId;
};

export const getRequestId = () => {
  const context = getRequestContext();
  return context.requestId;
};

export const getTraceId = () => {
  const context = getRequestContext();
  return context.traceId;
};

export const getSpanId = () => {
  const context = getRequestContext();
  return context.spanId;
};

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

const clearContext = () => {
  asyncLocalStorage.disable();
};

export {
  createRequestContext,
  setRequestContext,
  clearContext,
  asyncLocalStorage,
};
