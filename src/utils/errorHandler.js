/**
 * Simple Error Handler Utility
 * Provides consistent error responses across the service
 */

export class ServiceError extends Error {
  constructor(message, statusCode = 500, details = []) {
    super(message);
    this.name = 'ServiceError';
    this.statusCode = statusCode;
    this.details = details;
    this.timestamp = new Date().toISOString();
  }
}

export class ValidationError extends ServiceError {
  constructor(message, details = []) {
    super(message, 400, details);
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends ServiceError {
  constructor(message = 'Authentication failed', details = []) {
    super(message, 401, details);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends ServiceError {
  constructor(message = 'Access denied', details = []) {
    super(message, 403, details);
    this.name = 'AuthorizationError';
  }
}

export class NotFoundError extends ServiceError {
  constructor(message = 'Resource not found', details = []) {
    super(message, 404, details);
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends ServiceError {
  constructor(message = 'Resource conflict', details = []) {
    super(message, 409, details);
    this.name = 'ConflictError';
  }
}

export class RateLimitError extends ServiceError {
  constructor(message = 'Rate limit exceeded', details = []) {
    super(message, 429, details);
    this.name = 'RateLimitError';
  }
}

export class ServiceUnavailableError extends ServiceError {
  constructor(message = 'Service temporarily unavailable', details = []) {
    super(message, 503, details);
    this.name = 'ServiceUnavailableError';
  }
}

/**
 * Format error response
 */
export function formatError(error, req) {
  const errorResponse = {
    error: {
      name: error.name || 'Error',
      message: error.message || 'An error occurred',
      statusCode: error.statusCode || 500,
      timestamp: error.timestamp || new Date().toISOString(),
      path: req?.path || 'unknown',
      method: req?.method || 'unknown'
    }
  };

  // Add details if available
  if (error.details && error.details.length > 0) {
    errorResponse.error.details = error.details;
  }

  // Add stack trace in development
  if (process.env.NODE_ENV === 'development' && error.stack) {
    errorResponse.error.stack = error.stack;
  }

  // Add correlation ID if available
  if (req?.correlationId) {
    errorResponse.error.correlationId = req.correlationId;
  }

  return errorResponse;
}

/**
 * Handle async errors in route handlers
 */
export function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/**
 * Global error handler middleware
 */
export function globalErrorHandler(error, req, res, next) {
  const errorResponse = formatError(error, req);
  
  // Log error
  console.error('Error occurred:', {
    error: error.message,
    stack: error.stack,
    path: req?.path,
    method: req?.method,
    correlationId: req?.correlationId
  });

  // Send error response
  res.status(errorResponse.error.statusCode).json(errorResponse);
}
