// src/utils/ApiError.js
class ApiError extends Error {
  constructor(statusCode, message, errors = undefined, stack = '') {
    // Convert string status codes to numbers
    const numericStatusCode = Number(statusCode);

    // Validate status code
    if (isNaN(numericStatusCode)) {
      throw new Error('Invalid HTTP status code');
    }

    // Call parent constructor with message
    super(message || 'API Error');

    // Set properties
    this.statusCode = numericStatusCode;
    this.success = false;
    this.errors = errors;
    this.isOperational = true;
    this.timestamp = new Date().toISOString();

    // Handle stack trace
    if (stack) {
      this.stack = stack;
    } else {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  toString() {
    return `ApiError: ${this.message}`;
  }

  toJSON() {
    return {
      statusCode: this.statusCode,
      message: this.message,
      errors: this.errors,
      success: this.success,
      isOperational: this.isOperational,
      timestamp: this.timestamp,
    };
  }
}

export { ApiError };
