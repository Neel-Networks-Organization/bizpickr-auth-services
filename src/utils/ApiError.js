// src/utils/ApiError.js
class ApiError extends Error {
  constructor(statusCode, message, errors = undefined, stack = '') {
    // Convert string status codes to numbers
    const numericStatusCode = Number(statusCode);
    // More flexible status code validation - allow negative numbers too
    if (isNaN(numericStatusCode)) {
      throw new Error('Invalid HTTP status code');
    }
    super(message);
    this.statusCode = numericStatusCode;
    this.message = message; // Keep the original message (can be undefined if explicitly passed)
    this.success = false;
    this.errors = errors;
    this.isOperational = true;
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
    };
  }
}
export { ApiError };
