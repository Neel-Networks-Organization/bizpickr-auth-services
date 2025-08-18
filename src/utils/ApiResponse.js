// src/utils/ApiResponse.js
class ApiResponse {
  constructor(statusCode, data, message, details = undefined) {
    // Convert string status codes to numbers
    const numericStatusCode = Number(statusCode);
    // Validate status code
    if (isNaN(numericStatusCode) || numericStatusCode < 0) {
      throw new Error('Invalid HTTP status code');
    }
    this.statusCode = numericStatusCode;
    this.data = data;
    this.message = message;
    this.success = numericStatusCode < 400;
    this.details = details;
    this.timestamp = new Date().toISOString();
    this.isOperational = true;
  }
  // Static factory methods for common responses
  static success(data, message = 'Success', details = undefined) {
    return new ApiResponse(200, data, message, details);
  }
  static created(
    data,
    message = 'Resource created successfully',
    details = undefined,
  ) {
    return new ApiResponse(201, data, message, details);
  }
  static noContent(message = 'No content', details = undefined) {
    return new ApiResponse(204, null, message, details);
  }
  static badRequest(data = null, message = 'Bad Request', details = undefined) {
    return new ApiResponse(400, data, message, details);
  }
  static unauthorized(
    data = null,
    message = 'Unauthorized',
    details = undefined,
  ) {
    return new ApiResponse(401, data, message, details);
  }
  static forbidden(data = null, message = 'Forbidden', details = undefined) {
    return new ApiResponse(403, data, message, details);
  }
  static notFound(
    data = null,
    message = 'Resource not found',
    details = undefined,
  ) {
    return new ApiResponse(404, data, message, details);
  }
  static conflict(data = null, message = 'Conflict', details = undefined) {
    return new ApiResponse(409, data, message, details);
  }
  static unprocessableEntity(
    data = null,
    message = 'Unprocessable Entity',
    details = undefined,
  ) {
    return new ApiResponse(422, data, message, details);
  }
  static internalServerError(
    data = null,
    message = 'Internal Server Error',
    details = undefined,
  ) {
    return new ApiResponse(500, data, message, details);
  }
  static serviceUnavailable(
    data = null,
    message = 'Service Unavailable',
    details = undefined,
  ) {
    return new ApiResponse(503, data, message, details);
  }
  // Add metadata to response
  addMetadata(metadata) {
    this.metadata = { ...this.metadata, ...metadata };
    return this;
  }
  // Add pagination info
  addPagination(page, limit, total, totalPages) {
    this.pagination = {
      page: Number(page),
      limit: Number(limit),
      total: Number(total),
      totalPages: Number(totalPages),
      hasNext: page < totalPages,
      hasPrev: page > 1,
    };
    return this;
  }
  // Add headers
  addHeaders(headers) {
    this.headers = { ...this.headers, ...headers };
    return this;
  }
  // Set cache control
  setCacheControl(maxAge = 3600, isPublic = true) {
    const visibility = isPublic ? 'public' : 'private';
    this.headers = {
      ...this.headers,
      'Cache-Control': `${visibility}, max-age=${maxAge}`,
    };
    return this;
  }
  // Convert to JSON
  toJSON() {
    const response = {
      statusCode: this.statusCode,
      success: this.success,
      message: this.message,
      data: this.data,
      timestamp: this.timestamp,
    };
    if (this.details) {
      response.details = this.details;
    }
    if (this.metadata) {
      response.metadata = this.metadata;
    }
    if (this.pagination) {
      response.pagination = this.pagination;
    }
    return response;
  }
  // Convert to string
  toString() {
    return `ApiResponse: ${this.statusCode} - ${this.message}`;
  }
  // Check if response is successful
  isSuccess() {
    return this.success;
  }
  // Check if response is an error
  isError() {
    return !this.success;
  }
  // Check if response is client error (4xx)
  isClientError() {
    return this.statusCode >= 400 && this.statusCode < 500;
  }
  // Check if response is server error (5xx)
  isServerError() {
    return this.statusCode >= 500 && this.statusCode < 600;
  }
  // Get response type
  getType() {
    if (this.statusCode < 200) return 'informational';
    if (this.statusCode < 300) return 'success';
    if (this.statusCode < 400) return 'redirection';
    if (this.statusCode < 500) return 'client_error';
    return 'server_error';
  }
  // Clone response
  clone() {
    const cloned = new ApiResponse(
      this.statusCode,
      this.data,
      this.message,
      this.details,
    );
    if (this.metadata) cloned.metadata = { ...this.metadata };
    if (this.pagination) cloned.pagination = { ...this.pagination };
    if (this.headers) cloned.headers = { ...this.headers };
    return cloned;
  }
  // Transform data
  transform(transformer) {
    if (typeof transformer === 'function') {
      this.data = transformer(this.data);
    }
    return this;
  }
  // Add custom fields
  addField(key, value) {
    this[key] = value;
    return this;
  }
}
export { ApiResponse };
