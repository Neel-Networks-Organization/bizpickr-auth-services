import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import { ApiResponse } from '../../../src/utils/ApiResponse.js';

describe('ApiResponse Utility Class', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Constructor', () => {
    it('should create ApiResponse with valid parameters', () => {
      // Arrange
      const statusCode = 200;
      const data = { id: 1, name: 'Test' };
      const message = 'Success';
      const details = { processed: true };

      // Act
      const response = new ApiResponse(statusCode, data, message, details);

      // Assert
      expect(response.statusCode).toBe(200);
      expect(response.data).toEqual({ id: 1, name: 'Test' });
      expect(response.message).toBe('Success');
      expect(response.details).toEqual({ processed: true });
      expect(response.success).toBe(true);
      expect(response.timestamp).toBeDefined();
      expect(response.isOperational).toBe(true);
    });

    it('should create ApiResponse with numeric status code string', () => {
      // Arrange
      const statusCode = '201';
      const data = { id: 1 };

      // Act
      const response = new ApiResponse(statusCode, data);

      // Assert
      expect(response.statusCode).toBe(201);
      expect(typeof response.statusCode).toBe('number');
    });

    it('should use default message when not provided', () => {
      // Arrange
      const statusCode = 200;
      const data = { id: 1 };

      // Act
      const response = new ApiResponse(statusCode, data);

      // Assert
      expect(response.message).toBe('OK');
    });

    it('should set success based on status code', () => {
      // Arrange
      const successCodes = [200, 201, 204];
      const errorCodes = [400, 401, 404, 500, 503];

      // Act & Assert
      successCodes.forEach(code => {
        const response = new ApiResponse(code, 'data');
        expect(response.success).toBe(true);
      });

      errorCodes.forEach(code => {
        const response = new ApiResponse(code, 'data');
        expect(response.success).toBe(false);
      });
    });

    it('should set timestamp to current time', () => {
      // Arrange
      const statusCode = 200;
      const data = { id: 1 };
      const beforeCreation = new Date();

      // Act
      const response = new ApiResponse(statusCode, data);
      const afterCreation = new Date();

      // Assert
      const responseTime = new Date(response.timestamp);
      expect(responseTime.getTime()).toBeGreaterThanOrEqual(
        beforeCreation.getTime()
      );
      expect(responseTime.getTime()).toBeLessThanOrEqual(
        afterCreation.getTime()
      );
    });
  });

  describe('Status Code Validation', () => {
    it('should accept valid HTTP status codes', () => {
      const validStatusCodes = [
        100, 200, 201, 204, 400, 401, 403, 404, 500, 503, 599,
      ];

      validStatusCodes.forEach(statusCode => {
        expect(() => new ApiResponse(statusCode, 'data')).not.toThrow();
      });
    });

    it('should accept string status codes and convert them', () => {
      const stringStatusCodes = ['200', '400', '500'];

      stringStatusCodes.forEach(statusCode => {
        const response = new ApiResponse(statusCode, 'data');
        expect(typeof response.statusCode).toBe('number');
        expect(response.statusCode).toBe(Number(statusCode));
      });
    });

    it('should throw error for invalid status code (NaN)', () => {
      // Arrange
      const invalidStatusCode = 'invalid';

      // Act & Assert
      expect(() => new ApiResponse(invalidStatusCode, 'data')).toThrow(
        'Invalid HTTP status code. Must be between 100 and 599'
      );
    });

    it('should throw error for status code below 100', () => {
      // Arrange
      const lowStatusCode = 99;

      // Act & Assert
      expect(() => new ApiResponse(lowStatusCode, 'data')).toThrow(
        'Invalid HTTP status code. Must be between 100 and 599'
      );
    });

    it('should throw error for status code above 599', () => {
      // Arrange
      const highStatusCode = 600;

      // Act & Assert
      expect(() => new ApiResponse(highStatusCode, 'data')).toThrow(
        'Invalid HTTP status code. Must be between 100 and 599'
      );
    });

    it('should throw error for null status code', () => {
      // Arrange
      const nullStatusCode = null;

      // Act & Assert
      expect(() => new ApiResponse(nullStatusCode, 'data')).toThrow(
        'Invalid HTTP status code. Must be between 100 and 599'
      );
    });

    it('should throw error for undefined status code', () => {
      // Arrange
      const undefinedStatusCode = undefined;

      // Act & Assert
      expect(() => new ApiResponse(undefinedStatusCode, 'data')).toThrow(
        'Invalid HTTP status code. Must be between 100 and 599'
      );
    });
  });

  describe('getDefaultMessage Method', () => {
    it('should return correct default messages for known status codes', () => {
      const testCases = [
        { code: 200, expected: 'OK' },
        { code: 201, expected: 'Created' },
        { code: 204, expected: 'No Content' },
        { code: 400, expected: 'Bad Request' },
        { code: 401, expected: 'Unauthorized' },
        { code: 403, expected: 'Forbidden' },
        { code: 404, expected: 'Not Found' },
        { code: 409, expected: 'Conflict' },
        { code: 422, expected: 'Unprocessable Entity' },
        { code: 500, expected: 'Internal Server Error' },
        { code: 503, expected: 'Service Unavailable' },
      ];

      testCases.forEach(({ code, expected }) => {
        const response = new ApiResponse(code, 'data');
        expect(response.message).toBe(expected);
      });
    });

    it('should return generic message for unknown status codes', () => {
      const unknownCodes = [100, 300];

      unknownCodes.forEach(code => {
        const response = new ApiResponse(code, 'data');
        expect(response.message).toBe('Response');
      });
    });

    it('should throw error for status codes above 599', () => {
      const highCodes = [600, 999];

      highCodes.forEach(code => {
        expect(() => new ApiResponse(code, 'data')).toThrow(
          'Invalid HTTP status code. Must be between 100 and 599'
        );
      });
    });
  });

  describe('Static Factory Methods', () => {
    describe('success', () => {
      it('should create success response with default values', () => {
        // Act
        const response = ApiResponse.success();

        // Assert
        expect(response.statusCode).toBe(200);
        expect(response.data).toBeUndefined();
        expect(response.message).toBe('Success');
        expect(response.success).toBe(true);
        expect(response.details).toBeUndefined();
      });

      it('should create success response with custom data and message', () => {
        // Arrange
        const data = { id: 1, name: 'Test' };
        const message = 'Operation completed';

        // Act
        const response = ApiResponse.success(data, message);

        // Assert
        expect(response.statusCode).toBe(200);
        expect(response.data).toEqual(data);
        expect(response.message).toBe(message);
        expect(response.success).toBe(true);
      });

      it('should create success response with details', () => {
        // Arrange
        const data = { id: 1 };
        const message = 'Success';
        const details = { processed: true, timestamp: Date.now() };

        // Act
        const response = ApiResponse.success(data, message, details);

        // Assert
        expect(response.details).toEqual(details);
      });
    });

    describe('created', () => {
      it('should create created response with default values', () => {
        // Act
        const response = ApiResponse.created();

        // Assert
        expect(response.statusCode).toBe(201);
        expect(response.data).toBeUndefined();
        expect(response.message).toBe('Resource created successfully');
        expect(response.success).toBe(true);
      });

      it('should create created response with custom data and message', () => {
        // Arrange
        const data = { id: 1, name: 'New User' };
        const message = 'User created successfully';

        // Act
        const response = ApiResponse.created(data, message);

        // Assert
        expect(response.statusCode).toBe(201);
        expect(response.data).toEqual(data);
        expect(response.message).toBe(message);
      });
    });

    describe('noContent', () => {
      it('should create no content response with default values', () => {
        // Act
        const response = ApiResponse.noContent();

        // Assert
        expect(response.statusCode).toBe(204);
        expect(response.data).toBeNull();
        expect(response.message).toBe('No content');
        expect(response.success).toBe(true);
      });

      it('should create no content response with custom message', () => {
        // Arrange
        const message = 'Resource deleted successfully';

        // Act
        const response = ApiResponse.noContent(message);

        // Assert
        expect(response.statusCode).toBe(204);
        expect(response.message).toBe(message);
      });
    });

    describe('badRequest', () => {
      it('should create bad request response with default values', () => {
        // Act
        const response = ApiResponse.badRequest();

        // Assert
        expect(response.statusCode).toBe(400);
        expect(response.data).toBeNull();
        expect(response.message).toBe('Bad Request');
        expect(response.success).toBe(false);
      });

      it('should create bad request response with custom data and message', () => {
        // Arrange
        const data = { errors: ['Field required'] };
        const message = 'Validation failed';

        // Act
        const response = ApiResponse.badRequest(data, message);

        // Assert
        expect(response.statusCode).toBe(400);
        expect(response.data).toEqual(data);
        expect(response.message).toBe(message);
      });
    });

    describe('unauthorized', () => {
      it('should create unauthorized response with default values', () => {
        // Act
        const response = ApiResponse.unauthorized();

        // Assert
        expect(response.statusCode).toBe(401);
        expect(response.data).toBeNull();
        expect(response.message).toBe('Unauthorized');
        expect(response.success).toBe(false);
      });

      it('should create unauthorized response with custom data and message', () => {
        // Arrange
        const data = { reason: 'Token expired' };
        const message = 'Authentication required';

        // Act
        const response = ApiResponse.unauthorized(data, message);

        // Assert
        expect(response.statusCode).toBe(401);
        expect(response.data).toEqual(data);
        expect(response.message).toBe(message);
      });
    });

    describe('forbidden', () => {
      it('should create forbidden response with default values', () => {
        // Act
        const response = ApiResponse.forbidden();

        // Assert
        expect(response.statusCode).toBe(403);
        expect(response.data).toBeNull();
        expect(response.message).toBe('Forbidden');
        expect(response.success).toBe(false);
      });

      it('should create forbidden response with custom data and message', () => {
        // Arrange
        const data = { requiredRole: 'admin' };
        const message = 'Insufficient permissions';

        // Act
        const response = ApiResponse.forbidden(data, message);

        // Assert
        expect(response.statusCode).toBe(403);
        expect(response.data).toEqual(data);
        expect(response.message).toBe(message);
      });
    });

    describe('notFound', () => {
      it('should create not found response with default values', () => {
        // Act
        const response = ApiResponse.notFound();

        // Assert
        expect(response.statusCode).toBe(404);
        expect(response.data).toBeNull();
        expect(response.message).toBe('Resource not found');
        expect(response.success).toBe(false);
      });

      it('should create not found response with custom data and message', () => {
        // Arrange
        const data = { resource: 'user', id: 999 };
        const message = 'User not found';

        // Act
        const response = ApiResponse.notFound(data, message);

        // Assert
        expect(response.statusCode).toBe(404);
        expect(response.data).toEqual(data);
        expect(response.message).toBe(message);
      });
    });

    describe('conflict', () => {
      it('should create conflict response with default values', () => {
        // Act
        const response = ApiResponse.conflict();

        // Assert
        expect(response.statusCode).toBe(409);
        expect(response.data).toBeNull();
        expect(response.message).toBe('Conflict');
        expect(response.success).toBe(false);
      });

      it('should create conflict response with custom data and message', () => {
        // Arrange
        const data = { existingResource: { id: 1, email: 'test@example.com' } };
        const message = 'Email already exists';

        // Act
        const response = ApiResponse.conflict(data, message);

        // Assert
        expect(response.statusCode).toBe(409);
        expect(response.data).toEqual(data);
        expect(response.message).toBe(message);
      });
    });

    describe('unprocessableEntity', () => {
      it('should create unprocessable entity response with default values', () => {
        // Act
        const response = ApiResponse.unprocessableEntity();

        // Assert
        expect(response.statusCode).toBe(422);
        expect(response.data).toBeNull();
        expect(response.message).toBe('Unprocessable Entity');
        expect(response.success).toBe(false);
      });

      it('should create unprocessable entity response with custom data and message', () => {
        // Arrange
        const data = { validationErrors: ['Invalid email format'] };
        const message = 'Validation failed';

        // Act
        const response = ApiResponse.unprocessableEntity(data, message);

        // Assert
        expect(response.statusCode).toBe(422);
        expect(response.data).toEqual(data);
        expect(response.message).toBe(message);
      });
    });

    describe('internalServerError', () => {
      it('should create internal server error response with default values', () => {
        // Act
        const response = ApiResponse.internalServerError();

        // Assert
        expect(response.statusCode).toBe(500);
        expect(response.data).toBeNull();
        expect(response.message).toBe('Internal Server Error');
        expect(response.success).toBe(false);
      });

      it('should create internal server error response with custom data and message', () => {
        // Arrange
        const data = { errorId: 'err_123', timestamp: Date.now() };
        const message = 'Database connection failed';

        // Act
        const response = ApiResponse.internalServerError(data, message);

        // Assert
        expect(response.statusCode).toBe(500);
        expect(response.data).toEqual(data);
        expect(response.message).toBe(message);
      });
    });

    describe('serviceUnavailable', () => {
      it('should create service unavailable response with default values', () => {
        // Act
        const response = ApiResponse.serviceUnavailable();

        // Assert
        expect(response.statusCode).toBe(503);
        expect(response.data).toBeNull();
        expect(response.message).toBe('Service Unavailable');
        expect(response.success).toBe(false);
      });

      it('should create service unavailable response with custom data and message', () => {
        // Arrange
        const data = { maintenance: true, estimatedTime: '2 hours' };
        const message = 'System maintenance in progress';

        // Act
        const response = ApiResponse.serviceUnavailable(data, message);

        // Assert
        expect(response.statusCode).toBe(503);
        expect(response.data).toEqual(data);
        expect(response.message).toBe(message);
      });
    });
  });

  describe('Instance Methods', () => {
    describe('addMetadata', () => {
      it('should add metadata to response', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');
        const metadata = { version: '1.0', environment: 'production' };

        // Act
        const result = response.addMetadata(metadata);

        // Assert
        expect(result).toBe(response);
        expect(response.metadata).toEqual(metadata);
      });

      it('should merge metadata with existing metadata', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');
        const initialMetadata = { version: '1.0' };
        const additionalMetadata = { environment: 'production' };

        // Act
        response.addMetadata(initialMetadata);
        response.addMetadata(additionalMetadata);

        // Assert
        expect(response.metadata).toEqual({
          version: '1.0',
          environment: 'production',
        });
      });

      it('should return response for chaining', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');
        const metadata = { version: '1.0' };

        // Act
        const result = response.addMetadata(metadata);

        // Assert
        expect(result).toBe(response);
      });
    });

    describe('addPagination', () => {
      it('should add pagination info to response', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');
        const page = 1;
        const limit = 10;
        const total = 100;
        const totalPages = 10;

        // Act
        const result = response.addPagination(page, limit, total, totalPages);

        // Assert
        expect(result).toBe(response);
        expect(response.pagination).toEqual({
          page: 1,
          limit: 10,
          total: 100,
          totalPages: 10,
          hasNext: true,
          hasPrev: false,
        });
      });

      it('should handle string pagination parameters', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');
        const page = '2';
        const limit = '20';
        const total = '150';
        const totalPages = '8';

        // Act
        response.addPagination(page, limit, total, totalPages);

        // Assert
        expect(response.pagination.page).toBe(2);
        expect(response.pagination.limit).toBe(20);
        expect(response.pagination.total).toBe(150);
        expect(response.pagination.totalPages).toBe(8);
      });

      it('should calculate hasNext and hasPrev correctly', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');

        // Act & Assert
        // First page
        response.addPagination(1, 10, 100, 10);
        expect(response.pagination.hasNext).toBe(true);
        expect(response.pagination.hasPrev).toBe(false);

        // Middle page
        response.addPagination(5, 10, 100, 10);
        expect(response.pagination.hasNext).toBe(true);
        expect(response.pagination.hasPrev).toBe(true);

        // Last page
        response.addPagination(10, 10, 100, 10);
        expect(response.pagination.hasNext).toBe(false);
        expect(response.pagination.hasPrev).toBe(true);
      });

      it('should return response for chaining', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');

        // Act
        const result = response.addPagination(1, 10, 100, 10);

        // Assert
        expect(result).toBe(response);
      });
    });

    describe('addHeaders', () => {
      it('should add headers to response', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');
        const headers = {
          'X-Custom-Header': 'value',
          Authorization: 'Bearer token',
        };

        // Act
        const result = response.addHeaders(headers);

        // Assert
        expect(result).toBe(response);
        expect(response.headers).toEqual(headers);
      });

      it('should merge headers with existing headers', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');
        const initialHeaders = { 'X-Version': '1.0' };
        const additionalHeaders = { 'X-Environment': 'production' };

        // Act
        response.addHeaders(initialHeaders);
        response.addHeaders(additionalHeaders);

        // Assert
        expect(response.headers).toEqual({
          'X-Version': '1.0',
          'X-Environment': 'production',
        });
      });

      it('should return response for chaining', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');
        const headers = { 'X-Custom': 'value' };

        // Act
        const result = response.addHeaders(headers);

        // Assert
        expect(result).toBe(response);
      });
    });

    describe('setCacheControl', () => {
      it('should set cache control headers with default values', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');

        // Act
        const result = response.setCacheControl();

        // Assert
        expect(result).toBe(response);
        expect(response.headers['Cache-Control']).toBe('public, max-age=3600');
      });

      it('should set cache control headers with custom values', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');
        const maxAge = 7200;
        const isPublic = false;

        // Act
        response.setCacheControl(maxAge, isPublic);

        // Assert
        expect(response.headers['Cache-Control']).toBe('private, max-age=7200');
      });

      it('should merge with existing headers', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');
        const existingHeaders = { 'Content-Type': 'application/json' };

        // Act
        response.addHeaders(existingHeaders);
        response.setCacheControl(1800, true);

        // Assert
        expect(response.headers).toEqual({
          'Content-Type': 'application/json',
          'Cache-Control': 'public, max-age=1800',
        });
      });

      it('should return response for chaining', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');

        // Act
        const result = response.setCacheControl(3600, true);

        // Assert
        expect(result).toBe(response);
      });
    });

    describe('transform', () => {
      it('should transform data using provided function', () => {
        // Arrange
        const response = new ApiResponse(200, { id: 1, name: 'Test' });
        const transformer = data => ({ ...data, transformed: true });

        // Act
        const result = response.transform(transformer);

        // Assert
        expect(result).toBe(response);
        expect(response.data).toEqual({
          id: 1,
          name: 'Test',
          transformed: true,
        });
      });

      it('should return response unchanged if transformer is not a function', () => {
        // Arrange
        const response = new ApiResponse(200, { id: 1 });
        const originalData = { ...response.data };

        // Act
        response.transform('not a function');
        response.transform(null);
        response.transform(undefined);

        // Assert
        expect(response.data).toEqual(originalData);
      });

      it('should return response for chaining', () => {
        // Arrange
        const response = new ApiResponse(200, { id: 1 });
        const transformer = data => data;

        // Act
        const result = response.transform(transformer);

        // Assert
        expect(result).toBe(response);
      });
    });

    describe('addField', () => {
      it('should add custom field to response', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');

        // Act
        const result = response.addField('customField', 'customValue');

        // Assert
        expect(result).toBe(response);
        expect(response.customField).toBe('customValue');
      });

      it('should return response for chaining', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');

        // Act
        const result = response.addField('test', 'value');

        // Assert
        expect(result).toBe(response);
      });
    });
  });

  describe('Utility Methods', () => {
    describe('isSuccess', () => {
      it('should return true for success status codes', () => {
        const successCodes = [200, 201, 204];

        successCodes.forEach(code => {
          const response = new ApiResponse(code, 'data');
          expect(response.isSuccess()).toBe(true);
        });
      });

      it('should return false for error status codes', () => {
        const errorCodes = [400, 401, 404, 500, 503];

        errorCodes.forEach(code => {
          const response = new ApiResponse(code, 'data');
          expect(response.isSuccess()).toBe(false);
        });
      });
    });

    describe('isError', () => {
      it('should return true for error status codes', () => {
        const errorCodes = [400, 401, 404, 500, 503];

        errorCodes.forEach(code => {
          const response = new ApiResponse(code, 'data');
          expect(response.isError()).toBe(true);
        });
      });

      it('should return false for success status codes', () => {
        const successCodes = [200, 201, 204];

        successCodes.forEach(code => {
          const response = new ApiResponse(code, 'data');
          expect(response.isSuccess()).toBe(true);
        });
      });
    });

    describe('isClientError', () => {
      it('should return true for client error status codes', () => {
        const clientErrorCodes = [400, 401, 403, 404, 409, 422];

        clientErrorCodes.forEach(code => {
          const response = new ApiResponse(code, 'data');
          expect(response.isClientError()).toBe(true);
        });
      });

      it('should return false for non-client error status codes', () => {
        const nonClientErrorCodes = [200, 201, 500, 503];

        nonClientErrorCodes.forEach(code => {
          const response = new ApiResponse(code, 'data');
          expect(response.isClientError()).toBe(false);
        });
      });
    });

    describe('isServerError', () => {
      it('should return true for server error status codes', () => {
        const serverErrorCodes = [500, 502, 503, 504];

        serverErrorCodes.forEach(code => {
          const response = new ApiResponse(code, 'data');
          expect(response.isServerError()).toBe(true);
        });
      });

      it('should return false for non-server error status codes', () => {
        const nonServerErrorCodes = [200, 201, 400, 401, 404];

        nonServerErrorCodes.forEach(code => {
          const response = new ApiResponse(code, 'data');
          expect(response.isServerError()).toBe(false);
        });
      });
    });

    describe('getType', () => {
      it('should return correct response types', () => {
        const testCases = [
          { code: 100, expected: 'informational' },
          { code: 200, expected: 'success' },
          { code: 300, expected: 'redirection' },
          { code: 400, expected: 'client_error' },
          { code: 500, expected: 'server_error' },
        ];

        testCases.forEach(({ code, expected }) => {
          const response = new ApiResponse(code, 'data');
          expect(response.getType()).toBe(expected);
        });
      });
    });
  });

  describe('Serialization Methods', () => {
    describe('toJSON', () => {
      it('should return JSON representation with all properties', () => {
        // Arrange
        const response = new ApiResponse(200, { id: 1 }, 'Success', {
          processed: true,
        });
        response.addMetadata({ version: '1.0' });
        response.addPagination(1, 10, 100, 10);
        response.addHeaders({ 'Content-Type': 'application/json' });

        // Act
        const result = response.toJSON();

        // Assert
        expect(result).toEqual({
          statusCode: 200,
          success: true,
          message: 'Success',
          data: { id: 1 },
          timestamp: response.timestamp,
          details: { processed: true },
          metadata: { version: '1.0' },
          pagination: {
            page: 1,
            limit: 10,
            total: 100,
            totalPages: 10,
            hasNext: true,
            hasPrev: false,
          },
          headers: { 'Content-Type': 'application/json' },
        });
      });

      it('should handle response without optional properties', () => {
        // Arrange
        const response = new ApiResponse(200, { id: 1 });

        // Act
        const result = response.toJSON();

        // Assert
        expect(result).toEqual({
          statusCode: 200,
          success: true,
          message: 'OK',
          data: { id: 1 },
          timestamp: response.timestamp,
        });
      });

      it('should include details when present', () => {
        // Arrange
        const response = new ApiResponse(200, 'data', 'Success', {
          debug: true,
        });

        // Act
        const result = response.toJSON();

        // Assert
        expect(result.details).toEqual({ debug: true });
      });

      it('should include metadata when present', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');
        response.addMetadata({ version: '1.0' });

        // Act
        const result = response.toJSON();

        // Assert
        expect(result.metadata).toEqual({ version: '1.0' });
      });

      it('should include pagination when present', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');
        response.addPagination(1, 10, 100, 10);

        // Act
        const result = response.toJSON();

        // Assert
        expect(result.pagination).toBeDefined();
        expect(result.pagination.page).toBe(1);
      });

      it('should include headers when present', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');
        response.addHeaders({ 'X-Custom': 'value' });

        // Act
        const result = response.toJSON();

        // Assert
        expect(result.headers).toEqual({ 'X-Custom': 'value' });
      });
    });

    describe('toString', () => {
      it('should return formatted string representation', () => {
        // Arrange
        const response = new ApiResponse(200, 'data', 'Success');

        // Act
        const result = response.toString();

        // Assert
        expect(result).toBe('ApiResponse: 200 - Success');
      });

      it('should handle default message', () => {
        // Arrange
        const response = new ApiResponse(200, 'data');

        // Act
        const result = response.toString();

        // Assert
        expect(result).toBe('ApiResponse: 200 - OK');
      });
    });
  });

  describe('clone Method', () => {
    it('should create exact copy of response', () => {
      // Arrange
      const original = new ApiResponse(200, { id: 1 }, 'Success', {
        debug: true,
      });
      original.addMetadata({ version: '1.0' });
      original.addPagination(1, 10, 100, 10);
      original.addHeaders({ 'Content-Type': 'application/json' });

      // Act
      const cloned = original.clone();

      // Assert
      expect(cloned).not.toBe(original);
      expect(cloned.statusCode).toBe(original.statusCode);
      expect(cloned.data).toEqual(original.data);
      expect(cloned.message).toBe(original.message);
      expect(cloned.details).toEqual(original.details);
      expect(cloned.metadata).toEqual(original.metadata);
      expect(cloned.pagination).toEqual(original.pagination);
      expect(cloned.headers).toEqual(original.headers);
      expect(cloned.timestamp).toBe(original.timestamp);
    });

    it('should create independent copy (modifying clone does not affect original)', () => {
      // Arrange
      const original = new ApiResponse(200, { id: 1 });
      original.addMetadata({ version: '1.0' });

      // Act
      const cloned = original.clone();
      cloned.addMetadata({ version: '2.0' });
      // Note: data is a reference, so modifying it will affect both original and clone
      // This is expected behavior for shallow cloning

      // Assert
      expect(original.metadata.version).toBe('1.0');
      expect(cloned.metadata.version).toBe('2.0');
      // Data is shared reference, so both will have the same value
      expect(original.data.id).toBe(1);
      expect(cloned.data.id).toBe(1);
    });

    it('should handle response without optional properties', () => {
      // Arrange
      const original = new ApiResponse(200, 'data');

      // Act
      const cloned = original.clone();

      // Assert
      expect(cloned.metadata).toBeUndefined();
      expect(cloned.pagination).toBeUndefined();
      expect(cloned.headers).toBeUndefined();
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle very large status codes', () => {
      // Arrange
      const largeStatusCode = 599;

      // Act
      const response = new ApiResponse(largeStatusCode, 'data');

      // Assert
      expect(response.statusCode).toBe(599);
    });

    it('should handle zero data', () => {
      // Arrange
      const statusCode = 200;
      const data = 0;

      // Act
      const response = new ApiResponse(statusCode, data);

      // Assert
      expect(response.data).toBe(0);
    });

    it('should handle null data', () => {
      // Arrange
      const statusCode = 200;
      const data = null;

      // Act
      const response = new ApiResponse(statusCode, data);

      // Assert
      expect(response.data).toBeNull();
    });

    it('should handle undefined data', () => {
      // Arrange
      const statusCode = 200;
      const data = undefined;

      // Act
      const response = new ApiResponse(statusCode, data);

      // Assert
      expect(response.data).toBeUndefined();
    });

    it('should handle empty string data', () => {
      // Arrange
      const statusCode = 200;
      const data = '';

      // Act
      const response = new ApiResponse(statusCode, data);

      // Assert
      expect(response.data).toBe('');
    });

    it('should handle boolean data', () => {
      // Arrange
      const statusCode = 200;
      const data = true;

      // Act
      const response = new ApiResponse(statusCode, data);

      // Assert
      expect(response.data).toBe(true);
    });

    it('should handle array data', () => {
      // Arrange
      const statusCode = 200;
      const data = [1, 2, 3, 'test'];

      // Act
      const response = new ApiResponse(statusCode, data);

      // Assert
      expect(response.data).toEqual([1, 2, 3, 'test']);
    });

    it('should handle function data', () => {
      // Arrange
      const statusCode = 200;
      const data = () => 'test';

      // Act
      const response = new ApiResponse(statusCode, data);

      // Assert
      expect(typeof response.data).toBe('function');
      expect(response.data()).toBe('test');
    });
  });

  describe('Performance Tests', () => {
    it('should create responses efficiently', () => {
      // Arrange
      const iterations = 1000;
      const startTime = Date.now();

      // Act
      for (let i = 0; i < iterations; i++) {
        new ApiResponse(200, `data ${i}`);
      }
      const endTime = Date.now();

      // Assert
      const averageTime = (endTime - startTime) / iterations;
      expect(averageTime).toBeLessThan(1); // Less than 1ms per response
    });

    it('should handle JSON serialization efficiently', () => {
      // Arrange
      const response = new ApiResponse(200, { id: 1, name: 'Test' });
      response.addMetadata({ version: '1.0' });
      response.addPagination(1, 10, 100, 10);
      const iterations = 1000;
      const startTime = Date.now();

      // Act
      for (let i = 0; i < iterations; i++) {
        response.toJSON();
      }
      const endTime = Date.now();

      // Assert
      const averageTime = (endTime - startTime) / iterations;
      expect(averageTime).toBeLessThan(0.1); // Less than 0.1ms per serialization
    });

    it('should handle cloning efficiently', () => {
      // Arrange
      const response = new ApiResponse(200, { id: 1 });
      response.addMetadata({ version: '1.0' });
      response.addPagination(1, 10, 100, 10);
      const iterations = 1000;
      const startTime = Date.now();

      // Act
      for (let i = 0; i < iterations; i++) {
        response.clone();
      }
      const endTime = Date.now();

      // Assert
      const averageTime = (endTime - startTime) / iterations;
      expect(averageTime).toBeLessThan(0.1); // Less than 0.1ms per clone
    });
  });

  describe('Method Chaining', () => {
    it('should support method chaining for all methods', () => {
      // Arrange
      const response = new ApiResponse(200, { id: 1 });

      // Act
      const result = response
        .addMetadata({ version: '1.0' })
        .addPagination(1, 10, 100, 10)
        .addHeaders({ 'Content-Type': 'application/json' })
        .setCacheControl(3600, true)
        .transform(data => ({ ...data, transformed: true }))
        .addField('custom', 'value');

      // Assert
      expect(result).toBe(response);
      expect(response.metadata).toBeDefined();
      expect(response.pagination).toBeDefined();
      expect(response.headers).toBeDefined();
      expect(response.data.transformed).toBe(true);
      expect(response.custom).toBe('value');
    });

    it('should maintain chain integrity with error responses', () => {
      // Arrange
      const response = new ApiResponse(400, { errors: ['Invalid input'] });

      // Act
      const result = response
        .addMetadata({ debug: true })
        .addHeaders({ 'X-Error-Code': 'VALIDATION_FAILED' });

      // Assert
      expect(result).toBe(response);
      expect(response.success).toBe(false);
      expect(response.metadata.debug).toBe(true);
      expect(response.headers['X-Error-Code']).toBe('VALIDATION_FAILED');
    });
  });
});
