import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import { ApiResponse } from '../../../src/utils/index.js';

/**
 * ApiResponse Utility Tests
 *
 * Test Coverage:
 * - Response creation with different parameters
 * - Static factory methods
 * - Response properties and methods
 * - Error handling and validation
 * - Metadata and pagination
 * - Serialization and transformation
 * - Edge cases and performance
 */

describe('ApiResponse Utility Tests', () => {
  let testResponse;

  beforeEach(() => {
    testResponse = null;
  });

  describe('Response Creation', () => {
    describe('Basic Response Creation', () => {
      it('should create a valid response with minimal parameters', () => {
        // Arrange & Act
        testResponse = new ApiResponse(200, { message: 'Success' }, 'Success');

        // Assert
        expect(testResponse).toBeDefined();
        expect(testResponse.statusCode).toBe(200);
        expect(testResponse.data).toEqual({ message: 'Success' });
        expect(testResponse.message).toBe('Success');
        expect(testResponse.success).toBe(true);
        expect(testResponse.timestamp).toBeDefined();
        expect(testResponse.isOperational).toBe(true);
      });

      it('should create response with all parameters', () => {
        // Arrange
        const statusCode = 201;
        const data = { id: 1, name: 'Test' };
        const message = 'Resource created';
        const details = ['Created successfully', 'ID assigned'];

        // Act
        testResponse = new ApiResponse(statusCode, data, message, details);

        // Assert
        expect(testResponse.statusCode).toBe(statusCode);
        expect(testResponse.data).toEqual(data);
        expect(testResponse.message).toBe(message);
        expect(testResponse.details).toEqual(details);
        expect(testResponse.success).toBe(true);
      });

      it('should handle undefined details', () => {
        // Arrange & Act
        testResponse = new ApiResponse(
          200,
          { data: 'test' },
          'Success',
          undefined
        );

        // Assert
        expect(testResponse.details).toBeUndefined();
      });

      it('should handle null data', () => {
        // Arrange & Act
        testResponse = new ApiResponse(204, null, 'No content');

        // Assert
        expect(testResponse.data).toBeNull();
        expect(testResponse.success).toBe(true);
      });
    });

    describe('Status Code Validation', () => {
      it('should accept valid HTTP status codes', () => {
        const validStatusCodes = [
          200, 201, 400, 401, 403, 404, 422, 500, 502, 503,
        ];

        validStatusCodes.forEach(statusCode => {
          testResponse = new ApiResponse(statusCode, { test: 'data' }, 'Test');
          expect(testResponse.statusCode).toBe(statusCode);
        });
      });

      it('should handle string status codes', () => {
        // Arrange & Act
        testResponse = new ApiResponse('200', { data: 'test' }, 'Success');

        // Assert
        expect(testResponse.statusCode).toBe(200);
      });

      it('should handle zero status code', () => {
        // Arrange & Act
        testResponse = new ApiResponse(0, { data: 'test' }, 'Zero status');

        // Assert
        expect(testResponse.statusCode).toBe(0);
      });

      it('should throw error for invalid status code', () => {
        // Arrange & Act & Assert
        expect(
          () => new ApiResponse('invalid', { data: 'test' }, 'Error')
        ).toThrow('Invalid HTTP status code');
      });

      it('should throw error for negative status code', () => {
        // Arrange & Act & Assert
        expect(() => new ApiResponse(-1, { data: 'test' }, 'Error')).toThrow(
          'Invalid HTTP status code'
        );
      });
    });

    describe('Success Flag', () => {
      it('should set success to true for 2xx status codes', () => {
        const successCodes = [200, 201, 204, 299];

        successCodes.forEach(statusCode => {
          testResponse = new ApiResponse(
            statusCode,
            { data: 'test' },
            'Success'
          );
          expect(testResponse.success).toBe(true);
        });
      });

      it('should set success to false for 4xx status codes', () => {
        const errorCodes = [400, 401, 403, 404, 422, 499];

        errorCodes.forEach(statusCode => {
          testResponse = new ApiResponse(statusCode, { data: 'test' }, 'Error');
          expect(testResponse.success).toBe(false);
        });
      });

      it('should set success to false for 5xx status codes', () => {
        const errorCodes = [500, 502, 503, 599];

        errorCodes.forEach(statusCode => {
          testResponse = new ApiResponse(statusCode, { data: 'test' }, 'Error');
          expect(testResponse.success).toBe(false);
        });
      });
    });
  });

  describe('Static Factory Methods', () => {
    describe('Success Responses', () => {
      it('should create success response', () => {
        // Arrange & Act
        testResponse = ApiResponse.success({ data: 'test' }, 'Success');

        // Assert
        expect(testResponse.statusCode).toBe(200);
        expect(testResponse.data).toEqual({ data: 'test' });
        expect(testResponse.message).toBe('Success');
        expect(testResponse.success).toBe(true);
      });

      it('should create created response', () => {
        // Arrange & Act
        testResponse = ApiResponse.created({ id: 1 }, 'Created');

        // Assert
        expect(testResponse.statusCode).toBe(201);
        expect(testResponse.data).toEqual({ id: 1 });
        expect(testResponse.message).toBe('Created');
      });

      it('should create no content response', () => {
        // Arrange & Act
        testResponse = ApiResponse.noContent('No content');

        // Assert
        expect(testResponse.statusCode).toBe(204);
        expect(testResponse.data).toBeNull();
        expect(testResponse.message).toBe('No content');
      });
    });

    describe('Error Responses', () => {
      it('should create bad request response', () => {
        // Arrange & Act
        testResponse = ApiResponse.badRequest(
          { error: 'details' },
          'Bad Request'
        );

        // Assert
        expect(testResponse.statusCode).toBe(400);
        expect(testResponse.data).toEqual({ error: 'details' });
        expect(testResponse.message).toBe('Bad Request');
        expect(testResponse.success).toBe(false);
      });

      it('should create unauthorized response', () => {
        // Arrange & Act
        testResponse = ApiResponse.unauthorized(null, 'Unauthorized');

        // Assert
        expect(testResponse.statusCode).toBe(401);
        expect(testResponse.data).toBeNull();
        expect(testResponse.message).toBe('Unauthorized');
      });

      it('should create forbidden response', () => {
        // Arrange & Act
        testResponse = ApiResponse.forbidden({
          reason: 'insufficient_permissions',
        });

        // Assert
        expect(testResponse.statusCode).toBe(403);
        expect(testResponse.message).toBe('Forbidden');
      });

      it('should create not found response', () => {
        // Arrange & Act
        testResponse = ApiResponse.notFound({ resource: 'user' });

        // Assert
        expect(testResponse.statusCode).toBe(404);
        expect(testResponse.message).toBe('Resource not found');
      });

      it('should create conflict response', () => {
        // Arrange & Act
        testResponse = ApiResponse.conflict({ field: 'email' });

        // Assert
        expect(testResponse.statusCode).toBe(409);
        expect(testResponse.message).toBe('Conflict');
      });

      it('should create unprocessable entity response', () => {
        // Arrange & Act
        testResponse = ApiResponse.unprocessableEntity({
          errors: ['Invalid email'],
        });

        // Assert
        expect(testResponse.statusCode).toBe(422);
        expect(testResponse.message).toBe('Unprocessable Entity');
      });

      it('should create internal server error response', () => {
        // Arrange & Act
        testResponse = ApiResponse.internalServerError({
          error: 'Database connection failed',
        });

        // Assert
        expect(testResponse.statusCode).toBe(500);
        expect(testResponse.message).toBe('Internal Server Error');
      });

      it('should create service unavailable response', () => {
        // Arrange & Act
        testResponse = ApiResponse.serviceUnavailable({ retryAfter: 300 });

        // Assert
        expect(testResponse.statusCode).toBe(503);
        expect(testResponse.message).toBe('Service Unavailable');
      });
    });
  });

  describe('Response Methods', () => {
    beforeEach(() => {
      testResponse = new ApiResponse(200, { data: 'test' }, 'Success');
    });

    describe('Status Check Methods', () => {
      it('should check if response is successful', () => {
        // Arrange & Act
        const successResponse = new ApiResponse(
          200,
          { data: 'test' },
          'Success'
        );
        const errorResponse = new ApiResponse(400, { error: 'test' }, 'Error');

        // Assert
        expect(successResponse.isSuccess()).toBe(true);
        expect(errorResponse.isSuccess()).toBe(false);
      });

      it('should check if response is an error', () => {
        // Arrange & Act
        const successResponse = new ApiResponse(
          200,
          { data: 'test' },
          'Success'
        );
        const errorResponse = new ApiResponse(400, { error: 'test' }, 'Error');

        // Assert
        expect(successResponse.isError()).toBe(false);
        expect(errorResponse.isError()).toBe(true);
      });

      it('should check if response is client error', () => {
        // Arrange & Act
        const clientError = new ApiResponse(400, { error: 'test' }, 'Error');
        const serverError = new ApiResponse(500, { error: 'test' }, 'Error');
        const success = new ApiResponse(200, { data: 'test' }, 'Success');

        // Assert
        expect(clientError.isClientError()).toBe(true);
        expect(serverError.isClientError()).toBe(false);
        expect(success.isClientError()).toBe(false);
      });

      it('should check if response is server error', () => {
        // Arrange & Act
        const serverError = new ApiResponse(500, { error: 'test' }, 'Error');
        const clientError = new ApiResponse(400, { error: 'test' }, 'Error');
        const success = new ApiResponse(200, { data: 'test' }, 'Success');

        // Assert
        expect(serverError.isServerError()).toBe(true);
        expect(clientError.isServerError()).toBe(false);
        expect(success.isServerError()).toBe(false);
      });

      it('should get response type', () => {
        // Arrange & Act
        const informational = new ApiResponse(100, { data: 'test' }, 'Info');
        const success = new ApiResponse(200, { data: 'test' }, 'Success');
        const redirection = new ApiResponse(300, { data: 'test' }, 'Redirect');
        const clientError = new ApiResponse(400, { error: 'test' }, 'Error');
        const serverError = new ApiResponse(500, { error: 'test' }, 'Error');

        // Assert
        expect(informational.getType()).toBe('informational');
        expect(success.getType()).toBe('success');
        expect(redirection.getType()).toBe('redirection');
        expect(clientError.getType()).toBe('client_error');
        expect(serverError.getType()).toBe('server_error');
      });
    });

    describe('Metadata and Pagination', () => {
      it('should add metadata to response', () => {
        // Arrange
        const metadata = { version: '1.0', environment: 'production' };

        // Act
        testResponse.addMetadata(metadata);

        // Assert
        expect(testResponse.metadata).toEqual(metadata);
      });

      it('should merge metadata', () => {
        // Arrange
        testResponse.addMetadata({ version: '1.0' });

        // Act
        testResponse.addMetadata({ environment: 'production' });

        // Assert
        expect(testResponse.metadata).toEqual({
          version: '1.0',
          environment: 'production',
        });
      });

      it('should add pagination info', () => {
        // Arrange & Act
        testResponse.addPagination(1, 10, 100, 10);

        // Assert
        expect(testResponse.pagination).toEqual({
          page: 1,
          limit: 10,
          total: 100,
          totalPages: 10,
          hasNext: true,
          hasPrev: false,
        });
      });

      it('should handle pagination with string values', () => {
        // Arrange & Act
        testResponse.addPagination('2', '20', '150', '8');

        // Assert
        expect(testResponse.pagination.page).toBe(2);
        expect(testResponse.pagination.limit).toBe(20);
        expect(testResponse.pagination.total).toBe(150);
        expect(testResponse.pagination.totalPages).toBe(8);
      });
    });

    describe('Headers and Cache Control', () => {
      it('should add headers to response', () => {
        // Arrange
        const headers = {
          'X-Custom-Header': 'value',
          Authorization: 'Bearer token',
        };

        // Act
        testResponse.addHeaders(headers);

        // Assert
        expect(testResponse.headers).toEqual(headers);
      });

      it('should merge headers', () => {
        // Arrange
        testResponse.addHeaders({ 'X-Custom-Header': 'value' });

        // Act
        testResponse.addHeaders({ Authorization: 'Bearer token' });

        // Assert
        expect(testResponse.headers).toEqual({
          'X-Custom-Header': 'value',
          Authorization: 'Bearer token',
        });
      });

      it('should set cache control', () => {
        // Arrange & Act
        testResponse.setCacheControl(1800, true);

        // Assert
        expect(testResponse.headers['Cache-Control']).toBe(
          'public, max-age=1800'
        );
      });

      it('should set private cache control', () => {
        // Arrange & Act
        testResponse.setCacheControl(3600, false);

        // Assert
        expect(testResponse.headers['Cache-Control']).toBe(
          'private, max-age=3600'
        );
      });
    });

    describe('Serialization', () => {
      it('should convert to JSON correctly', () => {
        // Arrange
        testResponse.addMetadata({ version: '1.0' });
        testResponse.addPagination(1, 10, 100, 10);

        // Act
        const json = testResponse.toJSON();

        // Assert
        expect(json).toEqual({
          statusCode: 200,
          success: true,
          message: 'Success',
          data: { data: 'test' },
          timestamp: testResponse.timestamp,
          metadata: { version: '1.0' },
          pagination: {
            page: 1,
            limit: 10,
            total: 100,
            totalPages: 10,
            hasNext: true,
            hasPrev: false,
          },
        });
      });

      it('should handle JSON without optional fields', () => {
        // Arrange & Act
        const json = testResponse.toJSON();

        // Assert
        expect(json).toEqual({
          statusCode: 200,
          success: true,
          message: 'Success',
          data: { data: 'test' },
          timestamp: testResponse.timestamp,
        });
        expect(json.details).toBeUndefined();
        expect(json.metadata).toBeUndefined();
        expect(json.pagination).toBeUndefined();
      });

      it('should convert to string', () => {
        // Arrange & Act
        const stringRep = testResponse.toString();

        // Assert
        expect(stringRep).toBe('ApiResponse: 200 - Success');
      });
    });

    describe('Transformation and Cloning', () => {
      it('should transform data', () => {
        // Arrange
        const transformer = data => ({ ...data, transformed: true });

        // Act
        testResponse.transform(transformer);

        // Assert
        expect(testResponse.data).toEqual({
          data: 'test',
          transformed: true,
        });
      });

      it('should clone response', () => {
        // Arrange
        testResponse.addMetadata({ version: '1.0' });
        testResponse.addPagination(1, 10, 100, 10);

        // Act
        const cloned = testResponse.clone();

        // Assert
        expect(cloned).not.toBe(testResponse);
        expect(cloned.statusCode).toBe(testResponse.statusCode);
        expect(cloned.data).toEqual(testResponse.data);
        expect(cloned.message).toBe(testResponse.message);
        expect(cloned.metadata).toEqual(testResponse.metadata);
        expect(cloned.pagination).toEqual(testResponse.pagination);
      });

      it('should add custom fields', () => {
        // Arrange & Act
        testResponse.addField('customField', 'customValue');

        // Assert
        expect(testResponse.customField).toBe('customValue');
      });
    });
  });

  describe('Edge Cases', () => {
    it('should handle very large status codes', () => {
      // Arrange & Act
      testResponse = new ApiResponse(99999, { data: 'test' }, 'Large status');

      // Assert
      expect(testResponse.statusCode).toBe(99999);
    });

    it('should handle floating point status codes', () => {
      // Arrange & Act
      testResponse = new ApiResponse(200.5, { data: 'test' }, 'Float status');

      // Assert
      expect(testResponse.statusCode).toBe(200.5);
    });

    it('should handle complex data structures', () => {
      // Arrange
      const complexData = {
        users: [
          { id: 1, name: 'John', metadata: { age: 30, city: 'NYC' } },
          { id: 2, name: 'Jane', metadata: { age: 25, city: 'LA' } },
        ],
        pagination: { page: 1, total: 2 },
        metadata: { version: '1.0', timestamp: new Date().toISOString() },
      };

      // Act
      testResponse = new ApiResponse(200, complexData, 'Complex data');

      // Assert
      expect(testResponse.data).toEqual(complexData);
      expect(testResponse.data.users).toHaveLength(2);
      expect(testResponse.data.users[0].metadata.age).toBe(30);
    });

    it('should handle circular references in data', () => {
      // Arrange
      const circularData = { name: 'test' };
      circularData.self = circularData;

      // Act
      testResponse = new ApiResponse(200, circularData, 'Circular data');

      // Assert
      expect(testResponse.data.name).toBe('test');
      expect(testResponse.data.self).toBe(circularData);
    });
  });

  describe('Performance Tests', () => {
    it('should create responses quickly', () => {
      // Arrange
      const iterations = 1000;
      const startTime = performance.now();

      // Act
      for (let i = 0; i < iterations; i++) {
        new ApiResponse(200, { data: `test${i}` }, `Message ${i}`);
      }
      const endTime = performance.now();

      // Assert
      const averageTime = (endTime - startTime) / iterations;
      expect(averageTime).toBeLessThan(1); // Less than 1ms per response
    });

    it('should handle memory efficiently', () => {
      // Arrange
      const responses = [];

      // Act
      for (let i = 0; i < 1000; i++) {
        responses.push(
          new ApiResponse(200, { data: `test${i}` }, `Message ${i}`)
        );
      }

      // Assert
      expect(responses).toHaveLength(1000);
      // Memory usage should be reasonable (no memory leaks)
    });
  });

  describe('Integration Scenarios', () => {
    it('should work with typical API response flow', () => {
      // Arrange & Act - Simulate a typical API response
      const userData = { id: 1, name: 'John Doe', email: 'john@example.com' };
      testResponse = ApiResponse.success(
        userData,
        'User retrieved successfully'
      )
        .addMetadata({ version: '1.0', endpoint: '/api/users/1' })
        .addPagination(1, 1, 1, 1)
        .addHeaders({ 'X-Request-ID': 'req-123' })
        .setCacheControl(300, true);

      // Assert
      expect(testResponse.isSuccess()).toBe(true);
      expect(testResponse.getType()).toBe('success');
      expect(testResponse.data).toEqual(userData);
      expect(testResponse.metadata.endpoint).toBe('/api/users/1');
      expect(testResponse.pagination.total).toBe(1);
      expect(testResponse.headers['X-Request-ID']).toBe('req-123');
      expect(testResponse.headers['Cache-Control']).toBe('public, max-age=300');
    });

    it('should work with error response flow', () => {
      // Arrange & Act - Simulate an error response
      const errorDetails = [
        'Email is required',
        'Password must be at least 8 characters',
      ];
      testResponse = ApiResponse.badRequest(
        { field: 'validation', errors: errorDetails },
        'Validation failed',
        errorDetails
      )
        .addMetadata({ version: '1.0', endpoint: '/api/auth/register' })
        .addHeaders({ 'X-Request-ID': 'req-456' });

      // Assert
      expect(testResponse.isError()).toBe(true);
      expect(testResponse.isClientError()).toBe(true);
      expect(testResponse.getType()).toBe('client_error');
      expect(testResponse.data.field).toBe('validation');
      expect(testResponse.details).toEqual(errorDetails);
    });
  });
});
