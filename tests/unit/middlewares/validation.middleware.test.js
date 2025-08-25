import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from '@jest/globals';
import { validateRequest } from '../../../src/middlewares/validation.middleware.js';
import { ApiError } from '../../../src/utils/index.js';

describe('Validation Middleware Unit Tests', () => {
  let mockReq, mockRes, mockNext;

  beforeEach(() => {
    jest.clearAllMocks();

    mockReq = {
      body: {},
      query: {},
      params: {},
      headers: {},
    };
    mockRes = {};
    mockNext = jest.fn();
  });

  describe('validateRequest', () => {
    it('should pass validation for valid data', () => {
      // Arrange
      const schema = {
        body: {
          email: 'test@example.com',
          password: 'Password123',
        },
        query: {},
        params: {},
      };

      // Act
      validateRequest(schema)(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should validate body schema', () => {
      // Arrange
      const bodySchema = {
        email: { type: 'string', required: true },
        password: { type: 'string', required: true },
      };

      mockReq.body = {
        email: 'test@example.com',
        password: 'Password123',
      };

      // Act
      validateRequest({ body: bodySchema })(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should validate query schema', () => {
      // Arrange
      const querySchema = {
        page: { type: 'number', required: false },
        limit: { type: 'number', required: false },
      };

      mockReq.query = {
        page: '1',
        limit: '10',
      };

      // Act
      validateRequest({ query: querySchema })(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should validate params schema', () => {
      // Arrange
      const paramsSchema = {
        id: { type: 'string', required: true },
      };

      mockReq.params = {
        id: 'user-123',
      };

      // Act
      validateRequest({ params: paramsSchema })(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should validate multiple schemas simultaneously', () => {
      // Arrange
      const schema = {
        body: {
          email: { type: 'string', required: true },
        },
        query: {
          page: { type: 'number', required: false },
        },
        params: {
          id: { type: 'string', required: true },
        },
      };

      mockReq.body = { email: 'test@example.com' };
      mockReq.query = { page: '1' };
      mockReq.params = { id: 'user-123' };

      // Act
      validateRequest(schema)(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should handle missing required body fields', () => {
      // Arrange
      const bodySchema = {
        email: { type: 'string', required: true },
        password: { type: 'string', required: true },
      };

      mockReq.body = {
        email: 'test@example.com',
        // password missing
      };

      // Act
      validateRequest({ body: bodySchema })(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Validation error',
        })
      );
    });

    it('should handle missing required query fields', () => {
      // Arrange
      const querySchema = {
        userId: { type: 'string', required: true },
      };

      mockReq.query = {}; // userId missing

      // Act
      validateRequest({ query: querySchema })(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Validation error',
        })
      );
    });

    it('should handle missing required params fields', () => {
      // Arrange
      const paramsSchema = {
        id: { type: 'string', required: true },
      };

      mockReq.params = {}; // id missing

      // Act
      validateRequest({ params: paramsSchema })(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Validation error',
        })
      );
    });

    it('should handle type validation errors', () => {
      // Arrange
      const bodySchema = {
        age: { type: 'number', required: true },
      };

      mockReq.body = {
        age: 'not-a-number',
      };

      // Act
      validateRequest({ body: bodySchema })(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Validation error',
        })
      );
    });

    it('should handle string length validation', () => {
      // Arrange
      const bodySchema = {
        name: { type: 'string', required: true, minLength: 3, maxLength: 50 },
      };

      mockReq.body = {
        name: 'ab', // Too short
      };

      // Act
      validateRequest({ body: bodySchema })(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Validation error',
        })
      );
    });

    it('should handle email format validation', () => {
      // Arrange
      const bodySchema = {
        email: { type: 'string', required: true, format: 'email' },
      };

      mockReq.body = {
        email: 'invalid-email',
      };

      // Act
      validateRequest({ body: bodySchema })(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Validation error',
        })
      );
    });

    it('should handle URL format validation', () => {
      // Arrange
      const bodySchema = {
        website: { type: 'string', required: false, format: 'url' },
      };

      mockReq.body = {
        website: 'not-a-url',
      };

      // Act
      validateRequest({ body: bodySchema })(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Validation error',
        })
      );
    });

    it('should handle enum validation', () => {
      // Arrange
      const bodySchema = {
        status: {
          type: 'string',
          required: true,
          enum: ['active', 'inactive'],
        },
      };

      mockReq.body = {
        status: 'invalid-status',
      };

      // Act
      validateRequest({ body: bodySchema })(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Validation error',
        })
      );
    });

    it('should handle number range validation', () => {
      // Arrange
      const bodySchema = {
        age: { type: 'number', required: true, min: 18, max: 100 },
      };

      mockReq.body = {
        age: 15, // Too young
      };

      // Act
      validateRequest({ body: bodySchema })(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Validation error',
        })
      );
    });

    it('should handle array validation', () => {
      // Arrange
      const bodySchema = {
        tags: { type: 'array', required: true, minItems: 1, maxItems: 5 },
      };

      mockReq.body = {
        tags: [], // Empty array
      };

      // Act
      validateRequest({ body: bodySchema })(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Validation error',
        })
      );
    });

    it('should handle nested object validation', () => {
      // Arrange
      const bodySchema = {
        address: {
          type: 'object',
          required: true,
          properties: {
            street: { type: 'string', required: true },
            city: { type: 'string', required: true },
          },
        },
      };

      mockReq.body = {
        address: {
          street: '123 Main St',
          // city missing
        },
      };

      // Act
      validateRequest({ body: bodySchema })(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Validation error',
        })
      );
    });

    it('should handle custom validation functions', () => {
      // Arrange
      const bodySchema = {
        password: {
          type: 'string',
          required: true,
          custom: value => {
            if (value.length < 8) {
              return 'Password must be at least 8 characters long';
            }
            return null;
          },
        },
      };

      mockReq.body = {
        password: 'short',
      };

      // Act
      validateRequest({ body: bodySchema })(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Validation error',
        })
      );
    });

    it('should handle custom validation functions that pass', () => {
      // Arrange
      const bodySchema = {
        password: {
          type: 'string',
          required: true,
          custom: value => {
            if (value.length < 8) {
              return 'Password must be at least 8 characters long';
            }
            return null;
          },
        },
      };

      mockReq.body = {
        password: 'longpassword',
      };

      // Act
      validateRequest({ body: bodySchema })(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should handle empty schema gracefully', () => {
      // Arrange
      const emptySchema = {};

      // Act
      validateRequest(emptySchema)(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should handle null schema gracefully', () => {
      // Arrange
      const nullSchema = null;

      // Act
      validateRequest(nullSchema)(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should handle undefined schema gracefully', () => {
      // Arrange
      const undefinedSchema = undefined;

      // Act
      validateRequest(undefinedSchema)(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });
  });

  describe('Schema Validation', () => {
    it('should validate complex nested schemas', () => {
      // Arrange
      const complexSchema = {
        body: {
          user: {
            type: 'object',
            required: true,
            properties: {
              profile: {
                type: 'object',
                required: true,
                properties: {
                  firstName: { type: 'string', required: true },
                  lastName: { type: 'string', required: true },
                  age: { type: 'number', required: true, min: 18 },
                },
              },
              preferences: {
                type: 'array',
                required: false,
                items: {
                  type: 'string',
                  enum: ['email', 'sms', 'push'],
                },
              },
            },
          },
        },
      };

      mockReq.body = {
        user: {
          profile: {
            firstName: 'John',
            lastName: 'Doe',
            age: 25,
          },
          preferences: ['email', 'sms'],
        },
      };

      // Act
      validateRequest(complexSchema)(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should handle array of objects validation', () => {
      // Arrange
      const arraySchema = {
        body: {
          items: {
            type: 'array',
            required: true,
            items: {
              type: 'object',
              properties: {
                id: { type: 'string', required: true },
                quantity: { type: 'number', required: true, min: 1 },
              },
            },
          },
        },
      };

      mockReq.body = {
        items: [
          { id: 'item-1', quantity: 2 },
          { id: 'item-2', quantity: 1 },
        ],
      };

      // Act
      validateRequest(arraySchema)(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should validate array of objects with errors', () => {
      // Arrange
      const arraySchema = {
        body: {
          items: {
            type: 'array',
            required: true,
            items: {
              type: 'object',
              properties: {
                id: { type: 'string', required: true },
                quantity: { type: 'number', required: true, min: 1 },
              },
            },
          },
        },
      };

      mockReq.body = {
        items: [
          { id: 'item-1', quantity: 0 }, // Invalid quantity
          { id: 'item-2', quantity: 1 },
        ],
      };

      // Act
      validateRequest(arraySchema)(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Validation error',
        })
      );
    });
  });

  describe('Error Handling', () => {
    it('should create proper ApiError for validation failures', () => {
      // Arrange
      const bodySchema = {
        email: { type: 'string', required: true },
      };

      mockReq.body = {}; // email missing

      // Act
      validateRequest({ body: bodySchema })(mockReq, mockRes, mockNext);

      // Assert
      const error = mockNext.mock.calls[0][0];
      expect(error).toBeInstanceOf(ApiError);
      expect(error.statusCode).toBe(400);
      expect(error.message).toBe('Validation error');
      expect(error.errors).toBeDefined();
      expect(error.errors.length).toBeGreaterThan(0);
    });

    it('should include detailed error information', () => {
      // Arrange
      const bodySchema = {
        email: { type: 'string', required: true, format: 'email' },
        password: { type: 'string', required: true, minLength: 8 },
      };

      mockReq.body = {
        email: 'invalid-email',
        password: 'short',
      };

      // Act
      validateRequest({ body: bodySchema })(mockReq, mockRes, mockNext);

      // Assert
      const error = mockNext.mock.calls[0][0];
      expect(error.errors.length).toBe(2);
      expect(error.errors[0]).toHaveProperty('field');
      expect(error.errors[0]).toHaveProperty('message');
      expect(error.errors[1]).toHaveProperty('field');
      expect(error.errors[1]).toHaveProperty('message');
    });
  });

  describe('Performance Tests', () => {
    it('should handle large schemas efficiently', () => {
      // Arrange
      const largeSchema = {
        body: {},
      };

      // Create a large schema with many fields
      for (let i = 0; i < 100; i++) {
        largeSchema.body[`field${i}`] = {
          type: 'string',
          required: false,
        };
      }

      mockReq.body = {};
      for (let i = 0; i < 100; i++) {
        mockReq.body[`field${i}`] = `value${i}`;
      }

      // Act
      const startTime = Date.now();
      validateRequest(largeSchema)(mockReq, mockRes, mockNext);
      const endTime = Date.now();

      // Assert
      expect(endTime - startTime).toBeLessThan(10); // Less than 10ms
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should handle deep nested schemas efficiently', () => {
      // Arrange
      const deepSchema = {
        body: {
          level1: {
            type: 'object',
            properties: {
              level2: {
                type: 'object',
                properties: {
                  level3: {
                    type: 'object',
                    properties: {
                      level4: {
                        type: 'object',
                        properties: {
                          level5: {
                            type: 'string',
                            required: true,
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      };

      mockReq.body = {
        level1: {
          level2: {
            level3: {
              level4: {
                level5: 'deep-value',
              },
            },
          },
        },
      };

      // Act
      const startTime = Date.now();
      validateRequest(deepSchema)(mockReq, mockRes, mockNext);
      const endTime = Date.now();

      // Assert
      expect(endTime - startTime).toBeLessThan(5); // Less than 5ms
      expect(mockNext).toHaveBeenCalledWith();
    });
  });
});
