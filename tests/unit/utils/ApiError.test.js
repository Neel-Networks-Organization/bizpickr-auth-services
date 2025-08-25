import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import { ApiError } from '../../../src/utils/ApiError.js';

describe('ApiError Utility Class', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Constructor', () => {
    it('should create ApiError with valid parameters', () => {
      // Arrange
      const statusCode = 400;
      const message = 'Bad Request';
      const errors = ['Field is required'];
      const stack = 'Error stack trace';

      // Act
      const error = new ApiError(statusCode, message, errors, stack);

      // Assert
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(ApiError);
      expect(error.statusCode).toBe(400);
      expect(error.message).toBe('Bad Request');
      expect(error.errors).toEqual(['Field is required']);
      expect(error.success).toBe(false);
      expect(error.isOperational).toBe(true);
      expect(error.timestamp).toBeDefined();
      expect(error.stack).toBe('Error stack trace');
    });

    it('should create ApiError with numeric status code string', () => {
      // Arrange
      const statusCode = '404';
      const message = 'Not Found';

      // Act
      const error = new ApiError(statusCode, message);

      // Assert
      expect(error.statusCode).toBe(404);
      expect(typeof error.statusCode).toBe('number');
    });

    it('should create ApiError with default message when not provided', () => {
      // Arrange
      const statusCode = 500;

      // Act
      const error = new ApiError(statusCode);

      // Assert
      expect(error.message).toBe('API Error');
    });

    it('should create ApiError with default errors when not provided', () => {
      // Arrange
      const statusCode = 400;
      const message = 'Bad Request';

      // Act
      const error = new ApiError(statusCode, message);

      // Assert
      expect(error.errors).toBeUndefined();
    });

    it('should create ApiError with default stack when not provided', () => {
      // Arrange
      const statusCode = 500;
      const message = 'Internal Server Error';

      // Act
      const error = new ApiError(statusCode, message);

      // Assert
      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('ApiError');
    });

    it('should create ApiError with current timestamp', () => {
      // Arrange
      const statusCode = 200;
      const message = 'OK';
      const beforeCreation = new Date();

      // Act
      const error = new ApiError(statusCode, message);
      const afterCreation = new Date();

      // Assert
      const errorTime = new Date(error.timestamp);
      expect(errorTime.getTime()).toBeGreaterThanOrEqual(
        beforeCreation.getTime()
      );
      expect(errorTime.getTime()).toBeLessThanOrEqual(afterCreation.getTime());
    });
  });

  describe('Status Code Validation', () => {
    it('should accept valid HTTP status codes', () => {
      const validStatusCodes = [200, 201, 400, 401, 403, 404, 500, 503];

      validStatusCodes.forEach(statusCode => {
        expect(() => new ApiError(statusCode, 'Test')).not.toThrow();
      });
    });

    it('should accept string status codes and convert them', () => {
      const stringStatusCodes = ['200', '400', '500'];

      stringStatusCodes.forEach(statusCode => {
        const error = new ApiError(statusCode, 'Test');
        expect(typeof error.statusCode).toBe('number');
        expect(error.statusCode).toBe(Number(statusCode));
      });
    });

    it('should throw error for invalid status code (NaN)', () => {
      // Arrange
      const invalidStatusCode = 'invalid';

      // Act & Assert
      expect(() => new ApiError(invalidStatusCode, 'Test')).toThrow(
        'Invalid HTTP status code'
      );
    });

    it('should handle null status code by converting to 0', () => {
      // Arrange
      const nullStatusCode = null;

      // Act
      const error = new ApiError(nullStatusCode, 'Test');

      // Assert
      expect(error.statusCode).toBe(0);
    });

    it('should handle undefined status code by converting to NaN and throwing error', () => {
      // Arrange
      const undefinedStatusCode = undefined;

      // Act & Assert
      expect(() => new ApiError(undefinedStatusCode, 'Test')).toThrow(
        'Invalid HTTP status code'
      );
    });

    it('should handle empty string status code by converting to 0', () => {
      // Arrange
      const emptyStatusCode = '';

      // Act
      const error = new ApiError(emptyStatusCode, 'Test');

      // Assert
      expect(error.statusCode).toBe(0);
    });
  });

  describe('Message Handling', () => {
    it('should handle empty message', () => {
      // Arrange
      const statusCode = 400;
      const emptyMessage = '';

      // Act
      const error = new ApiError(statusCode, emptyMessage);

      // Assert
      expect(error.message).toBe('API Error');
    });

    it('should handle null message', () => {
      // Arrange
      const statusCode = 400;
      const nullMessage = null;

      // Act
      const error = new ApiError(statusCode, nullMessage);

      // Assert
      expect(error.message).toBe('API Error');
    });

    it('should handle undefined message', () => {
      // Arrange
      const statusCode = 400;
      const undefinedMessage = undefined;

      // Act
      const error = new ApiError(statusCode, undefinedMessage);

      // Assert
      expect(error.message).toBe('API Error');
    });

    it('should handle long messages', () => {
      // Arrange
      const statusCode = 400;
      const longMessage = 'A'.repeat(1000);

      // Act
      const error = new ApiError(statusCode, longMessage);

      // Assert
      expect(error.message).toBe(longMessage);
    });

    it('should handle special characters in message', () => {
      // Arrange
      const statusCode = 400;
      const specialMessage = 'Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?';

      // Act
      const error = new ApiError(statusCode, specialMessage);

      // Assert
      expect(error.message).toBe(specialMessage);
    });

    it('should handle unicode characters in message', () => {
      // Arrange
      const statusCode = 400;
      const unicodeMessage = 'Unicode: 🚀 测试 テスト';

      // Act
      const error = new ApiError(statusCode, unicodeMessage);

      // Assert
      expect(error.message).toBe(unicodeMessage);
    });
  });

  describe('Errors Array Handling', () => {
    it('should handle empty errors array', () => {
      // Arrange
      const statusCode = 400;
      const message = 'Bad Request';
      const emptyErrors = [];

      // Act
      const error = new ApiError(statusCode, message, emptyErrors);

      // Assert
      expect(error.errors).toEqual([]);
    });

    it('should handle single error string', () => {
      // Arrange
      const statusCode = 400;
      const message = 'Bad Request';
      const singleError = 'Field is required';

      // Act
      const error = new ApiError(statusCode, message, singleError);

      // Assert
      expect(error.errors).toBe(singleError);
    });

    it('should handle multiple errors array', () => {
      // Arrange
      const statusCode = 400;
      const message = 'Bad Request';
      const multipleErrors = [
        'Field is required',
        'Invalid format',
        'Too short',
      ];

      // Act
      const error = new ApiError(statusCode, message, multipleErrors);

      // Assert
      expect(error.errors).toEqual(multipleErrors);
      expect(error.errors.length).toBe(3);
    });

    it('should handle null errors', () => {
      // Arrange
      const statusCode = 400;
      const message = 'Bad Request';
      const nullErrors = null;

      // Act
      const error = new ApiError(statusCode, message, nullErrors);

      // Assert
      expect(error.errors).toBeNull();
    });

    it('should handle undefined errors', () => {
      // Arrange
      const statusCode = 400;
      const message = 'Bad Request';
      const undefinedErrors = undefined;

      // Act
      const error = new ApiError(statusCode, message, undefinedErrors);

      // Assert
      expect(error.errors).toBeUndefined();
    });

    it('should handle errors with special characters', () => {
      // Arrange
      const statusCode = 400;
      const message = 'Bad Request';
      const specialErrors = ['Special: !@#$%^&*()', 'Unicode: 🚀 测试'];

      // Act
      const error = new ApiError(statusCode, message, specialErrors);

      // Assert
      expect(error.errors).toEqual(specialErrors);
    });
  });

  describe('Stack Trace Handling', () => {
    it('should use provided stack trace', () => {
      // Arrange
      const statusCode = 500;
      const message = 'Internal Server Error';
      const customStack = 'Custom stack trace\nat line 10\nat line 20';

      // Act
      const error = new ApiError(statusCode, message, undefined, customStack);

      // Assert
      expect(error.stack).toBe(customStack);
    });

    it('should generate stack trace when not provided', () => {
      // Arrange
      const statusCode = 500;
      const message = 'Internal Server Error';

      // Act
      const error = new ApiError(statusCode, message);

      // Assert
      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('ApiError');
      expect(error.stack).toContain('at');
    });

    it('should handle empty stack trace string by generating default stack', () => {
      // Arrange
      const statusCode = 500;
      const message = 'Internal Server Error';
      const emptyStack = '';

      // Act
      const error = new ApiError(statusCode, message, undefined, emptyStack);

      // Assert
      // Empty string is falsy, so it will generate default stack trace
      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('ApiError');
    });
  });

  describe('Inheritance and Prototype', () => {
    it('should inherit from Error class', () => {
      // Arrange
      const statusCode = 400;
      const message = 'Bad Request';

      // Act
      const error = new ApiError(statusCode, message);

      // Assert
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(ApiError);
      expect(Object.getPrototypeOf(error)).toBe(ApiError.prototype);
    });

    it('should have correct constructor name', () => {
      // Arrange
      const statusCode = 400;
      const message = 'Bad Request';

      // Act
      const error = new ApiError(statusCode, message);

      // Assert
      expect(error.constructor.name).toBe('ApiError');
    });

    it('should maintain prototype chain', () => {
      // Arrange
      const statusCode = 400;
      const message = 'Bad Request';

      // Act
      const error = new ApiError(statusCode, message);

      // Assert
      expect(error.hasOwnProperty('statusCode')).toBe(true);
      expect(error.hasOwnProperty('message')).toBe(true);
      expect(error.hasOwnProperty('success')).toBe(true);
      expect(error.hasOwnProperty('isOperational')).toBe(true);
      expect(error.hasOwnProperty('timestamp')).toBe(true);
    });
  });

  describe('toString Method', () => {
    it('should return formatted string representation', () => {
      // Arrange
      const statusCode = 400;
      const message = 'Bad Request';
      const error = new ApiError(statusCode, message);

      // Act
      const result = error.toString();

      // Assert
      expect(result).toBe('ApiError: Bad Request');
    });

    it('should handle empty message in toString', () => {
      // Arrange
      const statusCode = 400;
      const error = new ApiError(statusCode);

      // Act
      const result = error.toString();

      // Assert
      expect(result).toBe('ApiError: API Error');
    });

    it('should handle special characters in toString', () => {
      // Arrange
      const statusCode = 400;
      const specialMessage = 'Special: !@#$%^&*() 🚀';
      const error = new ApiError(statusCode, specialMessage);

      // Act
      const result = error.toString();

      // Assert
      expect(result).toBe(`ApiError: ${specialMessage}`);
    });
  });

  describe('toJSON Method', () => {
    it('should return JSON representation with all properties', () => {
      // Arrange
      const statusCode = 400;
      const message = 'Bad Request';
      const errors = ['Field is required'];
      const error = new ApiError(statusCode, message, errors);

      // Act
      const result = error.toJSON();

      // Assert
      expect(result).toEqual({
        statusCode: 400,
        message: 'Bad Request',
        errors: ['Field is required'],
        success: false,
        isOperational: true,
        timestamp: error.timestamp,
      });
    });

    it('should handle undefined errors in JSON', () => {
      // Arrange
      const statusCode = 400;
      const message = 'Bad Request';
      const error = new ApiError(statusCode, message);

      // Act
      const result = error.toJSON();

      // Assert
      expect(result.errors).toBeUndefined();
    });

    it('should handle null errors in JSON', () => {
      // Arrange
      const statusCode = 400;
      const message = 'Bad Request';
      const error = new ApiError(statusCode, message, null);

      // Act
      const result = error.toJSON();

      // Assert
      expect(result.errors).toBeNull();
    });

    it('should handle empty errors array in JSON', () => {
      // Arrange
      const statusCode = 400;
      const message = 'Bad Request';
      const error = new ApiError(statusCode, message, []);

      // Act
      const result = error.toJSON();

      // Assert
      expect(result.errors).toEqual([]);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle very large status codes', () => {
      // Arrange
      const largeStatusCode = 999999;

      // Act
      const error = new ApiError(largeStatusCode, 'Test');

      // Assert
      expect(error.statusCode).toBe(999999);
    });

    it('should handle zero status code', () => {
      // Arrange
      const zeroStatusCode = 0;

      // Act
      const error = new ApiError(zeroStatusCode, 'Test');

      // Assert
      expect(error.statusCode).toBe(0);
    });

    it('should handle negative status codes', () => {
      // Arrange
      const negativeStatusCode = -100;

      // Act
      const error = new ApiError(negativeStatusCode, 'Test');

      // Assert
      expect(error.statusCode).toBe(-100);
    });

    it('should handle floating point status codes', () => {
      // Arrange
      const floatStatusCode = 400.5;

      // Act
      const error = new ApiError(floatStatusCode, 'Test');

      // Assert
      expect(error.statusCode).toBe(400.5);
    });

    it('should handle boolean status codes', () => {
      // Arrange
      const booleanStatusCode = true;

      // Act
      const error = new ApiError(booleanStatusCode, 'Test');

      // Assert
      expect(error.statusCode).toBe(1);
    });
  });

  describe('Performance Tests', () => {
    it('should create errors efficiently', () => {
      // Arrange
      const iterations = 1000;
      const startTime = Date.now();

      // Act
      for (let i = 0; i < iterations; i++) {
        new ApiError(400, `Error ${i}`);
      }
      const endTime = Date.now();

      // Assert
      const averageTime = (endTime - startTime) / iterations;
      expect(averageTime).toBeLessThan(1); // Less than 1ms per error
    });

    it('should handle JSON serialization efficiently', () => {
      // Arrange
      const error = new ApiError(400, 'Test', ['Error 1', 'Error 2']);
      const iterations = 1000;
      const startTime = Date.now();

      // Act
      for (let i = 0; i < iterations; i++) {
        error.toJSON();
      }
      const endTime = Date.now();

      // Assert
      const averageTime = (endTime - startTime) / iterations;
      expect(averageTime).toBeLessThan(0.1); // Less than 0.1ms per serialization
    });
  });

  describe('Common Error Scenarios', () => {
    it('should handle validation errors', () => {
      // Arrange
      const validationErrors = [
        'Email is required',
        'Password must be at least 8 characters',
        'Invalid phone number format',
      ];

      // Act
      const error = new ApiError(422, 'Validation failed', validationErrors);

      // Assert
      expect(error.statusCode).toBe(422);
      expect(error.message).toBe('Validation failed');
      expect(error.errors).toEqual(validationErrors);
      expect(error.success).toBe(false);
    });

    it('should handle authentication errors', () => {
      // Arrange
      const authErrors = ['Invalid credentials', 'Token expired'];

      // Act
      const error = new ApiError(401, 'Authentication failed', authErrors);

      // Assert
      expect(error.statusCode).toBe(401);
      expect(error.message).toBe('Authentication failed');
      expect(error.errors).toEqual(authErrors);
    });

    it('should handle authorization errors', () => {
      // Act
      const error = new ApiError(403, 'Access denied');

      // Assert
      expect(error.statusCode).toBe(403);
      expect(error.message).toBe('Access denied');
      expect(error.errors).toBeUndefined();
    });

    it('should handle not found errors', () => {
      // Act
      const error = new ApiError(404, 'Resource not found');

      // Assert
      expect(error.statusCode).toBe(404);
      expect(error.message).toBe('Resource not found');
    });

    it('should handle server errors', () => {
      // Act
      const error = new ApiError(500, 'Internal server error');

      // Assert
      expect(error.statusCode).toBe(500);
      expect(error.message).toBe('Internal server error');
    });

    it('should handle service unavailable errors', () => {
      // Act
      const error = new ApiError(503, 'Service temporarily unavailable');

      // Assert
      expect(error.statusCode).toBe(503);
      expect(error.message).toBe('Service temporarily unavailable');
    });
  });
});
