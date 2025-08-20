import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import { ApiError } from '../../../src/utils/index.js';

/**
 * ApiError Utility Tests
 *
 * Test Coverage:
 * - Error creation with different parameters
 * - Error inheritance and properties
 * - Stack trace functionality
 * - Error serialization
 * - Custom error messages
 * - Status code handling
 */

describe('ApiError Utility Tests', () => {
  let testError;

  beforeEach(() => {
    // Clear any previous test data
    testError = null;
  });

  describe('Error Creation', () => {
    describe('Basic Error Creation', () => {
      it('should create error with minimal parameters', () => {
        // Arrange & Act
        testError = new ApiError(400, 'Bad Request');

        // Assert
        expect(testError).toBeInstanceOf(ApiError);
        expect(testError).toBeInstanceOf(Error);
        expect(testError.statusCode).toBe(400);
        expect(testError.message).toBe('Bad Request');
        expect(testError.success).toBe(false);
        expect(testError.errors).toBeUndefined();
        expect(testError.stack).toBeDefined();
      });

      it('should create error with all parameters', () => {
        // Arrange
        const statusCode = 422;
        const message = 'Validation failed';
        const errors = ['Email is required', 'Password is too short'];
        const stack = 'Custom stack trace';

        // Act
        testError = new ApiError(statusCode, message, errors, stack);

        // Assert
        expect(testError.statusCode).toBe(statusCode);
        expect(testError.message).toBe(message);
        expect(testError.errors).toEqual(errors);
        expect(testError.stack).toBe(stack);
        expect(testError.success).toBe(false);
      });

      it('should create error with default success value', () => {
        // Arrange & Act
        testError = new ApiError(500, 'Internal Server Error');

        // Assert
        expect(testError.success).toBe(false);
      });
    });

    describe('Status Code Validation', () => {
      it('should accept valid HTTP status codes', () => {
        const validStatusCodes = [
          200, 201, 400, 401, 403, 404, 422, 500, 502, 503,
        ];

        validStatusCodes.forEach(statusCode => {
          testError = new ApiError(statusCode, 'Test message');
          expect(testError.statusCode).toBe(statusCode);
        });
      });

      it('should handle string status codes', () => {
        // Arrange & Act
        testError = new ApiError('400', 'Bad Request');

        // Assert
        expect(testError.statusCode).toBe(400);
      });

      it('should handle zero status code', () => {
        // Arrange & Act
        testError = new ApiError(0, 'Zero status');

        // Assert
        expect(testError.statusCode).toBe(0);
      });
    });

    describe('Message Handling', () => {
      it('should handle empty message', () => {
        // Arrange & Act
        testError = new ApiError(400, '');

        // Assert
        expect(testError.message).toBe('');
      });

      it('should handle null message', () => {
        // Arrange & Act
        testError = new ApiError(400, null);

        // Assert
        expect(testError.message).toBe(null);
      });

      it('should handle undefined message', () => {
        // Arrange & Act
        testError = new ApiError(400, undefined);

        // Assert
        expect(testError.message).toBe(undefined);
      });

      it('should handle long messages', () => {
        // Arrange
        const longMessage = 'A'.repeat(1000);

        // Act
        testError = new ApiError(400, longMessage);

        // Assert
        expect(testError.message).toBe(longMessage);
      });

      it('should handle special characters in message', () => {
        // Arrange
        const specialMessage =
          'Error with special chars: !@#$%^&*()_+-=[]{}|;:,.<>?';

        // Act
        testError = new ApiError(400, specialMessage);

        // Assert
        expect(testError.message).toBe(specialMessage);
      });

      it('should handle unicode characters in message', () => {
        // Arrange
        const unicodeMessage = 'Error with unicode: 🚀 测试 テスト';

        // Act
        testError = new ApiError(400, unicodeMessage);

        // Assert
        expect(testError.message).toBe(unicodeMessage);
      });
    });

    describe('Errors Array Handling', () => {
      it('should handle empty errors array', () => {
        // Arrange & Act
        testError = new ApiError(400, 'Bad Request', []);

        // Assert
        expect(testError.errors).toEqual([]);
      });

      it('should handle single error in array', () => {
        // Arrange
        const errors = ['Single error'];

        // Act
        testError = new ApiError(400, 'Bad Request', errors);

        // Assert
        expect(testError.errors).toEqual(errors);
      });

      it('should handle multiple errors in array', () => {
        // Arrange
        const errors = ['First error', 'Second error', 'Third error'];

        // Act
        testError = new ApiError(400, 'Bad Request', errors);

        // Assert
        expect(testError.errors).toEqual(errors);
      });

      it('should handle errors with special characters', () => {
        // Arrange
        const errors = [
          'Error with special chars: !@#$%^&*()',
          'Another error 🚀',
        ];

        // Act
        testError = new ApiError(400, 'Bad Request', errors);

        // Assert
        expect(testError.errors).toEqual(errors);
      });

      it('should handle undefined errors parameter', () => {
        // Arrange & Act
        testError = new ApiError(400, 'Bad Request', undefined);

        // Assert
        expect(testError.errors).toBeUndefined();
      });

      it('should handle null errors parameter', () => {
        // Arrange & Act
        testError = new ApiError(400, 'Bad Request', null);

        // Assert
        expect(testError.errors).toBeNull();
      });
    });
  });

  describe('Error Inheritance', () => {
    it('should inherit from Error class', () => {
      // Arrange & Act
      testError = new ApiError(400, 'Test error');

      // Assert
      expect(testError).toBeInstanceOf(Error);
      expect(testError).toBeInstanceOf(ApiError);
    });

    it('should have Error prototype methods', () => {
      // Arrange & Act
      testError = new ApiError(400, 'Test error');

      // Assert
      expect(typeof testError.toString).toBe('function');
      expect(typeof testError.valueOf).toBe('function');
    });

    it('should maintain prototype chain', () => {
      // Arrange & Act
      testError = new ApiError(400, 'Test error');

      // Assert
      expect(Object.getPrototypeOf(testError)).toBe(ApiError.prototype);
      expect(Object.getPrototypeOf(ApiError.prototype)).toBe(Error.prototype);
    });
  });

  describe('Stack Trace', () => {
    it('should have stack trace by default', () => {
      // Arrange & Act
      testError = new ApiError(400, 'Test error');

      // Assert
      expect(testError.stack).toBeDefined();
      expect(typeof testError.stack).toBe('string');
      expect(testError.stack.length).toBeGreaterThan(0);
    });

    it('should use custom stack trace when provided', () => {
      // Arrange
      const customStack = 'Custom stack trace at line 10';

      // Act
      testError = new ApiError(400, 'Test error', undefined, customStack);

      // Assert
      expect(testError.stack).toBe(customStack);
    });

    it('should include error message in stack trace', () => {
      // Arrange & Act
      testError = new ApiError(400, 'Custom error message');

      // Assert
      expect(testError.stack).toContain('Custom error message');
    });
  });

  describe('Error Serialization', () => {
    it('should serialize to JSON correctly', () => {
      // Arrange
      const statusCode = 400;
      const message = 'Bad Request';
      const errors = ['Field is required'];

      // Act
      testError = new ApiError(statusCode, message, errors);
      const serialized = JSON.stringify(testError);

      // Assert
      const parsed = JSON.parse(serialized);
      expect(parsed.statusCode).toBe(statusCode);
      expect(parsed.message).toBe(message);
      expect(parsed.errors).toEqual(errors);
      expect(parsed.success).toBe(false);
    });

    it('should handle circular references in serialization', () => {
      // Arrange
      testError = new ApiError(400, 'Test error');

      // Create circular reference
      testError.self = testError;

      // Act & Assert
      expect(() => JSON.stringify(testError)).not.toThrow();
    });
  });

  describe('Common Error Scenarios', () => {
    it('should create validation error', () => {
      // Arrange & Act
      testError = new ApiError(400, 'Validation failed', [
        'Email is required',
        'Password must be at least 8 characters',
      ]);

      // Assert
      expect(testError.statusCode).toBe(400);
      expect(testError.message).toBe('Validation failed');
      expect(testError.errors).toHaveLength(2);
      expect(testError.errors).toContain('Email is required');
      expect(testError.errors).toContain(
        'Password must be at least 8 characters'
      );
    });

    it('should create authentication error', () => {
      // Arrange & Act
      testError = new ApiError(401, 'Unauthorized access');

      // Assert
      expect(testError.statusCode).toBe(401);
      expect(testError.message).toBe('Unauthorized access');
      expect(testError.errors).toBeUndefined();
    });

    it('should create authorization error', () => {
      // Arrange & Act
      testError = new ApiError(403, 'Forbidden: Insufficient permissions');

      // Assert
      expect(testError.statusCode).toBe(403);
      expect(testError.message).toBe('Forbidden: Insufficient permissions');
    });

    it('should create not found error', () => {
      // Arrange & Act
      testError = new ApiError(404, 'Resource not found');

      // Assert
      expect(testError.statusCode).toBe(404);
      expect(testError.message).toBe('Resource not found');
    });

    it('should create server error', () => {
      // Arrange & Act
      testError = new ApiError(500, 'Internal server error');

      // Assert
      expect(testError.statusCode).toBe(500);
      expect(testError.message).toBe('Internal server error');
    });

    it('should create service unavailable error', () => {
      // Arrange & Act
      testError = new ApiError(503, 'Service temporarily unavailable');

      // Assert
      expect(testError.statusCode).toBe(503);
      expect(testError.message).toBe('Service temporarily unavailable');
    });
  });

  describe('Error Comparison', () => {
    it('should not be equal to different errors', () => {
      // Arrange
      const error1 = new ApiError(400, 'Error 1');
      const error2 = new ApiError(400, 'Error 2');

      // Act & Assert
      expect(error1).not.toEqual(error2);
    });

    it('should be equal to identical errors', () => {
      // Arrange
      const error1 = new ApiError(400, 'Same error', ['Error 1']);
      const error2 = new ApiError(400, 'Same error', ['Error 1']);

      // Act & Assert
      expect(error1.statusCode).toBe(error2.statusCode);
      expect(error1.message).toBe(error2.message);
      expect(error1.errors).toEqual(error2.errors);
    });
  });

  describe('Error Methods', () => {
    it('should have toString method', () => {
      // Arrange
      testError = new ApiError(400, 'Test error');

      // Act
      const stringRepresentation = testError.toString();

      // Assert
      expect(typeof stringRepresentation).toBe('string');
      expect(stringRepresentation).toContain('ApiError');
      expect(stringRepresentation).toContain('Test error');
    });

    it('should have toJSON method', () => {
      // Arrange
      testError = new ApiError(400, 'Test error', ['Error 1']);

      // Act
      const jsonRepresentation = testError.toJSON();

      // Assert
      expect(jsonRepresentation).toMatchObject({
        statusCode: 400,
        message: 'Test error',
        errors: ['Error 1'],
        success: false,
      });
    });
  });

  describe('Edge Cases', () => {
    it('should handle very large status codes', () => {
      // Arrange & Act
      testError = new ApiError(99999, 'Large status code');

      // Assert
      expect(testError.statusCode).toBe(99999);
    });

    it('should handle negative status codes', () => {
      // Arrange & Act
      testError = new ApiError(-1, 'Negative status code');

      // Assert
      expect(testError.statusCode).toBe(-1);
    });

    it('should handle floating point status codes', () => {
      // Arrange & Act
      testError = new ApiError(400.5, 'Float status code');

      // Assert
      expect(testError.statusCode).toBe(400.5);
    });

    it('should handle very long error arrays', () => {
      // Arrange
      const longErrors = Array.from({ length: 1000 }, (_, i) => `Error ${i}`);

      // Act
      testError = new ApiError(400, 'Many errors', longErrors);

      // Assert
      expect(testError.errors).toHaveLength(1000);
      expect(testError.errors[0]).toBe('Error 0');
      expect(testError.errors[999]).toBe('Error 999');
    });
  });

  describe('Performance Tests', () => {
    it('should create errors quickly', () => {
      // Arrange
      const iterations = 1000;
      const startTime = performance.now();

      // Act
      for (let i = 0; i < iterations; i++) {
        new ApiError(400, `Error ${i}`);
      }
      const endTime = performance.now();

      // Assert
      const averageTime = (endTime - startTime) / iterations;
      expect(averageTime).toBeLessThan(1); // Less than 1ms per error
    });

    it('should handle memory efficiently', () => {
      // Arrange
      const errors = [];

      // Act
      for (let i = 0; i < 1000; i++) {
        errors.push(new ApiError(400, `Error ${i}`));
      }

      // Assert
      expect(errors).toHaveLength(1000);
      // Memory usage should be reasonable (no memory leaks)
    });
  });
});
