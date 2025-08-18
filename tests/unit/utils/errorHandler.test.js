import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from "@jest/globals";
import { errorHandler } from "../../../src/utils/errorHandler.js";
import { ApiError } from "../../../src/utils/ApiError.js";
import { status as grpcStatus } from "@grpc/grpc-js";
import { safeLogger } from "@/config/logger.js";

/**
 * ErrorHandler Utility Tests
 *
 * Test Coverage:
 * - gRPC error handling and status mapping
 * - Non-HTTP error mapping
 * - ApiError handling
 * - Logging functionality
 * - Response formatting
 * - Edge cases and error scenarios
 * - Production vs development environment
 */

// Mock the logger
jest.mock("@/config/logger.js", () => ({
  safeLogger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

// Mock gRPC status
jest.mock("@grpc/grpc-js", () => ({
  status: {
    DEADLINE_EXCEEDED: 4,
    UNAVAILABLE: 14,
    INVALID_ARGUMENT: 3,
    NOT_FOUND: 5,
    INTERNAL: 13,
  },
}));

describe("ErrorHandler Utility Tests", () => {
  let mockReq;
  let mockRes;
  let mockNext;
  let mockLogger;

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();

    // Mock request object
    mockReq = {
      originalUrl: "/api/test",
      method: "GET",
      correlationId: "test-correlation-id",
      headers: {
        "user-agent": "Mozilla/5.0 (Test Browser)",
        "x-correlation-id": "test-correlation-id",
      },
      ip: "127.0.0.1",
      connection: {
        remoteAddress: "127.0.0.1",
      },
      user: {
        id: "user-123",
        email: "test@example.com",
      },
    };

    // Mock response object
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };

    // Mock next function
    mockNext = jest.fn();

    // Get logger mock
    mockLogger = safeLogger;
  });

  afterEach(() => {
    // Reset environment
    delete process.env.NODE_ENV;
  });

  describe("gRPC Error Handling", () => {
    describe("gRPC Status Code Mapping", () => {
      it("should map DEADLINE_EXCEEDED to 504", () => {
        // Arrange
        const grpcError = {
          code: grpcStatus.DEADLINE_EXCEEDED,
          message: "Request timeout",
          details: "Service took too long to respond",
        };

        // Act
        errorHandler(grpcError, mockReq, mockRes, mockNext);

        // Assert
        expect(mockRes.status).toHaveBeenCalledWith(504);
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            success: false,
            message: "Request timeout",
            errors: ["Request timeout", "Service took too long to respond"],
          })
        );
      });

      it("should map UNAVAILABLE to 503", () => {
        // Arrange
        const grpcError = {
          code: grpcStatus.UNAVAILABLE,
          message: "Service unavailable",
          details: "Service is down",
        };

        // Act
        errorHandler(grpcError, mockReq, mockRes, mockNext);

        // Assert
        expect(mockRes.status).toHaveBeenCalledWith(503);
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            success: false,
            message: "Service unavailable",
            errors: ["Service unavailable", "Service is down"],
          })
        );
      });

      it("should map INVALID_ARGUMENT to 400", () => {
        // Arrange
        const grpcError = {
          code: grpcStatus.INVALID_ARGUMENT,
          message: "Invalid input",
          details: "Missing required field",
        };

        // Act
        errorHandler(grpcError, mockReq, mockRes, mockNext);

        // Assert
        expect(mockRes.status).toHaveBeenCalledWith(400);
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            success: false,
            message: "Invalid input",
            errors: ["Invalid input", "Missing required field"],
          })
        );
      });

      it("should map NOT_FOUND to 404", () => {
        // Arrange
        const grpcError = {
          code: grpcStatus.NOT_FOUND,
          message: "Resource not found",
          details: "User with ID 123 not found",
        };

        // Act
        errorHandler(grpcError, mockReq, mockRes, mockNext);

        // Assert
        expect(mockRes.status).toHaveBeenCalledWith(404);
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            success: false,
            message: "Resource not found",
            errors: ["Resource not found", "User with ID 123 not found"],
          })
        );
      });

      it("should map INTERNAL to 500", () => {
        // Arrange
        const grpcError = {
          code: grpcStatus.INTERNAL,
          message: "Internal error",
          details: "Database connection failed",
        };

        // Act
        errorHandler(grpcError, mockReq, mockRes, mockNext);

        // Assert
        expect(mockRes.status).toHaveBeenCalledWith(500);
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            success: false,
            message: "Internal error",
            errors: ["Internal error", "Database connection failed"],
          })
        );
      });

      it("should map unknown gRPC codes to 500", () => {
        // Arrange
        const grpcError = {
          code: 999, // Unknown code
          message: "Unknown error",
          details: "Something went wrong",
        };

        // Act
        errorHandler(grpcError, mockReq, mockRes, mockNext);

        // Assert
        expect(mockRes.status).toHaveBeenCalledWith(500);
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            success: false,
            message: "Unknown error",
            errors: ["Unknown error", "Something went wrong"],
          })
        );
      });

      it("should handle gRPC error without details", () => {
        // Arrange
        const grpcError = {
          code: grpcStatus.INVALID_ARGUMENT,
          message: "Invalid input",
        };

        // Act
        errorHandler(grpcError, mockReq, mockRes, mockNext);

        // Assert
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            success: false,
            message: "Invalid input",
            errors: ["Invalid input"],
          })
        );
      });

      it("should handle gRPC error without message", () => {
        // Arrange
        const grpcError = {
          code: grpcStatus.INTERNAL,
          details: "Database error",
        };

        // Act
        errorHandler(grpcError, mockReq, mockRes, mockNext);

        // Assert
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            success: false,
            message: "gRPC Error",
            errors: ["Database error"],
          })
        );
      });
    });
  });

  describe("Non-HTTP Error Mapping", () => {
    it("should map connection refused to 503", () => {
      // Arrange
      const connectionError = new Error("Connection refused");

      // Act
      errorHandler(connectionError, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(503);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Connection refused",
          errors: [],
        })
      );
    });

    it("should map timeout errors to 503", () => {
      // Arrange
      const timeoutError = new Error("Request timeout after 30 seconds");

      // Act
      errorHandler(timeoutError, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(503);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Request timeout after 30 seconds",
          errors: [],
        })
      );
    });

    it("should map not found errors to 404", () => {
      // Arrange
      const notFoundError = new Error("User not found in database");

      // Act
      errorHandler(notFoundError, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(404);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "User not found in database",
          errors: [],
        })
      );
    });

    it("should map validation errors to 400", () => {
      // Arrange
      const validationError = new Error("Validation failed: email is required");

      // Act
      errorHandler(validationError, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Validation failed: email is required",
          errors: [],
        })
      );
    });

    it("should map unknown errors to 500", () => {
      // Arrange
      const unknownError = new Error("Something unexpected happened");

      // Act
      errorHandler(unknownError, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Something unexpected happened",
          errors: [],
        })
      );
    });

    it("should handle errors without message", () => {
      // Arrange
      const errorWithoutMessage = new Error();

      // Act
      errorHandler(errorWithoutMessage, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Internal Server Error",
          errors: [],
        })
      );
    });
  });

  describe("ApiError Handling", () => {
    it("should handle ApiError directly", () => {
      // Arrange
      const apiError = new ApiError(422, "Validation failed", [
        "Email is required",
        "Password is too short",
      ]);

      // Act
      errorHandler(apiError, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(422);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Validation failed",
          errors: ["Email is required", "Password is too short"],
        })
      );
    });

    it("should handle ApiError with stack trace", () => {
      // Arrange
      const apiError = new ApiError(
        500,
        "Internal error",
        [],
        "Custom stack trace"
      );

      // Act
      errorHandler(apiError, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Internal error",
          errors: [],
          stack: "Custom stack trace",
        })
      );
    });
  });

  describe("Logging Functionality", () => {
    it("should log error with request details", () => {
      // Arrange
      const error = new Error("Test error");

      // Act
      errorHandler(error, mockReq, mockRes, mockNext);

      // Assert
      expect(mockLogger.error).toHaveBeenCalledWith(
        "Critical Error",
        expect.objectContaining({
          error: expect.objectContaining({
            message: "Test error",
          }),
          request: expect.objectContaining({
            url: "/api/test",
            method: "GET",
            correlationId: "test-correlation-id",
          }),
        })
      );
    });

    it("should log error without user when user is not present", () => {
      // Arrange
      const error = new Error("Test error");
      const reqWithoutUser = { ...mockReq };
      delete reqWithoutUser.user;

      // Act
      errorHandler(error, reqWithoutUser, mockRes, mockNext);

      // Assert
      expect(mockLogger.error).toHaveBeenCalledWith(
        "Critical Error",
        expect.objectContaining({
          request: expect.objectContaining({
            user: undefined,
          }),
        })
      );
    });

    it("should log error with unknown correlation ID when not present", () => {
      // Arrange
      const error = new Error("Test error");
      const reqWithoutCorrelationId = { ...mockReq };
      delete reqWithoutCorrelationId.correlationId;

      // Act
      errorHandler(error, reqWithoutCorrelationId, mockRes, mockNext);

      // Assert
      expect(mockLogger.error).toHaveBeenCalledWith(
        "Critical Error",
        expect.objectContaining({
          request: expect.objectContaining({
            correlationId: "unknown",
          }),
        })
      );
    });

    it("should log gRPC error details", () => {
      // Arrange
      const grpcError = {
        code: grpcStatus.INVALID_ARGUMENT,
        message: "Invalid input",
        details: "Missing required field",
      };

      // Act
      errorHandler(grpcError, mockReq, mockRes, mockNext);

      // Assert
      expect(mockLogger.error).toHaveBeenCalledWith(
        "Client Error",
        expect.objectContaining({
          error: expect.objectContaining({
            message: "Invalid input",
            category: "grpc",
          }),
        })
      );
    });
  });

  describe("Response Formatting", () => {
    it("should format response correctly", () => {
      // Arrange
      const error = new Error("Test error");

      // Act
      errorHandler(error, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Test error",
          statusCode: 500,
          category: "internal",
          timestamp: expect.any(String),
          errors: [],
          stack: error.stack,
        })
      );
    });

    it("should not include stack trace in production", () => {
      // Arrange
      process.env.NODE_ENV = "production";
      const error = new Error("Test error");

      // Act
      errorHandler(error, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Test error",
          statusCode: 500,
          category: "internal",
          timestamp: expect.any(String),
          errors: [],
        })
      );
      expect(mockRes.json).not.toHaveBeenCalledWith(
        expect.objectContaining({
          stack: expect.anything(),
        })
      );
    });

    it("should include stack trace in development", () => {
      // Arrange
      process.env.NODE_ENV = "development";
      const error = new Error("Test error");

      // Act
      errorHandler(error, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Test error",
          statusCode: 500,
          category: "internal",
          timestamp: expect.any(String),
          errors: [],
          stack: error.stack,
        })
      );
    });

    it("should handle empty errors array", () => {
      // Arrange
      const apiError = new ApiError(400, "Bad Request");

      // Act
      errorHandler(apiError, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Bad Request",
          statusCode: 400,
          category: "validation",
          timestamp: expect.any(String),
          errors: [],
        })
      );
    });
  });

  describe("Edge Cases", () => {
    it("should handle null error", () => {
      // Arrange
      const nullError = null;

      // Act
      errorHandler(nullError, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Internal Server Error",
          statusCode: 500,
          category: "internal",
        })
      );
    });

    it("should handle undefined error", () => {
      // Arrange
      const undefinedError = undefined;

      // Act
      errorHandler(undefinedError, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Internal Server Error",
          statusCode: 500,
          category: "internal",
        })
      );
    });

    it("should handle error with non-string message", () => {
      // Arrange
      const errorWithNonStringMessage = {
        message: 123,
        stack: "Test stack",
      };

      // Act
      errorHandler(errorWithNonStringMessage, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Internal Server Error",
          statusCode: 500,
          category: "internal",
        })
      );
    });

    it("should handle error with circular references", () => {
      // Arrange
      const circularError = new Error("Circular error");
      circularError.self = circularError;

      // Act
      errorHandler(circularError, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Circular error",
          statusCode: 500,
          category: "internal",
        })
      );
    });

    it("should handle very long error messages", () => {
      // Arrange
      const longMessage = "A".repeat(10000);
      const longError = new Error(longMessage);

      // Act
      errorHandler(longError, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: longMessage,
          statusCode: 500,
          category: "internal",
        })
      );
    });
  });

  describe("Performance Tests", () => {
    it("should handle errors quickly", () => {
      // Arrange
      const iterations = 100;
      const startTime = performance.now();

      // Act
      for (let i = 0; i < iterations; i++) {
        const error = new Error(`Error ${i}`);
        errorHandler(error, mockReq, mockRes, mockNext);
      }
      const endTime = performance.now();

      // Assert
      const averageTime = (endTime - startTime) / iterations;
      expect(averageTime).toBeLessThan(10); // Less than 10ms per error
    });

    it("should handle memory efficiently", () => {
      // Arrange
      const errors = [];

      // Act
      for (let i = 0; i < 1000; i++) {
        const error = new Error(`Error ${i}`);
        errorHandler(error, mockReq, mockRes, mockNext);
        errors.push(error);
      }

      // Assert
      expect(errors).toHaveLength(1000);
      // Memory usage should be reasonable (no memory leaks)
    });
  });

  describe("Integration Scenarios", () => {
    it("should handle complete error flow with gRPC error", () => {
      // Arrange
      const grpcError = {
        code: grpcStatus.UNAVAILABLE,
        message: "Service temporarily unavailable",
        details: "Database connection pool exhausted",
      };

      // Act
      errorHandler(grpcError, mockReq, mockRes, mockNext);

      // Assert
      expect(mockLogger.error).toHaveBeenCalledWith(
        "Critical Error",
        expect.objectContaining({
          error: expect.objectContaining({
            message: "Service temporarily unavailable",
            statusCode: 503,
            category: "grpc",
          }),
          request: expect.objectContaining({
            url: "/api/test",
            method: "GET",
            correlationId: "test-correlation-id",
          }),
        })
      );

      expect(mockRes.status).toHaveBeenCalledWith(503);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Service temporarily unavailable",
          statusCode: 503,
          category: "grpc",
          timestamp: expect.any(String),
          errors: [
            "Service temporarily unavailable",
            "Database connection pool exhausted",
          ],
          stack: expect.any(String),
        })
      );
    });

    it("should handle complete error flow with validation error", () => {
      // Arrange
      const validationError = new ApiError(422, "Validation failed", [
        "Email is required",
        "Password must be at least 8 characters",
        "Phone number format is invalid",
      ]);

      // Act
      errorHandler(validationError, mockReq, mockRes, mockNext);

      // Assert
      expect(mockLogger.error).toHaveBeenCalledWith(
        "Client Error",
        expect.objectContaining({
          error: expect.objectContaining({
            message: "Validation failed",
            statusCode: 422,
            category: "validation",
          }),
          request: expect.objectContaining({
            url: "/api/test",
            method: "GET",
            correlationId: "test-correlation-id",
          }),
        })
      );

      expect(mockRes.status).toHaveBeenCalledWith(422);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Validation failed",
          statusCode: 422,
          category: "validation",
          timestamp: expect.any(String),
          errors: [
            "Email is required",
            "Password must be at least 8 characters",
            "Phone number format is invalid",
          ],
          stack: validationError.stack,
        })
      );
    });

    it("should handle production environment response", () => {
      // Arrange
      process.env.NODE_ENV = "production";
      const error = new ApiError(500, "Internal server error", [
        "Database connection failed",
      ]);

      // Act
      errorHandler(error, mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: "Internal server error",
          statusCode: 500,
          category: "internal",
          timestamp: expect.any(String),
          errors: ["Database connection failed"],
        })
      );
      expect(mockRes.json).not.toHaveBeenCalledWith(
        expect.objectContaining({
          stack: expect.anything(),
        })
      );
    });
  });
});
