import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from "@jest/globals";
import {
  asyncHandler,
  getActiveRequests,
  getRequestStats,
  clearRequestData,
  asyncHandlerWithTimeout,
  asyncHandlerWithRetry,
  asyncHandlerWithValidation,
  asyncHandlerWithLogging,
  asyncHandlerWithTiming,
} from "../../../src/utils/asyncHandler.js";
import { ApiError } from "../../../src/utils/ApiError.js";

/**
 * AsyncHandler Utility Tests
 *
 * Test Coverage:
 * - Basic async handler functionality
 * - Error handling and propagation
 * - Performance monitoring and timing
 * - Request tracking and correlation IDs
 * - Timeout handling
 * - Retry logic with exponential backoff
 * - Request validation
 * - Pre/post handler middleware
 * - Error transformation
 * - Memory leak prevention
 * - Factory functions
 * - Edge cases and performance
 */

// Mock the logger
jest.mock("@auth/config/logger.js", () => ({
  safeLogger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

describe("AsyncHandler Utility Tests", () => {
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
      url: "/api/test",
      method: "GET",
      headers: {
        "user-agent": "Mozilla/5.0 (Test Browser)",
        "content-type": "application/json",
      },
      body: {},
      query: {},
      user: {
        id: "user-123",
        email: "test@example.com",
      },
      ip: "192.168.1.1",
      connection: {
        remoteAddress: "192.168.1.1",
      },
    };

    // Mock response object
    mockRes = {
      statusCode: 200,
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };

    // Mock next function
    mockNext = jest.fn();

    // Get logger mock
    const { safeLogger } = await import("@auth/config/logger.js");
    mockLogger = safeLogger;

    // Clear any existing request data
    clearRequestData();
  });

  afterEach(() => {
    // Clean up after each test
    clearRequestData();
  });

  describe("Basic Async Handler Functionality", () => {
    it("should handle successful async operations", async () => {
      // Arrange
      const handler = async (req, res) => {
        return { success: true, data: "test" };
      };
      const wrappedHandler = asyncHandler(handler);

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Request completed",
        expect.objectContaining({
          url: "/api/test",
          method: "GET",
          statusCode: 200,
        })
      );
    });

    it("should handle synchronous operations", async () => {
      // Arrange
      const handler = (req, res) => {
        return { success: true, data: "sync" };
      };
      const wrappedHandler = asyncHandler(handler);

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Request completed",
        expect.objectContaining({
          url: "/api/test",
          method: "GET",
        })
      );
    });

    it("should handle errors and pass them to next", async () => {
      // Arrange
      const error = new Error("Test error");
      const handler = async () => {
        throw error;
      };
      const wrappedHandler = asyncHandler(handler);

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(error);
      expect(mockLogger.error).toHaveBeenCalledWith(
        "Request failed",
        expect.objectContaining({
          error: expect.objectContaining({
            message: "Test error",
          }),
        })
      );
    });

    it("should handle ApiError instances", async () => {
      // Arrange
      const apiError = new ApiError(400, "Bad Request", ["Invalid input"]);
      const handler = async () => {
        throw apiError;
      };
      const wrappedHandler = asyncHandler(handler);

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(apiError);
      expect(mockLogger.error).toHaveBeenCalledWith(
        "Request failed",
        expect.objectContaining({
          error: expect.objectContaining({
            message: "Bad Request",
          }),
        })
      );
    });
  });

  describe("Request Correlation and Tracking", () => {
    it("should generate correlation ID if not present", async () => {
      // Arrange
      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler);

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockReq.correlationId).toBeDefined();
      expect(mockReq.correlationId).toMatch(/^req-\d+-\w+$/);
    });

    it("should use existing correlation ID if present", async () => {
      // Arrange
      mockReq.correlationId = "existing-correlation-id";
      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler);

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockReq.correlationId).toBe("existing-correlation-id");
    });

    it("should track active requests", async () => {
      // Arrange
      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler);

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      const activeRequests = getActiveRequests();
      expect(activeRequests).toHaveLength(0); // Should be cleaned up after completion
    });

    it("should provide request statistics", () => {
      // Arrange & Act
      const stats = getRequestStats();

      // Assert
      expect(stats).toEqual({
        activeRequests: 0,
        totalRequests: 0,
        averageDuration: "0ms",
      });
    });
  });

  describe("Timeout Handling", () => {
    it("should handle request timeout", async () => {
      // Arrange
      const handler = async () => {
        await new Promise((resolve) => setTimeout(resolve, 100));
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler, { timeout: 50 });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 408,
          message: "Request timeout",
        })
      );
    });

    it("should not timeout if request completes quickly", async () => {
      // Arrange
      const handler = async () => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler, { timeout: 1000 });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Request completed",
        expect.any(Object)
      );
    });

    it("should disable timeout when set to 0", async () => {
      // Arrange
      const handler = async () => {
        await new Promise((resolve) => setTimeout(resolve, 100));
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler, { timeout: 0 });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Request completed",
        expect.any(Object)
      );
    });
  });

  describe("Retry Logic", () => {
    it("should retry failed requests", async () => {
      // Arrange
      let attempts = 0;
      const handler = async () => {
        attempts++;
        if (attempts < 3) {
          throw new Error("Temporary failure");
        }
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler, { retryAttempts: 2 });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(attempts).toBe(3);
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockLogger.warn).toHaveBeenCalledTimes(2); // 2 retry attempts
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Request completed",
        expect.any(Object)
      );
    });

    it("should fail after all retry attempts", async () => {
      // Arrange
      const error = new Error("Persistent failure");
      const handler = async () => {
        throw error;
      };
      const wrappedHandler = asyncHandler(handler, { retryAttempts: 2 });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(error);
      expect(mockLogger.warn).toHaveBeenCalledTimes(2); // 2 retry attempts
      expect(mockLogger.error).toHaveBeenCalledWith(
        "Request failed",
        expect.objectContaining({
          attempts: 3,
        })
      );
    });

    it("should use exponential backoff for retries", async () => {
      // Arrange
      let attempts = 0;
      const startTime = Date.now();
      const handler = async () => {
        attempts++;
        if (attempts < 3) {
          throw new Error("Temporary failure");
        }
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler, { retryAttempts: 2 });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      const endTime = Date.now();
      const totalTime = endTime - startTime;
      expect(totalTime).toBeGreaterThan(1000); // Should have delays between retries
      expect(attempts).toBe(3);
    });
  });

  describe("Request Validation", () => {
    it("should validate requests when enabled", async () => {
      // Arrange
      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler, { enableValidation: true });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Request completed",
        expect.any(Object)
      );
    });

    it("should reject invalid requests", async () => {
      // Arrange
      const invalidReq = { ...mockReq };
      delete invalidReq.method;

      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler, { enableValidation: true });

      // Act
      await wrappedHandler(invalidReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: "Invalid request",
        })
      );
    });

    it("should validate content type for POST requests", async () => {
      // Arrange
      const postReq = {
        ...mockReq,
        method: "POST",
        headers: {}, // No content-type
      };

      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler, { enableValidation: true });

      // Act
      await wrappedHandler(postReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: "Invalid request",
        })
      );
    });

    it("should validate body size", async () => {
      // Arrange
      const largeBodyReq = {
        ...mockReq,
        method: "POST",
        body: { data: "x".repeat(11 * 1024 * 1024) }, // 11MB
      };

      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler, { enableValidation: true });

      // Act
      await wrappedHandler(largeBodyReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: "Invalid request",
        })
      );
    });
  });

  describe("Pre/Post Handler Middleware", () => {
    it("should execute pre-handler middleware", async () => {
      // Arrange
      const preHandler = jest.fn();
      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler, { preHandler });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(preHandler).toHaveBeenCalledWith(mockReq, mockRes);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it("should execute post-handler middleware", async () => {
      // Arrange
      const postHandler = jest.fn();
      const handler = async (req, res) => {
        return { success: true, data: "test" };
      };
      const wrappedHandler = asyncHandler(handler, { postHandler });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(postHandler).toHaveBeenCalledWith(mockReq, mockRes, {
        success: true,
        data: "test",
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it("should handle pre-handler errors gracefully", async () => {
      // Arrange
      const preHandler = async () => {
        throw new Error("Pre-handler error");
      };
      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler, { preHandler });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockLogger.warn).toHaveBeenCalledWith(
        "Pre-handler error",
        expect.objectContaining({
          error: "Pre-handler error",
        })
      );
      expect(mockNext).not.toHaveBeenCalled();
    });

    it("should handle post-handler errors gracefully", async () => {
      // Arrange
      const postHandler = async () => {
        throw new Error("Post-handler error");
      };
      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler, { postHandler });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockLogger.warn).toHaveBeenCalledWith(
        "Post-handler error",
        expect.objectContaining({
          error: "Post-handler error",
        })
      );
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe("Error Transformation", () => {
    it("should transform errors using custom transformer", async () => {
      // Arrange
      const originalError = new Error("Original error");
      const transformedError = new ApiError(500, "Transformed error");

      const errorTransformer = jest.fn().mockReturnValue(transformedError);
      const handler = async () => {
        throw originalError;
      };
      const wrappedHandler = asyncHandler(handler, { errorTransformer });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(errorTransformer).toHaveBeenCalledWith(
        originalError,
        mockReq,
        mockRes
      );
      expect(mockNext).toHaveBeenCalledWith(transformedError);
    });

    it("should handle transformer that returns null", async () => {
      // Arrange
      const originalError = new Error("Original error");
      const errorTransformer = jest.fn().mockReturnValue(null);
      const handler = async () => {
        throw originalError;
      };
      const wrappedHandler = asyncHandler(handler, { errorTransformer });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(null);
    });
  });

  describe("Factory Functions", () => {
    it("should create handler with timeout", async () => {
      // Arrange
      const handler = async () => {
        await new Promise((resolve) => setTimeout(resolve, 100));
        return { success: true };
      };
      const wrappedHandler = asyncHandlerWithTimeout(50)(handler);

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 408,
          message: "Request timeout",
        })
      );
    });

    it("should create handler with retry", async () => {
      // Arrange
      let attempts = 0;
      const handler = async () => {
        attempts++;
        if (attempts < 2) {
          throw new Error("Temporary failure");
        }
        return { success: true };
      };
      const wrappedHandler = asyncHandlerWithRetry(1)(handler);

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(attempts).toBe(2);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it("should create handler with validation", async () => {
      // Arrange
      const invalidReq = { ...mockReq };
      delete invalidReq.method;

      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandlerWithValidation(handler);

      // Act
      await wrappedHandler(invalidReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: "Invalid request",
        })
      );
    });

    it("should create handler with logging", async () => {
      // Arrange
      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandlerWithLogging(handler);

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Request completed",
        expect.any(Object)
      );
    });

    it("should create handler with timing", async () => {
      // Arrange
      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandlerWithTiming(handler);

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Request completed",
        expect.objectContaining({
          duration: expect.stringMatching(/\d+ms/),
        })
      );
    });
  });

  describe("Configuration Options", () => {
    it("should disable timing when configured", async () => {
      // Arrange
      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler, { enableTiming: false });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Request completed",
        expect.any(Object)
      );
    });

    it("should disable logging when configured", async () => {
      // Arrange
      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler, { enableLogging: false });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockLogger.info).not.toHaveBeenCalled();
      expect(mockLogger.error).not.toHaveBeenCalled();
    });

    it("should handle all options disabled", async () => {
      // Arrange
      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler, {
        enableTiming: false,
        enableLogging: false,
        enableValidation: false,
        timeout: 0,
        retryAttempts: 0,
      });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockLogger.info).not.toHaveBeenCalled();
      expect(mockLogger.error).not.toHaveBeenCalled();
    });
  });

  describe("Edge Cases", () => {
    it("should handle null/undefined handlers", async () => {
      // Arrange
      const wrappedHandler = asyncHandler(null);

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          message: expect.stringContaining("null"),
        })
      );
    });

    it("should handle handlers that return undefined", async () => {
      // Arrange
      const handler = async () => {
        return undefined;
      };
      const wrappedHandler = asyncHandler(handler);

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Request completed",
        expect.any(Object)
      );
    });

    it("should handle very long request URLs", async () => {
      // Arrange
      const longUrlReq = {
        ...mockReq,
        originalUrl: "/api/" + "a".repeat(10000),
      };

      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler);

      // Act
      await wrappedHandler(longUrlReq, mockRes, mockNext);

      // Assert
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Request completed",
        expect.any(Object)
      );
    });

    it("should handle circular references in request body", async () => {
      // Arrange
      const circularBody = { name: "test" };
      circularBody.self = circularBody;

      const circularReq = {
        ...mockReq,
        body: circularBody,
      };

      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler, { enableValidation: true });

      // Act
      await wrappedHandler(circularReq, mockRes, mockNext);

      // Assert
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Request completed",
        expect.any(Object)
      );
    });
  });

  describe("Performance Tests", () => {
    it("should handle requests quickly", async () => {
      // Arrange
      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler);
      const iterations = 100;
      const startTime = performance.now();

      // Act
      for (let i = 0; i < iterations; i++) {
        await wrappedHandler(mockReq, mockRes, mockNext);
      }
      const endTime = performance.now();

      // Assert
      const averageTime = (endTime - startTime) / iterations;
      expect(averageTime).toBeLessThan(10); // Less than 10ms per request
    });

    it("should handle memory efficiently", async () => {
      // Arrange
      const handler = async (req, res) => {
        return { success: true };
      };
      const wrappedHandler = asyncHandler(handler);
      const requests = [];

      // Act
      for (let i = 0; i < 1000; i++) {
        await wrappedHandler(mockReq, mockRes, mockNext);
        requests.push(i);
      }

      // Assert
      expect(requests).toHaveLength(1000);
      const stats = getRequestStats();
      expect(stats.activeRequests).toBe(0); // Should be cleaned up
    });
  });

  describe("Integration Scenarios", () => {
    it("should handle complete request lifecycle", async () => {
      // Arrange
      const preHandler = jest.fn();
      const postHandler = jest.fn();
      const errorTransformer = jest.fn();

      const handler = async (req, res) => {
        return { success: true, data: "processed" };
      };

      const wrappedHandler = asyncHandler(handler, {
        enableTiming: true,
        enableLogging: true,
        enableValidation: true,
        timeout: 5000,
        retryAttempts: 1,
        preHandler,
        postHandler,
        errorTransformer,
      });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(preHandler).toHaveBeenCalledWith(mockReq, mockRes);
      expect(postHandler).toHaveBeenCalledWith(mockReq, mockRes, {
        success: true,
        data: "processed",
      });
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Request completed",
        expect.objectContaining({
          duration: expect.stringMatching(/\d+ms/),
          statusCode: 200,
        })
      );
    });

    it("should handle error scenario with all features", async () => {
      // Arrange
      const error = new Error("Database connection failed");
      const transformedError = new ApiError(503, "Service unavailable");

      const preHandler = jest.fn();
      const postHandler = jest.fn();
      const errorTransformer = jest.fn().mockReturnValue(transformedError);

      const handler = async () => {
        throw error;
      };

      const wrappedHandler = asyncHandler(handler, {
        enableTiming: true,
        enableLogging: true,
        enableValidation: true,
        timeout: 5000,
        retryAttempts: 2,
        preHandler,
        postHandler,
        errorTransformer,
      });

      // Act
      await wrappedHandler(mockReq, mockRes, mockNext);

      // Assert
      expect(preHandler).toHaveBeenCalled();
      expect(postHandler).not.toHaveBeenCalled();
      expect(errorTransformer).toHaveBeenCalledWith(error, mockReq, mockRes);
      expect(mockNext).toHaveBeenCalledWith(transformedError);
      expect(mockLogger.warn).toHaveBeenCalledTimes(2); // 2 retry attempts
      expect(mockLogger.error).toHaveBeenCalledWith(
        "Request failed",
        expect.objectContaining({
          attempts: 3,
          duration: expect.stringMatching(/\d+ms/),
        })
      );
    });
  });
});
