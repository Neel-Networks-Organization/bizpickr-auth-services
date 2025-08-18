import { jest } from "@jest/globals";
import grpc from "@grpc/grpc-js";
import { startGrpcServer, stopGrpcServer } from "@/grpc/server/auth.server.js";
import { env } from "@/config/env.js";
import * as authService from "@/grpc/services/authService.js";

// Mock dependencies
jest.mock("@/config/env.js");
jest.mock("@/grpc/services/authService.js");
jest.mock("@/config/logger.js", () => ({
  safeLogger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
  },
}));

describe("gRPC Auth Server Integration", () => {
  let client;
  let serverAddress;

  beforeAll(async () => {
    // Mock environment variables
    env.GRPC_AUTH_SERVICE_HOST = "localhost";
    env.GRPC_AUTH_SERVICE_PORT = "50051";

    serverAddress = `${env.GRPC_AUTH_SERVICE_HOST}:${env.GRPC_AUTH_SERVICE_PORT}`;

    // Start gRPC server
    await startGrpcServer();

    // Create gRPC client
    client = new grpc.Client(serverAddress, grpc.credentials.createInsecure());
  });

  afterAll(async () => {
    // Cleanup
    if (client) {
      client.close();
    }
    await stopGrpcServer();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("Server Initialization", () => {
    it("should start gRPC server successfully", async () => {
      expect(serverAddress).toBe("localhost:50051");
    });

    it("should handle server startup errors gracefully", async () => {
      // Mock server bind to fail
      const mockBindAsync = jest
        .fn()
        .mockImplementation((address, credentials, callback) => {
          callback(new Error("Port already in use"));
        });

      const mockServer = {
        bindAsync: mockBindAsync,
        addService: jest.fn(),
      };

      jest.doMock("@grpc/grpc-js", () => ({
        ...jest.requireActual("@grpc/grpc-js"),
        Server: jest.fn().mockImplementation(() => mockServer),
      }));

      await expect(startGrpcServer()).rejects.toThrow("Port already in use");
    });
  });

  describe("Login Service", () => {
    it("should handle valid login request", (done) => {
      const loginRequest = {
        email: "test@example.com",
        password: "password123",
      };

      const expectedResponse = {
        token: "mock-jwt-token",
        userId: "user-123",
      };

      // Mock auth service
      authService.login.mockResolvedValue(expectedResponse);

      client.Login(loginRequest, (err, response) => {
        expect(err).toBeNull();
        expect(response).toEqual(expectedResponse);
        expect(authService.login).toHaveBeenCalledWith(loginRequest);
        done();
      });
    });

    it("should handle login with missing email", (done) => {
      const loginRequest = {
        password: "password123",
        // missing email
      };

      client.Login(loginRequest, (err, response) => {
        expect(err).not.toBeNull();
        expect(err.code).toBe(grpc.status.INVALID_ARGUMENT);
        expect(err.message).toContain("Email and password required");
        done();
      });
    });

    it("should handle login with missing password", (done) => {
      const loginRequest = {
        email: "test@example.com",
        // missing password
      };

      client.Login(loginRequest, (err, response) => {
        expect(err).not.toBeNull();
        expect(err.code).toBe(grpc.status.INVALID_ARGUMENT);
        expect(err.message).toContain("Email and password required");
        done();
      });
    });

    it("should handle authentication failure", (done) => {
      const loginRequest = {
        email: "invalid@example.com",
        password: "wrongpassword",
      };

      // Mock auth service to throw error
      authService.login.mockRejectedValue(new Error("Invalid credentials"));

      client.Login(loginRequest, (err, response) => {
        expect(err).not.toBeNull();
        expect(err.code).toBe(grpc.status.UNAUTHENTICATED);
        done();
      });
    });

    it("should handle service errors gracefully", (done) => {
      const loginRequest = {
        email: "test@example.com",
        password: "password123",
      };

      // Mock auth service to throw unexpected error
      authService.login.mockRejectedValue(
        new Error("Database connection failed")
      );

      client.Login(loginRequest, (err, response) => {
        expect(err).not.toBeNull();
        expect(err.code).toBe(grpc.status.INTERNAL);
        done();
      });
    });
  });

  describe("Register Service", () => {
    it("should handle valid registration request", (done) => {
      const registerRequest = {
        email: "newuser@example.com",
        password: "password123",
        name: "New User",
      };

      const expectedResponse = {
        userId: "user-456",
      };

      // Mock auth service
      authService.register.mockResolvedValue(expectedResponse.userId);

      client.Register(registerRequest, (err, response) => {
        expect(err).toBeNull();
        expect(response).toEqual(expectedResponse);
        expect(authService.register).toHaveBeenCalledWith(registerRequest);
        done();
      });
    });

    it("should handle registration with missing email", (done) => {
      const registerRequest = {
        password: "password123",
        name: "New User",
        // missing email
      };

      client.Register(registerRequest, (err, response) => {
        expect(err).not.toBeNull();
        expect(err.code).toBe(grpc.status.INVALID_ARGUMENT);
        expect(err.message).toContain("Email, password, and name required");
        done();
      });
    });

    it("should handle registration with missing password", (done) => {
      const registerRequest = {
        email: "newuser@example.com",
        name: "New User",
        // missing password
      };

      client.Register(registerRequest, (err, response) => {
        expect(err).not.toBeNull();
        expect(err.code).toBe(grpc.status.INVALID_ARGUMENT);
        expect(err.message).toContain("Email, password, and name required");
        done();
      });
    });

    it("should handle registration with missing name", (done) => {
      const registerRequest = {
        email: "newuser@example.com",
        password: "password123",
        // missing name
      };

      client.Register(registerRequest, (err, response) => {
        expect(err).not.toBeNull();
        expect(err.code).toBe(grpc.status.INVALID_ARGUMENT);
        expect(err.message).toContain("Email, password, and name required");
        done();
      });
    });

    it("should handle duplicate email registration", (done) => {
      const registerRequest = {
        email: "existing@example.com",
        password: "password123",
        name: "Existing User",
      };

      // Mock auth service to throw duplicate email error
      authService.register.mockRejectedValue(new Error("Email already exists"));

      client.Register(registerRequest, (err, response) => {
        expect(err).not.toBeNull();
        expect(err.code).toBe(grpc.status.ALREADY_EXISTS);
        done();
      });
    });
  });

  describe("ValidateToken Service", () => {
    it("should handle valid token validation", (done) => {
      const tokenRequest = {
        token: "valid-jwt-token",
      };

      const expectedResponse = {
        valid: true,
        userId: "user-123",
      };

      // Mock auth service
      authService.validateToken.mockResolvedValue(expectedResponse);

      client.ValidateToken(tokenRequest, (err, response) => {
        expect(err).toBeNull();
        expect(response).toEqual(expectedResponse);
        expect(authService.validateToken).toHaveBeenCalledWith(
          tokenRequest.token
        );
        done();
      });
    });

    it("should handle token validation with missing token", (done) => {
      const tokenRequest = {};
      // missing token

      client.ValidateToken(tokenRequest, (err, response) => {
        expect(err).not.toBeNull();
        expect(err.code).toBe(grpc.status.INVALID_ARGUMENT);
        expect(err.message).toContain("Token required");
        done();
      });
    });

    it("should handle invalid token", (done) => {
      const tokenRequest = {
        token: "invalid-jwt-token",
      };

      // Mock auth service to throw invalid token error
      authService.validateToken.mockRejectedValue(new Error("Invalid token"));

      client.ValidateToken(tokenRequest, (err, response) => {
        expect(err).not.toBeNull();
        expect(err.code).toBe(grpc.status.UNAUTHENTICATED);
        done();
      });
    });

    it("should handle expired token", (done) => {
      const tokenRequest = {
        token: "expired-jwt-token",
      };

      // Mock auth service to throw expired token error
      authService.validateToken.mockRejectedValue(new Error("Token expired"));

      client.ValidateToken(tokenRequest, (err, response) => {
        expect(err).not.toBeNull();
        expect(err.code).toBe(grpc.status.UNAUTHENTICATED);
        done();
      });
    });
  });

  describe("Metadata Handling", () => {
    it("should handle correlation ID in metadata", (done) => {
      const loginRequest = {
        email: "test@example.com",
        password: "password123",
      };

      const metadata = new grpc.Metadata();
      metadata.add("correlationId", "test-correlation-123");

      const expectedResponse = {
        token: "mock-jwt-token",
        userId: "user-123",
      };

      authService.login.mockResolvedValue(expectedResponse);

      client.Login(loginRequest, metadata, (err, response) => {
        expect(err).toBeNull();
        expect(response).toEqual(expectedResponse);
        done();
      });
    });

    it("should generate correlation ID when not provided", (done) => {
      const loginRequest = {
        email: "test@example.com",
        password: "password123",
      };

      const expectedResponse = {
        token: "mock-jwt-token",
        userId: "user-123",
      };

      authService.login.mockResolvedValue(expectedResponse);

      client.Login(loginRequest, (err, response) => {
        expect(err).toBeNull();
        expect(response).toEqual(expectedResponse);
        done();
      });
    });
  });

  describe("Error Mapping", () => {
    it("should map 400 errors to INVALID_ARGUMENT", (done) => {
      const loginRequest = {
        email: "test@example.com",
        password: "password123",
      };

      // Mock auth service to throw 400 error
      const apiError = new Error("Bad Request");
      apiError.statusCode = 400;
      authService.login.mockRejectedValue(apiError);

      client.Login(loginRequest, (err, response) => {
        expect(err.code).toBe(grpc.status.INVALID_ARGUMENT);
        done();
      });
    });

    it("should map 401 errors to UNAUTHENTICATED", (done) => {
      const loginRequest = {
        email: "test@example.com",
        password: "password123",
      };

      // Mock auth service to throw 401 error
      const apiError = new Error("Unauthorized");
      apiError.statusCode = 401;
      authService.login.mockRejectedValue(apiError);

      client.Login(loginRequest, (err, response) => {
        expect(err.code).toBe(grpc.status.UNAUTHENTICATED);
        done();
      });
    });

    it("should map 404 errors to NOT_FOUND", (done) => {
      const loginRequest = {
        email: "test@example.com",
        password: "password123",
      };

      // Mock auth service to throw 404 error
      const apiError = new Error("Not Found");
      apiError.statusCode = 404;
      authService.login.mockRejectedValue(apiError);

      client.Login(loginRequest, (err, response) => {
        expect(err.code).toBe(grpc.status.NOT_FOUND);
        done();
      });
    });

    it("should map 409 errors to ALREADY_EXISTS", (done) => {
      const registerRequest = {
        email: "existing@example.com",
        password: "password123",
        name: "User",
      };

      // Mock auth service to throw 409 error
      const apiError = new Error("Conflict");
      apiError.statusCode = 409;
      authService.register.mockRejectedValue(apiError);

      client.Register(registerRequest, (err, response) => {
        expect(err.code).toBe(grpc.status.ALREADY_EXISTS);
        done();
      });
    });

    it("should map 500 errors to INTERNAL", (done) => {
      const loginRequest = {
        email: "test@example.com",
        password: "password123",
      };

      // Mock auth service to throw 500 error
      const apiError = new Error("Internal Server Error");
      apiError.statusCode = 500;
      authService.login.mockRejectedValue(apiError);

      client.Login(loginRequest, (err, response) => {
        expect(err.code).toBe(grpc.status.INTERNAL);
        done();
      });
    });
  });

  describe("Server Shutdown", () => {
    it("should handle graceful shutdown", async () => {
      await expect(stopGrpcServer()).resolves.not.toThrow();
    });

    it("should handle shutdown errors gracefully", async () => {
      // Mock server shutdown to fail
      const mockTryShutdown = jest.fn().mockImplementation((callback) => {
        callback(new Error("Shutdown failed"));
      });

      const mockForceShutdown = jest.fn();

      const mockServer = {
        tryShutdown: mockTryShutdown,
        forceShutdown: mockForceShutdown,
      };

      jest.doMock("@grpc/grpc-js", () => ({
        ...jest.requireActual("@grpc/grpc-js"),
        Server: jest.fn().mockImplementation(() => mockServer),
      }));

      await expect(stopGrpcServer()).resolves.not.toThrow();
      expect(mockForceShutdown).toHaveBeenCalled();
    });
  });

  describe("Performance", () => {
    it("should handle concurrent requests", (done) => {
      const loginRequest = {
        email: "test@example.com",
        password: "password123",
      };

      const expectedResponse = {
        token: "mock-jwt-token",
        userId: "user-123",
      };

      authService.login.mockResolvedValue(expectedResponse);

      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(
          new Promise((resolve, reject) => {
            client.Login(loginRequest, (err, response) => {
              if (err) reject(err);
              else resolve(response);
            });
          })
        );
      }

      Promise.all(promises)
        .then((responses) => {
          expect(responses).toHaveLength(10);
          responses.forEach((response) => {
            expect(response).toEqual(expectedResponse);
          });
          done();
        })
        .catch(done);
    });

    it("should handle request timeouts", (done) => {
      const loginRequest = {
        email: "test@example.com",
        password: "password123",
      };

      // Mock auth service to delay response

      authService.login.mockImplementation(
        () => new Promise((resolve) => setTimeout(resolve, 2000))
      );

      const deadline = new Date();
      deadline.setSeconds(deadline.getSeconds() + 1); // 1 second timeout

      client.Login(loginRequest, { deadline }, (err, response) => {
        expect(err).not.toBeNull();
        expect(err.code).toBe(grpc.status.DEADLINE_EXCEEDED);
        done();
      });
    });
  });
});
