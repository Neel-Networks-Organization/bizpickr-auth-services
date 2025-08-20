import { jest } from '@jest/globals';
import grpc from '@grpc/grpc-js';
import { createUserProfile, getUserById } from '@/grpc/client/user.client.js';
import { env } from '@/config/env.js';
import { ApiError } from '@/utils/index.js';

// Mock dependencies
jest.mock('@/config/env.js');
jest.mock('@/config/logger.js', () => ({
  safeLogger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
  },
}));

describe('gRPC User Client Integration', () => {
  let mockClient;
  let mockChannel;

  beforeEach(() => {
    jest.clearAllMocks();

    // Mock environment variables
    env.GRPC_USER_SERVICE_HOST = 'localhost';
    env.GRPC_USER_SERVICE_PORT = '50052';

    // Mock gRPC client
    mockClient = {
      CreateProfile: jest.fn(),
      GetUserById: jest.fn(),
    };

    // Mock gRPC channel
    mockChannel = {
      getConnectivityState: jest.fn(),
      watchConnectivityState: jest.fn(),
      close: jest.fn(),
    };

    // Mock grpc.Client
    jest.doMock('@grpc/grpc-js', () => ({
      ...jest.requireActual('@grpc/grpc-js'),
      Client: jest.fn().mockImplementation(() => mockClient),
    }));
  });

  describe('createUserProfile', () => {
    it('should create user profile successfully', async () => {
      const userData = {
        email: 'test@example.com',
        type: 'customer',
        fullName: 'Test User',
        role: 'user',
        reportsToId: null,
        reportsToRole: null,
      };

      const expectedResponse = {
        userId: 'user-123',
        message: 'User profile created successfully',
        success: true,
      };

      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        callback(null, expectedResponse);
      });

      const result = await createUserProfile(userData);

      expect(result).toEqual(expectedResponse);
      expect(mockClient.CreateProfile).toHaveBeenCalledWith(
        userData,
        expect.objectContaining({ deadline: expect.any(Number) }),
        expect.any(Function)
      );
    });

    it('should handle user service unavailable error', async () => {
      const userData = {
        email: 'test@example.com',
        type: 'customer',
        fullName: 'Test User',
        role: 'user',
      };

      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        const error = new Error('User service is not available');
        error.code = grpc.status.UNAVAILABLE;
        callback(error);
      });

      await expect(createUserProfile(userData)).rejects.toThrow(
        'User service is not available'
      );
    });

    it('should handle user not found error', async () => {
      const userData = {
        email: 'test@example.com',
        type: 'customer',
        fullName: 'Test User',
        role: 'user',
      };

      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        const error = new Error('User not found');
        error.code = grpc.status.NOT_FOUND;
        callback(error);
      });

      await expect(createUserProfile(userData)).rejects.toThrow(
        'User not found'
      );
    });

    it('should handle validation errors', async () => {
      const userData = {
        email: 'invalid-email',
        type: 'customer',
        fullName: 'Test User',
        role: 'user',
      };

      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        const error = new Error('Invalid email format');
        error.code = grpc.status.INVALID_ARGUMENT;
        callback(error);
      });

      await expect(createUserProfile(userData)).rejects.toThrow(
        'Invalid email format'
      );
    });

    it('should handle timeout errors', async () => {
      const userData = {
        email: 'test@example.com',
        type: 'customer',
        fullName: 'Test User',
        role: 'user',
      };

      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        const error = new Error('Request timeout');
        error.code = grpc.status.DEADLINE_EXCEEDED;
        callback(error);
      });

      await expect(createUserProfile(userData)).rejects.toThrow(
        'Request timeout'
      );
    });

    it('should handle internal server errors', async () => {
      const userData = {
        email: 'test@example.com',
        type: 'customer',
        fullName: 'Test User',
        role: 'user',
      };

      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        const error = new Error('Internal server error');
        error.code = grpc.status.INTERNAL;
        callback(error);
      });

      await expect(createUserProfile(userData)).rejects.toThrow(
        'Internal server error'
      );
    });

    it('should use correct deadline for requests', async () => {
      const userData = {
        email: 'test@example.com',
        type: 'customer',
        fullName: 'Test User',
        role: 'user',
      };

      const expectedResponse = {
        userId: 'user-123',
        message: 'User profile created successfully',
        success: true,
      };

      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        expect(options.deadline).toBeGreaterThan(Date.now());
        expect(options.deadline).toBeLessThanOrEqual(Date.now() + 10000);
        callback(null, expectedResponse);
      });

      await createUserProfile(userData);
    });

    it('should handle missing optional fields', async () => {
      const userData = {
        email: 'test@example.com',
        type: 'customer',
        fullName: 'Test User',
        role: 'user',
        // missing reportsToId and reportsToRole
      };

      const expectedResponse = {
        userId: 'user-123',
        message: 'User profile created successfully',
        success: true,
      };

      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        callback(null, expectedResponse);
      });

      const result = await createUserProfile(userData);

      expect(result).toEqual(expectedResponse);
    });

    it('should handle admin user creation', async () => {
      const userData = {
        email: 'admin@example.com',
        type: 'admin',
        fullName: 'Admin User',
        role: 'admin',
        reportsToId: null,
        reportsToRole: null,
      };

      const expectedResponse = {
        userId: 'admin-123',
        message: 'Admin profile created successfully',
        success: true,
      };

      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        callback(null, expectedResponse);
      });

      const result = await createUserProfile(userData);

      expect(result).toEqual(expectedResponse);
    });
  });

  describe('getUserById', () => {
    it('should get user by ID successfully', async () => {
      const userId = 'user-123';
      const type = 'customer';

      const expectedResponse = {
        userId: 'user-123',
        email: 'test@example.com',
        fullName: 'Test User',
        type: 'customer',
        role: 'user',
        success: true,
      };

      mockClient.GetUserById.mockImplementation((data, options, callback) => {
        callback(null, expectedResponse);
      });

      const result = await getUserById(userId, type);

      expect(result).toEqual(expectedResponse);
      expect(mockClient.GetUserById).toHaveBeenCalledWith(
        { userId, type },
        expect.objectContaining({ deadline: expect.any(Number) }),
        expect.any(Function)
      );
    });

    it('should handle user not found error', async () => {
      const userId = 'non-existent-user';
      const type = 'customer';

      mockClient.GetUserById.mockImplementation((data, options, callback) => {
        const error = new Error('User not found');
        error.code = grpc.status.NOT_FOUND;
        callback(error);
      });

      await expect(getUserById(userId, type)).rejects.toThrow('User not found');
    });

    it('should handle invalid user ID format', async () => {
      const userId = 'invalid-id-format';
      const type = 'customer';

      mockClient.GetUserById.mockImplementation((data, options, callback) => {
        const error = new Error('Invalid user ID format');
        error.code = grpc.status.INVALID_ARGUMENT;
        callback(error);
      });

      await expect(getUserById(userId, type)).rejects.toThrow(
        'Invalid user ID format'
      );
    });

    it('should handle user type mismatch', async () => {
      const userId = 'user-123';
      const type = 'admin'; // wrong type

      mockClient.GetUserById.mockImplementation((data, options, callback) => {
        const error = new Error('User type mismatch');
        error.code = grpc.status.FAILED_PRECONDITION;
        callback(error);
      });

      await expect(getUserById(userId, type)).rejects.toThrow(
        'User type mismatch'
      );
    });

    it('should handle timeout errors', async () => {
      const userId = 'user-123';
      const type = 'customer';

      mockClient.GetUserById.mockImplementation((data, options, callback) => {
        const error = new Error('Request timeout');
        error.code = grpc.status.DEADLINE_EXCEEDED;
        callback(error);
      });

      await expect(getUserById(userId, type)).rejects.toThrow(
        'Request timeout'
      );
    });

    it('should handle service unavailable errors', async () => {
      const userId = 'user-123';
      const type = 'customer';

      mockClient.GetUserById.mockImplementation((data, options, callback) => {
        const error = new Error('Service unavailable');
        error.code = grpc.status.UNAVAILABLE;
        callback(error);
      });

      await expect(getUserById(userId, type)).rejects.toThrow(
        'Service unavailable'
      );
    });

    it('should handle different user types', async () => {
      const testCases = [
        { userId: 'user-123', type: 'customer' },
        { userId: 'admin-456', type: 'admin' },
        { userId: 'vendor-789', type: 'vendor' },
      ];

      for (const testCase of testCases) {
        const expectedResponse = {
          userId: testCase.userId,
          email: `${testCase.type}@example.com`,
          fullName: `${testCase.type} User`,
          type: testCase.type,
          role: testCase.type,
          success: true,
        };

        mockClient.GetUserById.mockImplementation((data, options, callback) => {
          callback(null, expectedResponse);
        });

        const result = await getUserById(testCase.userId, testCase.type);

        expect(result).toEqual(expectedResponse);
        expect(result.type).toBe(testCase.type);
      }
    });

    it('should use correct deadline for requests', async () => {
      const userId = 'user-123';
      const type = 'customer';

      const expectedResponse = {
        userId: 'user-123',
        email: 'test@example.com',
        fullName: 'Test User',
        type: 'customer',
        role: 'user',
        success: true,
      };

      mockClient.GetUserById.mockImplementation((data, options, callback) => {
        expect(options.deadline).toBeGreaterThan(Date.now());
        expect(options.deadline).toBeLessThanOrEqual(Date.now() + 10000);
        callback(null, expectedResponse);
      });

      await getUserById(userId, type);
    });
  });

  describe('Error Handling', () => {
    it('should map gRPC status codes to HTTP status codes correctly', async () => {
      const statusCodeMappings = [
        { grpcCode: grpc.status.INVALID_ARGUMENT, httpCode: 400 },
        { grpcCode: grpc.status.UNAUTHENTICATED, httpCode: 401 },
        { grpcCode: grpc.status.PERMISSION_DENIED, httpCode: 403 },
        { grpcCode: grpc.status.NOT_FOUND, httpCode: 404 },
        { grpcCode: grpc.status.ALREADY_EXISTS, httpCode: 409 },
        { grpcCode: grpc.status.INTERNAL, httpCode: 500 },
        { grpcCode: grpc.status.UNAVAILABLE, httpCode: 500 },
      ];

      for (const mapping of statusCodeMappings) {
        const userData = {
          email: 'test@example.com',
          type: 'customer',
          fullName: 'Test User',
          role: 'user',
        };

        mockClient.CreateProfile.mockImplementation(
          (data, options, callback) => {
            const error = new Error('Test error');
            error.code = mapping.grpcCode;
            callback(error);
          }
        );

        try {
          await createUserProfile(userData);
        } catch (error) {
          expect(error).toBeInstanceOf(ApiError);
          expect(error.statusCode).toBe(mapping.httpCode);
        }
      }
    });

    it('should handle unknown gRPC status codes', async () => {
      const userData = {
        email: 'test@example.com',
        type: 'customer',
        fullName: 'Test User',
        role: 'user',
      };

      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        const error = new Error('Unknown error');
        error.code = 999; // Unknown status code
        callback(error);
      });

      try {
        await createUserProfile(userData);
      } catch (error) {
        expect(error).toBeInstanceOf(ApiError);
        expect(error.statusCode).toBe(500); // Default to 500
      }
    });

    it('should include error details in ApiError', async () => {
      const userData = {
        email: 'test@example.com',
        type: 'customer',
        fullName: 'Test User',
        role: 'user',
      };

      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        const error = new Error('Validation failed');
        error.code = grpc.status.INVALID_ARGUMENT;
        error.details = 'Email format is invalid';
        callback(error);
      });

      try {
        await createUserProfile(userData);
      } catch (error) {
        expect(error).toBeInstanceOf(ApiError);
        expect(error.message).toContain('Validation failed');
        expect(error.errors).toContain('Email format is invalid');
      }
    });
  });

  describe('Connection Management', () => {
    it('should handle connection state changes', async () => {
      const userData = {
        email: 'test@example.com',
        type: 'customer',
        fullName: 'Test User',
        role: 'user',
      };

      // Mock connection state changes
      mockChannel.getConnectivityState.mockReturnValue(
        grpc.connectivityState.READY
      );

      const expectedResponse = {
        userId: 'user-123',
        message: 'User profile created successfully',
        success: true,
      };

      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        callback(null, expectedResponse);
      });

      const result = await createUserProfile(userData);

      expect(result).toEqual(expectedResponse);
    });

    it('should handle connection failures gracefully', async () => {
      const userData = {
        email: 'test@example.com',
        type: 'customer',
        fullName: 'Test User',
        role: 'user',
      };

      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        const error = new Error('Connection failed');
        error.code = grpc.status.UNAVAILABLE;
        callback(error);
      });

      await expect(createUserProfile(userData)).rejects.toThrow(
        'Connection failed'
      );
    });
  });

  describe('Performance', () => {
    it('should handle concurrent requests efficiently', async () => {
      const userData = {
        email: 'test@example.com',
        type: 'customer',
        fullName: 'Test User',
        role: 'user',
      };

      const expectedResponse = {
        userId: 'user-123',
        message: 'User profile created successfully',
        success: true,
      };

      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        callback(null, expectedResponse);
      });

      const promises = [];
      for (let i = 0; i < 5; i++) {
        promises.push(createUserProfile(userData));
      }

      const results = await Promise.all(promises);

      expect(results).toHaveLength(5);
      results.forEach(result => {
        expect(result).toEqual(expectedResponse);
      });
    });

    it('should respect request deadlines', async () => {
      const userData = {
        email: 'test@example.com',
        type: 'customer',
        fullName: 'Test User',
        role: 'user',
      };

      // Mock slow response
      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        setTimeout(() => {
          const error = new Error('Request timeout');
          error.code = grpc.status.DEADLINE_EXCEEDED;
          callback(error);
        }, 15000); // 15 seconds delay
      });

      const startTime = Date.now();

      try {
        await createUserProfile(userData);
      } catch (error) {
        const endTime = Date.now();
        expect(endTime - startTime).toBeLessThan(11000); // Should timeout within 10 seconds
        expect(error.message).toContain('Request timeout');
      }
    });
  });

  describe('Data Validation', () => {
    it('should validate required fields in user data', async () => {
      const invalidUserData = {
        // missing email
        type: 'customer',
        fullName: 'Test User',
        role: 'user',
      };

      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        const error = new Error('Missing required field: email');
        error.code = grpc.status.INVALID_ARGUMENT;
        callback(error);
      });

      await expect(createUserProfile(invalidUserData)).rejects.toThrow(
        'Missing required field: email'
      );
    });

    it('should validate email format', async () => {
      const userData = {
        email: 'invalid-email-format',
        type: 'customer',
        fullName: 'Test User',
        role: 'user',
      };

      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        const error = new Error('Invalid email format');
        error.code = grpc.status.INVALID_ARGUMENT;
        callback(error);
      });

      await expect(createUserProfile(userData)).rejects.toThrow(
        'Invalid email format'
      );
    });

    it('should validate user type values', async () => {
      const userData = {
        email: 'test@example.com',
        type: 'invalid-type',
        fullName: 'Test User',
        role: 'user',
      };

      mockClient.CreateProfile.mockImplementation((data, options, callback) => {
        const error = new Error('Invalid user type');
        error.code = grpc.status.INVALID_ARGUMENT;
        callback(error);
      });

      await expect(createUserProfile(userData)).rejects.toThrow(
        'Invalid user type'
      );
    });
  });
});
