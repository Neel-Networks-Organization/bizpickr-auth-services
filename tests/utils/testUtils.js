import { jest } from '@jest/globals';

/**
 * Test Utilities for Auth Service
 * Industry standard test helpers and mocks
 */

// Common test data
export const TEST_DATA = {
  users: {
    customer: {
      id: 1,
      fullName: 'Test Customer',
      email: 'customer@test.com',
      password: 'password123',
      type: 'customer',
      role: 'user',
      userId: 101,
    },
    vendor: {
      id: 2,
      fullName: 'Test Vendor',
      email: 'vendor@test.com',
      password: 'password123',
      type: 'vendor',
      role: 'manager',
      userId: 102,
    },
  },
  tokens: {
    accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.access',
    refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.refresh',
    invalidToken: 'invalid.token.here',
  },
  errors: {
    validation: {
      statusCode: 400,
      message: 'Validation error',
      errors: ['Email is required', 'Password must be at least 8 characters'],
    },
    unauthorized: {
      statusCode: 401,
      message: 'Unauthorized access',
    },
    notFound: {
      statusCode: 404,
      message: 'Resource not found',
    },
    serverError: {
      statusCode: 500,
      message: 'Internal server error',
    },
  },
};

// Mock Express request/response objects
export const createMockRequest = (overrides = {}) => ({
  body: {},
  params: {},
  query: {},
  headers: {},
  cookies: {},
  user: null,
  ...overrides,
});

export const createMockResponse = () => {
  const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    cookie: jest.fn().mockReturnThis(),
    clearCookie: jest.fn().mockReturnThis(),
    setHeader: jest.fn().mockReturnThis(),
    end: jest.fn().mockReturnThis(),
  };
  return res;
};

export const createMockNext = () => jest.fn();

// Database mocks
export const createMockSequelizeModel = (data = {}) => ({
  id: 1,
  createdAt: new Date(),
  updatedAt: new Date(),
  ...data,
  save: jest.fn().mockResolvedValue(true),
  update: jest.fn().mockResolvedValue([1]),
  destroy: jest.fn().mockResolvedValue(1),
  reload: jest.fn().mockResolvedValue(true),
});

// Redis mocks
export const createMockRedis = () => ({
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  exists: jest.fn(),
  expire: jest.fn(),
  connect: jest.fn(),
  disconnect: jest.fn(),
});

// JWT mocks
export const createMockJWT = () => ({
  sign: jest.fn(),
  verify: jest.fn(),
  decode: jest.fn(),
});

// Email service mocks
export const createMockEmailService = () => ({
  sendEmail: jest.fn(),
  sendVerificationEmail: jest.fn(),
  sendPasswordResetEmail: jest.fn(),
});

// Validation helpers
export const validateApiResponse = (response, expectedStatus = 200) => {
  expect(response.status).toHaveBeenCalledWith(expectedStatus);
  expect(response.json).toHaveBeenCalledWith(
    expect.objectContaining({
      statusCode: expectedStatus,
      success: true,
      data: expect.any(Object),
    })
  );
};

export const validateApiError = (next, expectedError) => {
  expect(next).toHaveBeenCalledWith(
    expect.objectContaining({
      statusCode: expectedError.statusCode,
      message: expectedError.message,
    })
  );
};

// Async test helpers
export const waitForAsync = (ms = 100) =>
  new Promise(resolve => setTimeout(resolve, ms));

// Test environment setup
export const setupTestEnvironment = () => {
  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = 'test-secret';
  process.env.JWT_REFRESH_SECRET = 'test-refresh-secret';
  process.env.REDIS_URL = 'redis://localhost:6379';
  process.env.DATABASE_URL = 'mysql://test:test@localhost:3306/test_db';
};

// Clean up test environment
export const cleanupTestEnvironment = () => {
  jest.clearAllMocks();
  jest.clearAllTimers();
  jest.resetModules();
};

// Performance test helpers
export const measurePerformance = async (fn, iterations = 1000) => {
  const start = performance.now();

  for (let i = 0; i < iterations; i++) {
    await fn();
  }

  const end = performance.now();
  const avgTime = (end - start) / iterations;

  return {
    totalTime: end - start,
    averageTime: avgTime,
    iterations,
  };
};

// Load test helpers
export const createLoadTestScenario = (concurrentUsers, duration) => {
  return {
    concurrentUsers,
    duration,
    rampUpTime: duration * 0.1, // 10% ramp up
    rampDownTime: duration * 0.1, // 10% ramp down
  };
};

// Security test helpers
export const testSecurityHeaders = response => {
  expect(response.setHeader).toHaveBeenCalledWith(
    'X-Content-Type-Options',
    'nosniff'
  );
  expect(response.setHeader).toHaveBeenCalledWith('X-Frame-Options', 'DENY');
  expect(response.setHeader).toHaveBeenCalledWith(
    'X-XSS-Protection',
    '1; mode=block'
  );
};

// Rate limiting test helpers
export const testRateLimiting = async (requestFn, limit = 100) => {
  const requests = [];

  // Make requests up to the limit
  for (let i = 0; i < limit + 1; i++) {
    requests.push(requestFn());
  }

  const responses = await Promise.all(requests);
  const tooManyRequests = responses.filter(
    res => res.status === 429 || res.body?.statusCode === 429
  );

  expect(tooManyRequests.length).toBeGreaterThan(0);
};

export default {
  TEST_DATA,
  createMockRequest,
  createMockResponse,
  createMockNext,
  createMockSequelizeModel,
  createMockRedis,
  createMockJWT,
  createMockEmailService,
  validateApiResponse,
  validateApiError,
  waitForAsync,
  setupTestEnvironment,
  cleanupTestEnvironment,
  measurePerformance,
  createLoadTestScenario,
  testSecurityHeaders,
  testRateLimiting,
};
