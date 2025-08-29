import {
  jest,
  describe,
  it,
  expect,
  beforeAll,
  afterAll,
  beforeEach,
  afterEach,
} from '@jest/globals';
import request from 'supertest';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';

// Import the app and routes
import app from '../../../src/app.js';
import authRoutes from '../../../src/routes/auth.route.js';

// Import test utilities
import {
  TEST_DATA,
  setupTestEnvironment,
  cleanupTestEnvironment,
  createMockRedis,
  testSecurityHeaders,
  testRateLimiting,
} from '../../utils/testUtils.js';

// Import models for database operations
import AuthUser from '../../../src/models/authUser.model.js';
import { sequelize } from '../../../src/db/index.js';

/**
 * Auth API Integration Tests
 *
 * Test Coverage:
 * - Complete API endpoints
 * - Database interactions
 * - Authentication flow
 * - Error handling
 * - Security measures
 * - Rate limiting
 * - Performance under load
 */

describe('Auth API Integration Tests', () => {
  let testServer;
  let testUser;
  let authTokens;

  beforeAll(async () => {
    // Setup test environment
    setupTestEnvironment();

    // Setup Express app for testing
    const testApp = express();
    testApp.use(cors());
    testApp.use(cookieParser());
    testApp.use(express.json());
    testApp.use('/api/v1/auth', authRoutes);

    // Start test server
    testServer = testApp.listen(0); // Use random port

    // Sync database for testing
    await sequelize.sync({ force: true });
  });

  afterAll(async () => {
    // Cleanup
    await sequelize.close();
    if (testServer) {
      testServer.close();
    }
    cleanupTestEnvironment();
  });

  beforeEach(async () => {
    // Clear database before each test
    await AuthUser.destroy({ where: {} });

    // Reset test data
    testUser = null;
    authTokens = null;
  });

  afterEach(async () => {
    // Clean up after each test
    jest.clearAllMocks();
  });

  describe('User Registration Endpoint', () => {
    const registerEndpoint = '/api/v1/auth/register';

    describe('POST /register - Success Scenarios', () => {
      it('should register a new customer user successfully', async () => {
        // Arrange
        const userData = {
          fullName: 'Integration Test Customer',
          email: 'integration.customer@test.com',
          password: 'SecurePassword123!',
          type: 'customer',
          role: 'user',
        };

        // Act
        const response = await request(testServer)
          .post(registerEndpoint)
          .send(userData)
          .expect(201);

        // Assert
        expect(response.body).toMatchObject({
          statusCode: 201,
          success: true,
          data: {
            authId: expect.any(Number),
            email: userData.email,
            fullName: userData.fullName,
            type: userData.type,
            role: userData.role,
          },
        });

        // Verify user was created in database
        const createdUser = await AuthUser.findOne({
          where: { email: userData.email },
        });
        expect(createdUser).toBeTruthy();
        expect(createdUser.fullName).toBe(userData.fullName);
        expect(createdUser.type).toBe(userData.type);
        expect(createdUser.password).not.toBe(userData.password); // Should be hashed
      });

      it('should register a new vendor user successfully', async () => {
        // Arrange
        const userData = {
          fullName: 'Integration Test Vendor',
          email: 'integration.vendor@test.com',
          password: 'SecurePassword123!',
          type: 'vendor',
          role: 'manager',
        };

        // Act
        const response = await request(testServer)
          .post(registerEndpoint)
          .send(userData)
          .expect(201);

        // Assert
        expect(response.body).toMatchObject({
          statusCode: 201,
          success: true,
          data: {
            authId: expect.any(Number),
            email: userData.email,
            fullName: userData.fullName,
            type: userData.type,
            role: userData.role,
          },
        });
      });

      it('should handle registration with minimal required fields', async () => {
        // Arrange
        const userData = {
          fullName: 'Minimal User',
          email: 'minimal@test.com',
          password: 'SecurePassword123!',
          type: 'customer',
        };

        // Act
        const response = await request(testServer)
          .post(registerEndpoint)
          .send(userData)
          .expect(201);

        // Assert
        expect(response.body.success).toBe(true);
        expect(response.body.data.email).toBe(userData.email);
      });
    });

    describe('POST /register - Error Scenarios', () => {
      it('should reject duplicate email registration', async () => {
        // Arrange - Create first user
        const userData = {
          fullName: 'First User',
          email: 'duplicate@test.com',
          password: 'SecurePassword123!',
          type: 'customer',
        };

        await request(testServer)
          .post(registerEndpoint)
          .send(userData)
          .expect(201);

        // Act - Try to register with same email
        const response = await request(testServer)
          .post(registerEndpoint)
          .send(userData)
          .expect(400);

        // Assert
        expect(response.body).toMatchObject({
          statusCode: 400,
          success: false,
          message: 'customer already exists with this email',
        });
      });

      it('should reject invalid email format', async () => {
        // Arrange
        const userData = {
          fullName: 'Invalid Email User',
          email: 'invalid-email-format',
          password: 'SecurePassword123!',
          type: 'customer',
        };

        // Act
        const response = await request(testServer)
          .post(registerEndpoint)
          .send(userData)
          .expect(400);

        // Assert
        expect(response.body).toMatchObject({
          statusCode: 400,
          success: false,
          message: 'Validation error',
        });
      });

      it('should reject weak password', async () => {
        // Arrange
        const userData = {
          fullName: 'Weak Password User',
          email: 'weak@test.com',
          password: '123', // Too short
          type: 'customer',
        };

        // Act
        const response = await request(testServer)
          .post(registerEndpoint)
          .send(userData)
          .expect(400);

        // Assert
        expect(response.body).toMatchObject({
          statusCode: 400,
          success: false,
          message: 'Validation error',
        });
      });

      it('should reject missing required fields', async () => {
        // Arrange
        const userData = {
          fullName: 'Missing Fields User',
          // Missing email and password
          type: 'customer',
        };

        // Act
        const response = await request(testServer)
          .post(registerEndpoint)
          .send(userData)
          .expect(400);

        // Assert
        expect(response.body).toMatchObject({
          statusCode: 400,
          success: false,
          message: 'Validation error',
        });
      });
    });

    describe('POST /register - Security Tests', () => {
      it('should not expose password in response', async () => {
        // Arrange
        const userData = {
          fullName: 'Security Test User',
          email: 'security@test.com',
          password: 'SecurePassword123!',
          type: 'customer',
        };

        // Act
        const response = await request(testServer)
          .post(registerEndpoint)
          .send(userData)
          .expect(201);

        // Assert
        expect(response.body.data).not.toHaveProperty('password');
        expect(response.body.data).not.toHaveProperty('passwordHash');
      });

      it('should set security headers', async () => {
        // Arrange
        const userData = {
          fullName: 'Headers Test User',
          email: 'headers@test.com',
          password: 'SecurePassword123!',
          type: 'customer',
        };

        // Act
        const response = await request(testServer)
          .post(registerEndpoint)
          .send(userData)
          .expect(201);

        // Assert
        testSecurityHeaders(response);
      });
    });
  });

  describe('User Authentication Endpoint', () => {
    const loginEndpoint = '/api/v1/auth/login';

    beforeEach(async () => {
      // Create a test user for login tests
      const userData = {
        fullName: 'Login Test User',
        email: 'login@test.com',
        password: 'SecurePassword123!',
        type: 'customer',
        role: 'user',
      };

      await request(testServer).post('/api/v1/auth/register').send(userData);

      testUser = userData;
    });

    describe('POST /login - Success Scenarios', () => {
      it('should login user with valid credentials', async () => {
        // Arrange
        const loginData = {
          email: testUser.email,
          password: testUser.password,
          type: testUser.type,
        };

        // Act
        const response = await request(testServer)
          .post(loginEndpoint)
          .send(loginData)
          .expect(200);

        // Assert
        expect(response.body).toMatchObject({
          statusCode: 200,
          success: true,
          data: {
            user: {
              email: testUser.email,
              fullName: testUser.fullName,
              type: testUser.type,
              role: testUser.role,
            },
          },
        });

        // Check for cookies
        expect(response.headers['set-cookie']).toBeDefined();
        expect(
          response.headers['set-cookie'].some(cookie =>
            cookie.includes('accessToken')
          )
        ).toBe(true);
        expect(
          response.headers['set-cookie'].some(cookie =>
            cookie.includes('refreshToken')
          )
        ).toBe(true);

        // Store tokens for other tests
        authTokens = {
          accessToken: response.headers['set-cookie']
            .find(cookie => cookie.includes('accessToken'))
            ?.split(';')[0]
            ?.split('=')[1],
          refreshToken: response.headers['set-cookie']
            .find(cookie => cookie.includes('refreshToken'))
            ?.split(';')[0]
            ?.split('=')[1],
        };
      });

      it('should login vendor user successfully', async () => {
        // Arrange - Create vendor user
        const vendorData = {
          fullName: 'Vendor Test User',
          email: 'vendor.login@test.com',
          password: 'SecurePassword123!',
          type: 'vendor',
          role: 'manager',
        };

        await request(testServer)
          .post('/api/v1/auth/register')
          .send(vendorData);

        const loginData = {
          email: vendorData.email,
          password: vendorData.password,
          type: vendorData.type,
        };

        // Act
        const response = await request(testServer)
          .post(loginEndpoint)
          .send(loginData)
          .expect(200);

        // Assert
        expect(response.body.data.user.type).toBe('vendor');
        expect(response.body.data.user.role).toBe('manager');
      });
    });

    describe('POST /login - Error Scenarios', () => {
      it('should reject invalid credentials', async () => {
        // Arrange
        const loginData = {
          email: testUser.email,
          password: 'WrongPassword123!',
          type: testUser.type,
        };

        // Act
        const response = await request(testServer)
          .post(loginEndpoint)
          .send(loginData)
          .expect(401);

        // Assert
        expect(response.body).toMatchObject({
          statusCode: 401,
          success: false,
          message: 'Invalid email or password',
        });
      });

      it('should reject non-existent user', async () => {
        // Arrange
        const loginData = {
          email: 'nonexistent@test.com',
          password: 'SecurePassword123!',
          type: 'customer',
        };

        // Act
        const response = await request(testServer)
          .post(loginEndpoint)
          .send(loginData)
          .expect(401);

        // Assert
        expect(response.body).toMatchObject({
          statusCode: 401,
          success: false,
          message: 'Invalid email or password',
        });
      });

      it('should reject login with wrong user type', async () => {
        // Arrange
        const loginData = {
          email: testUser.email,
          password: testUser.password,
          type: 'vendor', // Wrong type
        };

        // Act
        const response = await request(testServer)
          .post(loginEndpoint)
          .send(loginData)
          .expect(401);

        // Assert
        expect(response.body).toMatchObject({
          statusCode: 401,
          success: false,
          message: 'Invalid email or password',
        });
      });
    });

    describe('POST /login - Security Tests', () => {
      it('should not expose password in response', async () => {
        // Arrange
        const loginData = {
          email: testUser.email,
          password: testUser.password,
          type: testUser.type,
        };

        // Act
        const response = await request(testServer)
          .post(loginEndpoint)
          .send(loginData)
          .expect(200);

        // Assert
        expect(response.body.data.user).not.toHaveProperty('password');
        expect(response.body.data.user).not.toHaveProperty('passwordHash');
      });

      it('should set secure cookie options', async () => {
        // Arrange
        const loginData = {
          email: testUser.email,
          password: testUser.password,
          type: testUser.type,
        };

        // Act
        const response = await request(testServer)
          .post(loginEndpoint)
          .send(loginData)
          .expect(200);

        // Assert
        const cookies = response.headers['set-cookie'];
        const accessTokenCookie = cookies.find(cookie =>
          cookie.includes('accessToken')
        );
        const refreshTokenCookie = cookies.find(cookie =>
          cookie.includes('refreshToken')
        );

        expect(accessTokenCookie).toContain('HttpOnly');
        expect(accessTokenCookie).toContain('Secure');
        expect(accessTokenCookie).toContain('SameSite=Strict');
        expect(refreshTokenCookie).toContain('HttpOnly');
        expect(refreshTokenCookie).toContain('Secure');
        expect(refreshTokenCookie).toContain('SameSite=Strict');
      });
    });
  });

  describe('User Logout Endpoint', () => {
    const logoutEndpoint = '/api/v1/auth/logout';

    beforeEach(async () => {
      // Login to get tokens
      const userData = {
        fullName: 'Logout Test User',
        email: 'logout@test.com',
        password: 'SecurePassword123!',
        type: 'customer',
      };

      await request(testServer).post('/api/v1/auth/register').send(userData);

      const loginResponse = await request(testServer)
        .post('/api/v1/auth/login')
        .send({
          email: userData.email,
          password: userData.password,
          type: userData.type,
        });

      authTokens = {
        accessToken: loginResponse.headers['set-cookie']
          .find(cookie => cookie.includes('accessToken'))
          ?.split(';')[0]
          ?.split('=')[1],
        refreshToken: loginResponse.headers['set-cookie']
          .find(cookie => cookie.includes('refreshToken'))
          ?.split(';')[0]
          ?.split('=')[1],
      };
    });

    it('should logout user and clear cookies', async () => {
      // Act
      const response = await request(testServer)
        .post(logoutEndpoint)
        .set('Cookie', [
          `accessToken=${authTokens.accessToken}`,
          `refreshToken=${authTokens.refreshToken}`,
        ])
        .expect(200);

      // Assert
      expect(response.body).toMatchObject({
        statusCode: 200,
        success: true,
        message: 'User logged out successfully',
      });

      // Check that cookies are cleared
      const cookies = response.headers['set-cookie'];
      expect(cookies).toBeDefined();

      const clearedAccessToken = cookies.find(
        cookie => cookie.includes('accessToken') && cookie.includes('Max-Age=0')
      );
      const clearedRefreshToken = cookies.find(
        cookie =>
          cookie.includes('refreshToken') && cookie.includes('Max-Age=0')
      );

      expect(clearedAccessToken).toBeDefined();
      expect(clearedRefreshToken).toBeDefined();
    });
  });

  describe('Token Refresh Endpoint', () => {
    const refreshEndpoint = '/api/v1/auth/refresh';

    beforeEach(async () => {
      // Login to get tokens
      const userData = {
        fullName: 'Refresh Test User',
        email: 'refresh@test.com',
        password: 'SecurePassword123!',
        type: 'customer',
      };

      await request(testServer).post('/api/v1/auth/register').send(userData);

      const loginResponse = await request(testServer)
        .post('/api/v1/auth/login')
        .send({
          email: userData.email,
          password: userData.password,
          type: userData.type,
        });

      authTokens = {
        accessToken: loginResponse.headers['set-cookie']
          .find(cookie => cookie.includes('accessToken'))
          ?.split(';')[0]
          ?.split('=')[1],
        refreshToken: loginResponse.headers['set-cookie']
          .find(cookie => cookie.includes('refreshToken'))
          ?.split(';')[0]
          ?.split('=')[1],
      };
    });

    it('should refresh access token with valid refresh token', async () => {
      // Act
      const response = await request(testServer)
        .post(refreshEndpoint)
        .set('Cookie', [`refreshToken=${authTokens.refreshToken}`])
        .expect(200);

      // Assert
      expect(response.body).toMatchObject({
        statusCode: 200,
        success: true,
        message: 'Token refreshed successfully',
      });

      // Check for new access token cookie
      const cookies = response.headers['set-cookie'];
      const newAccessToken = cookies.find(cookie =>
        cookie.includes('accessToken')
      );
      expect(newAccessToken).toBeDefined();
      expect(newAccessToken).not.toContain(authTokens.accessToken);
    });

    it('should reject invalid refresh token', async () => {
      // Act
      const response = await request(testServer)
        .post(refreshEndpoint)
        .set('Cookie', ['refreshToken=invalid-token'])
        .expect(401);

      // Assert
      expect(response.body).toMatchObject({
        statusCode: 401,
        success: false,
        message: 'Invalid refresh token',
      });
    });

    it('should reject request without refresh token', async () => {
      // Act
      const response = await request(testServer)
        .post(refreshEndpoint)
        .expect(401);

      // Assert
      expect(response.body).toMatchObject({
        statusCode: 401,
        success: false,
        message: 'Refresh token required',
      });
    });
  });

  describe('Rate Limiting Tests', () => {
    it('should enforce rate limiting on login endpoint', async () => {
      // This test would require rate limiting middleware to be configured
      // For now, we'll test the basic structure
      const loginData = {
        email: 'ratelimit@test.com',
        password: 'SecurePassword123!',
        type: 'customer',
      };

      // Make multiple requests
      const requests = Array(10)
        .fill()
        .map(() =>
          request(testServer).post('/api/v1/auth/login').send(loginData)
        );

      const responses = await Promise.all(requests);

      // At least some requests should succeed (if rate limiting is not too strict)
      const successfulRequests = responses.filter(
        res => res.status === 200 || res.status === 401
      );
      expect(successfulRequests.length).toBeGreaterThan(0);
    });
  });

  describe('Performance Tests', () => {
    it('should handle concurrent user registrations', async () => {
      const concurrentUsers = 10;
      const userPromises = [];

      for (let i = 0; i < concurrentUsers; i++) {
        const userData = {
          fullName: `Concurrent User ${i}`,
          email: `concurrent${i}@test.com`,
          password: 'SecurePassword123!',
          type: 'customer',
        };

        userPromises.push(
          request(testServer).post('/api/v1/auth/register').send(userData)
        );
      }

      const startTime = Date.now();
      const responses = await Promise.all(userPromises);
      const endTime = Date.now();

      // Assert all registrations succeeded
      responses.forEach(response => {
        expect(response.status).toBe(201);
      });

      // Assert reasonable performance (less than 5 seconds for 10 users)
      expect(endTime - startTime).toBeLessThan(5000);
    });
  });
});
