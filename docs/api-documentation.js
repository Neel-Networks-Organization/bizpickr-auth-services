/**
 * API Documentation Generator
 *
 * Features:
 * - OpenAPI 3.0 specification
 * - Comprehensive endpoint documentation
 * - Request/response schemas
 * - Authentication documentation
 * - Error codes and responses
 * - Examples and usage
 * - Interactive documentation
 */
export const apiSpec = {
  openapi: '3.0.3',
  info: {
    title: 'BizPickr Authentication Service API',
    description:
      'Enterprise-grade authentication microservice with comprehensive security features',
    version: '1.0.0',
    contact: {
      name: 'Neel Networks',
      email: 'support@neelnetworks.com',
      url: 'https://neelnetworks.com',
    },
    license: {
      name: 'ISC',
      url: 'https://opensource.org/licenses/ISC',
    },
  },
  servers: [
    {
      url: 'http://localhost:3001',
      description: 'Development server',
    },
    {
      url: 'https://api.bizpickr.com/auth',
      description: 'Production server',
    },
  ],
  security: [
    {
      BearerAuth: [],
    },
    {
      ApiKeyAuth: [],
    },
  ],
  paths: {
    // ✅ Authentication Routes
    '/api/v1/auth/signup': {
      post: {
        summary: 'User Registration',
        description: 'Register a new user account',
        tags: ['Authentication'],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['fullName', 'email', 'password', 'type'],
                properties: {
                  fullName: {
                    type: 'string',
                    minLength: 2,
                    maxLength: 100,
                    example: 'John Doe',
                  },
                  email: {
                    type: 'string',
                    format: 'email',
                    example: 'john.doe@example.com',
                  },
                  password: {
                    type: 'string',
                    minLength: 8,
                    maxLength: 128,
                    example: 'SecurePassword123!',
                  },
                  type: {
                    type: 'string',
                    enum: ['customer', 'vendor', 'admin'],
                    example: 'customer',
                  },
                  role: {
                    type: 'string',
                    enum: ['user', 'premium', 'enterprise'],
                    default: 'user',
                    example: 'user',
                  },
                },
              },
            },
          },
        },
        responses: {
          201: {
            description: 'User registered successfully',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/SuccessResponse',
                },
              },
            },
          },
          400: {
            description: 'Validation error',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ValidationError',
                },
              },
            },
          },
          409: {
            description: 'User already exists',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
    '/api/v1/auth/login': {
      post: {
        summary: 'User Login',
        description: 'Authenticate user and get access tokens',
        tags: ['Authentication'],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['email', 'password', 'type'],
                properties: {
                  email: {
                    type: 'string',
                    format: 'email',
                    example: 'john.doe@example.com',
                  },
                  password: {
                    type: 'string',
                    example: 'SecurePassword123!',
                  },
                  type: {
                    type: 'string',
                    enum: ['customer', 'vendor', 'admin'],
                    example: 'customer',
                  },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Login successful',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/LoginResponse',
                },
              },
            },
          },
          401: {
            description: 'Invalid credentials',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          404: {
            description: 'User not found',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
    '/api/v1/auth/refresh': {
      post: {
        summary: 'Refresh Token',
        description: 'Get new access token using refresh token',
        tags: ['Authentication'],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['refreshToken'],
                properties: {
                  refreshToken: {
                    type: 'string',
                    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                  },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Token refreshed successfully',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/TokenResponse',
                },
              },
            },
          },
          401: {
            description: 'Invalid refresh token',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
    '/api/v1/auth/logout': {
      post: {
        summary: 'User Logout',
        description: 'Logout user and invalidate tokens',
        tags: ['Authentication'],
        security: [
          {
            BearerAuth: [],
          },
        ],
        responses: {
          200: {
            description: 'Logout successful',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/SuccessResponse',
                },
              },
            },
          },
        },
      },
    },
    // ✅ JWK Routes
    '/api/v1/jwk/keys': {
      get: {
        summary: 'Get JWK Keys',
        description: 'Retrieve JSON Web Keys for token verification',
        tags: ['JWK'],
        responses: {
          200: {
            description: 'JWK keys retrieved successfully',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/JWKResponse',
                },
              },
            },
          },
        },
      },
    },
    // ✅ Company Routes
    '/api/v1/company/register': {
      post: {
        summary: 'Company Registration',
        description: 'Register a new company account',
        tags: ['Company'],
        security: [
          {
            BearerAuth: [],
          },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/CompanyRegistration',
              },
            },
          },
        },
        responses: {
          201: {
            description: 'Company registered successfully',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/SuccessResponse',
                },
              },
            },
          },
        },
      },
    },
    // ✅ Admin Routes
    '/api/v1/admin/users': {
      get: {
        summary: 'Get All Users',
        description: 'Retrieve all users (admin only)',
        tags: ['Admin'],
        security: [
          {
            BearerAuth: [],
          },
        ],
        parameters: [
          {
            name: 'page',
            in: 'query',
            description: 'Page number',
            schema: { type: 'integer', minimum: 1, default: 1 },
          },
          {
            name: 'limit',
            in: 'query',
            description: 'Items per page',
            schema: { type: 'integer', minimum: 1, maximum: 100, default: 20 },
          },
          {
            name: 'type',
            in: 'query',
            description: 'Filter by user type',
            schema: { type: 'string', enum: ['customer', 'vendor', 'admin'] },
          },
        ],
        responses: {
          200: {
            description: 'Users retrieved successfully',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/UserListResponse',
                },
              },
            },
          },
        },
      },
    },
  },
  components: {
    securitySchemes: {
      BearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
      ApiKeyAuth: {
        type: 'apiKey',
        in: 'header',
        name: 'X-API-Key',
      },
    },
    schemas: {
      // ✅ Success Response
      SuccessResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: true },
          message: {
            type: 'string',
            example: 'Operation completed successfully',
          },
          data: { type: 'object' },
          timestamp: { type: 'string', format: 'date-time' },
        },
      },
      // ✅ Error Response
      ErrorResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: false },
          message: { type: 'string', example: 'An error occurred' },
          errors: {
            type: 'array',
            items: { type: 'string' },
            example: ['Invalid email format', 'Password too short'],
          },
          timestamp: { type: 'string', format: 'date-time' },
        },
      },
      // ✅ Validation Error
      ValidationError: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: false },
          message: { type: 'string', example: 'Validation failed' },
          errors: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                field: { type: 'string' },
                message: { type: 'string' },
                value: { type: 'string' },
              },
            },
          },
          timestamp: { type: 'string', format: 'date-time' },
        },
      },
      // ✅ Login Response
      LoginResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: true },
          message: { type: 'string', example: 'Login successful' },
          data: {
            type: 'object',
            properties: {
              user: {
                type: 'object',
                properties: {
                  id: { type: 'string', format: 'uuid' },
                  fullName: { type: 'string' },
                  email: { type: 'string' },
                  type: { type: 'string' },
                  role: { type: 'string' },
                },
              },
              tokens: {
                type: 'object',
                properties: {
                  accessToken: { type: 'string' },
                  refreshToken: { type: 'string' },
                  expiresIn: { type: 'number' },
                },
              },
            },
          },
          timestamp: { type: 'string', format: 'date-time' },
        },
      },
      // ✅ Token Response
      TokenResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: true },
          message: { type: 'string', example: 'Token refreshed successfully' },
          data: {
            type: 'object',
            properties: {
              accessToken: { type: 'string' },
              refreshToken: { type: 'string' },
              expiresIn: { type: 'number' },
            },
          },
          timestamp: { type: 'string', format: 'date-time' },
        },
      },
      // ✅ JWK Response
      JWKResponse: {
        type: 'object',
        properties: {
          keys: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                kty: { type: 'string' },
                kid: { type: 'string' },
                use: { type: 'string' },
                alg: { type: 'string' },
                n: { type: 'string' },
                e: { type: 'string' },
              },
            },
          },
        },
      },
      // ✅ Company Registration
      CompanyRegistration: {
        type: 'object',
        required: ['name', 'type', 'taxId'],
        properties: {
          name: { type: 'string', minLength: 2, maxLength: 200 },
          type: {
            type: 'string',
            enum: ['corporation', 'llc', 'partnership', 'sole_proprietorship'],
          },
          taxId: { type: 'string', pattern: '^[0-9]{9}$' },
          industry: { type: 'string' },
          website: { type: 'string', format: 'uri' },
          phone: { type: 'string' },
          address: {
            type: 'object',
            properties: {
              street: { type: 'string' },
              city: { type: 'string' },
              state: { type: 'string' },
              zipCode: { type: 'string' },
              country: { type: 'string' },
            },
          },
        },
      },
      // ✅ User List Response
      UserListResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: true },
          message: { type: 'string', example: 'Users retrieved successfully' },
          data: {
            type: 'object',
            properties: {
              users: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    id: { type: 'string', format: 'uuid' },
                    fullName: { type: 'string' },
                    email: { type: 'string' },
                    type: { type: 'string' },
                    role: { type: 'string' },
                    status: { type: 'string' },
                    createdAt: { type: 'string', format: 'date-time' },
                  },
                },
              },
              pagination: {
                type: 'object',
                properties: {
                  page: { type: 'integer' },
                  limit: { type: 'integer' },
                  total: { type: 'integer' },
                  pages: { type: 'integer' },
                },
              },
            },
          },
          timestamp: { type: 'string', format: 'date-time' },
        },
      },
    },
  },
  tags: [
    {
      name: 'Authentication',
      description: 'User authentication and authorization',
    },
    {
      name: 'JWK',
      description: 'JSON Web Key management',
    },
    {
      name: 'Company',
      description: 'Company registration and management',
    },
    {
      name: 'Admin',
      description: 'Administrative operations (admin only)',
    },
  ],
};
// ✅ Export API specification
export default apiSpec;
