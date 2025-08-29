import express from 'express';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import ipRateLimit from '../middlewares/rateLimiter.middleware.js';
import { asyncHandler } from '../utils/index.js';
import { env } from '../config/env.js';

const router = express.Router();

// Swagger configuration
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'AuthService API',
      version: '1.0.0',
      description: 'Authentication and Authorization Microservice API',
      contact: {
        name: 'Neel Networks',
        email: 'support@neelnetworks.com',
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
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
    security: [
      {
        bearerAuth: [],
      },
    ],
  },
  apis: ['./src/routes/*.js', './src/models/*.js'],
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

// Serve Swagger UI with rate limiting
router.use('/', swaggerUi.serve);
router.get(
  '/',
  ipRateLimit({
    windowMs: env.services.rateLimit.defaultWindow,
    maxRequests: env.services.rateLimit.defaultLimit,
  }),
  swaggerUi.setup(swaggerSpec, {
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: 'AuthService API Documentation',
  })
);

// Serve OpenAPI spec with rate limiting
router.get(
  '/swagger.json',
  ipRateLimit({
    windowMs: env.services.rateLimit.defaultWindow,
    maxRequests: Math.floor(env.services.rateLimit.defaultLimit / 2),
  }),
  asyncHandler((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(swaggerSpec);
  })
);

export default router;
