import express from 'express';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import { rateLimiter, auditLog } from '../middlewares/auth.middleware.js';
import { asyncHandler } from '../utils/index.js';

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
  rateLimiter('docs-ui', { windowMs: 15 * 60 * 1000, max: 100 }),
  auditLog('docs_ui_access'),
  swaggerUi.setup(swaggerSpec, {
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: 'AuthService API Documentation',
  }),
);

// Serve OpenAPI spec with rate limiting
router.get(
  '/swagger.json',
  rateLimiter('docs-spec', { windowMs: 15 * 60 * 1000, max: 50 }),
  auditLog('docs_spec_access'),
  asyncHandler((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(swaggerSpec);
  }),
);

export default router;
