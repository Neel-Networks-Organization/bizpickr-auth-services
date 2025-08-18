import express from 'express';
import cors from 'cors';
import helmet from 'helmet';

import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import compression from 'compression';

import { safeLogger } from './config/logger.js';
import {
  correlationIdMiddleware,
  enterpriseLoggingMiddleware,
  enterpriseRateLimit,
  enterpriseSecurityMiddleware,
  enterpriseValidationMiddleware,
  enterpriseErrorHandler,
  enterpriseAuthMiddleware
} from './middlewares/enterprise.middleware.js';
import {
  checkDb,
  checkRedis,
  checkRabbitMQ,
  checkGrpc,
  checkMongoDB,
} from './utils/healthChecks.js';
const allowedOrigins = ['http://localhost:3000'];
const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ✅ Basic Security with Helmet
app.use(helmet());

// ✅ Simple CORS
app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));

// ✅ Basic Compression
app.use(compression());

// ✅ Basic Body Parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ✅ Cookie Parser
app.use(cookieParser());

// ✅ Enterprise Middlewares (Essential for SaaS)
app.use(correlationIdMiddleware);
app.use(enterpriseLoggingMiddleware);
app.use(enterpriseRateLimit(100, 15 * 60 * 1000)); // 100 requests per 15 minutes
app.use(enterpriseSecurityMiddleware);
app.use(enterpriseValidationMiddleware);
// ✅ Static Files with Security
app.use(
  '/public',
  express.static(path.join(__dirname, '..', 'public'), {
    maxAge: '1d',
    etag: true,
    lastModified: true,
    setHeaders: (res, path) => {
      if (path.endsWith('.js')) {
        res.setHeader('Content-Type', 'application/javascript');
      }
      res.setHeader('X-Content-Type-Options', 'nosniff');
    },
  }),
);
// ✅ API Routes
import authRoutes from './routes/auth.route.js';
import userRoutes from './routes/user.routes.js';
import sessionRoutes from './routes/session.route.js';
import passwordRoutes from './routes/password.route.js';
import jwkRoutes from './routes/jwk.route.js';
import metricsRoutes from './routes/metrics.route.js';

// Route Registration
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/users', userRoutes);
app.use('/api/v1/sessions', sessionRoutes);
app.use('/api/v1/password', passwordRoutes);
app.use('/api/v1/jwk', jwkRoutes);
app.use('/api/v1/metrics', metricsRoutes);

// ✅ Health Check Routes
import healthRoutes from './routes/health.route.js';
app.use('/health', healthRoutes);

// ✅ Metrics Routes
app.use('/metrics', metricsRoutes);

// ✅ API Documentation
import docsRoutes from './routes/docs.route.js';
app.use('/api-docs', docsRoutes);

// ✅ Enterprise 404 Handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Route not found',
    message: `Cannot ${req.method} ${req.url}`,
    correlationId: req.correlationId
  });
});

// ✅ Enterprise Error Handler
app.use(enterpriseErrorHandler);

export { app };
