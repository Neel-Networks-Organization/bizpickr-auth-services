import express from 'express';
import helmet from 'helmet';

import cookieParser from 'cookie-parser';
import compression from 'compression';

import {
  correlationIdMiddleware,
  enterpriseLoggingMiddleware,
  enterpriseRateLimit,
  enterpriseSecurityMiddleware,
  enterpriseValidationMiddleware,
  enterpriseErrorHandler,
  enterpriseCorsMiddleware,
} from './middlewares/enterprise.middleware.js';
import { getGlobalRateLimitConfig } from './config/rateLimit.config.js';

const app = express();

// ✅ Basic Security with Helmet
app.use(helmet());

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
// ✅ Use centralized rate limit configuration
app.use(
  enterpriseRateLimit(
    getGlobalRateLimitConfig().maxRequests,
    getGlobalRateLimitConfig().windowMs
  )
);
app.use(enterpriseSecurityMiddleware);
app.use(enterpriseValidationMiddleware);
app.use(enterpriseCorsMiddleware());

// ✅ API Routes
import authRoutes from './routes/auth.route.js';
import sessionRoutes from './routes/session.route.js';
import passwordRoutes from './routes/password.route.js';
import jwkRoutes from './routes/jwk.route.js';

// Route Registration
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/sessions', sessionRoutes);
app.use('/api/v1/password', passwordRoutes);
app.use('/api/v1/jwk', jwkRoutes);

// ✅ API Documentation
import docsRoutes from './routes/docs.route.js';
app.use('/api-docs', docsRoutes);

// ✅ Enterprise 404 Handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Route not found',
    message: `Cannot ${req.method} ${req.url}`,
    correlationId: req.correlationId,
  });
});

// ✅ Enterprise Error Handler
app.use(enterpriseErrorHandler);

export { app };
