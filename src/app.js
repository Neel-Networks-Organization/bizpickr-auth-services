import express from 'express';
import cors from 'cors';
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
} from './middlewares/enterprise.middleware.js';

// 🛡️ Security & Rate Limiting Middlewares
import {
  securityHeaders,
  corsMiddleware,
  requestSizeLimit,
  sanitizeInput,
} from './middlewares/security.middleware.js';

import { ipRateLimit } from './middlewares/rateLimiter.middleware.js';

const allowedOrigins = ['http://localhost:3000'];
const app = express();

// ✅ Basic Security with Helmet
app.use(helmet());

// ✅ Simple CORS
app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
  })
);

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
app.use(enterpriseRateLimit(100, 15 * 60 * 1000));
app.use(enterpriseSecurityMiddleware);
app.use(enterpriseValidationMiddleware);

// 🛡️ ENHANCED SECURITY MIDDLEWARES
app.use(securityHeaders()); // Security headers (CSP, XSS protection)
app.use(corsMiddleware()); // Enhanced CORS protection
app.use(requestSizeLimit('10mb')); // Request size limits (DoS protection)
app.use(sanitizeInput); // Input sanitization (XSS protection)

// 🚫 RATE LIMITING MIDDLEWARES
app.use(ipRateLimit); // Global IP rate limiting
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
