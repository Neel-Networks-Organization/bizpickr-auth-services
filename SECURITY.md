# 🔒 AuthService Security Documentation

## Overview

This document outlines the comprehensive security measures implemented in the AuthService microservice, covering authentication, authorization, data protection, and infrastructure security.

## 🛡️ Security Architecture

### Security Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Security                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   JWT Auth  │  │   Rate Lim  │  │   Input Validation  │ │
│  │             │  │             │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────────────────────────────────────────────┐
│                    Transport Security                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │     HTTPS   │  │   CORS      │  │   Security Headers  │ │
│  │             │  │             │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────────────────────────────────────────────┐
│                    Data Security                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Password  │  │   Token     │  │   Audit Logging     │ │
│  │   Hashing   │  │   Encryption │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 🔐 Authentication Security

### JWT (JSON Web Token) Security

#### **Token Structure**

```javascript
// Access Token (Short-lived)
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user-uuid",
    "iat": 1640995200,
    "exp": 1640996100,
    "iss": "auth-service",
    "aud": "bizpickr-app",
    "type": "access",
    "role": "customer",
    "permissions": ["read:profile", "write:profile"]
  }
}

// Refresh Token (Long-lived)
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user-uuid",
    "iat": 1640995200,
    "exp": 1641600000,
    "iss": "auth-service",
    "aud": "bizpickr-app",
    "type": "refresh",
    "jti": "unique-refresh-token-id"
  }
}
```

#### **Security Measures**

- **Strong Secret Keys**: 256-bit minimum for JWT signing
- **Token Expiration**: Access tokens expire in 15 minutes
- **Refresh Token Rotation**: New refresh token on each use
- **Token Blacklisting**: Invalidated tokens stored in Redis
- **Audit Logging**: All token operations logged

```javascript
// JWT Configuration
const jwtConfig = {
  accessToken: {
    secret: process.env.JWT_SECRET,
    expiresIn: '15m',
    algorithm: 'HS256',
  },
  refreshToken: {
    secret: process.env.REFRESH_TOKEN_SECRET,
    expiresIn: '7d',
    algorithm: 'HS256',
  },
};
```

### Password Security

#### **Password Hashing**

```javascript
// bcrypt Configuration
const bcryptConfig = {
  rounds: 12, // Cost factor (2^12 = 4096 iterations)
  saltRounds: 12, // Salt generation rounds
  maxLength: 128, // Maximum password length
  minLength: 8, // Minimum password length
};

// Password hashing
const hashPassword = async password => {
  return await bcrypt.hash(password, bcryptConfig.rounds);
};

// Password verification
const verifyPassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};
```

#### **Password Policy**

```javascript
// Password validation rules
const passwordRules = {
  minLength: 8,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  preventCommonPasswords: true,
  preventUserInfo: true,
};

// Password strength validation
const validatePasswordStrength = (password, userInfo) => {
  const checks = {
    length: password.length >= passwordRules.minLength,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    numbers: /\d/.test(password),
    special: /[!@#$%^&*(),.?":{}|<>]/.test(password),
    notCommon: !commonPasswords.includes(password.toLowerCase()),
    notUserInfo: !containsUserInfo(password, userInfo),
  };

  return Object.values(checks).every(Boolean);
};
```

### Two-Factor Authentication (2FA)

#### **TOTP Implementation**

```javascript
// TOTP Configuration
const totpConfig = {
  algorithm: 'sha1',
  digits: 6,
  period: 30,
  window: 1, // Allow 1 period before/after
  issuer: 'BizPickr',
};

// Generate TOTP secret
const generateTOTPSecret = () => {
  return speakeasy.generateSecret({
    name: totpConfig.issuer,
    issuer: totpConfig.issuer,
    length: 32,
  });
};

// Verify TOTP code
const verifyTOTPCode = (secret, token) => {
  return speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token,
    window: totpConfig.window,
    algorithm: totpConfig.algorithm,
    digits: totpConfig.digits,
    period: totpConfig.period,
  });
};
```

#### **Backup Codes**

```javascript
// Generate backup codes
const generateBackupCodes = (count = 10) => {
  const codes = [];
  for (let i = 0; i < count; i++) {
    codes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
  }
  return codes.map(code => ({
    code: code,
    used: false,
    usedAt: null,
  }));
};

// Verify backup code
const verifyBackupCode = (backupCodes, code) => {
  const backupCode = backupCodes.find(bc => bc.code === code && !bc.used);
  if (backupCode) {
    backupCode.used = true;
    backupCode.usedAt = new Date();
    return true;
  }
  return false;
};
```

## 🚫 Authorization Security

### Role-Based Access Control (RBAC)

#### **Role Hierarchy**

```javascript
const roleHierarchy = {
  super_admin: [
    'admin',
    'requirement_coordinator',
    'salesman',
    'caller',
    'support',
    'hr_admin',
    'customer',
    'vendor',
  ],
  admin: [
    'requirement_coordinator',
    'salesman',
    'caller',
    'support',
    'hr_admin',
    'customer',
    'vendor',
  ],
  requirement_coordinator: ['salesman', 'caller', 'customer', 'vendor'],
  salesman: ['customer', 'vendor'],
  caller: ['customer', 'vendor'],
  support: ['customer', 'vendor'],
  hr_admin: ['customer', 'vendor'],
  customer: [],
  vendor: [],
};

// Permission mapping
const permissions = {
  // User management
  'user:read': ['admin', 'requirement_coordinator', 'support', 'hr_admin'],
  'user:write': ['admin', 'requirement_coordinator'],
  'user:delete': ['admin'],

  // Profile management
  'profile:read': ['*'],
  'profile:write': ['*'],

  // Session management
  'session:read': ['admin', 'requirement_coordinator', 'support'],
  'session:terminate': ['admin', 'requirement_coordinator', 'support'],

  // System management
  'system:metrics': ['admin', 'requirement_coordinator'],
  'system:logs': ['admin'],
  'system:config': ['admin'],
};
```

#### **Permission Checking**

```javascript
// Check user permissions
const hasPermission = (user, permission) => {
  const userRole = user.role;
  const allowedRoles = permissions[permission] || [];

  // Check direct permission
  if (allowedRoles.includes(userRole)) {
    return true;
  }

  // Check role hierarchy
  const userHierarchy = roleHierarchy[userRole] || [];
  return userHierarchy.some(role => allowedRoles.includes(role));
};

// Middleware for permission checking
const requirePermission = permission => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!hasPermission(req.user, permission)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
};
```

## 🛡️ Application Security

### Input Validation

#### **Joi Schema Validation**

```javascript
// User registration validation
const signupSchema = Joi.object({
  email: Joi.string().email().required().max(255).custom(emailValidator),

  password: Joi.string()
    .min(8)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .required(),

  fullName: Joi.string()
    .min(2)
    .max(100)
    .pattern(/^[a-zA-Z\s]+$/)
    .required(),

  type: Joi.string().valid('customer', 'vendor', 'staff', 'admin').required(),

  role: Joi.string()
    .valid(
      'customer',
      'vendor',
      'salesman',
      'caller',
      'requirement_coordinator',
      'admin',
      'support',
      'hr_admin',
      'super_admin'
    )
    .default('customer'),

  phone: Joi.string()
    .pattern(/^\+?[1-9]\d{1,14}$/)
    .optional(),

  termsAccepted: Joi.boolean().valid(true).required(),

  privacyAccepted: Joi.boolean().valid(true).required(),
});

// Custom email validator
const emailValidator = (value, helpers) => {
  // Check for disposable email domains
  if (isDisposableEmail(value)) {
    return helpers.error('any.invalid');
  }

  // Check for common patterns
  if (value.includes('test') || value.includes('example')) {
    return helpers.error('any.invalid');
  }

  return value;
};
```

#### **SQL Injection Prevention**

```javascript
// Parameterized queries with Sequelize
const findUserByEmail = async email => {
  return await User.findOne({
    where: {
      email: email, // Automatically parameterized
    },
  });
};

// Raw queries with parameterization
const rawQuery = async email => {
  return await sequelize.query(
    'SELECT * FROM auth_users WHERE email = :email',
    {
      replacements: { email: email },
      type: QueryTypes.SELECT,
    }
  );
};
```

### Rate Limiting

#### **Rate Limiter Configuration**

```javascript
// Rate limiter configuration
const rateLimitConfig = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: req => {
    // Use user ID if authenticated, otherwise IP
    return req.user ? req.user.id : req.ip;
  },
  skip: req => {
    // Skip rate limiting for health checks
    return req.path === '/health';
  },
};

// Endpoint-specific rate limits
const endpointRateLimits = {
  signup: { windowMs: 15 * 60 * 1000, max: 5 },
  login: { windowMs: 15 * 60 * 1000, max: 10 },
  passwordReset: { windowMs: 60 * 60 * 1000, max: 3 },
  emailVerification: { windowMs: 60 * 60 * 1000, max: 5 },
  twoFactor: { windowMs: 5 * 60 * 1000, max: 10 },
};
```

### Security Headers

#### **Helmet Configuration**

```javascript
// Security headers with Helmet
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xssFilter: true,
    frameguard: { action: 'deny' },
  })
);
```

## 🔒 Data Security

### Data Encryption

#### **Sensitive Data Encryption**

```javascript
// AES-256 encryption for sensitive data
const crypto = require('crypto');

const encryptionConfig = {
  algorithm: 'aes-256-gcm',
  keyLength: 32,
  ivLength: 16,
  tagLength: 16,
};

// Encrypt sensitive data
const encryptData = (data, key) => {
  const iv = crypto.randomBytes(encryptionConfig.ivLength);
  const cipher = crypto.createCipher(encryptionConfig.algorithm, key);

  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const tag = cipher.getAuthTag();

  return {
    encrypted: encrypted,
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
  };
};

// Decrypt sensitive data
const decryptData = (encryptedData, key, iv, tag) => {
  const decipher = crypto.createDecipher(encryptionConfig.algorithm, key);
  decipher.setAuthTag(Buffer.from(tag, 'hex'));

  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
};
```

### Data Sanitization

#### **Input Sanitization**

```javascript
// XSS prevention
const sanitizeInput = input => {
  if (typeof input !== 'string') return input;

  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
};

// SQL injection prevention
const sanitizeSQL = input => {
  if (typeof input !== 'string') return input;

  return input
    .replace(/'/g, "''")
    .replace(/--/g, '')
    .replace(/;/g, '')
    .replace(/\/\*/g, '')
    .replace(/\*\//g, '');
};
```

## 📊 Audit Logging

### Security Event Logging

```javascript
// Audit log structure
const auditLogSchema = {
  userId: String, // User who performed the action
  action: String, // Action performed
  resourceType: String, // Type of resource affected
  resourceId: String, // ID of resource affected
  details: Object, // Additional details
  ipAddress: String, // IP address of request
  userAgent: String, // User agent string
  status: String, // Success/failure status
  severity: String, // Low/Medium/High/Critical
  timestamp: Date, // When the action occurred
};

// Security events to log
const securityEvents = [
  'USER_LOGIN',
  'USER_LOGOUT',
  'USER_REGISTERED',
  'PASSWORD_CHANGE',
  'PASSWORD_RESET',
  'EMAIL_VERIFICATION',
  'TWO_FACTOR_ENABLED',
  'TWO_FACTOR_DISABLED',
  'SUSPICIOUS_ACTIVITY',
  'RATE_LIMIT_EXCEEDED',
  'INVALID_TOKEN',
  'PERMISSION_DENIED',
  'ADMIN_ACTION',
];

// Log security event
const logSecurityEvent = async event => {
  await AuditLog.create({
    userId: event.userId || 'anonymous',
    action: event.action,
    resourceType: event.resourceType,
    resourceId: event.resourceId,
    details: event.details,
    ipAddress: event.ipAddress,
    userAgent: event.userAgent,
    status: event.status,
    severity: event.severity,
    timestamp: new Date(),
  });
};
```

## 🚨 Threat Detection

### Suspicious Activity Detection

```javascript
// Device fingerprinting
const deviceFingerprint = {
  userAgent: req.headers['user-agent'],
  ipAddress: req.ip,
  acceptLanguage: req.headers['accept-language'],
  acceptEncoding: req.headers['accept-encoding'],
  screenResolution: req.headers['x-screen-resolution'],
  timezone: req.headers['x-timezone'],
};

// Suspicious activity detection
const detectSuspiciousActivity = async (userId, activity) => {
  const userDevices = await getUserDevices(userId);
  const currentDevice = generateDeviceFingerprint(activity);

  // Check for unusual location
  const isUnusualLocation = await checkUnusualLocation(
    userDevices,
    currentDevice
  );

  // Check for unusual time
  const isUnusualTime = await checkUnusualTime(userId, activity.timestamp);

  // Check for multiple failed attempts
  const failedAttempts = await getFailedAttempts(userId, '5m');

  // Determine risk level
  let riskLevel = 'low';
  if (isUnusualLocation || isUnusualTime) riskLevel = 'medium';
  if (failedAttempts > 5) riskLevel = 'high';
  if (failedAttempts > 10) riskLevel = 'critical';

  return {
    riskLevel,
    isUnusualLocation,
    isUnusualTime,
    failedAttempts,
    requiresAction: riskLevel === 'high' || riskLevel === 'critical',
  };
};
```

### Brute Force Protection

```javascript
// Brute force protection
const bruteForceProtection = {
  maxAttempts: 5,
  windowMs: 15 * 60 * 1000, // 15 minutes
  lockoutDuration: 30 * 60 * 1000, // 30 minutes
};

// Check for brute force attempts
const checkBruteForceAttempts = async (identifier, action) => {
  const key = `brute_force:${action}:${identifier}`;
  const attempts = await redis.get(key);

  if (attempts && parseInt(attempts) >= bruteForceProtection.maxAttempts) {
    // Account is locked
    await lockAccount(identifier, bruteForceProtection.lockoutDuration);
    return {
      locked: true,
      remainingTime: await getLockoutRemainingTime(identifier),
    };
  }

  // Increment attempt counter
  await redis.incr(key);
  await redis.expire(key, bruteForceProtection.windowMs);

  return { locked: false, attempts: parseInt(attempts || 0) + 1 };
};
```

## 🔐 OAuth Security

### OAuth 2.0 Security

```javascript
// OAuth state parameter for CSRF protection
const generateOAuthState = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Verify OAuth state
const verifyOAuthState = (state, storedState) => {
  return crypto.timingSafeEqual(
    Buffer.from(state, 'hex'),
    Buffer.from(storedState, 'hex')
  );
};

// OAuth callback security
const handleOAuthCallback = async (req, res) => {
  const { code, state } = req.query;
  const storedState = req.session.oauthState;

  // Verify state parameter
  if (!verifyOAuthState(state, storedState)) {
    return res.status(400).json({ error: 'Invalid OAuth state' });
  }

  // Clear state from session
  delete req.session.oauthState;

  try {
    // Exchange code for tokens
    const tokens = await exchangeCodeForTokens(code);

    // Get user info
    const userInfo = await getUserInfo(tokens.access_token);

    // Create or update user
    const user = await findOrCreateUser(userInfo);

    // Create session
    const session = await createSession(user.id, req);

    res.json({ success: true, session });
  } catch (error) {
    res.status(400).json({ error: 'OAuth authentication failed' });
  }
};
```

## 🛡️ Infrastructure Security

### Docker Security

```dockerfile
# Security-focused Dockerfile
FROM node:18-alpine

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY . .

# Change ownership to non-root user
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3001/health || exit 1

# Start application
CMD ["npm", "start"]
```

### Network Security

```javascript
// CORS configuration
const corsConfig = {
  origin: (origin, callback) => {
    const allowedOrigins = [
      'https://yourdomain.com',
      'https://app.yourdomain.com',
      'https://admin.yourdomain.com',
    ];

    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'X-Correlation-ID',
  ],
  maxAge: 86400,
};
```

## 📋 Security Checklist

### Pre-Deployment Security Checklist

- [ ] **Environment Variables**: All secrets properly configured
- [ ] **SSL/TLS**: HTTPS enabled with valid certificates
- [ ] **Firewall**: Ports properly configured
- [ ] **Database**: Secure connections with SSL
- [ ] **Redis**: Authentication enabled
- [ ] **Logging**: Security events being logged
- [ ] **Monitoring**: Security alerts configured
- [ ] **Backup**: Secure backup procedures in place

### Runtime Security Checklist

- [ ] **Rate Limiting**: Properly configured and working
- [ ] **Input Validation**: All inputs validated
- [ ] **Authentication**: JWT tokens properly validated
- [ ] **Authorization**: RBAC properly implemented
- [ ] **Audit Logging**: All security events logged
- [ ] **Error Handling**: No sensitive data in error messages
- [ ] **Session Management**: Sessions properly managed
- [ ] **Data Encryption**: Sensitive data encrypted

### Security Monitoring

```javascript
// Security monitoring alerts
const securityAlerts = {
  failedLogins: {
    threshold: 5,
    window: '5m',
    action: 'lock_account',
  },
  suspiciousActivity: {
    threshold: 1,
    window: '1m',
    action: 'notify_admin',
  },
  rateLimitExceeded: {
    threshold: 10,
    window: '1m',
    action: 'block_ip',
  },
  invalidTokens: {
    threshold: 20,
    window: '5m',
    action: 'investigate',
  },
};

// Send security alert
const sendSecurityAlert = async alert => {
  await logSecurityEvent({
    action: 'SECURITY_ALERT',
    details: alert,
    severity: 'high',
    status: 'alert',
  });

  // Send notification to security team
  await notifySecurityTeam(alert);
};
```

## 🚨 Incident Response

### Security Incident Response Plan

1. **Detection**: Automated monitoring detects security events
2. **Assessment**: Evaluate severity and impact
3. **Containment**: Isolate affected systems
4. **Investigation**: Analyze root cause
5. **Remediation**: Fix security vulnerabilities
6. **Recovery**: Restore normal operations
7. **Post-Incident**: Document lessons learned

### Security Contact Information

- **Security Team**: security@yourdomain.com
- **Emergency Contact**: +1-XXX-XXX-XXXX
- **Bug Bounty**: security.yourdomain.com
- **Security Policy**: security.yourdomain.com/policy

---

**This security documentation ensures comprehensive protection of the AuthService microservice and its data.**
