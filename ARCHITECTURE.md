# 🏗️ AuthService Architecture Documentation

## Overview

The AuthService is a **microservice-based authentication system** designed for enterprise applications. It follows **Domain-Driven Design (DDD)** principles and implements **Clean Architecture** patterns for maintainability, scalability, and security.

## 🎯 Architecture Principles

### 1. **Single Responsibility Principle**

Each service and component has a single, well-defined responsibility.

### 2. **Separation of Concerns**

Clear boundaries between different layers and components.

### 3. **Dependency Inversion**

High-level modules don't depend on low-level modules.

### 4. **Interface Segregation**

Clients depend only on the interfaces they use.

### 5. **Open/Closed Principle**

Open for extension, closed for modification.

## 🏛️ System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Applications                      │
│  (Web App, Mobile App, API Gateway, Other Microservices)   │
└─────────────────────┬───────────────────────────────────────┘
                      │ HTTP/HTTPS
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    API Gateway Layer                        │
│  (Rate Limiting, CORS, Security Headers, Load Balancing)   │
└─────────────────────┬───────────────────────────────────────┘
                      │ HTTP/HTTPS
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   AuthService Microservice                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   Controllers   │  │    Services     │  │   Models    │ │
│  │   (HTTP Layer)  │  │ (Business Logic)│  │ (Data Layer)│ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
└─────────────────────┬───────────────────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│   MySQL     │ │  MongoDB    │ │    Redis    │
│(Transactional│ │   (Logs)    │ │   (Cache)   │
│    Data)    │ │             │ │             │
└─────────────┘ └─────────────┘ └─────────────┘
```

### Service Layer Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Presentation Layer                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ Controllers │  │   Routes    │  │   Middlewares       │ │
│  │             │  │             │  │  (Auth, Validation) │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────────────────────────────────────────────┐
│                    Business Logic Layer                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ AuthService │  │UserService  │  │  SessionService     │ │
│  │             │  │             │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │OAuthService │  │2FAService   │  │  EmailService       │ │
│  │             │  │             │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────────────────────────────────────────────┐
│                    Data Access Layer                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Models    │  │   Cache     │  │   Event System      │ │
│  │ (Sequelize) │  │   (Redis)   │  │   (RabbitMQ)        │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────────────────────────────────────────────┐
│                    Infrastructure Layer                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   MySQL     │  │  MongoDB    │  │   External APIs     │ │
│  │  Database   │  │  Database   │  │  (OAuth, Email)     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Component Architecture

### 1. **Controllers Layer**

**Purpose**: Handle HTTP requests and responses

**Components**:

- `auth.controller.js` - Authentication operations
- `user.controller.js` - User management
- `session.controller.js` - Session operations
- `password.controller.js` - Password operations
- `jwk.controller.js` - JWT key management

**Responsibilities**:

- Request validation
- Response formatting
- Error handling
- HTTP status codes
- Content negotiation

### 2. **Services Layer**

**Purpose**: Business logic implementation

**Core Services**:

- `auth.service.js` - Core authentication logic
- `user.service.js` - User management
- `session.service.js` - Session management
- `password.service.js` - Password operations
- `jwk.service.js` - JWT key management

**Security Services**:

- `oauth.service.js` - OAuth integration
- `twoFactor.service.js` - 2FA implementation
- `deviceFingerprint.service.js` - Device security

**Support Services**:

- `email.service.js` - Email operations
- `emailVerification.service.js` - Email verification
- `errorClassification.service.js` - Error handling

### 3. **Models Layer**

**Purpose**: Data access and persistence

**MySQL Models** (Transactional Data):

- `authUser.model.js` - User accounts
- `session.model.js` - User sessions
- `passwordReset.model.js` - Password resets
- `emailVerification.model.js` - Email verifications

**MongoDB Models** (Logging Data):

- `userActivity.model.js` - User activity logs
- `auditLog.model.js` - System audit logs

### 4. **Middleware Layer**

**Purpose**: Cross-cutting concerns

**Security Middlewares**:

- `auth.middleware.js` - JWT authentication
- `security.middleware.js` - Security headers
- `rateLimiter.middleware.js` - Rate limiting
- `validation.middleware.js` - Input validation

**Operational Middlewares**:

- `audit.middleware.js` - Audit logging
- `logging.middleware.js` - Request logging
- `performance.middleware.js` - Performance monitoring
- `errorHandler.middleware.js` - Error handling

## 🗄️ Data Architecture

### Database Strategy

#### **MySQL Database** (Primary - Transactional Data)

**Purpose**: ACID-compliant transactional data

**Tables**:

```sql
-- Core user data
auth_users
├── id (UUID, Primary Key)
├── email (VARCHAR, Unique)
├── password_hash (VARCHAR)
├── full_name (VARCHAR)
├── type (ENUM: customer, vendor, staff, admin)
├── role (ENUM: customer, vendor, salesman, caller, requirement_coordinator, admin, support, hr_admin, super_admin)
├── is_active (BOOLEAN)
├── email_verified (BOOLEAN)
├── two_factor_enabled (BOOLEAN)
└── created_at, updated_at, deleted_at

-- Session management
sessions
├── id (UUID, Primary Key)
├── user_id (UUID, Foreign Key)
├── refresh_token (VARCHAR)
├── device_info (JSON)
├── ip_address (VARCHAR)
├── user_agent (VARCHAR)
├── is_active (BOOLEAN)
└── created_at, updated_at

-- Password operations
password_resets
├── id (UUID, Primary Key)
├── user_id (UUID, Foreign Key)
├── token (VARCHAR)
├── expires_at (TIMESTAMP)
├── used_at (TIMESTAMP)
└── created_at

-- Email verification
email_verifications
├── id (UUID, Primary Key)
├── user_id (UUID, Foreign Key)
├── token (VARCHAR)
├── expires_at (TIMESTAMP)
├── verified_at (TIMESTAMP)
└── created_at
```

#### **MongoDB Database** (Secondary - Logging Data)

**Purpose**: High-volume, flexible log data

**Collections**:

```javascript
// User activity logs
userActivity
├── userId (String - MySQL UUID)
├── action (String)
├── details (Object)
├── ipAddress (String)
├── userAgent (String)
├── timestamp (Date)
└── metadata (Object)

// System audit logs
auditLog
├── userId (String - MySQL UUID)
├── action (String)
├── resourceType (String)
├── resourceId (String)
├── details (Object)
├── ipAddress (String)
├── userAgent (String)
├── status (String)
├── severity (String)
└── timestamp (Date)
```

### **Redis Cache** (Tertiary - Performance)

**Purpose**: High-speed caching and session storage

**Cache Keys**:

```redis
# User data cache
user:{userId} -> User object (TTL: 15 minutes)

# Session cache
session:{sessionId} -> Session object (TTL: 24 hours)

# JWT keys cache
jwk:public -> Public keys (TTL: 1 hour)

# Rate limiting
rate_limit:{endpoint}:{userId} -> Request count (TTL: window)

# Device fingerprinting
device:{fingerprint} -> Device info (TTL: 30 days)
```

## 🔄 Event Architecture

### Event-Driven Communication

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AuthService   │───▶│   RabbitMQ      │───▶│  Other Services │
│                 │    │   (Events)      │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Event Emitter │    │   Event Queue   │    │  Event Consumer │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Event Types

```javascript
// User events
USER_REGISTERED;
USER_LOGIN;
USER_LOGOUT;
USER_PROFILE_UPDATED;
USER_DELETED;

// Security events
PASSWORD_CHANGED;
EMAIL_VERIFIED;
TWO_FACTOR_ENABLED;
TWO_FACTOR_DISABLED;
SUSPICIOUS_ACTIVITY;

// Session events
SESSION_CREATED;
SESSION_INVALIDATED;
SESSION_EXPIRED;

// System events
SERVICE_STARTED;
SERVICE_STOPPED;
HEALTH_CHECK;
```

## 🔐 Security Architecture

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

### Security Features

#### **Authentication Security**

- **JWT with refresh tokens** for secure session management
- **Password hashing** with bcrypt (12 rounds)
- **Two-factor authentication** with TOTP
- **OAuth 2.0 integration** for social login
- **Device fingerprinting** for suspicious activity detection

#### **Application Security**

- **Rate limiting** per endpoint and user
- **Input validation** with comprehensive Joi schemas
- **SQL injection prevention** with parameterized queries
- **XSS protection** with security headers
- **CSRF protection** with tokens
- **Audit logging** for compliance and security monitoring

#### **Infrastructure Security**

- **Docker containerization** with non-root user
- **Health checks** for all dependencies
- **Graceful shutdown** handling
- **Environment-based configuration**
- **Secure defaults** for production

## 📊 Performance Architecture

### Caching Strategy

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │───▶│   Redis Cache   │───▶│   Database      │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Cache Hit     │    │   Cache Miss    │    │   Database Hit  │
│   (Fast)        │    │   (Medium)      │    │   (Slow)        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Performance Optimizations

#### **Database Optimization**

- **Connection pooling** for MySQL
- **Indexing strategy** for frequently queried fields
- **Query optimization** with Sequelize
- **Read replicas** for read-heavy operations

#### **Caching Optimization**

- **Multi-level caching** (Memory → Redis → Database)
- **Cache warming** for frequently accessed data
- **Cache invalidation** strategies
- **TTL optimization** based on data volatility

#### **Application Optimization**

- **Compression** middleware for responses
- **Response caching** for static data
- **Async operations** for non-blocking I/O
- **Connection pooling** for external services

## 🔄 Scalability Architecture

### Horizontal Scaling

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Balancer │───▶│  AuthService 1  │    │  AuthService 2  │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Shared Cache  │    │   Shared DB     │    │   Shared Queue  │
│   (Redis)       │    │   (MySQL)       │    │   (RabbitMQ)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Vertical Scaling

- **Resource allocation** based on load
- **Memory optimization** with garbage collection
- **CPU optimization** with worker threads
- **I/O optimization** with async operations

## 🧪 Testing Architecture

### Testing Pyramid

```
┌─────────────────────────────────────────────────────────────┐
│                    E2E Tests (10%)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ Auth Flow   │  │ User Flow   │  │  Integration Flow   │ │
│  │             │  │             │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                      │
┌─────────────────────────────────────────────────────────────┐
│                  Integration Tests (20%)                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ API Tests   │  │ DB Tests    │  │  External API Tests │ │
│  │             │  │             │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                      │
┌─────────────────────────────────────────────────────────────┐
│                    Unit Tests (70%)                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ Services    │  │ Controllers │  │  Utils & Helpers    │ │
│  │             │  │             │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Testing Strategy

#### **Unit Tests**

- **Service layer** testing with mocked dependencies
- **Controller layer** testing with mocked services
- **Utility functions** testing with edge cases
- **Validation logic** testing with various inputs

#### **Integration Tests**

- **API endpoints** testing with real HTTP requests
- **Database operations** testing with test database
- **Cache operations** testing with Redis
- **External services** testing with mocked APIs

#### **End-to-End Tests**

- **Authentication flows** testing complete user journeys
- **Error scenarios** testing error handling
- **Performance testing** with load testing tools
- **Security testing** with vulnerability scanning

## 📈 Monitoring Architecture

### Monitoring Stack

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │───▶│   Metrics       │───▶│   Dashboard     │
│   (AuthService) │    │   (Prometheus)  │    │   (Grafana)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Logs          │    │   Traces        │    │   Alerts        │
│   (Loki)        │    │   (Jaeger)      │    │   (AlertManager)│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Monitoring Metrics

#### **Application Metrics**

- **Request rate** (RPS)
- **Response time** (latency)
- **Error rate** (4xx, 5xx)
- **Success rate** (2xx)

#### **Business Metrics**

- **User registrations** per day
- **Login attempts** per hour
- **Failed logins** per day
- **2FA usage** percentage

#### **Infrastructure Metrics**

- **CPU usage** percentage
- **Memory usage** percentage
- **Disk usage** percentage
- **Network I/O** bytes

## 🚀 Deployment Architecture

### Container Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Container                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Node.js   │  │  Express.js │  │   Application Code  │ │
│  │   Runtime   │  │   Framework │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Service   │  │   Ingress   │  │   ConfigMap         │ │
│  │             │  │             │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────────────────────────────────────────────┐
│                    Infrastructure                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Load      │  │   Database  │  │   Cache & Queue     │ │
│  │   Balancer  │  │   Cluster   │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Deployment Strategy

#### **Blue-Green Deployment**

- **Zero downtime** deployments
- **Instant rollback** capability
- **Traffic switching** between versions
- **Database migration** handling

#### **Canary Deployment**

- **Gradual rollout** to users
- **Performance monitoring** during rollout
- **Automatic rollback** on issues
- **A/B testing** capability

## 🔧 Configuration Architecture

### Configuration Management

```
┌─────────────────────────────────────────────────────────────┐
│                    Environment Variables                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Core      │  │   Database  │  │   External          │ │
│  │   Config    │  │   Config    │  │   Services          │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────────────────────────────────────────────┐
│                    Configuration Files                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   env.js    │  │ database.js │  │   dev.js            │ │
│  │             │  │             │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────────────────────────────────────────────┐
│                    Application                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Validation│  │   Defaults  │  │   Type Checking     │ │
│  │             │  │             │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Configuration Strategy

#### **Environment-Based Configuration**

- **Development**: Local development settings
- **Staging**: Pre-production testing
- **Production**: Live environment settings

#### **Feature Flags**

- **Feature toggles** for gradual rollout
- **A/B testing** configuration
- **Performance tuning** parameters
- **Security settings** per environment

## 📚 Conclusion

The AuthService architecture is designed for:

- **Scalability**: Horizontal and vertical scaling
- **Security**: Multi-layer security approach
- **Performance**: Optimized caching and database strategies
- **Maintainability**: Clean architecture principles
- **Reliability**: Comprehensive testing and monitoring
- **Observability**: Complete logging and metrics

This architecture supports enterprise-grade authentication requirements while maintaining flexibility for future enhancements and integrations.
