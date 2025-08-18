# 🚀 Development Guide - AuthService

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Prerequisites](#-prerequisites)
- [Setup](#-setup)
- [Development Commands](#-development-commands)
- [Project Structure](#-project-structure)
- [Configuration](#-configuration)
- [Database Setup](#-database-setup)
- [Testing](#-testing)
- [API Testing](#-api-testing)
- [Debugging](#-debugging)
- [Development Workflow](#-development-workflow)
- [Troubleshooting](#-troubleshooting)

## ⚡ Quick Start

**Get up and running in 5 minutes!**

```bash
# Clone the repository
git clone <repository-url>
cd authService

# Quick start (installs dependencies, sets up environment, seeds data, runs tests)
npm run quick-start

# Start development server
npm run dev
```

**That's it!** 🎉 Your development environment is ready.

## 📋 Prerequisites

- **Node.js** 18.0.0 or higher
- **npm** 8.0.0 or higher
- **Git** for version control
- **Docker** (optional, for local database services)
- **VSCode** (recommended, with extensions)

### 🛠️ Recommended VSCode Extensions

Install these extensions for the best development experience:

```json
{
  "recommendations": [
    "esbenp.prettier-vscode",
    "dbaeumer.vscode-eslint",
    "Orta.vscode-jest",
    "PKief.material-icon-theme",
    "ms-vscode.vscode-docker"
  ]
}
```

## 🔧 Setup

### 1. Environment Setup

```bash
# Install dependencies
npm install

# Setup development environment
npm run dev:setup

# Seed development data
npm run dev:seed
```

### 2. Database Services

**Option A: Using Docker (Recommended)**

```bash
# Start all services
npm run docker:compose

# Or start individual services
docker-compose up mysql redis mongodb rabbitmq
```

**Option B: Local Installation**

- Install MySQL 8.0+
- Install Redis 6.0+
- Install MongoDB 5.0+
- Install RabbitMQ 3.8+

### 3. Configuration

The service uses structured configuration files instead of `.env` files:

- **Development**: `src/config/dev.js`
- **Production**: `src/config/production.js`
- **Test**: `src/config/test.js`

## 🎯 Development Commands

### 🚀 Core Commands

```bash
# Start development server with hot reload
npm run dev

# Start with debugging enabled
npm run dev:debug

# Start production server
npm start

# Start production with debugging
npm run start:debug

# Clean development (minimal logs)
npm run dev:quiet

# Silent development (only errors)
npm run dev:silent
```

### 🧪 Testing Commands

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage

# Run specific test suites
npm run test:unit
npm run test:integration
npm run test:e2e

# Run performance tests
npm run test:performance

# Run API tests
npm run test:api
```

### 🗄️ Database Commands

```bash
# Run migrations
npm run migrate

# Undo all migrations
npm run migrate:undo

# Check migration status
npm run migrate:status

# Seed development data
npm run dev:seed

# Reset database (undo + migrate + seed)
npm run db:reset

# Fresh database setup
npm run db:fresh
```

### 🛠️ Development Tools

```bash
# Monitor development environment
npm run dev:monitor

# Check service health
npm run dev:health

# Test API endpoints
npm run dev:api

# Monitor logs
npm run dev:logs

# Monitor only errors
npm run dev:errors

# Clear all caches
npm run cache:clear

# Reset development environment
npm run dev:reset
```

### 🔍 Code Quality

```bash
# Lint code
npm run lint

# Fix linting issues
npm run lint:fix

# Format code
npm run format

# Check code formatting
npm run format:check

# Type checking
npm run type-check
```

### 🐳 Docker Commands

```bash
# Build Docker image
npm run docker:build

# Run Docker container
npm run docker:run

# Start Docker Compose services
npm run docker:compose

# Stop Docker Compose services
npm run docker:compose:down
```

## 📁 Project Structure

```
authService/
├── src/                          # Source code
│   ├── config/                   # Configuration files
│   ├── controllers/              # Request handlers
│   ├── middlewares/              # Express middlewares
│   ├── models/                   # Database models
│   ├── routes/                   # API routes
│   ├── services/                 # Business logic
│   ├── utils/                    # Utility functions
│   ├── validators/               # Input validation
│   ├── app.js                    # Express app setup
│   └── index.js                  # Application entry point
├── tests/                        # Test files
│   ├── unit/                     # Unit tests
│   ├── integration/              # Integration tests
│   ├── e2e/                      # End-to-end tests
│   └── performance/              # Performance tests
├── scripts/                      # Development scripts
├── docs/                         # Documentation
├── postman/                      # API testing collections
├── migrations/                   # Database migrations
└── logs/                         # Application logs
```

## ⚙️ Configuration

### Development Configuration

The service uses a structured configuration approach:

```javascript
// src/config/dev.js
export const devConfig = {
  // Core settings
  port: 3001,
  nodeEnv: 'development',

  // Database settings
  mysql: {
    /* MySQL configuration */
  },
  mongodb: {
    /* MongoDB configuration */
  },
  redis: {
    /* Redis configuration */
  },

  // Security settings
  jwt: {
    /* JWT configuration */
  },
  security: {
    /* Security settings */
  },

  // Feature flags
  features: {
    /* Feature toggles */
  },
};
```

### Environment Variables (Development Optimized)

Key environment variables for clean development experience:

```bash
# Core Configuration
NODE_ENV=development
PORT=3001
HOST=localhost

# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_NAME=auth_service
DB_USER=root
DB_PASSWORD=your-password
DB_LOGGING=false

# Redis Configuration
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0
REDIS_MAX_RETRIES_PER_REQUEST=2
REDIS_MAX_RECONNECT_ATTEMPTS=2

# JWT & Security
JWT_SECRET=dev-jwt-secret-key-change-in-production
REFRESH_TOKEN_SECRET=dev-refresh-secret-key-change-in-production
JWT_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d

# Logging (Development Optimized)
LOG_LEVEL=warn
LOG_TO_CONSOLE=false
LOG_TO_FILE=true
LOG_FILE_ENABLED=true
LOG_FILE_MAX_SIZE=5m
LOG_FILE_MAX_FILES=7d
DB_LOGGING=false

# Feature Flags (Development)
FEATURE_AUDIT_LOGGING=false
FEATURE_METRICS=false
FEATURE_CACHE_LOGGING=false
FEATURE_GRPC_LOGGING=false
FEATURE_RABBITMQ_LOGGING=false
FEATURE_DATABASE_LOGGING=false
FEATURE_HTTP_LOGGING=false
```

## 🗄️ Database Setup

### MySQL Setup

```sql
-- Create database
CREATE DATABASE auth_service CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user (optional)
CREATE USER 'auth_user'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON auth_service.* TO 'auth_user'@'localhost';
FLUSH PRIVILEGES;
```

### Redis Setup

```bash
# Start Redis server
redis-server

# Test connection
redis-cli ping
```

### MongoDB Setup

```bash
# Start MongoDB
mongod

# Create database
mongo
use auth_service
```

## 🧪 Testing

### Running Tests

```bash
# Run all tests
npm test

# Run specific test file
npm run test:single -- tests/unit/auth.test.js

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

### Test Structure

- **Unit Tests**: Test individual functions and modules
- **Integration Tests**: Test API endpoints and database operations
- **E2E Tests**: Test complete user workflows
- **Performance Tests**: Load testing with K6

### Writing Tests

```javascript
// Example test
describe('Auth Service', () => {
  it('should register a new user', async () => {
    const userData = {
      email: 'test@example.com',
      password: 'password123',
      fullName: 'Test User',
    };

    const result = await authService.registerUser(userData);
    expect(result).toBeDefined();
    expect(result.email).toBe(userData.email);
  });
});
```

## 🔌 API Testing

### Using Postman

```bash
# Run API tests
npm run test:api

# Run specific collection
newman run postman/collections/auth-service.postman_collection.json
```

### Using cURL

```bash
# Health check
curl http://localhost:3001/health

# User registration
curl -X POST http://localhost:3001/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123",
    "fullName": "Test User"
  }'
```

### Test Accounts

Pre-configured test accounts for development:

| Role                    | Email                                | Password        |
| ----------------------- | ------------------------------------ | --------------- |
| Admin                   | admin@bizpickr.com                   | Admin@123       |
| Requirement Coordinator | requirement_coordinator@bizpickr.com | Requirement@123 |
| Salesman                | salesman@bizpickr.com                | Sales@123       |
| Caller                  | caller@bizpickr.com                  | Caller@123      |
| Vendor                  | vendor@bizpickr.com                  | Vendor@123      |
| Customer                | customer@bizpickr.com                | Customer@123    |
| Support                 | support@bizpickr.com                 | Support@123     |

## 🐛 Debugging

### Debug Mode

```bash
# Start with debugging enabled
npm run dev:debug

# Attach debugger in VSCode
# Press F5 or use the debug panel
```

### Logging

```bash
# Monitor application logs
npm run dev:logs

# Monitor only errors
npm run dev:errors

# View specific log files
tail -f logs/combined-*.log
tail -f logs/error-*.log
```

### Health Checks

```bash
# Check service health
npm run dev:health

# Check database connections
curl http://localhost:3001/health
```

### Common Issues

1. **Port already in use**: Change port in config or kill existing process
2. **Database connection failed**: Check if database services are running
3. **Migration errors**: Run `npm run db:reset` to reset database
4. **Redis connection failed**: Start Redis server or use Docker
5. **Too many logs**: Use `npm run dev:quiet` or `npm run dev:silent`
6. **Console too verbose**: Set `LOG_TO_CONSOLE=false` in your `.env`
7. **Environment issues**: Run `npm run dev:reset` to reset environment
8. **Health check failed**: Run `npm run dev:health` to diagnose issues

## 🔄 Development Workflow

### 1. Feature Development

```bash
# Create feature branch
git checkout -b feature/new-feature

# Make changes and test
npm run test:watch

# Commit changes
git add .
git commit -m "feat: add new feature"

# Push and create PR
git push origin feature/new-feature
```

### 2. Code Quality

```bash
# Before committing
npm run lint
npm run format
npm test

# Or use pre-commit hooks (automatic)
git commit -m "feat: new feature"
```

### 3. Testing Strategy

1. **Unit Tests**: Write for all new functions
2. **Integration Tests**: Test API endpoints
3. **E2E Tests**: Test complete workflows
4. **Performance Tests**: For critical paths

## 🚨 Troubleshooting

### Common Problems

| Problem                    | Solution                                        |
| -------------------------- | ----------------------------------------------- |
| Port 3001 in use           | Change port in config or kill process           |
| Database connection failed | Check if services are running                   |
| Migration errors           | Run `npm run db:reset`                          |
| Redis connection failed    | Start Redis or use Docker                       |
| Tests failing              | Check database state and run `npm run db:fresh` |

### Getting Help

1. **Check logs**: `npm run dev:logs` - View all application logs
2. **Check errors only**: `npm run dev:errors` - View only error logs
3. **Monitor environment**: `npm run dev:monitor` - Monitor system resources
4. **Check health**: `npm run dev:health` - Check service health status
5. **Reset environment**: `npm run dev:reset` - Reset development environment
6. **Clean console**: Use `npm run dev:quiet` or `npm run dev:silent` for minimal output

### Performance Issues

```bash
# Monitor performance
npm run dev:monitor

# Run performance tests
npm run test:performance

# Check memory usage
npm run dev:health
```

## 🎉 Happy Coding!

Your development environment is now fully configured and ready for productive development!

**Quick Reference:**

- 🚀 Start: `npm run dev`
- 🔇 Quiet: `npm run dev:quiet`
- 🤫 Silent: `npm run dev:silent`
- 🧪 Test: `npm test`
- 🔍 Debug: `npm run dev:debug`
- 📊 Monitor: `npm run dev:monitor`
- 📝 Logs: `npm run dev:logs`
- ❌ Errors: `npm run dev:errors`
- 🗄️ Reset: `npm run db:reset`

**Development Modes:**

- **Normal**: `npm run dev` - All logs with full debugging information
- **Quiet**: `npm run dev:quiet` - Minimal logs, only warnings and errors
- **Silent**: `npm run dev:silent` - Minimal output, only errors

**Need help?** Check the logs, run health checks, or reset the environment!
