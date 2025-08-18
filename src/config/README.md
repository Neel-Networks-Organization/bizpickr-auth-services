# Configuration Management

This directory contains centralized configuration management for the Auth Service, following industry best practices to eliminate repetition and improve maintainability.

## Configuration Files

### 1. `env.js` - Main Environment Configuration

- **Purpose**: Central environment variable management and validation
- **Features**:
  - Environment validation and type checking
  - Security configuration
  - Application settings
  - Feature flags
  - Monitoring and logging configuration
  - Compliance settings

### 2. `database.js` - Database Configuration

- **Purpose**: Centralized MySQL database configuration
- **Features**:
  - Connection pooling optimization
  - SSL configuration
  - Performance settings
  - Retry mechanisms
  - Validation and error handling

### 3. `redis.js` - Redis Configuration

- **Purpose**: Centralized Redis configuration
- **Features**:
  - Connection management
  - Cluster and Sentinel support
  - Performance optimization
  - Health monitoring
  - Retry strategies

## Best Practices Implemented

### 1. **Separation of Concerns**

- Each configuration type has its own dedicated file
- Clear boundaries between different configuration domains
- Easy to maintain and extend

### 2. **Environment-Based Configuration**

- All configurations support environment variables
- Sensible defaults for development
- Production-ready security settings

### 3. **Validation and Type Checking**

- Comprehensive validation for all configuration values
- Type checking with fallback defaults
- Early error detection during startup

### 4. **Performance Optimization**

- Connection pooling for databases
- Retry mechanisms with exponential backoff
- Health monitoring and metrics

### 5. **Security**

- SSL/TLS configuration for production
- Secure defaults
- Environment-specific security settings

## Usage Examples

### Database Configuration

```javascript
import { databaseConfig, validateDatabaseConfig } from './config/database.js';

// Validate configuration
validateDatabaseConfig();

// Use configuration
const { mysql } = databaseConfig;
console.log(`Connecting to ${mysql.host}:${mysql.port}/${mysql.database}`);
```

### Redis Configuration

```javascript
import { redisConfig, validateRedisConfig } from './config/redis.js';

// Validate configuration
validateRedisConfig();

// Use configuration
console.log(`Connecting to Redis at ${redisConfig.host}:${redisConfig.port}`);
```

### Environment Configuration

```javascript
import { env } from './config/env.js';

// Access any configuration
console.log(`Server running on port ${env.PORT}`);
console.log(`Environment: ${env.NODE_ENV}`);
```

## Environment Variables

### Required Variables

- `NODE_ENV` - Environment (development/production)
- `PORT` - Server port
- `JWT_SECRET` - JWT signing secret
- `REFRESH_TOKEN_SECRET` - Refresh token secret
- `DB_HOST` - Database host
- `DB_NAME` - Database name
- `DB_USER` - Database username
- `DB_PASSWORD` - Database password
- `REDIS_HOST` - Redis host
- `REDIS_PORT` - Redis port

### Optional Variables

- `DB_PORT` - Database port (default: 3306)
- `DB_POOL_MAX` - Database pool max connections (default: 20)
- `DB_POOL_MIN` - Database pool min connections (default: 5)
- `REDIS_PASSWORD` - Redis password
- `REDIS_DB` - Redis database number (default: 0)
- `REDIS_TLS` - Enable TLS for Redis (default: false)

## Configuration Validation

All configuration files include validation functions that:

1. Check for required environment variables
2. Validate data types and ranges
3. Ensure logical consistency
4. Provide meaningful error messages

## Benefits of This Structure

1. **No Repetition**: Configuration is defined once and reused
2. **Type Safety**: All values are validated and typed
3. **Maintainability**: Easy to modify and extend
4. **Performance**: Optimized settings for production
5. **Security**: Secure defaults and validation
6. **Monitoring**: Built-in health checks and metrics
7. **Scalability**: Support for clustering and high availability

## Migration Guide

If you're updating from the old configuration structure:

1. **Database**: Use `databaseConfig.mysql` instead of `env.mysql`
2. **Redis**: Use `redisConfig` instead of `env.redis`
3. **Validation**: Call validation functions during initialization
4. **Imports**: Update import statements to use new configuration files

## Future Enhancements

- Configuration hot-reloading
- Configuration encryption for sensitive values
- Configuration versioning
- Configuration templates for different environments
- Configuration validation schemas
