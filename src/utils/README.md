# Utils - Authentication Service Utilities

This directory contains essential utility functions and classes used throughout the authentication service.

## 📁 File Structure

```
utils/
├── ApiError.js           # Custom error class for API responses
├── ApiResponse.js        # Standardized API response class
├── asyncHandler.js       # Async error handling for Express routes
├── validationUtils.js    # Input validation utilities
├── sharedUtils.js        # Common utility functions
├── circuitBreakers.js    # Circuit breaker pattern for internal services
├── index.js             # Central export file
└── README.md            # This file
```

## 🚀 Quick Start

```javascript
// Import all utilities
import {
  ApiError,
  ApiResponse,
  asyncHandler,
  validateEmail,
  createErrorResponse,
  createCircuitBreakers,
} from '../utils/index.js';

// Or import specific modules
import { ApiError } from '../utils/ApiError.js';
import { validationUtils } from '../utils/validationUtils.js';
```

## 📋 Core Classes

### ApiError

Custom error class for consistent API error responses.

```javascript
// Create API errors
const error = new ApiError(400, 'Bad Request', ['Invalid email format']);
const notFound = new ApiError(404, 'User not found');

// Use in Express error handling
app.use((error, req, res, next) => {
  if (error instanceof ApiError) {
    res.status(error.statusCode).json(error.toJSON());
  }
});
```

### ApiResponse

Standardized response class for consistent API responses.

```javascript
// Success responses
const response = ApiResponse.success(userData, 'User created successfully');
const created = ApiResponse.created(newUser);

// Error responses
const badRequest = ApiResponse.badRequest(null, 'Validation failed', errors);

// Add metadata
response.addMetadata({ version: '1.0' });
response.addPagination(1, 10, 100, 10);
```

## 🔄 Async Handlers

### asyncHandler

Wrapper for async route handlers with automatic error handling.

```javascript
// Route handler
app.get(
  '/users/:id',
  asyncHandler(async (req, res) => {
    const user = await userService.findById(req.params.id);
    if (!user) {
      throw new ApiError(404, 'User not found');
    }
    res.json(ApiResponse.success(user));
  })
);

// Middleware wrapper
app.use(
  asyncMiddleware(async (req, res, next) => {
    // Async middleware logic
  })
);
```

## ✅ Validation Utilities

### Input Validation

```javascript
// Email validation
const emailResult = validateEmail('user@example.com');
if (!emailResult.isValid) {
  console.log(emailResult.errors);
}

// Password validation
const passwordResult = validatePassword('MyPassword123');
if (!passwordResult.isValid) {
  console.log(passwordResult.errors);
}

// Required fields
const requiredResult = validateRequired(userData, ['email', 'password']);
if (!requiredResult.isValid) {
  console.log(requiredResult.errors);
}

// Other validations
validateUsername('john_doe');
validatePhoneNumber('+1234567890');
validateObjectId('507f1f77bcf86cd799439011');
validateUUID('123e4567-e89b-12d3-a456-426614174000');
```

### Input Sanitization

```javascript
// Sanitize strings
const clean = sanitizeInput('<script>alert("xss")</script>');

// Sanitize objects
const cleanUser = sanitizeObject(userData);
```

## 🛠️ Shared Utilities

### Response Helpers

```javascript
// Error responses
const errorResponse = createErrorResponse(400, 'Bad Request', [
  'Invalid input',
]);

// Success responses
const successResponse = createSuccessResponse(data, 'Operation successful');
```

### Logging Helpers

```javascript
// Structured logging
logInfo('User logged in', { userId: 123, timestamp: new Date() });
logError('Database connection failed', error, { service: 'auth' });
logWarn('Rate limit exceeded', { ip: req.ip });
logDebug('Processing request', { method: req.method, url: req.url });
```

### Common Utilities

```javascript
// String utilities
const slug = slugify('Hello World!'); // 'hello-world'
const truncated = truncateString('Long text...', 10); // 'Long text...'

// Array utilities
const chunks = chunkArray([1, 2, 3, 4, 5, 6], 2); // [[1,2], [3,4], [5,6]]
const unique = uniqueArray([1, 2, 2, 3, 3, 4]); // [1,2,3,4]

// Number utilities
const clamped = clamp(150, 0, 100); // 100
const inRange = isInRange(50, 0, 100); // true

// Date utilities
const formatted = formatDate(new Date());
const isValid = isValidDate('2023-12-25'); // true

// Random generation
const randomString = generateRandomString(16);
const randomNumber = generateRandomNumber(1000, 9999);
```

## ⚡ Circuit Breakers

### Service Protection

Circuit breakers protect the auth service from cascading failures when calling internal gRPC services.

```javascript
// Create circuit breakers
const circuitBreakers = createCircuitBreakers();

// Use in service calls
try {
  const result = await circuitBreakers.userService.execute(
    async () => await userServiceClient.getUser(userId)
  );
} catch (error) {
  // Handle circuit breaker errors
}

// Monitor health
const health = getCircuitBreakerHealth(circuitBreakers);
const stats = getCircuitBreakerStats(circuitBreakers);

// Reset if needed
resetAllCircuitBreakers(circuitBreakers);
```

### Configuration

Circuit breakers are configured with:

- **Timeout**: Maximum time to wait for service response
- **Error Threshold**: Percentage of errors before opening
- **Reset Timeout**: Time to wait before retrying
- **Volume Threshold**: Minimum calls before opening

## 🔧 Configuration

### Environment Variables

```bash
# Development mode (shows stack traces)
NODE_ENV=development

# Production mode (hides sensitive information)
NODE_ENV=production
```

### Logger Configuration

All utilities use the centralized logger from `../config/logger.js`.

## 📊 Best Practices

### 1. Error Handling

- Always use `ApiError` for application errors
- Use `asyncHandler` for route handlers
- Log errors with context information

### 2. Validation

- Validate all user inputs
- Sanitize data before processing
- Use appropriate validation functions

### 3. Responses

- Use `ApiResponse` for consistent formatting
- Include appropriate status codes
- Add metadata when useful

### 4. Circuit Breakers

- Configure appropriate timeouts
- Monitor circuit breaker health
- Implement fallback strategies

## 🚨 Error Codes

Common HTTP status codes used:

- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `422` - Unprocessable Entity
- `500` - Internal Server Error
- `503` - Service Unavailable

## 🔍 Debugging

### Development Mode

In development mode, utilities provide additional information:

- Full stack traces in errors
- Detailed logging
- Extended error details

### Production Mode

In production mode, utilities hide sensitive information:

- No stack traces in responses
- Minimal error details
- Secure logging

## 📚 Examples

### Complete Route Example

```javascript
import {
  asyncHandler,
  ApiResponse,
  ApiError,
  validateEmail,
} from '../utils/index.js';

app.post(
  '/register',
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // Validate input
    const emailValidation = validateEmail(email);
    if (!emailValidation.isValid) {
      throw new ApiError(400, 'Invalid email', emailValidation.errors);
    }

    // Process registration
    const user = await authService.register({ email, password });

    // Return success response
    res
      .status(201)
      .json(ApiResponse.created(user, 'User registered successfully'));
  })
);
```

### Service Call with Circuit Breaker

```javascript
import { createCircuitBreakers } from '../utils/circuitBreakers.js';

const circuitBreakers = createCircuitBreakers();

const getUserProfile = async userId => {
  try {
    return await circuitBreakers.userService.execute(
      async () => await userServiceClient.getProfile(userId)
    );
  } catch (error) {
    // Handle circuit breaker or service errors
    throw new ApiError(503, 'User service unavailable');
  }
};
```

## 🤝 Contributing

When adding new utilities:

1. Follow the existing naming conventions
2. Add comprehensive JSDoc comments
3. Include error handling
4. Add to the index.js exports
5. Update this README
6. Write tests for new functionality

## 📝 License

This utilities module is part of the authentication service and follows the same licensing terms.
