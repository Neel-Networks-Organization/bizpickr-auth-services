# Auth Service Test Suite

## Overview

This test suite provides comprehensive testing for the Auth Service microservice, following industry best practices and ensuring high code coverage, security, and performance standards.

## Test Structure

```
tests/
├── README.md                    # This documentation
├── setup.js                     # Global test setup and mocks
├── utils/
│   └── testUtils.js            # Common test utilities and helpers
├── unit/                        # Unit tests for individual components
│   ├── controllers/            # Controller logic tests
│   ├── services/               # Business logic tests
│   ├── models/                 # Database model tests
│   ├── middlewares/            # Middleware tests
│   ├── utils/                  # Utility function tests
│   └── validators/             # Input validation tests
├── integration/                # Integration tests
│   ├── api/                    # API endpoint tests
│   ├── database/               # Database integration tests
│   ├── grpc/                   # gRPC service tests
│   └── redis/                  # Redis integration tests
├── e2e/                        # End-to-end tests
├── performance/                # Performance and load tests
└── simple.test.js              # Basic sanity tests
```

## Test Categories

### 1. Unit Tests (`tests/unit/`)

**Purpose**: Test individual functions and components in isolation.

**Coverage**:

- Controller functions
- Service layer business logic
- Database models
- Middleware functions
- Utility functions
- Input validation

**Best Practices**:

- Mock all external dependencies
- Test both success and error scenarios
- Verify function calls and return values
- Test edge cases and boundary conditions
- Ensure 100% function coverage

**Example Structure**:

```javascript
describe('Component Name', () => {
  describe('Function Name', () => {
    describe('Success Scenarios', () => {
      it('should handle normal case', async () => {
        // Arrange
        // Act
        // Assert
      });
    });

    describe('Error Scenarios', () => {
      it('should handle error case', async () => {
        // Arrange
        // Act
        // Assert
      });
    });

    describe('Edge Cases', () => {
      it('should handle edge case', async () => {
        // Arrange
        // Act
        // Assert
      });
    });
  });
});
```

### 2. Integration Tests (`tests/integration/`)

**Purpose**: Test how components work together and interact with external services.

**Coverage**:

- API endpoints with real HTTP requests
- Database operations with test database
- gRPC service communication
- Redis cache operations
- External service integrations

**Best Practices**:

- Use test database (separate from development/production)
- Mock external services when appropriate
- Test complete user workflows
- Verify data persistence and consistency
- Test error handling across service boundaries

### 3. End-to-End Tests (`tests/e2e/`)

**Purpose**: Test complete user journeys from start to finish.

**Coverage**:

- Complete authentication flows
- User registration to login to logout
- Token refresh scenarios
- Error recovery flows

**Best Practices**:

- Use real browser automation (Playwright)
- Test user interactions
- Verify UI state changes
- Test accessibility and usability

### 4. Performance Tests (`tests/performance/`)

**Purpose**: Ensure the service meets performance requirements.

**Coverage**:

- Response time benchmarks
- Throughput under load
- Memory usage patterns
- Database query performance
- Rate limiting effectiveness

## Test Utilities

### Common Test Data (`testUtils.js`)

```javascript
import {
  TEST_DATA,
  createMockRequest,
  createMockResponse,
} from '../utils/testUtils.js';

// Use predefined test data
const userData = TEST_DATA.users.customer;

// Create mock objects
const req = createMockRequest({ body: userData });
const res = createMockResponse();
```

### Validation Helpers

```javascript
import { validateApiResponse, validateApiError } from '../utils/testUtils.js';

// Validate successful API responses
validateApiResponse(res, 201);

// Validate error responses
validateApiError(next, {
  statusCode: 400,
  message: 'Validation error',
});
```

### Performance Testing

```javascript
import { measurePerformance } from '../utils/testUtils.js';

const result = await measurePerformance(async () => {
  // Test function
}, 1000);

console.log(`Average time: ${result.averageTime}ms`);
```

## Running Tests

### Individual Test Execution

You can run individual test files or specific test categories for faster development:

```bash
# Run a specific test file
npm run test:single "tests/unit/utils/ApiError.test.js"

# Run all utility tests
npm run test:utils

# Run all controller tests
npm run test:controllers

# Run tests matching a pattern
npm run test:single "ApiError"
npm run test:single "auth.controller"
```

**Benefits of Individual Testing:**

- Faster feedback during development
- Focus on specific functionality
- Easier debugging
- Reduced test execution time
- Better development workflow

### Prerequisites

1. **Database Setup**: Ensure test database is configured
2. **Environment Variables**: Set `NODE_ENV=test`
3. **Dependencies**: Install all test dependencies

### Test Commands

```bash
# Run all tests
npm test

# Run specific test categories
npm run test:unit          # Unit tests only
npm run test:integration   # Integration tests only
npm run test:e2e          # End-to-end tests only

# Run specific unit test categories
npm run test:utils         # Utility tests only
npm run test:controllers   # Controller tests only
npm run test:services      # Service tests only
npm run test:models        # Model tests only
npm run test:middlewares   # Middleware tests only
npm run test:validators    # Validator tests only

# Run individual test file
npm run test:single "tests/unit/utils/ApiError.test.js"
npm run test:single "tests/unit/controllers/auth.controller.test.js"

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch

# Run performance tests
npm run test:performance
```

### Test Configuration

The test configuration is in `jest.config.js`:

```javascript
export default {
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.js'],
  setupFilesAfterEnv: ['<rootDir>/tests/setup.js'],
  testMatch: ['<rootDir>/tests/**/*.test.js', '<rootDir>/tests/**/*.spec.js'],
  collectCoverageFrom: [
    'src/**/*.js',
    '!src/index.js',
    '!src/config/**',
    '!**/node_modules/**',
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  testTimeout: 10000,
  verbose: true,
};
```

## Test Coverage Requirements

- **Overall Coverage**: Minimum 80%
- **Unit Tests**: 90%+ function coverage
- **Integration Tests**: All critical paths covered
- **Error Handling**: All error scenarios tested
- **Security**: All security measures verified

## Best Practices

### 1. Test Organization

- Group related tests using `describe` blocks
- Use descriptive test names that explain the scenario
- Follow AAA pattern (Arrange, Act, Assert)
- Keep tests independent and isolated

### 2. Mocking Strategy

- Mock external dependencies (databases, APIs, services)
- Use realistic mock data
- Verify mock interactions
- Reset mocks between tests

### 3. Test Data Management

- Use factory functions for test data
- Avoid hardcoded values
- Clean up test data after tests
- Use unique identifiers to prevent conflicts

### 4. Error Testing

- Test all error scenarios
- Verify error messages and status codes
- Test edge cases and boundary conditions
- Ensure proper error handling

### 5. Security Testing

- Test authentication and authorization
- Verify input validation
- Test for common vulnerabilities
- Check security headers

### 6. Performance Testing

- Set performance benchmarks
- Test under load
- Monitor resource usage
- Identify bottlenecks

## Common Patterns

### Database Testing

```javascript
beforeEach(async () => {
  await sequelize.sync({ force: true });
});

afterEach(async () => {
  await AuthUser.destroy({ where: {} });
});
```

### API Testing

```javascript
const response = await request(app)
  .post('/api/v1/auth/register')
  .send(userData)
  .expect(201);

expect(response.body).toMatchObject({
  statusCode: 201,
  success: true,
  data: expect.any(Object),
});
```

### Mock Verification

```javascript
expect(AuthUser.create).toHaveBeenCalledWith(
  expect.objectContaining({
    email: userData.email,
    fullName: userData.fullName,
  })
);
```

## Troubleshooting

### Common Issues

1. **ES6 Module Issues**: Ensure Jest is configured for ES modules
2. **Database Connection**: Check test database configuration
3. **Mock Issues**: Verify mock setup and cleanup
4. **Timeout Issues**: Increase test timeout for slow operations

### Debug Mode

```bash
# Run tests with debug output
DEBUG=* npm test

# Run specific test with debug
DEBUG=* npm test -- --testNamePattern="specific test name"
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
        with:
          node-version: '18'
      - run: npm ci
      - run: npm run test:coverage
      - run: npm run test:performance
```

## Contributing

When adding new tests:

1. Follow the existing test structure
2. Use the provided test utilities
3. Ensure adequate coverage
4. Update this documentation if needed
5. Run all tests before submitting

## Resources

- [Jest Documentation](https://jestjs.io/docs/getting-started)
- [Supertest Documentation](https://github.com/visionmedia/supertest)
- [Testing Best Practices](https://github.com/goldbergyoni/javascript-testing-best-practices)
- [API Testing Guide](https://www.postman.com/collections/api-testing)
