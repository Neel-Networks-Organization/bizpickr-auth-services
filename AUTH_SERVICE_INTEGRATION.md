# AuthService Integration Documentation

## Overview

This document explains the integration of the authService with notification and email services using RabbitMQ events.

## Key Changes Made

### 1. Event-Driven Architecture

- **Before**: Direct service calls for notifications and emails
- **After**: Event-driven communication using RabbitMQ
- **Benefit**: Loose coupling, better scalability, fault tolerance

### 2. User Creation Flow (Updated)

- **Signup**: Only creates basic auth user, sends welcome email and verification email
- **First Login**: Triggers `user.created` event to create user profile and related data
- **Subsequent Logins**: Normal login flow without profile creation

### 3. Service Responsibilities

#### AuthService (Authentication Only)

- User registration (basic auth data)
- User login/logout
- Token management
- Session management
- Password operations
- Email verification
- Two-factor authentication
- OAuth integration

#### UserService (Profile Management)

- User profile creation (triggered on first login)
- Profile updates
- User preferences
- User workspace/account setup

#### NotificationService

- Welcome notifications (on first login)
- Notification preferences setup
- Notification channels creation

#### EmailService

- Welcome emails (on first login)
- Email verification
- Password reset emails
- Email preferences setup

## Event Flow

### User Registration Flow

```
1. User signs up
   ↓
2. AuthService creates basic user in auth database
   ↓
3. Publishes events:
   - welcome.email (welcome email)
   - email.verification (verification email)
   ↓
4. EmailService processes email events
```

### User Login Flow

```
1. User logs in
   ↓
2. AuthService authenticates user
   ↓
3. If first login (no previous sessions):
   - Publishes user.created event
   ↓
4. UserService creates user profile
5. NotificationService sets up notifications
6. EmailService sends welcome email
```

### Password Reset Flow

```
1. User requests password reset
   ↓
2. AuthService generates reset token
   ↓
3. Publishes password.reset event
   ↓
4. EmailService sends reset email
```

## Integration Points

### RabbitMQ Configuration

- **Exchange**: `auth_exchange` (direct)
- **Queues**:
  - `user_created_queue` (handles user profile creation on first login)
  - `welcome_email_queue` (handles welcome emails)
  - `email_verification_queue` (handles verification emails)
  - `password_reset_queue` (handles reset emails)

### Message Types

- `user.created` - Triggered on first login
- `welcome.email` - Welcome email notification
- `email.verification` - Email verification
- `password.reset` - Password reset
- `user.verified` - Email verification completed
- `account.activation` - Account activation

## Configuration

### Environment Variables

```env
# RabbitMQ
RABBITMQ_URL=amqp://localhost:5672
RABBITMQ_USERNAME=guest
RABBITMQ_PASSWORD=guest

# Frontend URLs
FRONTEND_URL=http://localhost:3000

# Service URLs (for actual integration)
USER_SERVICE_URL=http://localhost:3001
NOTIFICATION_SERVICE_URL=http://localhost:3002
EMAIL_SERVICE_URL=http://localhost:3003
```

## Testing

### Test User Registration

```bash
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123",
    "fullName": "Test User",
    "phone": "+1234567890"
  }'
```

### Test User Login (First Time)

```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'
```

### Test Password Reset

```bash
curl -X POST http://localhost:3000/api/v1/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com"
  }'
```

## Monitoring

### Consumer Metrics

```javascript
// Get user created consumer metrics
const metrics = getUserCreatedConsumerMetrics();
console.log(metrics);
```

### Health Check

```javascript
// Check consumer health
const health = await checkConsumerHealth();
console.log(health);
```

## Next Steps

### 1. Replace Simulation Functions

Replace the simulation functions in `userCreatedConsumer.js` with actual API calls:

```javascript
// Replace this:
await simulateUserServiceIntegration(userId, email, fullName, type, role);

// With this:
await fetch(`${USER_SERVICE_URL}/api/v1/users`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ userId, email, fullName, type, role }),
});
```

### 2. Configure Service URLs

Set up environment variables for actual service endpoints.

### 3. Test Integration

Use the provided curl commands to test the complete flow.

### 4. Monitor Events

Use the metrics and health check functions to monitor event processing.

## Benefits

1. **Separation of Concerns**: AuthService focuses only on authentication
2. **Scalability**: Services can scale independently
3. **Fault Tolerance**: Failed events can be retried
4. **Loose Coupling**: Services communicate via events
5. **Better User Experience**: Profile creation happens on first login, not signup
