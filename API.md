# 📚 AuthService API Documentation

## Overview

This document provides comprehensive API documentation for the AuthService microservice, including all endpoints, request/response formats, authentication, and usage examples.

## 🔗 Base URL

```
Development: http://localhost:3001
Staging: https://auth-staging.yourdomain.com
Production: https://auth.yourdomain.com
```

## 🔐 Authentication

### JWT Authentication

The AuthService uses JWT (JSON Web Tokens) for authentication. Include the token in the Authorization header:

```
Authorization: Bearer <access_token>
```

### Token Types

- **Access Token**: Short-lived (15 minutes), used for API requests
- **Refresh Token**: Long-lived (7 days), used to obtain new access tokens

## 📋 API Endpoints

### Authentication Endpoints

#### **1. User Registration**

**POST** `/api/v1/auth/signup`

Register a new user account.

**Request Body:**

```json
{
  "fullName": "John Doe",
  "email": "john.doe@example.com",
  "password": "StrongP@ssw0rd!",
  "confirmPassword": "StrongP@ssw0rd!",
  "type": "customer",
  "role": "customer",
  "phone": "+1234567890",
  "termsAccepted": true,
  "privacyAccepted": true,
  "marketingConsent": false
}
```

**Response (201 Created):**

```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": {
      "id": "b2c1739b-011f-4e61-9120-c79c8eecbbab",
      "email": "john.doe@example.com",
      "fullName": "John Doe",
      "type": "customer",
      "role": "customer",
      "emailVerified": false,
      "twoFactorEnabled": false,
      "createdAt": "2024-01-01T00:00:00.000Z"
    },
    "session": {
      "id": "session-uuid",
      "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expiresAt": "2024-01-01T00:15:00.000Z"
    }
  }
}
```

**Error Responses:**

```json
// 400 Bad Request - Validation Error
{
  "success": false,
  "error": "Validation failed",
  "details": {
    "email": "Email is required",
    "password": "Password must be at least 8 characters"
  }
}

// 409 Conflict - Email Already Exists
{
  "success": false,
  "error": "Email already registered"
}
```

#### **2. User Login**

**POST** `/api/v1/auth/login`

Authenticate user and create session.

**Request Body:**

```json
{
  "email": "john.doe@example.com",
  "password": "StrongP@ssw0rd!"
}
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "id": "b2c1739b-011f-4e61-9120-c79c8eecbbab",
      "email": "john.doe@example.com",
      "fullName": "John Doe",
      "type": "customer",
      "role": "customer",
      "emailVerified": true,
      "twoFactorEnabled": false,
      "lastLoginAt": "2024-01-01T00:00:00.000Z"
    },
    "session": {
      "id": "session-uuid",
      "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expiresAt": "2024-01-01T00:15:00.000Z"
    }
  }
}
```

**Error Responses:**

```json
// 401 Unauthorized - Invalid Credentials
{
  "success": false,
  "error": "Invalid email or password"
}

// 423 Locked - Account Locked
{
  "success": false,
  "error": "Account temporarily locked",
  "data": {
    "lockedUntil": "2024-01-01T00:30:00.000Z"
  }
}
```

#### **3. User Logout**

**POST** `/api/v1/auth/logout`

Logout user and invalidate session.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Logout successful"
}
```

#### **4. Refresh Access Token**

**POST** `/api/v1/auth/refresh-token`

Get new access token using refresh token.

**Request Body:**

```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresAt": "2024-01-01T00:15:00.000Z"
  }
}
```

#### **5. Verify Token**

**POST** `/api/v1/auth/verify-token`

Verify JWT token validity.

**Request Body:**

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Token is valid",
  "data": {
    "valid": true,
    "user": {
      "id": "b2c1739b-011f-4e61-9120-c79c8eecbbab",
      "email": "john.doe@example.com",
      "role": "customer"
    }
  }
}
```

### OAuth Endpoints

#### **6. Google OAuth Login**

**GET** `/api/v1/auth/google`

Initiate Google OAuth login flow.

**Response (302 Redirect):**

```
Redirects to: https://accounts.google.com/oauth/authorize?...
```

#### **7. Google OAuth Callback**

**GET** `/api/v1/auth/google/callback`

Handle Google OAuth callback.

**Query Parameters:**

```
?code=<authorization_code>&state=<state_parameter>
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "OAuth login successful",
  "data": {
    "user": {
      "id": "b2c1739b-011f-4e61-9120-c79c8eecbbab",
      "email": "john.doe@gmail.com",
      "fullName": "John Doe",
      "provider": "google",
      "providerId": "google-user-id"
    },
    "session": {
      "id": "session-uuid",
      "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expiresAt": "2024-01-01T00:15:00.000Z"
    }
  }
}
```

### Email Verification Endpoints

#### **8. Verify Email**

**POST** `/api/v1/auth/verify-email`

Verify email address using verification token.

**Request Body:**

```json
{
  "token": "verification-token-from-email"
}
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Email verified successfully",
  "data": {
    "user": {
      "id": "b2c1739b-011f-4e61-9120-c79c8eecbbab",
      "email": "john.doe@example.com",
      "emailVerified": true,
      "emailVerifiedAt": "2024-01-01T00:00:00.000Z"
    }
  }
}
```

#### **9. Resend Verification Email**

**POST** `/api/v1/auth/resend-verification`

Resend email verification link.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Verification email sent successfully"
}
```

### Two-Factor Authentication Endpoints

#### **10. Enable 2FA**

**POST** `/api/v1/auth/2fa/enable`

Enable two-factor authentication for user.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "2FA enabled successfully",
  "data": {
    "qrCode": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
    "secret": "JBSWY3DPEHPK3PXP",
    "backupCodes": ["ABCD1234", "EFGH5678", "IJKL9012"]
  }
}
```

#### **11. Disable 2FA**

**POST** `/api/v1/auth/2fa/disable`

Disable two-factor authentication.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Request Body:**

```json
{
  "code": "123456"
}
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "2FA disabled successfully"
}
```

#### **12. Verify 2FA Code**

**POST** `/api/v1/auth/2fa/verify`

Verify 2FA code during login.

**Request Body:**

```json
{
  "code": "123456",
  "sessionId": "session-uuid"
}
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "2FA verification successful",
  "data": {
    "session": {
      "id": "session-uuid",
      "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expiresAt": "2024-01-01T00:15:00.000Z"
    }
  }
}
```

### User Management Endpoints

#### **13. Get Current User**

**GET** `/api/v1/users/profile`

Get current user profile information.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```json
{
  "success": true,
  "data": {
    "user": {
      "id": "b2c1739b-011f-4e61-9120-c79c8eecbbab",
      "email": "john.doe@example.com",
      "fullName": "John Doe",
      "phone": "+1234567890",
      "type": "customer",
      "role": "customer",
      "emailVerified": true,
      "twoFactorEnabled": false,
      "lastLoginAt": "2024-01-01T00:00:00.000Z",
      "createdAt": "2024-01-01T00:00:00.000Z",
      "updatedAt": "2024-01-01T00:00:00.000Z"
    }
  }
}
```

#### **14. Update User Profile**

**PUT** `/api/v1/users/profile`

Update user profile information.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Request Body:**

```json
{
  "fullName": "John Smith",
  "phone": "+1987654321"
}
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Profile updated successfully",
  "data": {
    "user": {
      "id": "b2c1739b-011f-4e61-9120-c79c8eecbbab",
      "fullName": "John Smith",
      "phone": "+1987654321",
      "updatedAt": "2024-01-01T00:00:00.000Z"
    }
  }
}
```

#### **15. Get User Activity**

**GET** `/api/v1/users/activity`

Get user activity log.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Query Parameters:**

```
?page=1&limit=10&type=login&startDate=2024-01-01&endDate=2024-01-31
```

**Response (200 OK):**

```json
{
  "success": true,
  "data": {
    "activities": [
      {
        "id": "activity-uuid",
        "action": "USER_LOGIN",
        "details": {
          "ipAddress": "192.168.1.1",
          "userAgent": "Mozilla/5.0...",
          "location": "New York, US"
        },
        "timestamp": "2024-01-01T00:00:00.000Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 10,
      "total": 50,
      "pages": 5
    }
  }
}
```

#### **16. Get User Sessions**

**GET** `/api/v1/users/sessions`

Get user's active sessions.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```json
{
  "success": true,
  "data": {
    "sessions": [
      {
        "id": "session-uuid",
        "deviceInfo": {
          "browser": "Chrome",
          "os": "Windows",
          "device": "Desktop"
        },
        "ipAddress": "192.168.1.1",
        "location": "New York, US",
        "lastActivityAt": "2024-01-01T00:00:00.000Z",
        "createdAt": "2024-01-01T00:00:00.000Z"
      }
    ]
  }
}
```

### Password Management Endpoints

#### **17. Change Password**

**PUT** `/api/v1/password/change`

Change user password.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Request Body:**

```json
{
  "currentPassword": "OldP@ssw0rd!",
  "newPassword": "NewP@ssw0rd!",
  "confirmPassword": "NewP@ssw0rd!"
}
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Password changed successfully"
}
```

#### **18. Request Password Reset**

**POST** `/api/v1/password/reset-request`

Request password reset email.

**Request Body:**

```json
{
  "email": "john.doe@example.com"
}
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Password reset email sent successfully"
}
```

#### **19. Reset Password**

**POST** `/api/v1/password/reset`

Reset password using reset token.

**Request Body:**

```json
{
  "token": "reset-token-from-email",
  "newPassword": "NewP@ssw0rd!",
  "confirmPassword": "NewP@ssw0rd!"
}
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Password reset successfully"
}
```

### Session Management Endpoints

#### **20. Get Active Sessions**

**GET** `/api/v1/sessions`

Get all active sessions for current user.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```json
{
  "success": true,
  "data": {
    "sessions": [
      {
        "id": "session-uuid",
        "deviceInfo": {
          "browser": "Chrome",
          "os": "Windows",
          "device": "Desktop"
        },
        "ipAddress": "192.168.1.1",
        "location": "New York, US",
        "lastActivityAt": "2024-01-01T00:00:00.000Z",
        "createdAt": "2024-01-01T00:00:00.000Z"
      }
    ]
  }
}
```

#### **21. Terminate Session**

**DELETE** `/api/v1/sessions/:sessionId`

Terminate a specific session.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Session terminated successfully"
}
```

#### **22. Terminate All Sessions**

**DELETE** `/api/v1/sessions`

Terminate all sessions except current one.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "All sessions terminated successfully"
}
```

### System Endpoints

#### **23. Health Check**

**GET** `/health`

Check service health status.

**Response (200 OK):**

```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "version": "1.0.0",
  "uptime": 3600,
  "services": {
    "database": "up",
    "redis": "up",
    "rabbitmq": "up",
    "mongodb": "up",
    "grpc": "up"
  },
  "metrics": {
    "requests": 1000,
    "errors": 5,
    "responseTime": 150
  }
}
```

#### **24. API Documentation**

**GET** `/api-docs`

Get interactive API documentation.

**Response (200 OK):**

```
Swagger UI interface
```

#### **25. Metrics**

**GET** `/metrics`

Get service metrics (Prometheus format).

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```
# HELP http_requests_total Total number of HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",route="/health",status_code="200"} 1000
http_requests_total{method="POST",route="/api/v1/auth/login",status_code="200"} 500
```

## 🔧 Error Handling

### Standard Error Response Format

```json
{
  "success": false,
  "error": "Error message",
  "code": "ERROR_CODE",
  "details": {
    "field": "Field-specific error message"
  },
  "timestamp": "2024-01-01T00:00:00.000Z",
  "correlationId": "correlation-uuid"
}
```

### Common Error Codes

| Code                  | HTTP Status | Description                     |
| --------------------- | ----------- | ------------------------------- |
| `VALIDATION_ERROR`    | 400         | Request validation failed       |
| `UNAUTHORIZED`        | 401         | Authentication required         |
| `FORBIDDEN`           | 403         | Insufficient permissions        |
| `NOT_FOUND`           | 404         | Resource not found              |
| `CONFLICT`            | 409         | Resource conflict               |
| `RATE_LIMIT_EXCEEDED` | 429         | Too many requests               |
| `INTERNAL_ERROR`      | 500         | Internal server error           |
| `SERVICE_UNAVAILABLE` | 503         | Service temporarily unavailable |

### Rate Limiting

Rate limits are applied per IP address and endpoint:

- **Signup**: 5 requests per 15 minutes
- **Login**: 10 requests per 15 minutes
- **Password Reset**: 3 requests per hour
- **Email Verification**: 5 requests per hour
- **2FA**: 10 requests per 5 minutes
- **General API**: 100 requests per 15 minutes

Rate limit headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640996100
```

## 📊 Request/Response Headers

### Standard Headers

| Header             | Description            | Example                                          |
| ------------------ | ---------------------- | ------------------------------------------------ |
| `Authorization`    | JWT token              | `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` |
| `Content-Type`     | Request content type   | `application/json`                               |
| `Accept`           | Response content type  | `application/json`                               |
| `X-Correlation-ID` | Request correlation ID | `correlation-uuid`                               |
| `X-Request-ID`     | Unique request ID      | `request-uuid`                                   |
| `User-Agent`       | Client user agent      | `Mozilla/5.0...`                                 |

### Response Headers

| Header                  | Description            | Example            |
| ----------------------- | ---------------------- | ------------------ |
| `X-Correlation-ID`      | Request correlation ID | `correlation-uuid` |
| `X-Request-ID`          | Unique request ID      | `request-uuid`     |
| `X-RateLimit-Limit`     | Rate limit maximum     | `100`              |
| `X-RateLimit-Remaining` | Rate limit remaining   | `95`               |
| `X-RateLimit-Reset`     | Rate limit reset time  | `1640996100`       |

## 🚀 Usage Examples

### JavaScript/Node.js

```javascript
// User registration
const registerUser = async (userData) => {
  const response = await fetch(
    "https://auth.yourdomain.com/api/v1/auth/signup",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(userData),
    }
  );

  return await response.json();
};

// User login
const loginUser = async (credentials) => {
  const response = await fetch(
    "https://auth.yourdomain.com/api/v1/auth/login",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(credentials),
    }
  );

  const data = await response.json();

  if (data.success) {
    // Store tokens
    localStorage.setItem("accessToken", data.data.session.accessToken);
    localStorage.setItem("refreshToken", data.data.session.refreshToken);
  }

  return data;
};

// Authenticated request
const getProfile = async () => {
  const token = localStorage.getItem("accessToken");

  const response = await fetch(
    "https://auth.yourdomain.com/api/v1/users/profile",
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    }
  );

  return await response.json();
};

// Refresh token
const refreshToken = async () => {
  const refreshToken = localStorage.getItem("refreshToken");

  const response = await fetch(
    "https://auth.yourdomain.com/api/v1/auth/refresh-token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ refreshToken }),
    }
  );

  const data = await response.json();

  if (data.success) {
    localStorage.setItem("accessToken", data.data.accessToken);
    localStorage.setItem("refreshToken", data.data.refreshToken);
  }

  return data;
};
```

### cURL Examples

```bash
# User registration
curl -X POST https://auth.yourdomain.com/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "fullName": "John Doe",
    "email": "john.doe@example.com",
    "password": "StrongP@ssw0rd!",
    "confirmPassword": "StrongP@ssw0rd!",
    "type": "customer",
    "role": "customer",
    "termsAccepted": true,
    "privacyAccepted": true
  }'

# User login
curl -X POST https://auth.yourdomain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "StrongP@ssw0rd!"
  }'

# Get user profile
curl -X GET https://auth.yourdomain.com/api/v1/users/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Refresh token
curl -X POST https://auth.yourdomain.com/api/v1/auth/refresh-token \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

### Python

```python
import requests
import json

# User registration
def register_user(user_data):
    response = requests.post(
        'https://auth.yourdomain.com/api/v1/auth/signup',
        headers={'Content-Type': 'application/json'},
        data=json.dumps(user_data)
    )
    return response.json()

# User login
def login_user(credentials):
    response = requests.post(
        'https://auth.yourdomain.com/api/v1/auth/login',
        headers={'Content-Type': 'application/json'},
        data=json.dumps(credentials)
    )
    return response.json()

# Authenticated request
def get_profile(access_token):
    response = requests.get(
        'https://auth.yourdomain.com/api/v1/users/profile',
        headers={
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
    )
    return response.json()

# Usage
user_data = {
    'fullName': 'John Doe',
    'email': 'john.doe@example.com',
    'password': 'StrongP@ssw0rd!',
    'confirmPassword': 'StrongP@ssw0rd!',
    'type': 'customer',
    'role': 'customer',
    'termsAccepted': True,
    'privacyAccepted': True
}

result = register_user(user_data)
print(result)
```

## 📋 API Versioning

The API uses URL versioning with the format `/api/v1/`. Future versions will be available at `/api/v2/`, `/api/v3/`, etc.

### Version Compatibility

- **v1**: Current stable version
- **v2**: Future version (planned)
- **v3**: Future version (planned)

### Deprecation Policy

- API versions are supported for at least 12 months after deprecation
- Deprecation notices are sent 6 months in advance
- Breaking changes are only introduced in new major versions

## 🔗 Related Documentation

- [Development Guide](./DEVELOPMENT.md)
- [Architecture Documentation](./ARCHITECTURE.md)
- [Security Documentation](./SECURITY.md)
- [Deployment Guide](./DEPLOYMENT.md)

---

**This API documentation provides comprehensive information for integrating with the AuthService microservice.**
