import { ApiError } from '../../utils/index.js';
import { safeLogger } from '../../config/logger.js';
import { getCorrelationId } from '../../config/requestContext.js';
import { authService } from '../../services/index.js';

/**
 * Simple gRPC Auth Service Wrapper
 * Delegates to the actual auth service
 */

/**
 * Login user
 */
export async function login(request) {
  try {
    const { email, password, device_info } = request;

    const result = await authService.loginUser({
      email,
      password,
      deviceInfo: device_info,
    });

    return {
      success: true,
      token: result.tokens.accessToken,
      refresh_token: result.tokens.refreshToken,
      user: {
        id: result.user.id,
        email: result.user.email,
        fullName: result.user.fullName,
        role: result.user.role,
        status: result.user.status,
      },
    };
  } catch (error) {
    safeLogger.error('gRPC login failed', { error: error.message });
    throw error;
  }
}

/**
 * Register user
 */
export async function register(request) {
  try {
    const { email, password, full_name, type, role } = request;

    const result = await authService.registerUser({
      email,
      password,
      fullName: full_name,
      type,
      role: role || 'user',
    });

    return {
      success: true,
      user: {
        id: result.id,
        email: result.email,
        fullName: result.fullName,
        type: result.type,
        role: result.role,
        status: result.status,
      },
    };
  } catch (error) {
    safeLogger.error('gRPC register failed', { error: error.message });
    throw error;
  }
}

/**
 * Validate token
 */
export async function validateToken(token, options = {}) {
  try {
    const result = await authService.verifyToken(token);

    return {
      valid: true,
      user: {
        id: result.id,
        email: result.email,
        role: result.role,
        status: result.status,
      },
    };
  } catch (error) {
    safeLogger.error('gRPC token validation failed', { error: error.message });
    return {
      valid: false,
      error: error.message,
    };
  }
}

/**
 * Refresh token
 */
export async function refreshToken(refreshToken, options = {}) {
  try {
    const result = await authService.refreshToken(refreshToken);

    return {
      success: true,
      token: result.tokens.accessToken,
      refresh_token: result.tokens.refreshToken,
    };
  } catch (error) {
    safeLogger.error('gRPC token refresh failed', { error: error.message });
    throw error;
  }
}

/**
 * Logout user
 */
export async function logout(token, options = {}) {
  try {
    // Note: The actual logout logic is in the HTTP controller
    // This is just a placeholder for gRPC compatibility
    return {
      success: true,
      message: 'Logout successful',
    };
  } catch (error) {
    safeLogger.error('gRPC logout failed', { error: error.message });
    throw error;
  }
}

/**
 * Get user sessions
 */
export async function getSessions(userId, options = {}) {
  try {
    // Note: Session management is handled by the session service
    // This is just a placeholder for gRPC compatibility
    return {
      sessions: [],
      totalSessions: 0,
    };
  } catch (error) {
    safeLogger.error('gRPC get sessions failed', { error: error.message });
    throw error;
  }
}

/**
 * Health check
 */
export async function healthCheck(options = {}) {
  try {
    const {
      detailed = false,
      checkDatabase = true,
      includeSystem = false,
    } = options;

    // Simple database check
    let dbStatus = 'unknown';
    if (checkDatabase) {
      const db = await import('../../db/index.js');

      if (db.default && db.default.sequelize) {
        try {
          await db.default.sequelize.authenticate();
          dbStatus = 'connected';
        } catch (error) {
          dbStatus = 'disconnected';
        }
      }
    }

    const response = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'auth-service-grpc',
      database: dbStatus,
    };

    // Add uptime if requested
    if (includeSystem) {
      response.uptime = Math.round(process.uptime());
      response.nodeVersion = process.version;
    }

    // Add detailed info if requested
    if (detailed) {
      response.details = {
        database: dbStatus,
        service: 'operational',
        checks: ['database', 'service'],
      };
    }

    return response;
  } catch (error) {
    return {
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      service: 'auth-service-grpc',
      error: error.message,
    };
  }
}
