import { publishEvent } from '../index.js';
import { safeLogger } from '../../config/logger.js';

/**
 * Authentication Events Emitter
 * Sends auth-related events to other microservices
 */

/**
 * Emit user registration event
 * @param {Object} userData - User registration data
 * @param {Object} options - Additional options
 */
export async function emitUserRegistered(userData, options = {}) {
  try {
    const eventData = {
      userId: userData.id,
      email: userData.email,
      fullName: userData.fullName,
      userType: userData.type,
      registrationDate: new Date().toISOString(),
      ...options,
    };

    await publishEvent('user.registered', eventData);

    safeLogger.info('User registered event emitted', {
      userId: userData.id,
      email: userData.email,
    });

    return true;
  } catch (error) {
    safeLogger.error('Failed to emit user registered event', {
      userId: userData.id,
      error: error.message,
    });
    throw error;
  }
}

/**
 * Emit user login event
 * @param {Object} loginData - Login data
 * @param {Object} options - Additional options
 */
export async function emitUserLoggedIn(loginData, options = {}) {
  try {
    const eventData = {
      userId: loginData.userId,
      email: loginData.email,
      loginTime: new Date().toISOString(),
      ipAddress: loginData.ipAddress,
      userAgent: loginData.userAgent,
      ...options,
    };

    await publishEvent('user.logged_in', eventData);

    safeLogger.info('User login event emitted', {
      userId: loginData.userId,
      email: loginData.email,
    });

    return true;
  } catch (error) {
    safeLogger.error('Failed to emit user login event', {
      userId: loginData.userId,
      error: error.message,
    });
    throw error;
  }
}

/**
 * Emit user logout event
 * @param {Object} logoutData - Logout data
 * @param {Object} options - Additional options
 */
export async function emitUserLoggedOut(logoutData, options = {}) {
  try {
    const eventData = {
      userId: logoutData.userId,
      email: logoutData.email,
      logoutTime: new Date().toISOString(),
      sessionId: logoutData.sessionId,
      ...options,
    };

    await publishEvent('user.logged_out', eventData);

    safeLogger.info('User logout event emitted', {
      userId: logoutData.userId,
      email: logoutData.email,
    });

    return true;
  } catch (error) {
    safeLogger.error('Failed to emit user logout event', {
      userId: logoutData.userId,
      error: error.message,
    });
    throw error;
  }
}

/**
 * Emit email verification event
 * @param {Object} verificationData - Verification data
 * @param {Object} options - Additional options
 */
export async function emitEmailVerified(verificationData, options = {}) {
  try {
    const eventData = {
      userId: verificationData.userId,
      email: verificationData.email,
      verificationTime: new Date().toISOString(),
      verificationMethod: verificationData.method,
      ...options,
    };

    await publishEvent('user.email_verified', eventData);

    safeLogger.info('Email verified event emitted', {
      userId: verificationData.userId,
      email: verificationData.email,
    });

    return true;
  } catch (error) {
    safeLogger.error('Failed to emit email verified event', {
      userId: verificationData.userId,
      error: error.message,
    });
    throw error;
  }
}

/**
 * Emit password reset event
 * @param {Object} resetData - Password reset data
 * @param {Object} options - Additional options
 */
export async function emitPasswordResetInitiated(resetData, options = {}) {
  try {
    const eventData = {
      userId: resetData.userId,
      email: resetData.email,
      resetTime: new Date().toISOString(),
      resetToken: resetData.resetToken,
      ...options,
    };

    await publishEvent('password.reset_initiated', eventData);

    safeLogger.info('Password reset initiated event emitted', {
      userId: resetData.userId,
      email: resetData.email,
    });

    return true;
  } catch (error) {
    safeLogger.error('Failed to emit password reset initiated event', {
      userId: resetData.userId,
      error: error.message,
    });
    throw error;
  }
}

/**
 * Emit password reset completed event
 * @param {Object} resetData - Password reset data
 * @param {Object} options - Additional options
 */
export async function emitPasswordResetCompleted(resetData, options = {}) {
  try {
    const eventData = {
      userId: resetData.userId,
      email: resetData.email,
      completionTime: new Date().toISOString(),
      ...options,
    };

    await publishEvent('password.reset_completed', eventData);

    safeLogger.info('Password reset completed event emitted', {
      userId: resetData.userId,
      email: resetData.email,
    });

    return true;
  } catch (error) {
    safeLogger.error('Failed to emit password reset completed event', {
      userId: resetData.userId,
      error: error.message,
    });
    throw error;
  }
}

/**
 * Emit session revoked event
 * @param {Object} sessionData - Session data
 * @param {Object} options - Additional options
 */
export async function emitSessionRevoked(sessionData, options = {}) {
  try {
    const eventData = {
      userId: sessionData.userId,
      sessionId: sessionData.sessionId,
      revocationTime: new Date().toISOString(),
      reason: sessionData.reason || 'manual_revocation',
      ...options,
    };

    await publishEvent('session.revoked', eventData);

    safeLogger.info('Session revoked event emitted', {
      userId: sessionData.userId,
      sessionId: sessionData.sessionId,
    });

    return true;
  } catch (error) {
    safeLogger.error('Failed to emit session revoked event', {
      userId: sessionData.userId,
      error: error.message,
    });
    throw error;
  }
}

/**
 * Emit account activation event
 * @param {Object} userData - User data
 * @param {Object} options - Additional options
 */
export async function emitAccountActivated(userData, options = {}) {
  try {
    const eventData = {
      userId: userData.id,
      email: userData.email,
      fullName: userData.fullName,
      userType: userData.type,
      activationDate: new Date().toISOString(),
      ...options,
    };

    await publishEvent('account.activated', eventData);

    safeLogger.info('Account activated event emitted', {
      userId: userData.id,
      email: userData.email,
    });

    return true;
  } catch (error) {
    safeLogger.error('Failed to emit account activated event', {
      userId: userData.id,
      error: error.message,
    });
    throw error;
  }
}

/**
 * Emit email verification event
 * @param {Object} userData - User data
 * @param {Object} options - Additional options
 */
export async function emitEmailVerification(userData, options = {}) {
  try {
    const eventData = {
      userId: userData.id,
      email: userData.email,
      fullName: userData.fullName,
      verificationToken: userData.id,
      template: 'email_verification',
      data: {
        userName: userData.fullName,
        email: userData.email,
        verificationLink: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email?token=${userData.id}`,
      },
      timestamp: new Date(),
      ...options,
    };

    await publishEvent('email.verification', eventData);

    safeLogger.info('Email verification event emitted', {
      userId: userData.id,
      email: userData.email,
    });

    return true;
  } catch (error) {
    safeLogger.error('Failed to emit email verification event', {
      userId: userData.id,
      error: error.message,
    });
    throw error;
  }
}
