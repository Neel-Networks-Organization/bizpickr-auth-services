import { User } from '../models/index.model.js';
import { safeLogger } from '../config/logger.js';
import { ApiError } from '../utils/index.js';
import { logAuditEvent } from './audit.service.js';
import { cryptoService, oauthService } from './index.js';
import authCache from '../cache/auth.cache.js';
import { Op } from 'sequelize';
import { env } from '../config/env.js';

class AuthService {
  constructor() {
    // Load security configuration from environment
    this.loadSecurityConfig();

    // Load rate limiting configuration
    this.loadRateLimitConfig();

    // Validate security configuration
    this.validateSecurityConfig();

    // Log initialization
    safeLogger.info('AuthService initialized', {
      security: this.securityConfig,
      rateLimit: this.rateLimitConfig,
    });
  }

  // Load security configuration
  loadSecurityConfig() {
    const config = env.services.auth;
    this.securityConfig = {
      // Authentication security
      maxLoginAttempts: config.maxLoginAttempts,
      lockoutDuration: config.lockoutDuration,
      maxFailedAttempts: config.maxFailedAttempts,
      accountLockDuration: config.accountLockDuration,

      // Password security
      passwordMinLength: config.passwordMinLength,
      passwordMaxLength: config.passwordMaxLength,
      bcryptRounds: config.bcryptRounds,
    };
  }

  // Load rate limiting configuration
  loadRateLimitConfig() {
    const config = env.services.auth;
    this.rateLimitConfig = {
      loginWindow: config.loginRateWindow,
      loginMax: config.loginRateLimit,
    };
  }

  // Get security configuration for debugging/admin purposes
  getSecurityConfig() {
    return {
      ...this.securityConfig,
      rateLimit: this.rateLimitConfig,
    };
  }

  // Validate security configuration
  validateSecurityConfig() {
    const errors = [];

    if (this.securityConfig.maxLoginAttempts < 1) {
      errors.push('MAX_LOGIN_ATTEMPTS must be at least 1');
    }

    if (this.securityConfig.lockoutDuration < 60000) {
      // 1 minute minimum
      errors.push('LOCKOUT_DURATION must be at least 1 minute (60000ms)');
    }

    if (
      this.securityConfig.maxFailedAttempts <
      this.securityConfig.maxLoginAttempts
    ) {
      errors.push(
        'MAX_FAILED_ATTEMPTS must be greater than or equal to MAX_LOGIN_ATTEMPTS'
      );
    }

    if (
      this.securityConfig.accountLockDuration <
      this.securityConfig.lockoutDuration
    ) {
      errors.push(
        'ACCOUNT_LOCK_DURATION must be greater than or equal to LOCKOUT_DURATION'
      );
    }

    if (errors.length > 0) {
      safeLogger.error('Security configuration validation failed', { errors });
      throw new Error(
        `Security configuration validation failed: ${errors.join(', ')}`
      );
    }

    safeLogger.info('Security configuration validation passed');
  }

  async registerUser(userData) {
    try {
      const { email, password, type, role } = userData;
      const existingUser = await User.findOne({ where: { email } });
      if (existingUser) {
        throw new ApiError(400, 'User with this email already exists');
      }

      // Create user
      const user = await User.create({
        email,
        password,
        type,
        role,
        status: 'pending',
        emailVerified: false,
      });

      await logAuditEvent('USER_REGISTERED', {
        userId: user.id,
        email: user.email,
        type,
        role,
        createdAt: user.createdAt,
      });

      safeLogger.info('User registered successfully', {
        userId: user.id,
        email: user.email,
      });

      return {
        id: user.id,
        email: user.email,
        type: user.type,
        role: user.role,
        status: user.status,
        emailVerified: user.emailVerified,
        createdAt: user.createdAt,
      };
    } catch (error) {
      safeLogger.error('User registration failed', {
        error: error.message,
        email: userData.email,
      });
      throw error;
    }
  }

  async loginUser(loginData) {
    try {
      const { email, password } = loginData;

      // Input validation
      if (!email || !password) {
        throw new ApiError(400, 'Email and password are required');
      }

      // Add email format validation
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        throw new ApiError(400, 'Please provide a valid email address');
      }

      // Add password strength validation
      if (password.length < this.securityConfig.passwordMinLength) {
        throw new ApiError(
          400,
          `Password must be at least ${this.securityConfig.passwordMinLength} characters long`
        );
      }

      if (password.length > this.securityConfig.passwordMaxLength) {
        throw new ApiError(
          400,
          `Password must not exceed ${this.securityConfig.passwordMaxLength} characters`
        );
      }

      // Check if account is temporarily locked
      const lockoutKey = `lockout:${email}`;
      const lockoutStatus = await authCache.get(lockoutKey);

      if (
        lockoutStatus &&
        lockoutStatus.attempts >= this.securityConfig.maxLoginAttempts
      ) {
        const lockoutTime = this.securityConfig.lockoutDuration;
        if (Date.now() - lockoutStatus.timestamp < lockoutTime) {
          const remainingTime = Math.ceil(
            (lockoutTime - (Date.now() - lockoutStatus.timestamp)) / 1000 / 60
          );
          throw new ApiError(
            429,
            `Account temporarily locked due to ${lockoutStatus.attempts} failed attempts. Try again in ${remainingTime} minutes. Max attempts: ${this.securityConfig.maxLoginAttempts}`
          );
        } else {
          // Reset lockout after time expires
          await authCache.delete(lockoutKey);
        }
      }

      const user = await User.findOne({ where: { email } });
      if (!user) {
        // Don't call handleFailedLogin for non-existent users
        // This prevents user enumeration attacks
        safeLogger.warn('Login attempt with non-existent email', {
          email,
          ipAddress: loginData.ipAddress,
          userAgent: loginData.userAgent,
        });
        throw new ApiError(
          401,
          `Invalid email or password. After ${this.securityConfig.maxFailedAttempts} failed attempts, account will be locked for ${Math.ceil(this.securityConfig.accountLockDuration / 1000 / 60)} minutes.`
        );
      }

      // Check if account is permanently locked by admin
      if (user.isLocked()) {
        safeLogger.warn('Login attempt on locked account', {
          userId: user.id,
          email: user.email,
          ipAddress: loginData.ipAddress,
        });
        throw new ApiError(401, 'Account is locked. Please contact support.');
      }

      // Check if account is suspended
      if (user.status === 'suspended') {
        safeLogger.warn('Login attempt on suspended account', {
          userId: user.id,
          email: user.email,
          ipAddress: loginData.ipAddress,
        });
        throw new ApiError(
          401,
          'Account is suspended. Please contact support.'
        );
      }

      // Check if account is pending verification
      if (user.status === 'pending') {
        safeLogger.info('Login attempt on pending account', {
          userId: user.id,
          email: user.email,
          ipAddress: loginData.ipAddress,
        });
        throw new ApiError(
          401,
          'Account pending verification. Please check your email and verify your account before logging in.'
        );
      }

      const isPasswordCorrect = await user.isPasswordCorrect(password);

      // Debug logging for password validation
      safeLogger.debug('Password validation attempt', {
        email: user.email,
        userId: user.id,
        passwordLength: password ? password.length : 0,
        hashedPasswordExists: !!user.password,
        isPasswordCorrect: isPasswordCorrect,
        userStatus: user.status,
        securityConfig: this.securityConfig, // Add security config for debugging
        timestamp: new Date().toISOString(),
      });

      if (!isPasswordCorrect) {
        // Only track failed attempts for existing users
        await this.handleFailedLogin(email);
        throw new ApiError(
          401,
          `Invalid email or password. After ${this.securityConfig.maxFailedAttempts} failed attempts, account will be locked for ${Math.ceil(this.securityConfig.accountLockDuration / 1000 / 60)} minutes.`
        );
      }

      // Reset failed attempts on successful login
      await authCache.delete(lockoutKey);

      // Reset database failed attempts counter
      if (user.failedLoginAttempts > 0) {
        await user.update({
          failedLoginAttempts: 0,
          lockedUntil: null,
        });
      }

      const { accessToken, refreshToken } =
        await cryptoService.generateTokens(user);

      // Update last login timestamp in database
      await user.update({
        lastLoginAt: new Date(),
        failedLoginAttempts: 0, // Reset failed attempts on successful login
        lockedUntil: null, // Clear any locks on successful login
      });

      await authCache.storeUserSession(user.id, {
        userId: user.id,
        email: user.email,
        role: user.role,
        type: user.type,
        status: user.status,
        emailVerified: user.emailVerified,
        createdAt: new Date().toISOString(),
        lastLoginAt: new Date().toISOString(),
        ipAddress: loginData.ipAddress,
        userAgent: loginData.userAgent,
      });

      await logAuditEvent('USER_LOGGED_IN', {
        userId: user.id,
        email: user.email,
        role: user.role,
        type: user.type,
        status: user.status,
        emailVerified: user.emailVerified,
        ipAddress: loginData.ipAddress,
        userAgent: loginData.userAgent,
        loginMethod: 'email',
      });

      safeLogger.info('User logged in successfully', {
        userId: user.id,
        email: user.email,
        ipAddress: loginData.ipAddress,
        loginMethod: 'email',
      });

      return {
        user: {
          id: user.id,
          email: user.email,
          type: user.type,
          role: user.role,
          status: user.status,
          emailVerified: user.emailVerified,
        },
        tokens: {
          accessToken,
          refreshToken,
        },
      };
    } catch (error) {
      safeLogger.error('User login failed', {
        error: error.message,
        email: loginData.email,
        ipAddress: loginData.ipAddress,
      });
      throw error;
    }
  }

  async handleFailedLogin(email) {
    try {
      const lockoutKey = `lockout:${email}`;
      const currentStatus = (await authCache.get(lockoutKey)) || {
        attempts: 0,
        timestamp: Date.now(),
      };

      currentStatus.attempts += 1;
      currentStatus.timestamp = Date.now();

      // Store for configured lockout duration
      await authCache.set(
        lockoutKey,
        currentStatus,
        this.securityConfig.lockoutDuration / 1000
      );

      // Update database failed attempts counter
      const user = await User.findOne({ where: { email } });
      if (user) {
        const newFailedAttempts = user.failedLoginAttempts + 1;
        let lockedUntil = null;

        // Lock account after max failed attempts for configured duration
        if (newFailedAttempts >= this.securityConfig.maxFailedAttempts) {
          lockedUntil = new Date(
            Date.now() + this.securityConfig.accountLockDuration
          );
        }

        await user.update({
          failedLoginAttempts: newFailedAttempts,
          lockedUntil: lockedUntil,
        });
      }

      // Log failed attempt
      await logAuditEvent('LOGIN_FAILED', {
        email,
        attempts: currentStatus.attempts,
        timestamp: new Date().toISOString(),
        ipAddress: currentStatus.ipAddress,
      });

      safeLogger.warn('Failed login attempt', {
        email,
        attempts: currentStatus.attempts,
        ipAddress: currentStatus.ipAddress,
      });
    } catch (error) {
      safeLogger.error('Failed to handle failed login', {
        email,
        error: error.message,
      });
    }
  }

  async unlockAccount(email, adminUserId) {
    try {
      const user = await User.findOne({ where: { email } });
      if (!user) {
        throw new ApiError(404, 'User not found');
      }

      // Remove lockout from cache
      const lockoutKey = `lockout:${email}`;
      await authCache.delete(lockoutKey);

      // Reset database lockout
      await user.update({
        failedLoginAttempts: 0,
        lockedUntil: null,
      });

      // Log unlock action
      await logAuditEvent('ACCOUNT_UNLOCKED', {
        userId: user.id,
        email: user.email,
        unlockedBy: adminUserId,
        timestamp: new Date().toISOString(),
      });

      safeLogger.info('Account unlocked successfully', {
        userId: user.id,
        email: user.email,
        unlockedBy: adminUserId,
      });

      return { message: 'Account unlocked successfully' };
    } catch (error) {
      safeLogger.error('Failed to unlock account', {
        email,
        error: error.message,
        adminUserId,
      });
      throw error;
    }
  }

  async getAccountStatus(email) {
    try {
      const user = await User.findOne({ where: { email } });
      if (!user) {
        throw new ApiError(404, 'User not found');
      }

      const lockoutKey = `lockout:${email}`;
      const lockoutStatus = await authCache.get(lockoutKey);

      return {
        userId: user.id,
        email: user.email,
        status: user.status,
        failedLoginAttempts: user.failedLoginAttempts,
        lockedUntil: user.lockedUntil,
        isLocked: user.isLocked(),
        isActive: user.isActive(),
        temporaryLockout: lockoutStatus
          ? {
              attempts: lockoutStatus.attempts,
              locked:
                lockoutStatus.attempts >= this.securityConfig.maxLoginAttempts,
              remainingTime:
                lockoutStatus.attempts >= this.securityConfig.maxLoginAttempts
                  ? Math.ceil(
                      (this.securityConfig.lockoutDuration -
                        (Date.now() - lockoutStatus.timestamp)) /
                        1000 /
                        60
                    )
                  : 0,
            }
          : null,
        lastLoginAt: user.lastLoginAt,
        createdAt: user.createdAt,
      };
    } catch (error) {
      safeLogger.error('Failed to get account status', {
        email,
        error: error.message,
      });
      throw error;
    }
  }

  async suspendAccount(email, reason, adminUserId) {
    try {
      const user = await User.findOne({ where: { email } });
      if (!user) {
        throw new ApiError(404, 'User not found');
      }

      // Update user status to suspended
      await user.update({
        status: 'suspended',
        suspendedAt: new Date(),
        suspendedBy: adminUserId,
        suspensionReason: reason,
      });

      // Clear any temporary lockouts
      const lockoutKey = `lockout:${email}`;
      await authCache.delete(lockoutKey);

      // Log suspension action
      await logAuditEvent('ACCOUNT_SUSPENDED', {
        userId: user.id,
        email: user.email,
        suspendedBy: adminUserId,
        reason: reason,
        timestamp: new Date().toISOString(),
      });

      safeLogger.info('Account suspended successfully', {
        userId: user.id,
        email: user.email,
        suspendedBy: adminUserId,
        reason: reason,
      });

      return {
        message: 'Account suspended successfully',
        userId: user.id,
        email: user.email,
        status: 'suspended',
        suspendedAt: user.suspendedAt,
      };
    } catch (error) {
      safeLogger.error('Failed to suspend account', {
        email,
        error: error.message,
        adminUserId,
      });
      throw error;
    }
  }

  async activateAccount(email, adminUserId) {
    try {
      const user = await User.findOne({ where: { email } });
      if (!user) {
        throw new ApiError(404, 'User not found');
      }

      // Update user status to active
      await user.update({
        status: 'active',
        suspendedAt: null,
        suspendedBy: null,
        suspensionReason: null,
        failedLoginAttempts: 0,
        lockedUntil: null,
      });

      // Clear any temporary lockouts
      const lockoutKey = `lockout:${email}`;
      await authCache.delete(lockoutKey);

      // Log activation action
      await logAuditEvent('ACCOUNT_ACTIVATED', {
        userId: user.id,
        email: user.email,
        activatedBy: adminUserId,
        timestamp: new Date().toISOString(),
      });

      safeLogger.info('Account activated successfully', {
        userId: user.id,
        email: user.email,
        activatedBy: adminUserId,
      });

      return {
        message: 'Account activated successfully',
        userId: user.id,
        email: user.email,
        status: 'active',
        activatedAt: new Date(),
      };
    } catch (error) {
      safeLogger.error('Failed to activate account', {
        email,
        error: error.message,
        adminUserId,
      });
      throw error;
    }
  }

  async getLockedAccounts({ page = 1, limit, status }) {
    if (!limit) {
      const config = env.services.auth;
      limit = config.defaultLimit;
    }
    try {
      const offset = (page - 1) * limit;
      const whereClause = {};

      // Filter by status if provided
      if (status) {
        whereClause.status = status;
      }

      // Add lockout conditions
      whereClause[Op.or] = [
        { status: 'suspended' },
        { lockedUntil: { [Op.gt]: new Date() } },
        {
          failedLoginAttempts: {
            [Op.gte]: this.securityConfig.maxLoginAttempts,
          },
        },
      ];

      const { count, rows } = await User.findAndCountAll({
        where: whereClause,
        attributes: [
          'id',
          'email',
          'type',
          'role',
          'status',
          'failedLoginAttempts',
          'lockedUntil',
          'suspendedAt',
          'suspendedBy',
          'suspensionReason',
          'createdAt',
          'lastLoginAt',
        ],
        order: [['createdAt', 'DESC']],
        limit: parseInt(limit),
        offset: parseInt(offset),
      });

      // Get temporary lockout status from cache
      const accountsWithLockout = await Promise.all(
        rows.map(async user => {
          const lockoutKey = `lockout:${user.email}`;
          const lockoutStatus = await authCache.get(lockoutKey);

          return {
            ...user.toJSON(),
            temporaryLockout: lockoutStatus
              ? {
                  attempts: lockoutStatus.attempts,
                  locked:
                    lockoutStatus.attempts >=
                    this.securityConfig.maxLoginAttempts,
                  remainingTime:
                    lockoutStatus.attempts >=
                    this.securityConfig.maxLoginAttempts
                      ? Math.ceil(
                          (this.securityConfig.lockoutDuration -
                            (Date.now() - lockoutStatus.timestamp)) /
                            1000 /
                            60
                        )
                      : 0,
                }
              : null,
          };
        })
      );

      return {
        accounts: accountsWithLockout,
        total: count,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(count / limit),
      };
    } catch (error) {
      safeLogger.error('Failed to get locked accounts', {
        error: error.message,
        page,
        limit,
        status,
      });
      throw error;
    }
  }

  async clearUserCache(userId, email) {
    try {
      // Clear all cache data for user
      await authCache.clearUserCache(userId, email);

      safeLogger.info('User cache cleared successfully', {
        userId,
        email,
      });

      return {
        message: 'User cache cleared successfully',
        userId,
        email,
        clearedAt: new Date(),
      };
    } catch (error) {
      safeLogger.error('Failed to clear user cache', {
        error: error.message,
        userId,
        email,
      });
      throw error;
    }
  }

  // Development helper method - activate pending account
  async activatePendingAccount(email) {
    try {
      const user = await User.findOne({ where: { email } });
      if (!user) {
        throw new ApiError(404, 'User not found');
      }

      if (user.status !== 'pending') {
        throw new ApiError(400, 'Account is not pending activation');
      }

      // Activate the account
      await user.update({
        status: 'active',
        emailVerified: true,
        emailVerifiedAt: new Date(),
      });

      safeLogger.info('Pending account activated for development', {
        userId: user.id,
        email: user.email,
      });

      return {
        message: 'Account activated successfully',
        userId: user.id,
        email: user.email,
        status: 'active',
        emailVerified: true,
      };
    } catch (error) {
      safeLogger.error('Failed to activate pending account', {
        email,
        error: error.message,
      });
      throw error;
    }
  }

  async refreshToken(refreshToken) {
    try {
      const userPayload = await cryptoService.verifyRefreshToken(refreshToken);

      // find from cache then db
      const user = await authCache.getUserSession(userPayload.userId);
      if (!user) {
        const user = await User.findByPk(userPayload.userId);
        await authCache.storeUserSession(user.id, user);
      }

      if (!user || user.status !== 'active') {
        throw new ApiError(401, 'User inactive');
      }

      const tokens = await cryptoService.generateTokens(user);
      return tokens;
    } catch (error) {
      safeLogger.error('Refresh token verification failed', {
        error: error.message,
        refreshToken,
      });
      throw error;
    }
  }

  async logoutUser(userPayload) {
    const { jti, userId } = userPayload;
    try {
      await cryptoService.revokeToken(jti);
      await authCache.removeUserSession(userId);

      await logAuditEvent('USER_LOGGED_OUT', {
        userId,
      });

      safeLogger.info('User logged out successfully', {
        userId,
      });

      return true;
    } catch (error) {
      safeLogger.error('User logout failed', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  async getUserById(userId) {
    try {
      const user = await User.findByPk(userId);
      if (!user) {
        throw new ApiError(404, 'User not found');
      }
      return user;
    } catch (error) {
      safeLogger.error('User retrieval failed', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  async googleOAuthLogin(code, deviceInfo) {
    try {
      return await oauthService.completeGoogleLogin(code, deviceInfo);
    } catch (error) {
      safeLogger.error('Google OAuth login failed', { error: error.message });
      throw error;
    }
  }
}

export default new AuthService();
