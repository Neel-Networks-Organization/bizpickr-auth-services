/**
 * Services Index - Export all services
 *
 * Centralized export point for all business logic services:
 * - AuthService: Core authentication
 * - UserService: User management
 * - SessionService: Session management
 * - PasswordService: Password operations
 * - JWKService: JSON Web Key operations
 * - OAuthService: OAuth integration
 * - EmailVerificationService: Email verification
 * - TwoFactorService: Two-factor authentication
 * - EmailService: Email operations
 * - PermissionService: Permission management
 */

import authService from './auth.service.js';
import userService from './user.service.js';
import sessionService from './session.service.js';
import passwordService from './password.service.js';
import jwkService from './jwk.service.js';
import oauthService from './oauth.service.js';
import emailVerificationService from './emailVerification.service.js';
import twoFactorService from './twoFactor.service.js';
import emailService from './email.service.js';
import permissionService from './permission.service.js';

// Service registry for dependency injection
const serviceRegistry = {
  auth: authService,
  user: userService,
  session: sessionService,
  password: passwordService,
  jwk: jwkService,
  oauth: oauthService,
  emailVerification: emailVerificationService,
  twoFactor: twoFactorService,
  email: emailService,
  permission: permissionService,
};

export {
  authService,
  userService,
  sessionService,
  passwordService,
  jwkService,
  oauthService,
  emailVerificationService,
  twoFactorService,
  emailService,
  permissionService,
};

/**
 * Get service by name
 * @param {string} serviceName - Service name
 * @returns {Object} Service instance
 */
export function getService(serviceName) {
  const service = serviceRegistry[serviceName];
  if (!service) {
    throw new Error(`Service '${serviceName}' not found`);
  }
  return service;
}

/**
 * Get all services
 * @returns {Object} All services
 */
export function getAllServices() {
  return { ...serviceRegistry };
}

export default serviceRegistry;
