/**
 * Services Index - Export all services
 *
 * Centralized export point for all business logic services:
 * - AuthService: Core authentication
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
import sessionService from './session.service.js';
import passwordService from './password.service.js';
import jwkService from './jwk.service.js';
import oauthService from './oauth.service.js';
import twoFactorService from './twoFactor.service.js';

// Service registry for dependency injection
const serviceRegistry = {
  auth: authService,
  session: sessionService,
  password: passwordService,
  jwk: jwkService,
  oauth: oauthService,
  twoFactor: twoFactorService,
};

export {
  authService,
  sessionService,
  passwordService,
  jwkService,
  oauthService,
  twoFactorService,
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
