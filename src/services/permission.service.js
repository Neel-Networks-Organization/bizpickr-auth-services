/**
 * Permission Service - Role-Based Access Control (RBAC)
 *
 * Handles all permission-related business logic:
 * - Role-based permissions
 * - Permission validation
 * - Access control
 * - Permission hierarchy
 */
import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import { authCache } from '../cache/auth.cache.js';

/**
 * Role-based permissions and responsibilities
 */
export const ROLE_PERMISSIONS = {
  // Customer permissions
  customer: [
    'lead:submit',
    'chat:send',
    'review:write',
    'proposal:accept',
    'profile:view',
    'profile:edit',
  ],
  // Vendor permissions
  vendor: [
    'lead:view',
    'lead:buy',
    'proposal:send',
    'deal:handle',
    'chat:send',
    'profile:view',
    'profile:edit',
  ],
  // Requirement Coordinator permissions
  requirement_coordinator: [
    'lead:review',
    'lead:distribute',
    'staff:manage',
    'performance:view',
    'chat:send',
    'profile:view',
  ],
  // Admin permissions
  admin: [
    'vendor:match',
    'lead:distribute',
    'verification:handle',
    'system:view',
    'user:manage',
    'profile:view',
  ],
  // HR Admin permissions
  hr_admin: [
    'hiring:manage',
    'candidate:review',
    'interview:schedule',
    'staff:onboard',
    'profile:view',
  ],
  // Super Admin permissions
  super_admin: ['*'], // All permissions
};

/**
 * Role hierarchy for access control
 */
export const ROLE_HIERARCHY = {
  customer: 1,
  vendor: 2,
  requirement_coordinator: 4,
  admin: 5,
  hr_admin: 6,
  super_admin: 7,
};

class PermissionService {
  constructor() {
    this.cacheTTL = 30 * 60; // 30 minutes
  }

  /**
   * Get user permissions based on role
   * @param {string} role - User role
   * @returns {Array} Array of permissions
   */
  getUserPermissions(role) {
    try {
      const permissions = ROLE_PERMISSIONS[role] || [];
      safeLogger.debug('Retrieved permissions for role', {
        role,
        permissionCount: permissions.length,
        correlationId: getCorrelationId(),
      });
      return permissions;
    } catch (error) {
      safeLogger.error('Failed to get user permissions', {
        role,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      return [];
    }
  }

  /**
   * Check if user has permission
   * @param {string} role - User role
   * @param {string} permission - Permission to check
   * @returns {boolean} Whether user has permission
   */
  hasPermission(role, permission) {
    try {
      const permissions = this.getUserPermissions(role);
      const hasPermission =
        permissions.includes(permission) || permissions.includes('*');

      safeLogger.debug('Permission check result', {
        role,
        permission,
        hasPermission,
        correlationId: getCorrelationId(),
      });

      return hasPermission;
    } catch (error) {
      safeLogger.error('Failed to check permission', {
        role,
        permission,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      return false;
    }
  }

  /**
   * Check if user can access role (hierarchy check)
   * @param {string} userRole - Current user role
   * @param {string} targetRole - Target role to access
   * @returns {boolean} Whether user can access target role
   */
  canAccessRole(userRole, targetRole) {
    try {
      const userLevel = ROLE_HIERARCHY[userRole] || 0;
      const targetLevel = ROLE_HIERARCHY[targetRole] || 0;
      const canAccess = userLevel >= targetLevel;

      safeLogger.debug('Role access check result', {
        userRole,
        targetRole,
        userLevel,
        targetLevel,
        canAccess,
        correlationId: getCorrelationId(),
      });

      return canAccess;
    } catch (error) {
      safeLogger.error('Failed to check role access', {
        userRole,
        targetRole,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      return false;
    }
  }

  /**
   * Get cached user permissions
   * @param {string} userId - User ID
   * @returns {Promise<Array>} Cached permissions
   */
  async getCachedUserPermissions(userId) {
    try {
      const cachedPermissions = await authCache.getUserPermissions(userId);
      if (cachedPermissions) {
        safeLogger.debug('Retrieved cached permissions', {
          userId,
          permissionCount: cachedPermissions.length,
          correlationId: getCorrelationId(),
        });
        return cachedPermissions;
      }
      return null;
    } catch (error) {
      safeLogger.error('Failed to get cached permissions', {
        userId,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      return null;
    }
  }

  /**
   * Cache user permissions
   * @param {string} userId - User ID
   * @param {Array} permissions - User permissions
   * @returns {Promise<void>}
   */
  async cacheUserPermissions(userId, permissions) {
    try {
      await authCache.storeUserPermissions(userId, permissions, {
        ttl: this.cacheTTL,
      });
      safeLogger.debug('Cached user permissions', {
        userId,
        permissionCount: permissions.length,
        correlationId: getCorrelationId(),
      });
    } catch (error) {
      safeLogger.error('Failed to cache user permissions', {
        userId,
        error: error.message,
        correlationId: getCorrelationId(),
      });
    }
  }

  /**
   * Invalidate user permissions cache
   * @param {string} userId - User ID
   * @returns {Promise<void>}
   */
  async invalidateUserPermissionsCache(userId) {
    try {
      await authCache.removeUserPermissions(userId);
      safeLogger.debug('Invalidated user permissions cache', {
        userId,
        correlationId: getCorrelationId(),
      });
    } catch (error) {
      safeLogger.error('Failed to invalidate user permissions cache', {
        userId,
        error: error.message,
        correlationId: getCorrelationId(),
      });
    }
  }

  /**
   * Validate role and type combination
   * @param {string} role - User role
   * @param {string} type - User type
   * @returns {Object} Validation result
   */
  validateRoleTypeCombination(role, type) {
    try {
      const validCombinations = {
        customer: ['customer'],
        vendor: ['vendor'],
        requirement_coordinator: ['staff'],
        admin: ['admin'],
        hr_admin: ['admin'],
        super_admin: ['admin'],
      };

      const allowedTypes = validCombinations[role];
      if (!allowedTypes || !allowedTypes.includes(type)) {
        return {
          isValid: false,
          error: `Invalid role-type combination: ${role} cannot be of type ${type}`,
        };
      }

      return { isValid: true };
    } catch (error) {
      safeLogger.error('Failed to validate role-type combination', {
        role,
        type,
        error: error.message,
        correlationId: getCorrelationId(),
      });
      return {
        isValid: false,
        error: 'Role-type validation failed',
      };
    }
  }

  /**
   * Get all available roles
   * @returns {Array} Array of available roles
   */
  getAvailableRoles() {
    return Object.keys(ROLE_PERMISSIONS);
  }

  /**
   * Get all available permissions
   * @returns {Array} Array of all available permissions
   */
  getAllPermissions() {
    const allPermissions = new Set();
    Object.values(ROLE_PERMISSIONS).forEach(permissions => {
      permissions.forEach(permission => {
        if (permission !== '*') {
          allPermissions.add(permission);
        }
      });
    });
    return Array.from(allPermissions);
  }

  /**
   * Check if role exists
   * @param {string} role - Role to check
   * @returns {boolean} Whether role exists
   */
  roleExists(role) {
    return Object.keys(ROLE_PERMISSIONS).includes(role);
  }

  /**
   * Get role hierarchy level
   * @param {string} role - Role to get level for
   * @returns {number} Hierarchy level
   */
  getRoleHierarchyLevel(role) {
    return ROLE_HIERARCHY[role] || 0;
  }
}

// Create singleton instance
const permissionService = new PermissionService();

export default permissionService;
// export { ROLE_PERMISSIONS, ROLE_HIERARCHY };
