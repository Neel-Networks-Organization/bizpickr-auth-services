/**
 * Permission Service Unit Tests
 *
 * Tests for the permission service functionality:
 * - Role-based permissions
 * - Permission validation
 * - Access control
 * - Role hierarchy
 */

import { jest } from '@jest/globals';
import permissionService, {
  ROLE_PERMISSIONS,
  ROLE_HIERARCHY,
} from '../../../src/services/permission.service.js';

describe('PermissionService', () => {
  describe('getUserPermissions', () => {
    it('should return permissions for valid role', () => {
      const permissions = permissionService.getUserPermissions('customer');
      expect(permissions).toEqual([
        'lead:submit',
        'chat:send',
        'review:write',
        'proposal:accept',
        'profile:view',
        'profile:edit',
      ]);
    });

    it('should return empty array for invalid role', () => {
      const permissions = permissionService.getUserPermissions('invalid_role');
      expect(permissions).toEqual([]);
    });

    it('should return all permissions for super_admin', () => {
      const permissions = permissionService.getUserPermissions('super_admin');
      expect(permissions).toEqual(['*']);
    });
  });

  describe('hasPermission', () => {
    it('should return true for valid permission', () => {
      const hasPermission = permissionService.hasPermission(
        'customer',
        'lead:submit'
      );
      expect(hasPermission).toBe(true);
    });

    it('should return false for invalid permission', () => {
      const hasPermission = permissionService.hasPermission(
        'customer',
        'invalid:permission'
      );
      expect(hasPermission).toBe(false);
    });

    it('should return true for super_admin with any permission', () => {
      const hasPermission = permissionService.hasPermission(
        'super_admin',
        'any:permission'
      );
      expect(hasPermission).toBe(true);
    });
  });

  describe('canAccessRole', () => {
    it('should return true for higher level role accessing lower level', () => {
      const canAccess = permissionService.canAccessRole('admin', 'customer');
      expect(canAccess).toBe(true);
    });

    it('should return false for lower level role accessing higher level', () => {
      const canAccess = permissionService.canAccessRole('customer', 'admin');
      expect(canAccess).toBe(false);
    });

    it('should return true for same level role', () => {
      const canAccess = permissionService.canAccessRole('admin', 'admin');
      expect(canAccess).toBe(true);
    });
  });

  describe('validateRoleTypeCombination', () => {
    it('should return valid for correct combination', () => {
      const result = permissionService.validateRoleTypeCombination(
        'customer',
        'customer'
      );
      expect(result.isValid).toBe(true);
    });

    it('should return invalid for incorrect combination', () => {
      const result = permissionService.validateRoleTypeCombination(
        'customer',
        'admin'
      );
      expect(result.isValid).toBe(false);
      expect(result.error).toContain('Invalid role-type combination');
    });
  });

  describe('getAvailableRoles', () => {
    it('should return all available roles', () => {
      const roles = permissionService.getAvailableRoles();
      expect(roles).toContain('customer');
      expect(roles).toContain('vendor');
      expect(roles).toContain('manager');
      expect(roles).toContain('admin');
      expect(roles).toContain('hr_admin');
      expect(roles).toContain('super_admin');
    });
  });

  describe('getAllPermissions', () => {
    it('should return all unique permissions', () => {
      const permissions = permissionService.getAllPermissions();
      expect(permissions).toContain('lead:submit');
      expect(permissions).toContain('chat:send');
      expect(permissions).toContain('profile:view');
      expect(permissions).not.toContain('*'); // Wildcard should not be included
    });
  });

  describe('roleExists', () => {
    it('should return true for existing role', () => {
      const exists = permissionService.roleExists('customer');
      expect(exists).toBe(true);
    });

    it('should return false for non-existing role', () => {
      const exists = permissionService.roleExists('invalid_role');
      expect(exists).toBe(false);
    });
  });

  describe('getRoleHierarchyLevel', () => {
    it('should return correct hierarchy level', () => {
      const level = permissionService.getRoleHierarchyLevel('admin');
      expect(level).toBe(5);
    });

    it('should return 0 for non-existing role', () => {
      const level = permissionService.getRoleHierarchyLevel('invalid_role');
      expect(level).toBe(0);
    });
  });

  describe('ROLE_PERMISSIONS', () => {
    it('should have correct structure', () => {
      expect(ROLE_PERMISSIONS).toHaveProperty('customer');
      expect(ROLE_PERMISSIONS).toHaveProperty('vendor');
      expect(ROLE_PERMISSIONS).toHaveProperty('manager');
      expect(ROLE_PERMISSIONS).toHaveProperty('admin');
      expect(ROLE_PERMISSIONS).toHaveProperty('hr_admin');
      expect(ROLE_PERMISSIONS).toHaveProperty('super_admin');
    });
  });

  describe('ROLE_HIERARCHY', () => {
    it('should have correct hierarchy levels', () => {
      expect(ROLE_HIERARCHY.customer).toBe(1);
      expect(ROLE_HIERARCHY.vendor).toBe(2);
      expect(ROLE_HIERARCHY.manager).toBe(4);
      expect(ROLE_HIERARCHY.admin).toBe(5);
      expect(ROLE_HIERARCHY.hr_admin).toBe(6);
      expect(ROLE_HIERARCHY.super_admin).toBe(7);
    });
  });
});
