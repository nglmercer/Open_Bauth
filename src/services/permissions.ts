// src/services/permissions.ts
import { getDatabase } from '../db/connection';
import type { 
  Role, 
  Permission, 
  CreateRoleData, 
  CreatePermissionData, 
  UpdatePermissionData,
  UpdateRoleData,
  AssignRoleData, 
  PermissionOptions,
  PermissionResult,
  RoleResult,
  AuthErrorType
} from '../types/auth';

/**
 * Permissions and role management service
 * Handles creation, assignment and verification of roles and permissions
 */
export class PermissionService {
  /**
   * Creates a new permission
   * @param data Permission data
   * @returns Resultado de la operación
   */
  async createPermission(data: CreatePermissionData): Promise<PermissionResult> {
    try {
      const db = getDatabase();

      // Validar datos
      const validation = this.validatePermissionData(data);
      if (!validation.isValid) {
        return {
          success: false,
          error: {
            type: 'VALIDATION_ERROR' as AuthErrorType,
            message: validation.error!
          }
        };
      }

      // Check if permission already exists
      const existingPermission = await this.findPermissionByName(data.name);
      if (existingPermission) {
        return {
          success: false,
          error: {
            type: 'VALIDATION_ERROR' as AuthErrorType,
            message: `Permission '${data.name}' already exists`
          }
        };
      }

      // Create permission
      const permissionId = crypto.randomUUID();
      const query = db.query(
        "INSERT INTO permissions (id, name, resource, action, description, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))"
      );
      query.run(permissionId, data.name, data.resource || 'default', data.action || 'read', data.description || null);

      // Get the created permission
      const permission = await this.findPermissionById(permissionId);
      if (!permission) {
        return {
          success: false,
          error: {
            type: 'DATABASE_ERROR' as AuthErrorType,
            message: 'Failed to create permission'
          }
        };
      }

      return {
        success: true,
        permission
      };
    } catch (error:any) {
      console.error('Error creating permission:', error);
      return {
        success: false,
        error: {
          type: 'DATABASE_ERROR' as AuthErrorType,
          message: `Failed to create permission: ${error.message}`
        }
      };
    }
  }

  /**
   * Creates a new role
   * @param data Role data
   * @returns Resultado de la operación
   */
  async createRole(data: CreateRoleData): Promise<RoleResult> {
    try {
      const db = getDatabase();

      // Validar datos
      const validation = this.validateRoleData(data);
      if (!validation.isValid) {
        return {
          success: false,
          error: {
            type: 'VALIDATION_ERROR' as AuthErrorType,
            message: validation.error!
          }
        };
      }

      // Check if role already exists
      const existingRole = await this.findRoleByName(data.name);
      if (existingRole) {
        return {
          success: false,
          error: {
            type: 'VALIDATION_ERROR' as AuthErrorType,
            message: `Role '${data.name}' already exists`
          }
        };
      }

      // Create role
      const roleId = crypto.randomUUID();
      const query = db.query(
        "INSERT INTO roles (id, name, description, is_active, created_at) VALUES (?, ?, ?, ?, datetime('now'))"
      );
      query.run(roleId, data.name, data.description || null, 1);

      // Assign permissions if provided
      if (data.permissions && data.permissions.length > 0) {
        const assignResult = await this.assignPermissionsToRole(roleId, data.permissions);
        if (!assignResult.success) {
          return assignResult;
        }
      }

      // Get the created role with permissions
      const role = await this.findRoleById(roleId, true);
      if (!role) {
        return {
          success: false,
          error: {
            type: 'DATABASE_ERROR' as AuthErrorType,
            message: 'Failed to create role'
          }
        };
      }

      return {
        success: true,
        role
      };
    } catch (error:any) {
      console.error('Error creating role:', error);
      return {
        success: false,
        error: {
          type: 'DATABASE_ERROR' as AuthErrorType,
          message: `Failed to create role: ${error.message}`
        }
      };
    }
  }

  /**
   * Assigns a role to a user
   * @param data Datos de asignación
   */
  async assignRoleToUser(data: AssignRoleData): Promise<PermissionResult> {
    try {
      const db = getDatabase();

      // Verify that user and role exist
      const userExists = await this.checkUserExists(data.userId);
      if (!userExists) {
        return {
          success: false,
          error: {
            type: 'NOT_FOUND_ERROR' as AuthErrorType,
            message: 'User not found'
          }
        };
      }

      const roleExists = await this.checkRoleExists(data.roleId);
      if (!roleExists) {
        return {
          success: false,
          error: {
            type: 'NOT_FOUND_ERROR' as AuthErrorType,
            message: 'Role not found'
          }
        };
      }

      // Check if assignment already exists
      const existingQuery = db.query(
        "SELECT id FROM user_roles WHERE user_id = ? AND role_id = ?"
      );
      const existingAssignment = existingQuery.all(data.userId, data.roleId) as any[];

      if (existingAssignment.length > 0) {
        return {
          success: false,
          error: {
            type: 'VALIDATION_ERROR' as AuthErrorType,
            message: 'User already has this role'
          }
        };
      }

      // Create assignment
      const insertQuery = db.query(
        "INSERT INTO user_roles (id, user_id, role_id, created_at) VALUES (?, ?, ?, datetime('now'))"
      );
      insertQuery.run(crypto.randomUUID(), data.userId, data.roleId);

      console.log(`✅ Role assigned to user: ${data.userId} -> ${data.roleId}`);
      return { success: true };
    } catch (error:any) {
      console.error('Error assigning role to user:', error);
      return {
        success: false,
        error: {
          type: 'DATABASE_ERROR' as AuthErrorType,
          message: `Failed to assign role: ${error.message}`
        }
      };
    }
  }

  /**
   * Removes a role from a user
   * @param userId User ID
   * @param roleId Role ID
   */
  async removeRoleFromUser(userId: string, roleId: string): Promise<PermissionResult> {
    try {
      const db = getDatabase();

      const query = db.query(
        "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?"
      );
      query.run(userId, roleId);

      console.log(`✅ Role removed from user: ${userId} -> ${roleId}`);
      return { success: true };
    } catch (error:any) {
      console.error('Error removing role from user:', error);
      return {
        success: false,
        error: {
          type: 'DATABASE_ERROR' as AuthErrorType,
          message: `Failed to remove role: ${error.message}`
        }
      };
    }
  }

  /**
   * Assigns permissions to a role
   * @param roleId Role ID
   * @param permissionIds Array of permission IDs
   */
  async assignPermissionsToRole(roleId: string, permissionIds: string[]): Promise<PermissionResult> {
    try {
      const db = getDatabase();

      // Verify that role exists
      const roleExists = await this.checkRoleExists(roleId);
      if (!roleExists) {
        return {
          success: false,
          error: {
            type: 'NOT_FOUND_ERROR' as AuthErrorType,
            message: 'Role not found'
          }
        };
      }

      // Verify that all permissions exist
      for (const permissionId of permissionIds) {
        const permissionExists = await this.checkPermissionExists(permissionId);
        if (!permissionExists) {
          return {
            success: false,
            error: {
              type: 'NOT_FOUND_ERROR' as AuthErrorType,
              message: `Permission not found: ${permissionId}`
            }
          };
        }
      }

      // Check duplicates and assign permissions
      for (const permissionId of permissionIds) {
        // Check if assignment already exists
        const existingQuery = db.query(
          "SELECT id FROM role_permissions WHERE role_id = ? AND permission_id = ?"
        );
        const existing = existingQuery.get(roleId, permissionId) as any;
        
        if (existing) {
          return {
            success: false,
            error: {
              type: 'VALIDATION_ERROR' as AuthErrorType,
              message: `Permission ${permissionId} is already assigned to role ${roleId}`
            }
          };
        }
        
        // Insert new assignment
        const insertQuery = db.query(
          "INSERT INTO role_permissions (id, role_id, permission_id, created_at) VALUES (?, ?, ?, datetime('now'))"
        );
        insertQuery.run(crypto.randomUUID(), roleId, permissionId);
      }

      return { success: true };
    } catch (error:any) {
      console.error('Error assigning permissions to role:', error);
      return {
        success: false,
        error: {
          type: 'DATABASE_ERROR' as AuthErrorType,
          message: `Failed to assign permissions: ${error.message}`
        }
      };
    }
  }

  /**
   * Assigns a specific permission to a role (individual method)
   * @param roleId Role ID
   * @param permissionId Permission ID
   */
  async assignPermissionToRole(roleId: string, permissionId: string): Promise<PermissionResult> {
    return this.assignPermissionsToRole(roleId, [permissionId]);
  }

  /**
   * Removes permissions from a role
   * @param roleId Role ID
   * @param permissionIds Array of permission IDs
   */
  async removePermissionsFromRole(roleId: string, permissionIds: string[]): Promise<PermissionResult> {
    try {
      const db = getDatabase();

      for (const permissionId of permissionIds) {
        const query = db.query(
          "DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?"
        );
        query.run(roleId, permissionId);
      }

      console.log(`✅ Permissions removed from role: ${roleId}`);
      return { success: true };
    } catch (error:any) {
      console.error('Error removing permissions from role:', error);
      return {
        success: false,
        error: {
          type: 'DATABASE_ERROR' as AuthErrorType,
          message: `Failed to remove permissions: ${error.message}`
        }
      };
    }
  }

  /**
   * Updates an existing permission
   * @param id Permission ID
   * @param data Update data
   */
  async updatePermission(id: string, data: UpdatePermissionData): Promise<PermissionResult> {
    try {
      const db = getDatabase();

      // Verify that permission exists
      const existingPermission = await this.findPermissionById(id);
      if (!existingPermission) {
        return {
          success: false,
          error: {
            type: 'NOT_FOUND_ERROR' as AuthErrorType,
            message: 'Permission not found'
          }
        };
      }

      // Verify that name is not in use by another permission
      if (data.name && data.name !== existingPermission.name) {
        const existingByName = await this.findPermissionByName(data.name);
        if (existingByName && existingByName.id !== id) {
          return {
            success: false,
            error: {
              type: 'VALIDATION_ERROR' as AuthErrorType,
              message: 'Permission name already exists'
            }
          };
        }
      }

      const query = db.query(
        "UPDATE permissions SET name = ?, resource = ?, action = ?, description = ? WHERE id = ?"
      );
      query.run(
        data.name || existingPermission.name,
        data.resource || existingPermission.resource,
        data.action || existingPermission.action,
        data.description !== undefined ? data.description : (existingPermission.description || null),
        id
      );

      const updatedPermission = await this.findPermissionById(id);
      console.log(`✅ Permission updated: ${updatedPermission?.name}`);
      
      return {
        success: true,
        permission: updatedPermission as Permission
      };
    } catch (error:any) {
      console.error('Error updating permission:', error);
      return {
        success: false,
        error: {
          type: 'DATABASE_ERROR' as AuthErrorType,
          message: `Failed to update permission: ${error.message}`
        }
      };
    }
  }

  /**
   * Deletes a permission
   * @param id Permission ID
   */
  async deletePermission(id: string): Promise<PermissionResult> {
    try {
      const db = getDatabase();

      // Verify that permission exists
      const existingPermission = await this.findPermissionById(id);
      if (!existingPermission) {
        return {
          success: false,
          error: {
            type: 'NOT_FOUND_ERROR' as AuthErrorType,
            message: 'Permission not found'
          }
        };
      }

      // Delete relationships first
      const deleteRelationsQuery = db.query(
        "DELETE FROM role_permissions WHERE permission_id = ?"
      );
      deleteRelationsQuery.run(id);

      // Delete the permission
      const deletePermissionQuery = db.query(
        "DELETE FROM permissions WHERE id = ?"
      );
      deletePermissionQuery.run(id);

      console.log(`✅ Permission deleted: ${existingPermission.name}`);
      return { success: true };
    } catch (error:any) {
      console.error('Error deleting permission:', error);
      return {
        success: false,
        error: {
          type: 'DATABASE_ERROR' as AuthErrorType,
          message: `Failed to delete permission: ${error.message}`
        }
      };
    }
  }

  /**
   * Updates an existing role
   * @param id Role ID
   * @param data Update data
   */
  async updateRole(id: string, data: UpdateRoleData): Promise<RoleResult> {
    try {
      const db = getDatabase();

      // Verify that role exists
      const existingRole = await this.findRoleById(id);
      if (!existingRole) {
        return {
          success: false,
          error: {
            type: 'NOT_FOUND_ERROR' as AuthErrorType,
            message: 'Role not found'
          }
        };
      }

      // Verify that name is not in use by another role
      if (data.name && data.name !== existingRole.name) {
        const existingByName = await this.findRoleByName(data.name);
        if (existingByName && existingByName.id !== id) {
          return {
            success: false,
            error: {
              type: 'VALIDATION_ERROR' as AuthErrorType,
              message: 'Role name already exists'
            }
          };
        }
      }

      const query = db.query(
        "UPDATE roles SET name = ?, description = ?, is_active = ? WHERE id = ?"
      );
      query.run(
        data.name || existingRole.name,
        data.description !== undefined ? data.description : (existingRole.description || null),
        data.isActive !== undefined ? (data.isActive ? 1 : 0) : (existingRole.isActive ? 1 : 0),
        id
      );

      const updatedRole = await this.findRoleById(id);
      console.log(`✅ Role updated: ${updatedRole?.name}`);
      
      return {
        success: true,
        role: updatedRole || undefined
      };
    } catch (error:any) {
      console.error('Error updating role:', error);
      return {
        success: false,
        error: {
          type: 'DATABASE_ERROR' as AuthErrorType,
          message: `Failed to update role: ${error.message}`
        }
      };
    }
  }

  /**
   * Deletes a role
   * @param id Role ID
   */
  async deleteRole(id: string): Promise<RoleResult> {
    try {
      const db = getDatabase();

      // Verify that role exists
      const existingRole = await this.findRoleById(id);
      if (!existingRole) {
        return {
          success: false,
          error: {
            type: 'NOT_FOUND_ERROR' as AuthErrorType,
            message: 'Role not found'
          }
        };
      }

      // Delete relationships with users
      const deleteUserRolesQuery = db.query(
        "DELETE FROM user_roles WHERE role_id = ?"
      );
      deleteUserRolesQuery.run(id);

      // Delete relationships with permissions
      const deleteRolePermissionsQuery = db.query(
        "DELETE FROM role_permissions WHERE role_id = ?"
      );
      deleteRolePermissionsQuery.run(id);

      // Delete the role
      const deleteRoleQuery = db.query(
        "DELETE FROM roles WHERE id = ?"
      );
      deleteRoleQuery.run(id);

      console.log(`✅ Role deleted: ${existingRole.name}`);
      return { success: true };
    } catch (error:any) {
      console.error('Error deleting role:', error);
      return {
        success: false,
        error: {
          type: 'DATABASE_ERROR' as AuthErrorType,
          message: `Failed to delete role: ${error.message}`
        }
      };
    }
  }

  /**
   * Removes a specific permission from a role
   * @param roleId Role ID
   * @param permissionId Permission ID
   */
  async removePermissionFromRole(roleId: string, permissionId: string): Promise<PermissionResult> {
    return this.removePermissionsFromRole(roleId, [permissionId]);
  }

  /**
   * Verifies if a user has a specific permission
   * @param userId User ID
   * @param permissionName Permission name
   * @param options Verification options
   * @returns true if user has the permission
   */
  async userHasPermission(
    userId: string, 
    permissionName: string, 
    options: PermissionOptions = {}
  ): Promise<boolean> {
    try {
      const db = getDatabase();

      // First check if user is active
      const userQuery = db.query(`
        SELECT is_active
        FROM users
        WHERE id = ?
      `);
      const userResult = userQuery.get(userId) as { is_active: number } | undefined;
      
      if (!userResult || !userResult.is_active) {
        return false;
      }

      // Check exact permission
      const exactQuery = db.query(`
        SELECT COUNT(*) as count
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        INNER JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = ? AND p.name = ?
      `);
      const exactResult = exactQuery.get(userId, permissionName) as { count: number };

      if (exactResult?.count > 0) {
        return true;
      }

      // Check wildcard permissions
      const wildcardQuery = db.query(`
        SELECT COUNT(*) as count
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        INNER JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = ? AND (p.name = '*:*' OR p.name = 'admin:*' OR p.resource = '*' OR p.action = '*')
      `);
      const wildcardResult = wildcardQuery.get(userId) as { count: number };

      return wildcardResult?.count > 0;
    } catch (error:any) {
      console.error('Error checking user permission:', error);
      return false;
    }
  }

  /**
   * Verifies if a user has a specific role
   * @param userId User ID
   * @param roleName Role name
   * @returns true if user has the role
   */
  async userHasRole(userId: string, roleName: string): Promise<boolean> {
    try {
      const db = getDatabase();
      
      const query = db.query(`
        SELECT COUNT(*) as count
        FROM user_roles ur
        INNER JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = ? AND r.name = ?
      `);
      
      const result = query.get(userId, roleName) as { count: number };
      
      return result?.count > 0;
    } catch (error:any) {
      console.error('Error checking user role:', error);
      return false;
    }
  }

  /**
   * Verifies if a user has all specified roles
   * @param userId User ID
   * @param roleNames Array of role names
   * @returns true if user has all roles
   */
  async userHasAllRoles(userId: string, roleNames: string[]): Promise<boolean> {
    try {
      for (const roleName of roleNames) {
        const hasRole = await this.userHasRole(userId, roleName);
        if (!hasRole) {
          return false;
        }
      }
      return true;
    } catch (error: any) {
      console.error('Error checking user roles:', error);
      return false;
    }
  }

  /**
   * Verifies if a user has at least one of the specified roles
   * @param userId User ID
   * @param roleNames Array of role names
   * @returns true if user has at least one role
   */
  async userHasAnyRole(userId: string, roleNames: string[]): Promise<boolean> {
    try {
      for (const roleName of roleNames) {
        const hasRole = await this.userHasRole(userId, roleName);
        if (hasRole) {
          return true;
        }
      }
      return false;
    } catch (error: any) {
      console.error('Error checking user roles:', error);
      return false;
    }
  }

  /**
   * Verifies if a user has all specified permissions
   * @param userId User ID
   * @param permissionNames Array of permission names
   * @returns true if user has all permissions
   */
  async userHasAllPermissions(userId: string, permissionNames: string[]): Promise<boolean> {
    try {
      for (const permissionName of permissionNames) {
        const hasPermission = await this.userHasPermission(userId, permissionName);
        if (!hasPermission) {
          return false;
        }
      }
      return true;
    } catch (error:any) {
      console.error('Error checking user permissions:', error);
      return false;
    }
  }

  /**
   * Verifies if a user has at least one of the specified permissions
   * @param userId User ID
   * @param permissionNames Array of permission names
   * @returns true if user has at least one permission
   */
  async userHasAnyPermission(userId: string, permissionNames: string[]): Promise<boolean> {
    try {
      for (const permissionName of permissionNames) {
        const hasPermission = await this.userHasPermission(userId, permissionName);
        if (hasPermission) {
          return true;
        }
      }
      return false;
    } catch (error:any) {
      console.error('Error checking user permissions:', error);
      return false;
    }
  }

  /**
   * Verifies if a user can access a specific resource
   * @param userId User ID
   * @param resource Resource name
   * @param action Action to perform (read, write, delete, etc.)
   * @returns true if user can access the resource
   */
  async userCanAccessResource(userId: string, resource: string, action: string): Promise<boolean> {
    try {
      const db = getDatabase();

      // Check exact permission
      const exactPermissionName = `${resource}:${action}`;
      const hasExactPermission = await this.userHasPermission(userId, exactPermissionName);
      
      if (hasExactPermission) {
        return true;
      }

      // Check specific wildcard permissions for resource and action
      const wildcardQuery = db.query(`
        SELECT COUNT(*) as count
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        INNER JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = ? AND (
          p.name = '*:*' OR 
          p.name = 'admin:*' OR 
          p.name = ? OR 
          p.name = ? OR 
          (p.resource = '*' AND p.action = '*') OR
          (p.resource = ? AND p.action = '*') OR
          (p.resource = '*' AND p.action = ?)
        )
      `);
      
      const wildcardResult = wildcardQuery.get(
        userId, 
        `${resource}:*`, 
        `*:${action}`, 
        resource, 
        action
      ) as { count: number };

      return wildcardResult?.count > 0;
    } catch (error:any) {
      console.error('Error checking resource access:', error);
      return false;
    }
  }

  /**
   * Verifies if a user has multiple permissions
   * @param userId User ID
   * @param permissionNames Array of permission names
   * @param options Verification options
   * @returns true if meets the criteria
   */
  async userHasPermissions(
    userId: string, 
    permissionNames: string[], 
    options: PermissionOptions = {}
  ): Promise<boolean> {
    try {
      if (permissionNames.length === 0) {
        return true;
      }

      const results = await Promise.all(
        permissionNames.map(permission => 
          this.userHasPermission(userId, permission, options)
        )
      );

      // If requireAll is true, all permissions must be present
      if (options.requireAll) {
        return results.every(result => result);
      }

      // By default, only one is required (OR)
      return results.some(result => result);
    } catch (error:any) {
      console.error('Error checking user permissions:', error);
      return false;
    }
  }

  /**
   * Gets all permissions for a user
   * @param userId User ID
   * @returns Array of permissions
   */
  async getUserPermissions(userId: string): Promise<Permission[]> {
    try {
      const db = getDatabase();

      const query = db.query(`
        SELECT DISTINCT p.id, p.name, p.resource, p.action, p.description, p.created_at
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        INNER JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = ?
        ORDER BY p.resource, p.action
      `);
      const result = query.all(userId) as any[];

      return result.map((row: any) => ({
        id: row.id,
        name: row.name,
        resource: row.resource,
        action: row.action,
        description: row.description,
        createdAt: new Date(row.created_at),
        updatedAt: new Date(row.created_at)
      }));
    } catch (error:any) {
      console.error('Error getting user permissions:', error);
      throw new Error(`Failed to get user permissions: ${error.message}`);
    }
  }

  /**
   * Finds a permission by ID
   * @param id Permission ID
   * @returns Permission or null
   */
  async findPermissionById(id: string): Promise<Permission | null> {
    try {
      const db = getDatabase();

      const query = db.query(
        "SELECT id, name, resource, action, description, created_at FROM permissions WHERE id = ?"
      );
      const result = query.get(id) as any;

      if (!result) {
        return null;
      }

      return {
        id: result.id,
        name: result.name,
        resource: result.resource,
        action: result.action,
        description: result.description,
        createdAt: new Date(result.created_at),
        updatedAt: new Date(result.created_at)
      };
    } catch (error:any) {
      console.error('Error finding permission by ID:', error);
      return null;
    }
  }

  /**
   * Finds a permission by name
   * @param name Permission name
   * @returns Permission or null
   */
  async findPermissionByName(name: string): Promise<Permission | null> {
    try {
      const db = getDatabase();

      const query = db.query(
        "SELECT id, name, resource, action, description, created_at FROM permissions WHERE name = ?"
      );
      const result = query.get(name) as any;

      if (!result) {
        return null;
      }

      return {
        id: result.id,
        name: result.name,
        resource: result.resource,
        action: result.action,
        description: result.description,
        createdAt: new Date(result.created_at),
        updatedAt: new Date(result.created_at)
      };
    } catch (error:any) {
      console.error('Error finding permission by name:', error);
      return null;
    }
  }

  /**
   * Finds a role by ID
   * @param id Role ID
   * @param includePermissions Whether to include permissions
   * @returns Role or null
   */
  async findRoleById(id: string, includePermissions: boolean = false): Promise<Role | null> {
    try {
      const db = getDatabase();

      const query = db.query(
        "SELECT id, name, description, created_at, is_active FROM roles WHERE id = ?"
      );
      const result = query.get(id) as any;

      if (!result) {
        return null;
      }

      const role: Role = {
        id: result.id,
        name: result.name,
        description: result.description,
        createdAt: new Date(result.created_at),
        updatedAt: new Date(result.created_at),
        isDefault: Boolean(result.is_active),
        isActive: Boolean(result.is_active),
        permissions: []
      };

      if (includePermissions) {
        role.permissions = await this.getRolePermissions(id);
      }

      return role;
    } catch (error:any) {
      console.error('Error finding role by ID:', error);
      return null;
    }
  }

  /**
   * Finds a role by name
   * @param name Role name
   * @param includePermissions Whether to include permissions
   * @returns Role or null
   */
  async findRoleByName(name: string, includePermissions: boolean = false): Promise<Role | null> {
    try {
      const db = getDatabase();

      const query = db.query(
        "SELECT id, name, description, created_at, is_active FROM roles WHERE name = ?"
      );
      const result = query.get(name) as any;

      if (!result) {
        return null;
      }

      const role: Role = {
        id: result.id,
        name: result.name,
        description: result.description,
        createdAt: new Date(result.created_at),
        updatedAt: new Date(result.created_at),
        isDefault: Boolean(result.is_active),
        isActive: Boolean(result.is_active),
        permissions: []
      };

      if (includePermissions) {
        role.permissions = await this.getRolePermissions(result.id);
      }

      return role;
    } catch (error:any) {
      console.error('Error finding role by name:', error);
      return null;
    }
  }

  /**
   * Gets permissions for a role
   * @param roleId Role ID
   * @returns Array of permissions
   */
  async getRolePermissions(roleId: string): Promise<Permission[]> {
    try {
      const db = getDatabase();

      const result = db.query(`
        SELECT p.id, p.name, p.resource, p.action, p.description, p.created_at
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = ?
        ORDER BY p.resource, p.action
      `).all(roleId);

      return result.map((row: any) => ({
        id: row.id,
        name: row.name,
        resource: row.resource,
        action: row.action,
        description: row.description,
        createdAt: new Date(row.created_at),
        updatedAt: new Date(row.created_at)
      }));
    } catch (error:any) {
      console.error('Error getting role permissions:', error);
      return [];
    }
  }

  /**
   * Gets all roles
   * @param includePermissions Whether to include permissions
   * @returns Array of roles
   */
  async getAllRoles(includePermissions: boolean = false): Promise<Role[]> {
    try {
      const db = getDatabase();

      const query = db.query(`
        SELECT id, name, description, created_at, is_active
        FROM roles
        ORDER BY name
      `);
      const result = query.all() as any[];

      const roles = [];
      for (const row of result as any[]) {
        const role: Role = {
          id: row.id,
          name: row.name,
          description: row.description,
          createdAt: new Date(row.created_at),
          updatedAt: new Date(row.created_at),
          isDefault: Boolean(row.is_active),
          isActive: Boolean(row.is_active),
          permissions: []
        };

        if (includePermissions) {
          role.permissions = await this.getRolePermissions(row.id);
        }

        roles.push(role);
      }

      return roles;
    } catch (error:any) {
      console.error('Error getting all roles:', error);
      throw new Error(`Failed to get roles: ${error.message}`);
    }
  }

  /**
   * Gets all permissions
   * @returns Array of permissions
   */
  async getAllPermissions(): Promise<Permission[]> {
    try {
      const db = getDatabase();

      const query = db.query(`
        SELECT id, name, resource, action, description, created_at
        FROM permissions
        ORDER BY resource, action
      `);
      const result = query.all() as any[];

      return result.map((row: any) => ({
        id: row.id,
        name: row.name,
        resource: row.resource,
        action: row.action,
        description: row.description,
        createdAt: new Date(row.created_at),
        updatedAt: new Date(row.created_at)
      }));
    } catch (error:any) {
      console.error('Error getting all permissions:', error);
      throw new Error(`Failed to get permissions: ${error.message}`);
    }
  }

  // Private validation and utility methods

  private validatePermissionData(data: CreatePermissionData): { isValid: boolean; error?: string } {
    if (!data.name || !data.resource || !data.action) {
      return {
        isValid: false,
        error: 'Name, resource, and action are required'
      };
    }

    if (data.name.length < 3) {
      return {
        isValid: false,
        error: 'Permission name must be at least 3 characters long'
      };
    }

    return { isValid: true };
  }

  private validateRoleData(data: CreateRoleData): { isValid: boolean; error?: string } {
    if (!data.name) {
      return {
        isValid: false,
        error: 'Role name is required'
      };
    }

    if (data.name.length < 3) {
      return {
        isValid: false,
        error: 'Role name must be at least 3 characters long'
      };
    }

    return { isValid: true };
  }

  private async checkUserExists(userId: string): Promise<boolean> {
    try {
      const db = getDatabase();
      const query = db.query("SELECT id FROM users WHERE id = ?");
      const result = query.get(userId) as any;
      return !!result;
    } catch (error:any) {
      console.error('Error checking user existence:', error);
      return false;
    }
  }

  private async checkRoleExists(roleId: string): Promise<boolean> {
    try {
      const db = getDatabase();
      const query = db.query("SELECT id FROM roles WHERE id = ?");
      const result = query.get(roleId) as any;
      return !!result;
    } catch (error:any) {
      console.error('Error checking role existence:', error);
      return false;
    }
  }

  private async checkPermissionExists(permissionId: string): Promise<boolean> {
    try {
      const db = getDatabase();
      const query = db.query("SELECT id FROM permissions WHERE id = ?");
      const result = query.get(permissionId) as any;
      return !!result;
    } catch (error:any) {
      console.error('Error checking permission existence:', error);
      return false;
    }
  }
}

/**
 * Singleton instance of the permission service
 */
let permissionServiceInstance: PermissionService | null = null;

/**
 * Initializes the permission service
 * @returns Permission service instance
 */
export function initPermissionService(): PermissionService {
  permissionServiceInstance = new PermissionService();
  return permissionServiceInstance;
}

/**
 * Gets the permission service instance
 * @returns Permission service instance
 * @throws Error if not initialized
 */
export function getPermissionService(): PermissionService {
  if (!permissionServiceInstance) {
    throw new Error('Permission Service not initialized. Call initPermissionService() first.');
  }
  return permissionServiceInstance;
}