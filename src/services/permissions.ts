// src/services/permissions.ts
import { getDatabase } from '../db/connection';
import { withTransaction } from '../database/transaction';
import { AuthErrorFactory } from '../errors/auth';
import { defaultLogger as logger } from '../logger';
// Logger interface for dependency injection
interface Logger {
  info(message: string, meta?: any): void;
  warn(message: string, meta?: any): void;
  error(message: string, meta?: any): void;
  debug(message: string, meta?: any): void;
}
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
  AuthErrorType,
  User,
} from '../types/auth';
import type { DatabaseTransaction } from '../types/common';
import type { Database } from 'bun:sqlite';

/**
 * Cache interface for permissions and roles
 */
interface PermissionCache {
  permissions: Map<string, Permission>;
  roles: Map<string, Role>;
  userPermissions: Map<string, Permission[]>;
  userRoles: Map<string, Role[]>;
  lastClearTime: number;
}

/**
   * Enhanced permissions and role management service
   * Handles creation, assignment and verification of roles and permissions
   * with transaction support, caching, and optimized queries
   */
  export class PermissionService {
  cache: PermissionCache;
  readonly CACHE_TTL = 5 * 60 * 1000; // 5 minutes
  readonly MAX_BATCH_SIZE = 100;
  logger: Logger;
  performanceMetrics: Map<string, { count: number; totalTime: number; avgTime: number }> = new Map();

  constructor(defaultLogger?: Logger) {
    this.cache = {
      permissions: new Map(),
      roles: new Map(),
      userPermissions: new Map(),
      userRoles: new Map(),
      lastClearTime: Date.now()
    };
    this.logger = defaultLogger || logger;
    this.logger.info('PermissionService initialized');
  }

  /**
   * Creates a new permission with transaction support
   * @param data Permission data
   * @param transaction Optional transaction
   * @returns Operation result
   */
  async createPermission(
    data: CreatePermissionData, 
    transaction?: DatabaseTransaction
  ): Promise<PermissionResult> {
    const startTime = Date.now();
    const operationId = `create-permission-${Date.now()}`;
    
    this.logger.info('Creating permission', { 
      operationId, 
      permissionName: data.name, 
      resource: data.resource, 
      action: data.action 
    });
    
    const operation = async (tx?: DatabaseTransaction) => {
      try {
        const db = tx?.getDatabase() || getDatabase();

        // Validate input data
        const validation = this.validatePermissionData(data);
        if (!validation.isValid) {
          throw AuthErrorFactory.validation(validation.error!, 'permission');
        }

        // Check if permission already exists
        const existingPermission = await this.findPermissionByName(data.name, tx);
        if (existingPermission) {
          throw AuthErrorFactory.validation(`Permission '${data.name}' already exists`, 'name');
        }

        // Create permission
        const permissionId = crypto.randomUUID();
        const query = db.query(
          "INSERT INTO permissions (id, name, resource, action, description, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))"
        );
        query.run(
          permissionId, 
          data.name, 
          data.resource || 'default', 
          data.action || 'read', 
          data.description || null
        );

        // Get the created permission
        const permission = await this.findPermissionById(permissionId, tx);
        if (!permission) {
          throw AuthErrorFactory.database('Failed to create permission', 'createPermission');
        }

        // Clear cache
        this.clearCache();

        const duration = Date.now() - startTime;
        this.updatePerformanceMetrics('createPermission', duration);
        
        this.logger.info('Permission created successfully', {
          operationId,
          permissionId: permission.id,
          duration: `${duration}ms`
        });

        return {
          success: true,
          permission
        };
      } catch (error: any) {
        const duration = Date.now() - startTime;
        
        this.logger.error('Failed to create permission', {
          operationId,
          error: error instanceof Error ? error.message : String(error),
          duration: `${duration}ms`,
          permissionData: data
        });
        
        if (error.type) {
          return {
            success: false,
            error
          };
        }
        throw AuthErrorFactory.fromUnknown(error, 'Failed to create permission');
      }
    };

    if (transaction) {
      return operation(transaction);
    }
    
    try {
      logger.info('🔍 DEBUG: About to call withTransaction for createPermission');
      const result = await withTransaction(async (tx) => {
        logger.info('🔍 DEBUG: Inside withTransaction callback for createPermission');
        const opResult = await operation(tx);
        logger.info('🔍 DEBUG: Operation result:', opResult);
        return opResult;
      });
      logger.info('🔍 DEBUG: withTransaction returned:', result);
      return result;
    } catch (error) {
      logger.info('🔍 DEBUG: withTransaction threw error:', {error});
      throw error;
    }
  }

  /**
   * Creates a new role with transaction support
   * @param data Role data
   * @param transaction Optional transaction
   * @returns Operation result
   */
  async createRole(
    data: CreateRoleData, 
    transaction?: DatabaseTransaction
  ): Promise<RoleResult> {
    const startTime = Date.now();
    const operationId = `create-role-${Date.now()}`;
    
    this.logger.info('Creating role', { 
      operationId, 
      roleName: data.name, 
      description: data.description 
    });
    
    const operation = async (tx?: DatabaseTransaction) => {
      try {
        const db = tx?.getDatabase() || getDatabase();

        // Validate input data
        const validation = this.validateRoleData(data);
        if (!validation.isValid) {
          throw AuthErrorFactory.validation(validation.error!, 'role');
        }

        // Check if role already exists
        const existingRole = await this.findRoleByName(data.name, false, tx);
        if (existingRole) {
          throw AuthErrorFactory.validation(`Role '${data.name}' already exists`, 'name');
        }

        // Create role
        const roleId = crypto.randomUUID();
        const query = db.query(
          "INSERT INTO roles (id, name, description, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))"
        );
        query.run(roleId, data.name, data.description || null, 1);

        // Assign permissions if provided
        if (data.permissions && data.permissions.length > 0) {
          const assignResult = await this.assignPermissionsToRole(roleId, data.permissions, tx);
          if (!assignResult.success) {
            throw assignResult.error;
          }
        }

        // Get the created role with permissions
        const role = await this.findRoleById(roleId, true, tx);
        if (!role) {
          throw AuthErrorFactory.database('Failed to create role', 'createRole');
        }

        // Clear cache
        this.clearCache();

        const duration = Date.now() - startTime;
        this.updatePerformanceMetrics('createRole', duration);
        
        this.logger.info('Role created successfully', {
          operationId,
          roleId: role.id,
          duration: `${duration}ms`
        });

        return {
          success: true,
          role
        };
      } catch (error: any) {
        const duration = Date.now() - startTime;
        
        this.logger.error('Failed to create role', {
          operationId,
          error: error instanceof Error ? error.message : String(error),
          duration: `${duration}ms`,
          roleData: data
        });
        
        if (error.type) {
          return {
            success: false,
            error
          };
        }
        throw AuthErrorFactory.fromUnknown(error, 'Failed to create role');
      }
    };

    if (transaction) {
      return operation(transaction);
    }
    
    return withTransaction(async (tx) => operation(tx));
  }

  /**
   * Assigns a role to a user with transaction support
   * @param data Assignment data
   * @param transaction Optional transaction
   */
  async assignRoleToUser(
    data: AssignRoleData, 
    transaction?: DatabaseTransaction
  ): Promise<PermissionResult> {
    const startTime = Date.now();
    const operationId = `assign-role-${Date.now()}`;
    
    this.logger.info('Assigning role to user', { 
      operationId, 
      userId: data.userId, 
      roleId: data.roleId 
    });
    
    const operation = async (tx?: DatabaseTransaction) => {
      try {
        const db = tx?.getDatabase() || getDatabase();

        // Verify that user and role exist
        const [userExists, roleExists] = await Promise.all([
          this.checkUserExists(data.userId, tx),
          this.checkRoleExists(data.roleId, tx)
        ]);

        if (!userExists) {
          throw AuthErrorFactory.userNotFound('User not found');
        }

        if (!roleExists) {
          throw AuthErrorFactory.notFound('Role not found');
        }

        // Check if assignment already exists
        const existingQuery = db.query(
          "SELECT id FROM user_roles WHERE user_id = ? AND role_id = ?"
        );
        const existingAssignment = existingQuery.get(data.userId, data.roleId);

        if (existingAssignment) {
          throw AuthErrorFactory.validation('User already has this role', 'assignment');
        }

        // Create assignment
        const insertQuery = db.query(
          "INSERT INTO user_roles (id, user_id, role_id, created_at) VALUES (?, ?, ?, datetime('now'))"
        );
        insertQuery.run(crypto.randomUUID(), data.userId, data.roleId);

        // Clear user cache
        this.clearUserCache(data.userId);

        const duration = Date.now() - startTime;
        this.updatePerformanceMetrics('assignRoleToUser', duration);
        
        this.logger.info('Role assigned to user successfully', {
          operationId,
          userId: data.userId,
          roleId: data.roleId,
          duration: `${duration}ms`
        });

        return { success: true };
      } catch (error: any) {
        const duration = Date.now() - startTime;
        
        this.logger.error('Failed to assign role to user', {
          operationId,
          userId: data.userId,
          roleId: data.roleId,
          error: error instanceof Error ? error.message : String(error),
          duration: `${duration}ms`
        });
        
        if (error.type) {
          return {
            success: false,
            error
          };
        }
        throw AuthErrorFactory.fromUnknown(error, 'Failed to assign role');
      }
    };

    if (transaction) {
      return operation(transaction);
    }
    
    return withTransaction(async (tx) => operation(tx));
  }

  /**
   * Assigns multiple permissions to a role with transaction support
   * @param roleId Role ID
   * @param permissionIds Array of permission IDs
   * @param transaction Optional transaction
   */
  async assignPermissionsToRole(
    roleId: string, 
    permissionIds: string[], 
    transaction?: DatabaseTransaction
  ): Promise<PermissionResult> {
    const operation = async (tx?: DatabaseTransaction) => {
      try {
        const db = tx?.getDatabase() || getDatabase();

        // Validate batch size
        if (permissionIds.length > this.MAX_BATCH_SIZE) {
          throw AuthErrorFactory.validation(`Cannot assign more than ${this.MAX_BATCH_SIZE} permissions at once`, 'batchSize');
        }

        // Verify that role exists
        const roleExists = await this.checkRoleExists(roleId, tx);
        if (!roleExists) {
          throw AuthErrorFactory.notFound('Role not found');
        }

        // Verify that all permissions exist in batch
        const permissionCheckQuery = db.query(
          `SELECT id FROM permissions WHERE id IN (${permissionIds.map(() => '?').join(',')})`
        );
        const existingPermissions = permissionCheckQuery.all(...permissionIds) as Array<{ id: string }>;
        
        if (existingPermissions.length !== permissionIds.length) {
          const existingIds = new Set(existingPermissions.map(p => p.id));
          const missingIds = permissionIds.filter(id => !existingIds.has(id));
          throw AuthErrorFactory.notFound(`Permissions not found: ${missingIds.join(', ')}`);
        }

        // Check for existing assignments in batch
        const existingQuery = db.query(
          `SELECT permission_id FROM role_permissions WHERE role_id = ? AND permission_id IN (${permissionIds.map(() => '?').join(',')})`
        );
        const existingAssignments = existingQuery.all(roleId, ...permissionIds) as Array<{ permission_id: string }>;
        
        if (existingAssignments.length > 0) {
          const duplicateIds = existingAssignments.map(a => a.permission_id);
          throw AuthErrorFactory.validation(`Permissions already assigned: ${duplicateIds.join(', ')}`, 'duplicateAssignment');
        }

        // Insert all assignments in batch
        const insertQuery = db.query(
          "INSERT INTO role_permissions (id, role_id, permission_id, created_at) VALUES (?, ?, ?, datetime('now'))"
        );
        
        for (const permissionId of permissionIds) {
          insertQuery.run(crypto.randomUUID(), roleId, permissionId);
        }

        // Clear cache
        this.clearCache();

        return { success: true };
      } catch (error: any) {
        if (error.type) {
          return {
            success: false,
            error
          };
        }
        throw AuthErrorFactory.fromUnknown(error, 'Failed to assign permissions');
      }
    };

    if (transaction) {
      return operation(transaction);
    }
    
    return withTransaction(async (tx) => operation(tx));
  }

  /**
   * Replaces all permissions for a role with a new set of permissions
   * @param roleId Role ID
   * @param permissionIds Array of permission IDs to replace existing ones
   * @param transaction Optional transaction
   */
  async replaceRolePermissions(
    roleId: string,
    permissionIds: string[],
    transaction?: DatabaseTransaction
  ): Promise<PermissionResult> {
    const startTime = Date.now();
    const operationId = `replace-role-permissions-${Date.now()}`;
    
    this.logger.info('Replacing role permissions', { operationId, roleId, permissionCount: permissionIds.length });
    
    const operation = async (tx?: DatabaseTransaction) => {
      try {
        const db = tx?.getDatabase() || getDatabase();

        // Validate batch size
        if (permissionIds.length > this.MAX_BATCH_SIZE) {
          throw AuthErrorFactory.validation(`Cannot assign more than ${this.MAX_BATCH_SIZE} permissions at once`, 'batchSize');
        }

        // Verify that role exists
        const roleExists = await this.checkRoleExists(roleId, tx);
        if (!roleExists) {
          throw AuthErrorFactory.notFound('Role not found');
        }

        // Verify that all permissions exist in batch (if any provided)
        if (permissionIds.length > 0) {
          const permissionCheckQuery = db.query(
            `SELECT id FROM permissions WHERE id IN (${permissionIds.map(() => '?').join(',')})`
          );
          const existingPermissions = permissionCheckQuery.all(...permissionIds) as Array<{ id: string }>;
          
          if (existingPermissions.length !== permissionIds.length) {
            const existingIds = new Set(existingPermissions.map(p => p.id));
            const missingIds = permissionIds.filter(id => !existingIds.has(id));
            throw AuthErrorFactory.notFound(`Permissions not found: ${missingIds.join(', ')}`);
          }
        }

        // Remove all existing permissions for the role
        const deleteQuery = db.query(
          "DELETE FROM role_permissions WHERE role_id = ?"
        );
        deleteQuery.run(roleId);

        // Insert new permissions (if any provided)
        if (permissionIds.length > 0) {
          const insertQuery = db.query(
            "INSERT INTO role_permissions (id, role_id, permission_id, created_at) VALUES (?, ?, ?, datetime('now'))"
          );
          
          for (const permissionId of permissionIds) {
            insertQuery.run(crypto.randomUUID(), roleId, permissionId);
          }
        }

        // Clear cache
        this.clearCache();

        const duration = Date.now() - startTime;
        this.updatePerformanceMetrics('replaceRolePermissions', duration);
        
        this.logger.info('Role permissions replaced successfully', {
          operationId,
          roleId,
          permissionCount: permissionIds.length,
          duration: `${duration}ms`
        });

        return { success: true };
      } catch (error: any) {
        const duration = Date.now() - startTime;
        
        this.logger.error('Failed to replace role permissions', {
          operationId,
          roleId,
          permissionCount: permissionIds.length,
          error: error instanceof Error ? error.message : String(error),
          duration: `${duration}ms`
        });
        
        if (error.type) {
          return {
            success: false,
            error
          };
        }
        throw AuthErrorFactory.fromUnknown(error, 'Failed to replace role permissions');
      }
    };

    if (transaction) {
      return operation(transaction);
    }
    
    return withTransaction(async (tx) => operation(tx));
  }

  /**
   * Optimized permission checking with caching
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
    const startTime = Date.now();
    const operationId = `check-permission-${Date.now()}`;
    
    this.logger.debug('Checking user permission', { operationId, userId, permissionName });
    
    try {
      // Check cache first
      const cacheKey = `${userId}:${permissionName}`;
      if (this.isCacheValid()) {
        const cachedPermissions = this.cache.userPermissions.get(userId);
        if (cachedPermissions) {
          const hasPermission = cachedPermissions.some(p => 
            p.name === permissionName || 
            p.name === '*:*' || 
            p.name === 'admin:*' ||
            this.matchesWildcard(p, permissionName)
          );
          return hasPermission;
        }
      }

      const db = getDatabase();

      // Single optimized query to check user permission
      const query = db.query(`
        SELECT COUNT(*) as count
        FROM users u
        INNER JOIN user_roles ur ON u.id = ur.user_id
        INNER JOIN roles r ON ur.role_id = r.id AND r.is_active = 1
        INNER JOIN role_permissions rp ON r.id = rp.role_id
        INNER JOIN permissions p ON rp.permission_id = p.id
        WHERE u.id = ? AND u.is_active = 1 AND (
          p.name = ? OR 
          p.name = '*:*' OR 
          p.name = 'admin:*' OR
          p.resource = '*' OR 
          p.action = '*' OR
          p.name LIKE ? OR
          p.name LIKE ?
        )
      `);
      
      const [resource, action] = permissionName.split(':');
      const result = query.get(
        userId, 
        permissionName, 
        `${resource}:*`, 
        `*:${action || '*'}`
      ) as { count: number };

      return result?.count > 0;
    } catch (error: any) {
      const duration = Date.now() - startTime;
      const authError = AuthErrorFactory.fromUnknown(error, 'Permission check failed');
      
      this.logger.error('Error checking user permission', {
        operationId,
        userId,
        permissionName,
        error: authError.message,
        duration: `${duration}ms`
      });
      
      return false;
    } finally {
      const duration = Date.now() - startTime;
      this.updatePerformanceMetrics('userHasPermission', duration);
    }
  }

  /**
   * Batch permission checking for multiple users
   * @param userIds Array of user IDs
   * @param permissionName Permission name
   * @returns Map of userId to boolean
   */
  async usersHavePermission(
    userIds: string[], 
    permissionName: string
  ): Promise<Map<string, boolean>> {
    const results = new Map<string, boolean>();
    
    if (userIds.length === 0) {
      return results;
    }

    try {
      const db = getDatabase();
      const placeholders = userIds.map(() => '?').join(',');
      
      const query = db.query(`
        SELECT DISTINCT u.id
        FROM users u
        INNER JOIN user_roles ur ON u.id = ur.user_id
        INNER JOIN roles r ON ur.role_id = r.id AND r.is_active = 1
        INNER JOIN role_permissions rp ON r.id = rp.role_id
        INNER JOIN permissions p ON rp.permission_id = p.id
        WHERE u.id IN (${placeholders}) AND u.is_active = 1 AND (
          p.name = ? OR 
          p.name = '*:*' OR 
          p.name = 'admin:*' OR
          p.resource = '*' OR 
          p.action = '*'
        )
      `);
      
      const usersWithPermission = query.all(...userIds, permissionName) as Array<{ id: string }>;
      const allowedUserIds = new Set(usersWithPermission.map(u => u.id));
      
      // Set results for all users
      for (const userId of userIds) {
        results.set(userId, allowedUserIds.has(userId));
      }
      
      return results;
    } catch (error: any) {
      console.error('Error checking batch user permissions:', AuthErrorFactory.fromUnknown(error, 'Batch permission check failed'));
      // Return false for all users on error
      for (const userId of userIds) {
        results.set(userId, false);
      }
      return results;
    }
  }

  /**
   * Get all permissions from the database
   * @param transaction Optional transaction
   * @returns Array of all permissions
   */
  async getAllPermissions(transaction?: DatabaseTransaction): Promise<Permission[]> {
    try {
      const db = transaction?.getDatabase() || getDatabase();
      
      const query = db.query(
        "SELECT id, name, resource, action, description, created_at FROM permissions ORDER BY name"
      );
      
      const permissionsData = query.all() as any[];
      return permissionsData.map(permData => ({
        id: permData.id,
        name: permData.name,
        resource: permData.resource,
        action: permData.action,
        description: permData.description,
        createdAt: permData.created_at,
        updatedAt: permData.updated_at
      }));
    } catch (error: any) {
      this.logger.error('Error getting all permissions:', AuthErrorFactory.fromUnknown(error, 'Failed to get all permissions'));
      return [];
    }
  }

  /**
   * Update an existing permission
   * @param permissionId Permission ID
   * @param data Update data
   * @param transaction Optional transaction
   * @returns Operation result
   */
  async updatePermission(
    permissionId: string,
    data: UpdatePermissionData,
    transaction?: DatabaseTransaction
  ): Promise<PermissionResult> {
    const startTime = Date.now();
    const operationId = `update-permission-${Date.now()}`;
    
    this.logger.info('Updating permission', { operationId, permissionId });
    
    const operation = async (tx?: DatabaseTransaction) => {
      try {
        const db = tx?.getDatabase() || getDatabase();

        // Check if permission exists
        const existingPermission = await this.findPermissionById(permissionId, tx);
        if (!existingPermission) {
          throw AuthErrorFactory.notFound('Permission not found');
        }

        // Build update query dynamically
        const updateFields = [];
        const values = [];
        
        if (data.description !== undefined) {
          updateFields.push('description = ?');
          values.push(data.description);
        }
        if (data.resource !== undefined) {
          updateFields.push('resource = ?');
          values.push(data.resource);
        }
        if (data.action !== undefined) {
          updateFields.push('action = ?');
          values.push(data.action);
        }

        if (updateFields.length === 0) {
          throw AuthErrorFactory.validation('No fields to update', 'updateData');
        }

        values.push(permissionId);
        
        const query = db.query(
          `UPDATE permissions SET ${updateFields.join(', ')} WHERE id = ?`
        );
        query.run(...values);

        // Get updated permission
        const permission = await this.findPermissionById(permissionId, tx);
        if (!permission) {
          throw AuthErrorFactory.database('Failed to update permission', 'updatePermission');
        }

        // Clear cache
        this.clearCache();

        const duration = Date.now() - startTime;
        this.updatePerformanceMetrics('updatePermission', duration);
        
        this.logger.info('Permission updated successfully', {
          operationId,
          permissionId,
          duration: `${duration}ms`
        });

        return {
          success: true,
          permission
        };
      } catch (error: any) {
        const duration = Date.now() - startTime;
        
        this.logger.error('Failed to update permission', {
          operationId,
          permissionId,
          error: error instanceof Error ? error.message : String(error),
          duration: `${duration}ms`
        });
        
        if (error.type) {
          return {
            success: false,
            error
          };
        }
        throw AuthErrorFactory.fromUnknown(error, 'Failed to update permission');
      }
    };

    if (transaction) {
      return operation(transaction);
    }
    
    return withTransaction(async (tx) => operation(tx));
  }

  /**
   * Delete a permission
   * @param permissionId Permission ID
   * @param transaction Optional transaction
   * @returns Operation result
   */
  async deletePermission(
    permissionId: string,
    transaction?: DatabaseTransaction
  ): Promise<PermissionResult> {
    const startTime = Date.now();
    const operationId = `delete-permission-${Date.now()}`;
    
    this.logger.info('Deleting permission', { operationId, permissionId });
    
    const operation = async (tx?: DatabaseTransaction) => {
      try {
        const db = tx?.getDatabase() || getDatabase();

        // Check if permission exists
        const existingPermission = await this.findPermissionById(permissionId, tx);
        if (!existingPermission) {
          throw AuthErrorFactory.notFound('Permission not found');
        }

        // Delete role-permission associations first
        const deleteRolePermsQuery = db.query(
          "DELETE FROM role_permissions WHERE permission_id = ?"
        );
        deleteRolePermsQuery.run(permissionId);

        // Delete the permission
        const deleteQuery = db.query(
          "DELETE FROM permissions WHERE id = ?"
        );
        deleteQuery.run(permissionId);

        // Clear cache
        this.clearCache();

        const duration = Date.now() - startTime;
        this.updatePerformanceMetrics('deletePermission', duration);
        
        this.logger.info('Permission deleted successfully', {
          operationId,
          permissionId,
          duration: `${duration}ms`
        });

        return { success: true };
      } catch (error: any) {
        const duration = Date.now() - startTime;
        
        this.logger.error('Failed to delete permission', {
          operationId,
          permissionId,
          error: error instanceof Error ? error.message : String(error),
          duration: `${duration}ms`
        });
        
        if (error.type) {
          return {
            success: false,
            error
          };
        }
        throw AuthErrorFactory.fromUnknown(error, 'Failed to delete permission');
      }
    };

    if (transaction) {
      return operation(transaction);
    }
    
    return withTransaction(async (tx) => operation(tx));
  }

  /**
   * Get all roles from the database
   * @param includePermissions Whether to include permissions for each role
   * @param transaction Optional transaction
   * @returns Array of all roles
   */
  async getAllRoles(
    includePermissions: boolean = false,
    transaction?: DatabaseTransaction
  ): Promise<Role[]> {
    try {
      const db = transaction?.getDatabase() || getDatabase();
      
      const query = db.query(
        "SELECT id, name, description, is_active, created_at, updated_at FROM roles ORDER BY name"
      );
      
      const rolesData = query.all() as any[];
      const roles = rolesData.map(roleData => ({
        id: roleData.id,
        name: roleData.name,
        description: roleData.description,
        isActive: Boolean(roleData.is_active),
        createdAt: roleData.created_at,
        updatedAt: roleData.updated_at || roleData.created_at,
        permissions: [] as Permission[]
      }));
      
      if (includePermissions) {
        for (const role of roles) {
          role.permissions = await this.getRolePermissions(role.id, transaction);
        }
      }
      
      return roles;
    } catch (error: any) {
      this.logger.error('Error getting all roles:', AuthErrorFactory.fromUnknown(error, 'Failed to get all roles'));
      return [];
    }
  }

  /**
   * Delete a role
   * @param roleId Role ID
   * @param transaction Optional transaction
   * @returns Operation result
   */
  async deleteRole(
    roleId: string,
    transaction?: DatabaseTransaction
  ): Promise<RoleResult> {
    const startTime = Date.now();
    const operationId = `delete-role-${Date.now()}`;
    
    this.logger.info('Deleting role', { operationId, roleId });
    
    const operation = async (tx?: DatabaseTransaction) => {
      try {
        const db = tx?.getDatabase() || getDatabase();

        // Check if role exists
        const existingRole = await this.findRoleById(roleId, false, tx);
        if (!existingRole) {
          throw AuthErrorFactory.notFound('Role not found');
        }

        // Delete user-role associations first
        const deleteUserRolesQuery = db.query(
          "DELETE FROM user_roles WHERE role_id = ?"
        );
        deleteUserRolesQuery.run(roleId);

        // Delete role-permission associations
        const deleteRolePermsQuery = db.query(
          "DELETE FROM role_permissions WHERE role_id = ?"
        );
        deleteRolePermsQuery.run(roleId);

        // Delete the role
        const deleteQuery = db.query(
          "DELETE FROM roles WHERE id = ?"
        );
        deleteQuery.run(roleId);

        // Clear cache
        this.clearCache();

        const duration = Date.now() - startTime;
        this.updatePerformanceMetrics('deleteRole', duration);
        
        this.logger.info('Role deleted successfully', {
          operationId,
          roleId,
          duration: `${duration}ms`
        });

        return { success: true };
      } catch (error: any) {
        const duration = Date.now() - startTime;
        
        this.logger.error('Failed to delete role', {
          operationId,
          roleId,
          error: error instanceof Error ? error.message : String(error),
          duration: `${duration}ms`
        });
        
        if (error.type) {
          return {
            success: false,
            error
          };
        }
        throw AuthErrorFactory.fromUnknown(error, 'Failed to delete role');
      }
    };

    if (transaction) {
      return operation(transaction);
    }
    
    return withTransaction(async (tx) => operation(tx));
  }

  /**
   * Update a role
   * @param roleId Role ID
   * @param data Update data
   * @param transaction Optional transaction
   * @returns Operation result
   */
  async updateRole(
    roleId: string,
    data: UpdateRoleData,
    transaction?: DatabaseTransaction
  ): Promise<RoleResult> {
    const startTime = Date.now();
    const operationId = `update-role-${Date.now()}`;
    
    this.logger.info('Updating role', { operationId, roleId, data });
    
    const operation = async (tx?: DatabaseTransaction) => {
      try {
        const db = tx?.getDatabase() || getDatabase();

        // Check if role exists
        const existingRole = await this.findRoleById(roleId, false, tx);
        if (!existingRole) {
          throw AuthErrorFactory.notFound('Role not found');
        }

        // Validate update data (only validate provided fields)
        const validation = this.validateRoleUpdateData(data);
        if (!validation.isValid) {
          throw AuthErrorFactory.validation(validation.error || 'Invalid role data');
        }

        // Check for name conflicts if name is being updated
        if (data.name && data.name !== existingRole.name) {
          const existingByName = await this.findRoleByName(data.name, false, tx);
          if (existingByName && existingByName.id !== roleId) {
            throw AuthErrorFactory.validation('Role with this name already exists');
          }
        }

        // Build update query
        const updateFields: string[] = [];
        const updateValues: any[] = [];
        
        if (data.name !== undefined) {
          updateFields.push('name = ?');
          updateValues.push(data.name);
        }
        
        if (data.description !== undefined) {
          updateFields.push('description = ?');
          updateValues.push(data.description);
        }
        
        if (data.isActive !== undefined) {
          updateFields.push('is_active = ?');
          updateValues.push(data.isActive ? 1 : 0);
        }
        
        updateFields.push('updated_at = ?');
        updateValues.push(new Date().toISOString());
        updateValues.push(roleId);

        const updateQuery = db.query(`
          UPDATE roles 
          SET ${updateFields.join(', ')}
          WHERE id = ?
        `);
        
        updateQuery.run(...updateValues);

        // Get updated role
        const updatedRole = await this.findRoleById(roleId, false, tx);
        if (!updatedRole) {
          throw AuthErrorFactory.validation('Failed to retrieve updated role');
        }

        // Clear cache
        this.clearCache();

        const duration = Date.now() - startTime;
        this.updatePerformanceMetrics('updateRole', duration);
        
        this.logger.info('Role updated successfully', {
          operationId,
          roleId,
          duration: `${duration}ms`
        });

        return {
          success: true,
          role: updatedRole
        };
      } catch (error: any) {
        const duration = Date.now() - startTime;
        
        this.logger.error('Failed to update role', {
          operationId,
          roleId,
          error: error instanceof Error ? error.message : String(error),
          duration: `${duration}ms`
        });
        
        if (error.type) {
          return {
            success: false,
            error
          };
        }
        throw AuthErrorFactory.fromUnknown(error, 'Failed to update role');
      }
    };

    if (transaction) {
      return operation(transaction);
    }
    
    return withTransaction(async (tx) => operation(tx));
  }

  /**
   * Assign a single permission to a role
   * @param roleId Role ID
   * @param permissionId Permission ID
   * @param transaction Optional transaction
   * @returns Operation result
   */
  async assignPermissionToRole(
    roleId: string,
    permissionId: string,
    transaction?: DatabaseTransaction
  ): Promise<PermissionResult> {
    return this.assignPermissionsToRole(roleId, [permissionId], transaction);
  }

  /**
   * Remove a permission from a role
   * @param roleId Role ID
   * @param permissionId Permission ID
   * @param transaction Optional transaction
   * @returns Operation result
   */
  async removePermissionFromRole(
    roleId: string,
    permissionId: string,
    transaction?: DatabaseTransaction
  ): Promise<PermissionResult> {
    const startTime = Date.now();
    const operationId = `remove-permission-from-role-${Date.now()}`;
    
    this.logger.info('Removing permission from role', { operationId, roleId, permissionId });
    
    const operation = async (tx?: DatabaseTransaction) => {
      try {
        const db = tx?.getDatabase() || getDatabase();

        // Verify that role and permission exist
        const [roleExists, permissionExists] = await Promise.all([
          this.checkRoleExists(roleId, tx),
          this.checkPermissionExists(permissionId, tx)
        ]);

        if (!roleExists) {
          throw AuthErrorFactory.notFound('Role not found');
        }

        if (!permissionExists) {
          throw AuthErrorFactory.notFound('Permission not found');
        }

        // Check if assignment exists
        const existingQuery = db.query(
          "SELECT id FROM role_permissions WHERE role_id = ? AND permission_id = ?"
        );
        const existingAssignment = existingQuery.get(roleId, permissionId);

        if (!existingAssignment) {
          throw AuthErrorFactory.notFound('Permission assignment not found');
        }

        // Remove assignment
        const deleteQuery = db.query(
          "DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?"
        );
        deleteQuery.run(roleId, permissionId);

        // Clear cache
        this.clearCache();

        const duration = Date.now() - startTime;
        this.updatePerformanceMetrics('removePermissionFromRole', duration);
        
        this.logger.info('Permission removed from role successfully', {
          operationId,
          roleId,
          permissionId,
          duration: `${duration}ms`
        });

        return { success: true };
      } catch (error: any) {
        const duration = Date.now() - startTime;
        
        this.logger.error('Failed to remove permission from role', {
          operationId,
          roleId,
          permissionId,
          error: error instanceof Error ? error.message : String(error),
          duration: `${duration}ms`
        });
        
        if (error.type) {
          return {
            success: false,
            error
          };
        }
        throw AuthErrorFactory.fromUnknown(error, 'Failed to remove permission from role');
      }
    };

    if (transaction) {
      return operation(transaction);
    }
    
    return withTransaction(async (tx) => operation(tx));
  }

  /**
   * Check if user has a specific role
   * @param userId User ID
   * @param roleName Role name
   * @param transaction Optional transaction
   * @returns true if user has the role
   */
  async userHasRole(
    userId: string,
    roleName: string,
    transaction?: DatabaseTransaction
  ): Promise<boolean> {
    try {
      const db = transaction?.getDatabase() || getDatabase();
      
      const query = db.query(`
        SELECT COUNT(*) as count
        FROM users u
        INNER JOIN user_roles ur ON u.id = ur.user_id
        INNER JOIN roles r ON ur.role_id = r.id
        WHERE u.id = ? AND r.name = ? AND u.is_active = 1 AND r.is_active = 1
      `);
      
      const result = query.get(userId, roleName) as { count: number };
      return result?.count > 0;
    } catch (error: any) {
      this.logger.error('Error checking user role:', AuthErrorFactory.fromUnknown(error, 'Failed to check user role'));
      return false;
    }
  }

  /**
   * Check if user has all specified permissions
   * @param userId User ID
   * @param permissionNames Array of permission names
   * @param transaction Optional transaction
   * @returns true if user has all permissions
   */
  async userHasAllPermissions(
    userId: string,
    permissionNames: string[],
    transaction?: DatabaseTransaction
  ): Promise<boolean> {
    if (permissionNames.length === 0) {
      return true;
    }

    try {
      for (const permissionName of permissionNames) {
        const hasPermission = await this.userHasPermission(userId, permissionName);
        if (!hasPermission) {
          return false;
        }
      }
      return true;
    } catch (error: any) {
      this.logger.error('Error checking user permissions:', AuthErrorFactory.fromUnknown(error, 'Failed to check user permissions'));
      return false;
    }
  }

  /**
   * Check if user has any of the specified permissions
   * @param userId User ID
   * @param permissionNames Array of permission names
   * @param transaction Optional transaction
   * @returns true if user has any permission
   */
  async userHasAnyPermission(
    userId: string,
    permissionNames: string[],
    transaction?: DatabaseTransaction
  ): Promise<boolean> {
    if (permissionNames.length === 0) {
      return false;
    }

    try {
      for (const permissionName of permissionNames) {
        const hasPermission = await this.userHasPermission(userId, permissionName);
        if (hasPermission) {
          return true;
        }
      }
      return false;
    } catch (error: any) {
      this.logger.error('Error checking user permissions:', AuthErrorFactory.fromUnknown(error, 'Failed to check user permissions'));
      return false;
    }
  }

  /**
   * Check if user has all specified roles
   * @param userId User ID
   * @param roleNames Array of role names
   * @param transaction Optional transaction
   * @returns true if user has all roles
   */
  async userHasAllRoles(
    userId: string,
    roleNames: string[],
    transaction?: DatabaseTransaction
  ): Promise<boolean> {
    if (roleNames.length === 0) {
      return true;
    }

    try {
      for (const roleName of roleNames) {
        const hasRole = await this.userHasRole(userId, roleName, transaction);
        if (!hasRole) {
          return false;
        }
      }
      return true;
    } catch (error: any) {
      this.logger.error('Error checking user roles:', AuthErrorFactory.fromUnknown(error, 'Failed to check user roles'));
      return false;
    }
  }

  /**
   * Check if user has any of the specified roles
   * @param userId User ID
   * @param roleNames Array of role names
   * @param transaction Optional transaction
   * @returns true if user has any role
   */
  async userHasAnyRole(
    userId: string,
    roleNames: string[],
    transaction?: DatabaseTransaction
  ): Promise<boolean> {
    if (roleNames.length === 0) {
      return false;
    }

    try {
      for (const roleName of roleNames) {
        const hasRole = await this.userHasRole(userId, roleName, transaction);
        if (hasRole) {
          return true;
        }
      }
      return false;
    } catch (error: any) {
      this.logger.error('Error checking user roles:', AuthErrorFactory.fromUnknown(error, 'Failed to check user roles'));
      return false;
    }
  }

  /**
   * Remove a role from a user
   * @param userId User ID
   * @param roleId Role ID
   * @param transaction Optional transaction
   * @returns Operation result
   */
  async removeRoleFromUser(
    userId: string,
    roleId: string,
    transaction?: DatabaseTransaction
  ): Promise<PermissionResult> {
    const startTime = Date.now();
    const operationId = `remove-role-from-user-${Date.now()}`;
    
    this.logger.info('Removing role from user', { operationId, userId, roleId });
    
    const operation = async (tx?: DatabaseTransaction) => {
      try {
        const db = tx?.getDatabase() || getDatabase();

        // Verify that user and role exist
        const [userExists, roleExists] = await Promise.all([
          this.checkUserExists(userId, tx),
          this.checkRoleExists(roleId, tx)
        ]);

        if (!userExists) {
          throw AuthErrorFactory.userNotFound('User not found');
        }

        if (!roleExists) {
          throw AuthErrorFactory.notFound('Role not found');
        }

        // Check if assignment exists
        const existingQuery = db.query(
          "SELECT id FROM user_roles WHERE user_id = ? AND role_id = ?"
        );
        const existingAssignment = existingQuery.get(userId, roleId);

        if (!existingAssignment) {
          throw AuthErrorFactory.notFound('Role assignment not found');
        }

        // Remove assignment
        const deleteQuery = db.query(
          "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?"
        );
        deleteQuery.run(userId, roleId);

        // Clear user cache
        this.clearUserCache(userId);

        const duration = Date.now() - startTime;
        this.updatePerformanceMetrics('removeRoleFromUser', duration);
        
        this.logger.info('Role removed from user successfully', {
          operationId,
          userId,
          roleId,
          duration: `${duration}ms`
        });

        return { success: true };
      } catch (error: any) {
        const duration = Date.now() - startTime;
        
        this.logger.error('Failed to remove role from user', {
          operationId,
          userId,
          roleId,
          error: error instanceof Error ? error.message : String(error),
          duration: `${duration}ms`
        });
        
        if (error.type) {
          return {
            success: false,
            error
          };
        }
        throw AuthErrorFactory.fromUnknown(error, 'Failed to remove role from user');
      }
    };

    if (transaction) {
      return operation(transaction);
    }
    
    return withTransaction(async (tx) => operation(tx));
  }

  /**
   * Check if user can access a specific resource with a specific action
   * @param userId User ID
   * @param resource Resource name
   * @param action Action name
   * @param transaction Optional transaction
   * @returns true if user can access the resource
   */
  async userCanAccessResource(
    userId: string,
    resource: string,
    action: string,
    transaction?: DatabaseTransaction
  ): Promise<boolean> {
    try {
      // Check for exact permission match
      const exactPermission = `${resource}:${action}`;
      if (await this.userHasPermission(userId, exactPermission)) {
        return true;
      }

      // Check for wildcard permissions
      const wildcardPermissions = [
        '*:*',
        `${resource}:*`,
        `*:${action}`,
        'admin:*'
      ];

      for (const permission of wildcardPermissions) {
        if (await this.userHasPermission(userId, permission)) {
          return true;
        }
      }

      return false;
    } catch (error: any) {
      this.logger.error('Error checking resource access:', AuthErrorFactory.fromUnknown(error, 'Failed to check resource access'));
      return false;
    }
  }

  /**
   * Get all permissions for a user with caching
   * @param userId User ID
   * @param transaction Optional transaction
   * @returns Array of permissions
   */
  async getUserPermissions(
    userId: string, 
    transaction?: DatabaseTransaction
  ): Promise<Permission[]> {
    // Check cache first
    if (this.isCacheValid() && !transaction) {
      const cached = this.cache.userPermissions.get(userId);
      if (cached) {
        return cached;
      }
    }

    try {
      const db = transaction?.getDatabase() || getDatabase();
      
      const query = db.query(`
        SELECT DISTINCT p.id, p.name, p.resource, p.action, p.description, p.created_at
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        INNER JOIN user_roles ur ON rp.role_id = ur.role_id
        INNER JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = ? AND r.is_active = 1
        ORDER BY p.name
      `);
      
      const permissionsData = query.all(userId) as any[];
      const permissions: Permission[] = permissionsData.map(permData => ({
        id: permData.id,
        name: permData.name,
        resource: permData.resource,
        action: permData.action,
        description: permData.description,
        createdAt: permData.created_at,
        updatedAt: permData.updated_at
      }));
      
      // Cache the result if not in transaction
      if (!transaction && this.isCacheValid()) {
        this.cache.userPermissions.set(userId, permissions);
      }
      
      return permissions;
    } catch (error: any) {
      console.error('Error getting user permissions:', AuthErrorFactory.fromUnknown(error, 'Failed to get user permissions'));
      return [];
    }
  }

  /**
   * Find permission by ID with caching
   * @param id Permission ID
   * @param transaction Optional transaction
   * @returns Permission or null
   */
  async findPermissionById(
    id: string, 
    transaction?: DatabaseTransaction
  ): Promise<Permission | null> {
    // Check cache first
    if (this.isCacheValid() && !transaction) {
      const cached = this.cache.permissions.get(id);
      if (cached) {
        return cached;
      }
    }

    try {
      const db = transaction?.getDatabase() || getDatabase();
      const query = db.query(
        "SELECT id, name, resource, action, description, created_at FROM permissions WHERE id = ?"
      );
      const permissionData = query.get(id) as any;
      
      if (!permissionData) {
        return null;
      }

      const permission: Permission = {
        id: permissionData.id,
        name: permissionData.name,
        resource: permissionData.resource,
        action: permissionData.action,
        description: permissionData.description,
        createdAt: permissionData.created_at,
        updatedAt: permissionData.updated_at
      };
      
      if (!transaction && this.isCacheValid()) {
        this.cache.permissions.set(id, permission);
      }
      
      return permission;
    } catch (error: any) {
      console.error('Error finding permission by ID:', AuthErrorFactory.fromUnknown(error, 'Failed to find permission by ID'));
      return null;
    }
  }

  /**
   * Find permission by name with caching
   * @param name Permission name
   * @param transaction Optional transaction
   * @returns Permission or null
   */
  async findPermissionByName(
    name: string, 
    transaction?: DatabaseTransaction
  ): Promise<Permission | null> {
    try {
      const db = transaction?.getDatabase() || getDatabase();
      const query = db.query(
        "SELECT id, name, resource, action, description, created_at FROM permissions WHERE name = ?"
      );
      const permissionData = query.get(name) as any;
      
      if (!permissionData) {
        return null;
      }

      const permission: Permission = {
        id: permissionData.id,
        name: permissionData.name,
        resource: permissionData.resource,
        action: permissionData.action,
        description: permissionData.description,
        createdAt: permissionData.created_at,
        updatedAt: permissionData.updated_at
      };
      
      if (!transaction && this.isCacheValid()) {
        this.cache.permissions.set(permission.id, permission);
      }
      
      return permission;
    } catch (error: any) {
      console.error('Error finding permission by name:', AuthErrorFactory.fromUnknown(error, 'Failed to find permission by name'));
      return null;
    }
  }

  /**
   * Find role by ID with caching
   * @param id Role ID
   * @param includePermissions Include permissions in result
   * @param transaction Optional transaction
   * @returns Role or null
   */
  async findRoleById(
    id: string, 
    includePermissions: boolean = false, 
    transaction?: DatabaseTransaction
  ): Promise<Role | null> {
    // Check cache first (only for basic role without permissions)
    if (this.isCacheValid() && !transaction && !includePermissions) {
      const cached = this.cache.roles.get(id);
      if (cached) {
        return cached;
      }
    }

    try {
      const db = transaction?.getDatabase() || getDatabase();
      const query = db.query(
        "SELECT id, name, description, is_active, created_at, updated_at FROM roles WHERE id = ?"
      );
      const roleData = query.get(id) as any;
      
      if (!roleData) {
        return null;
      }

      const role: Role = {
        id: roleData.id,
        name: roleData.name,
        description: roleData.description,
        isActive: Boolean(roleData.is_active),
        createdAt: roleData.created_at,
        updatedAt: roleData.updated_at || roleData.created_at,
        permissions: []
      };

      if (includePermissions) {
        role.permissions = await this.getRolePermissions(id, transaction);
      }

      // Cache basic role data
      if (!transaction && this.isCacheValid() && !includePermissions) {
        this.cache.roles.set(id, role);
      }
      
      return role;
    } catch (error: any) {
      console.error('Error finding role by ID:', AuthErrorFactory.fromUnknown(error, 'Failed to find role by ID'));
      return null;
    }
  }

  /**
   * Find role by name with caching
   * @param name Role name
   * @param includePermissions Include permissions in result
   * @param transaction Optional transaction
   * @returns Role or null
   */
  async findRoleByName(
    name: string, 
    includePermissions: boolean = false, 
    transaction?: DatabaseTransaction
  ): Promise<Role | null> {
    try {
      const db = transaction?.getDatabase() || getDatabase();
      const query = db.query(
        "SELECT id, name, description, is_active, created_at, updated_at FROM roles WHERE name = ?"
      );
      const roleData = query.get(name) as any;
      
      if (!roleData) {
        return null;
      }

      const role: Role = {
        id: roleData.id,
        name: roleData.name,
        description: roleData.description,
        isActive: Boolean(roleData.is_active),
        createdAt: roleData.created_at,
        updatedAt: roleData.updated_at || roleData.created_at,
        permissions: []
      };

      if (includePermissions) {
        role.permissions = await this.getRolePermissions(roleData.id, transaction);
      }

      // Cache basic role data
      if (!transaction && this.isCacheValid() && !includePermissions) {
        this.cache.roles.set(roleData.id, role);
      }
      
      return role;
    } catch (error: any) {
      console.error('Error finding role by name:', AuthErrorFactory.fromUnknown(error, 'Failed to find role by name'));
      return null;
    }
  }

  /**
   * Get permissions for a role
   * @param roleId Role ID
   * @param transaction Optional transaction
   * @returns Array of permissions
   */
  async getRolePermissions(
    roleId: string, 
    transaction?: DatabaseTransaction
  ): Promise<Permission[]> {
    try {
      const db = transaction?.getDatabase() || getDatabase();
      const query = db.query(`
        SELECT p.id, p.name, p.resource, p.action, p.description, p.created_at
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = ?
        ORDER BY p.name
      `);
      
      const permissionsData = query.all(roleId) as any[];
      return permissionsData.map(permData => ({
        id: permData.id,
        name: permData.name,
        resource: permData.resource,
        action: permData.action,
        description: permData.description,
        createdAt: permData.created_at,
        updatedAt: permData.updated_at
      }));
    } catch (error: any) {
      console.error('Error getting role permissions:', AuthErrorFactory.fromUnknown(error, 'Failed to get role permissions'));
      return [];
    }
  }

  /**
   * Enhanced validation with better error messages
   * @param data Permission data
   * @returns Validation result
   */
  validatePermissionData(data: CreatePermissionData): { isValid: boolean; error?: string } {
    // Check required fields
    if (!data.name?.trim() || !data.resource?.trim() || !data.action?.trim()) {
      return { isValid: false, error: 'Name, resource and action are required' };
    }

    // Simple pattern for allowed characters (including asterisks for wildcards)
    const validPattern = /^[a-zA-Z0-9_:*-]+$/;
    
    if (!validPattern.test(data.name)) {
      return { isValid: false, error: 'Invalid name format' };
    }

    if (!validPattern.test(data.action)) {
      return { isValid: false, error: 'Invalid action format' };
    }

    // Resource allows additional / character and asterisks
    if (!/^[a-zA-Z0-9_:/*-]+$/.test(data.resource)) {
      return { isValid: false, error: 'Invalid resource format' };
    }

    return { isValid: true };
  }

  /**
   * Enhanced role validation
   * @param data Role data
   * @returns Validation result
   */
  validateRoleData(data: CreateRoleData): { isValid: boolean; error?: string } {
    if (!data.name?.trim()) {
      return { isValid: false, error: 'Role name is required' };
    }

    if (data.name.length < 3) {
      return { isValid: false, error: 'Role name must be at least 3 characters long' };
    }

    if (data.name.length > 100) {
      return { isValid: false, error: 'Role name must not exceed 100 characters' };
    }

    if (data.description && data.description.length > 500) {
      return { isValid: false, error: 'Role description must not exceed 500 characters' };
    }

    // Validate role name pattern (alphanumeric, underscore, hyphen)
    const namePattern = /^[a-zA-Z0-9_-]+$/;
    if (!namePattern.test(data.name)) {
      return { isValid: false, error: 'Role name contains invalid characters. Only alphanumeric, underscore, and hyphen are allowed' };
    }

    return { isValid: true };
  }

  /**
   * Validate role update data (only validates provided fields)
   * @param data Partial role data for updates
   * @returns Validation result
   */
  validateRoleUpdateData(data: Partial<CreateRoleData>): { isValid: boolean; error?: string } {
    // If name is provided, validate it
    if (data.name !== undefined) {
      if (!data.name?.trim()) {
        return { isValid: false, error: 'Role name cannot be empty' };
      }

      if (data.name.length < 3) {
        return { isValid: false, error: 'Role name must be at least 3 characters long' };
      }

      if (data.name.length > 100) {
        return { isValid: false, error: 'Role name must not exceed 100 characters' };
      }

      // Validate role name pattern (alphanumeric, underscore, hyphen)
      const namePattern = /^[a-zA-Z0-9_-]+$/;
      if (!namePattern.test(data.name)) {
        return { isValid: false, error: 'Role name contains invalid characters. Only alphanumeric, underscore, and hyphen are allowed' };
      }
    }

    // If description is provided, validate it
    if (data.description !== undefined && data.description && data.description.length > 500) {
      return { isValid: false, error: 'Role description must not exceed 500 characters' };
    }

    return { isValid: true };
  }

  /**
   * Check if user exists with transaction support
   * @param userId User ID
   * @param transaction Optional transaction
   * @returns true if user exists
   */
  async checkUserExists(
    userId: string, 
    transaction?: DatabaseTransaction
  ): Promise<boolean> {
    try {
      const db = transaction?.getDatabase() || getDatabase();
      const query = db.query("SELECT 1 FROM users WHERE id = ? LIMIT 1");
      const result = query.get(userId);
      return !!result;
    } catch (error: any) {
      console.error('Error checking user existence:', AuthErrorFactory.fromUnknown(error, 'Failed to check user existence'));
      return false;
    }
  }

  /**
   * Check if role exists with transaction support
   * @param roleId Role ID
   * @param transaction Optional transaction
   * @returns true if role exists
   */
  async checkRoleExists(
    roleId: string, 
    transaction?: DatabaseTransaction
  ): Promise<boolean> {
    try {
      const db = transaction?.getDatabase() || getDatabase();
      const query = db.query("SELECT 1 FROM roles WHERE id = ? LIMIT 1");
      const result = query.get(roleId);
      return !!result;
    } catch (error: any) {
      console.error('Error checking role existence:', AuthErrorFactory.fromUnknown(error, 'Failed to check role existence'));
      return false;
    }
  }

  /**
   * Check if permission exists with transaction support
   * @param permissionId Permission ID
   * @param transaction Optional transaction
   * @returns true if permission exists
   */
  async checkPermissionExists(
    permissionId: string, 
    transaction?: DatabaseTransaction
  ): Promise<boolean> {
    try {
      const db = transaction?.getDatabase() || getDatabase();
      const query = db.query("SELECT 1 FROM permissions WHERE id = ? LIMIT 1");
      const result = query.get(permissionId);
      return !!result;
    } catch (error: any) {
      console.error('Error checking permission existence:', AuthErrorFactory.fromUnknown(error, 'Failed to check permission existence'));
      return false;
    }
  }

  /**
   * Check if cache is still valid
   * @returns true if cache is valid
   */
  isCacheValid(): boolean {
    return (Date.now() - this.cache.lastClearTime) < this.CACHE_TTL;
  }

  /**
   * Clear all cache
   */
  clearCache(): void {
    this.cache.permissions.clear();
    this.cache.roles.clear();
    this.cache.userPermissions.clear();
    this.cache.userRoles.clear();
    this.cache.lastClearTime = Date.now();
  }

  /**
   * Clear cache for specific user
   * @param userId User ID
   */
  clearUserCache(userId: string): void {
    this.cache.userPermissions.delete(userId);
    this.cache.userRoles.delete(userId);
  }

  /**
   * Update performance metrics for operations
   * @param operation Operation name
   * @param duration Duration in milliseconds
   */
  updatePerformanceMetrics(operation: string, duration: number): void {
    const current = this.performanceMetrics.get(operation) || { count: 0, totalTime: 0, avgTime: 0 };
    current.count++;
    current.totalTime += duration;
    current.avgTime = current.totalTime / current.count;
    this.performanceMetrics.set(operation, current);
  }

  /**
   * Get performance metrics for monitoring
   * @returns Performance metrics map
   */
  getPerformanceMetrics(): Map<string, { count: number; totalTime: number; avgTime: number }> {
    return new Map(this.performanceMetrics);
  }

  /**
   * Check if permission matches wildcard pattern
   * @param permission Permission object
   * @param permissionName Permission name to check
   * @returns true if matches
   */
  matchesWildcard(permission: Permission, permissionName: string): boolean {
    const [reqResource, reqAction] = permissionName.split(':');
    
    return (
      permission.resource === '*' ||
      permission.action === '*' ||
      (permission.resource === reqResource && permission.action === '*') ||
      (permission.resource === '*' && permission.action === reqAction)
    );
  }
}

/**
 * Dependency injection container for PermissionService
 */
class PermissionServiceContainer {
  static instance: PermissionService | null = null;

  static getInstance(): PermissionService {
    if (!this.instance) {
      this.instance = new PermissionService();
    }
    return this.instance;
  }

  static setInstance(service: PermissionService): void {
    this.instance = service;
  }

  static reset(): void {
    this.instance = null;
  }
}

/**
 * Initialize the permission service
 * @returns Permission service instance
 */
export function initPermissionService(): PermissionService {
  const service = new PermissionService();
  PermissionServiceContainer.setInstance(service);
  return service;
}

/**
 * Get the permission service instance
 * @returns Permission service instance
 */
export function getPermissionService(): PermissionService {
  return PermissionServiceContainer.getInstance();
}

/**
 * Reset the permission service (useful for testing)
 */
export function resetPermissionService(): void {
  PermissionServiceContainer.reset();
}