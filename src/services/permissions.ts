// src/services/permission.service.ts

import type { DatabaseInitializer } from '../database/database-initializer';
import type { BaseController } from '../database/base-controller';
import type { User, Role } from '../types/auth'; // Tipos compartidos
import {
  Permission,
  CreatePermissionData,
  UpdatePermissionData,
  CreateRoleData,
  UpdateRoleData,
  PermissionResult,
  RoleResult,
  AuthErrorType,
} from '../types/auth';

/**
 * Service for role and permission management (RBAC).
 */
export class PermissionService {
  private roleController: BaseController<Role>;
  private permissionController: BaseController<Permission>;
  private userRoleController: BaseController<{ id: string; user_id: string; role_id: string }>;
  private rolePermissionController: BaseController<{ id: string; role_id: string; permission_id: string }>;
  
  // Incluimos el userController para las comprobaciones de usuario
  private userController: BaseController<User>;

  constructor(dbInitializer: DatabaseInitializer) {
    this.roleController = dbInitializer.createController<Role>('roles');
    this.permissionController = dbInitializer.createController<Permission>('permissions');
    this.userRoleController = dbInitializer.createController('user_roles');
    this.rolePermissionController = dbInitializer.createController('role_permissions');
    this.userController = dbInitializer.createController<User>('users');
  }

  // --- Permission Methods ---

  async createPermission(data: CreatePermissionData): Promise<PermissionResult> {
    if (!data.name || !data.resource || !data.action) {
      return { success: false, error: { type: AuthErrorType.VALIDATION_ERROR, message: 'Name, resource, and action are required' } };
    }
    try {
      const existing = await this.permissionController.findFirst({ name: data.name });
      if (existing.data) {
        return { success: false, error: { type: AuthErrorType.PERMISSION_ERROR, message: `Permission '${data.name}' already exists` } };
      }
      const result = await this.permissionController.create(data);
      if (!result.success || !result.data) {
        return { success: false, error: { type: AuthErrorType.DATABASE_ERROR, message: result.error || 'Failed to create permission' } };
      }
      return { success: true, permission: result.data };
    } catch (error: any) {
      return { success: false, error: { type: AuthErrorType.DATABASE_ERROR, message: error.message } };
    }
  }

  async updatePermission(permissionId: string, data: UpdatePermissionData): Promise<PermissionResult> {
    const result = await this.permissionController.update(permissionId, data);
    if (!result.success || !result.data) {
      return { success: false, error: { type: AuthErrorType.DATABASE_ERROR, message: result.error || 'Failed to update permission' } };
    }
    return { success: true, permission: result.data };
  }

  async deletePermission(permissionId: string): Promise<PermissionResult> {
    try {
      // Primero, eliminar todas las asignaciones de este permiso a roles
      const assignments = await this.rolePermissionController.search({ permission_id: permissionId });
      if (assignments.data) {
        for (const assignment of assignments.data) {
          await this.rolePermissionController.delete(assignment.id);
        }
      }
      const result = await this.permissionController.delete(permissionId);
      if (!result.success) {
        return { success: false, error: { type: AuthErrorType.DATABASE_ERROR, message: result.error || 'Failed to delete permission' } };
      }
      return { success: true };
    } catch (error: any) {
      return { success: false, error: { type: AuthErrorType.DATABASE_ERROR, message: error.message } };
    }
  }

  // --- Role Methods ---

  async createRole(data: CreateRoleData): Promise<RoleResult> {
    if (!data.name) {
      return { success: false, error: { type: AuthErrorType.VALIDATION_ERROR, message: 'Role name is required' } };
    }
    try {
      const existing = await this.roleController.findFirst({ name: data.name });
      if (existing.data) {
        return { success: false, error: { type: AuthErrorType.ROLE_ERROR, message: `Role '${data.name}' already exists` } };
      }
      const result = await this.roleController.create(data);
      if (!result.success || !result.data) {
        return { success: false, error: { type: AuthErrorType.DATABASE_ERROR, message: result.error || 'Failed to create role' } };
      }
      return { success: true, role: result.data };
    } catch (error: any) {
      return { success: false, error: { type: AuthErrorType.DATABASE_ERROR, message: error.message } };
    }
  }

  async updateRole(roleId: string, data: UpdateRoleData): Promise<RoleResult> {
    const result = await this.roleController.update(roleId, data);
    if (!result.success || !result.data) {
      return { success: false, error: { type: AuthErrorType.DATABASE_ERROR, message: result.error || 'Failed to update role' } };
    }
    return { success: true, role: result.data };
  }

  async deleteRole(roleId: string): Promise<RoleResult> {
    try {
      // Eliminar asignaciones de este rol a usuarios y permisos
      const userAssignments = await this.userRoleController.search({ role_id: roleId });
      if (userAssignments.data) {
          for(const assignment of userAssignments.data) {
              // Usar el ID de la fila de asignación, no el ID del rol.
              await this.userRoleController.delete(assignment.id);
          }
      }

      const permAssignments = await this.rolePermissionController.search({ role_id: roleId });
      if (permAssignments.data) {
          for(const assignment of permAssignments.data) {
              // Esta parte ya estaba correcta
              await this.rolePermissionController.delete(assignment.id);
          }
      }
      
      // Ahora que las dependencias están limpias, podemos eliminar el rol.
      const result = await this.roleController.delete(roleId);
      if (!result.success) {
        return { success: false, error: { type: AuthErrorType.DATABASE_ERROR, message: result.error || 'Failed to delete role' } };
      }
      
      return { success: true };
    } catch (error: any) {
      return { success: false, error: { type: AuthErrorType.DATABASE_ERROR, message: error.message } };
    }
  }

  // --- Assignment Methods ---

  async assignPermissionToRole(roleId: string, permissionId: string): Promise<PermissionResult> {
    try {
      const existing = await this.rolePermissionController.findFirst({ role_id: roleId, permission_id: permissionId });
      if (existing.data) return { success: true }; // Already assigned
      
      const result = await this.rolePermissionController.create({ role_id: roleId, permission_id: permissionId });
      if (!result.success) {
        return { success: false, error: { type: AuthErrorType.DATABASE_ERROR, message: result.error || 'Failed to assign permission to role' } };
      }
      return { success: true };
    } catch (error: any) {
      return { success: false, error: { type: AuthErrorType.DATABASE_ERROR, message: error.message } };
    }
  }

  async removePermissionFromRole(roleId: string, permissionId: string): Promise<PermissionResult> {
    try {
      const assignment = await this.rolePermissionController.findFirst({ role_id: roleId, permission_id: permissionId });
      if (!assignment.data) {
        return { success: false, error: { type: AuthErrorType.NOT_FOUND_ERROR, message: 'Permission is not assigned to this role' } };
      }
      const result = await this.rolePermissionController.delete(assignment.data.id);
      if (!result.success) {
        return { success: false, error: { type: AuthErrorType.DATABASE_ERROR, message: result.error || 'Failed to remove permission from role' } };
      }
      return { success: true };
    } catch (error: any) {
      return { success: false, error: { type: AuthErrorType.DATABASE_ERROR, message: error.message } };
    }
  }

  async updateRolePermissions(roleId: string, permissionIds: string[]): Promise<PermissionResult> {
    try {
      // First remove all existing permissions for this role
      const existingAssignments = await this.rolePermissionController.search({ role_id: roleId });
      if (existingAssignments.data) {
        for (const assignment of existingAssignments.data) {
          await this.rolePermissionController.delete(assignment.id);
        }
      }

      // Then assign all new permissions
      for (const permissionId of permissionIds) {
        const result = await this.rolePermissionController.create({
          role_id: roleId,
          permission_id: permissionId
        });
        
        if (!result.success) {
          return {
            success: false,
            error: {
              type: AuthErrorType.DATABASE_ERROR,
              message: result.error || `Failed to assign permission ${permissionId} to role`
            }
          };
        }
      }

      return { success: true };
    } catch (error: any) {
      return {
        success: false,
        error: {
          type: AuthErrorType.DATABASE_ERROR,
          message: error.message
        }
      };
    }
  }

  // --- Data Retrieval & Check Methods ---

  async findPermissionByName(name: string): Promise<Permission | null> {
    const result = await this.permissionController.findFirst({ name });
    return result.data || null;
  }

  async findRoleByName(name: string): Promise<Role | null> {
    const result = await this.roleController.findFirst({ name });
    return result.data || null;
  }

  async getAllPermissions(): Promise<Permission[]> {
    const result = await this.permissionController.findAll({ limit: 1000 }); // Un límite razonable
    return result.data || [];
  }

  async getAllRoles(): Promise<Role[]> {
    const result = await this.roleController.findAll({ limit: 1000 });
    return result.data || [];
  }

  async getRolePermissions(roleId: string): Promise<Permission[]> {
    const assignments = await this.rolePermissionController.search({ role_id: roleId });
    if (!assignments.data || assignments.data.length === 0) return [];

    const permissionIds = assignments.data.map(a => a.permission_id);
    const result = await this.permissionController.search({ id: permissionIds });
    return result.data || [];
  }

  async userHasRole(userId: string, roleName: string): Promise<boolean> {
    const role = await this.roleController.findFirst({ name: roleName });
    if (!role.data) return false;

    const assignment = await this.userRoleController.findFirst({ user_id: userId, role_id: role.data.id });
    return !!assignment.data;
  }

  async userHasPermission(userId: string, permissionName: string): Promise<boolean> {
    const permission = await this.permissionController.findFirst({ name: permissionName });
    if (!permission.data) return false;
    
    // Obtener todos los roles del usuario
    const userRoleAssignments = await this.userRoleController.search({ user_id: userId });
    if (!userRoleAssignments.data || userRoleAssignments.data.length === 0) return false;

    const roleIds = userRoleAssignments.data.map(a => a.role_id);
    
    // Comprobar si alguno de esos roles tiene el permiso
    const rolePermissionAssignment = await this.rolePermissionController.findFirst({
        role_id: roleIds,
        permission_id: permission.data.id
    });
    
    return !!rolePermissionAssignment.data;
  }

  async userCanAccessResource(userId: string, resource: string, action: string): Promise<boolean> {
     // Obtener todos los roles del usuario
    const userRoleAssignments = await this.userRoleController.search({ user_id: userId });
    if (!userRoleAssignments.data || userRoleAssignments.data.length === 0) return false;

    const roleIds = userRoleAssignments.data.map(a => a.role_id);

    // Obtener todos los permisos asignados a esos roles
    const rolePermAssignments = await this.rolePermissionController.search({ role_id: roleIds });
    if (!rolePermAssignments.data || rolePermAssignments.data.length === 0) return false;

    const permissionIds = rolePermAssignments.data.map(a => a.permission_id);

    // Finalmente, comprobar si alguno de los permisos coincide con el recurso y la acción
    const permission = await this.permissionController.findFirst({
        id: permissionIds,
        resource: resource,
        action: action
    });

    return !!permission.data;
  }
}