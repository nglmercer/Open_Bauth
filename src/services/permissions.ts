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
 * Servicio de permisos y gestión de roles
 * Maneja la creación, asignación y verificación de roles y permisos
 */
export class PermissionService {
  /**
   * Crea un nuevo permiso
   * @param data Datos del permiso
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

      // Verificar si el permiso ya existe
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

      // Crear permiso
      const permissionId = crypto.randomUUID();
      const query = db.query(
        "INSERT INTO permissions (id, name, resource, action, description, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))"
      );
      query.run(permissionId, data.name, data.resource || 'default', data.action || 'read', data.description || null);

      // Obtener el permiso creado
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
   * Crea un nuevo rol
   * @param data Datos del rol
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

      // Verificar si el rol ya existe
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

      // Crear rol
      const roleId = crypto.randomUUID();
      const query = db.query(
        "INSERT INTO roles (id, name, description, is_active, created_at) VALUES (?, ?, ?, ?, datetime('now'))"
      );
      query.run(roleId, data.name, data.description || null, 1);

      // Asignar permisos si se proporcionan
      if (data.permissions && data.permissions.length > 0) {
        const assignResult = await this.assignPermissionsToRole(roleId, data.permissions);
        if (!assignResult.success) {
          return assignResult;
        }
      }

      // Obtener el rol creado con permisos
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
   * Asigna un rol a un usuario
   * @param data Datos de asignación
   */
  async assignRoleToUser(data: AssignRoleData): Promise<PermissionResult> {
    try {
      const db = getDatabase();

      // Verificar que el usuario y el rol existen
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

      // Verificar si la asignación ya existe
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

      // Crear asignación
      const insertQuery = db.query(
        "INSERT INTO user_roles (id, user_id, role_id, created_at) VALUES (?, ?, ?, datetime('now'))"
      );
      insertQuery.run(crypto.randomUUID(), data.userId, data.roleId);

      console.log(`✅ Rol asignado al usuario: ${data.userId} -> ${data.roleId}`);
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
   * Remueve un rol de un usuario
   * @param userId ID del usuario
   * @param roleId ID del rol
   */
  async removeRoleFromUser(userId: string, roleId: string): Promise<PermissionResult> {
    try {
      const db = getDatabase();

      const query = db.query(
        "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?"
      );
      query.run(userId, roleId);

      console.log(`✅ Rol removido del usuario: ${userId} -> ${roleId}`);
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
   * Asigna permisos a un rol
   * @param roleId ID del rol
   * @param permissionIds Array de IDs de permisos
   */
  async assignPermissionsToRole(roleId: string, permissionIds: string[]): Promise<PermissionResult> {
    try {
      const db = getDatabase();

      // Verificar que el rol existe
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

      // Verificar que todos los permisos existen
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

      // Verificar duplicados y asignar permisos
      for (const permissionId of permissionIds) {
        // Verificar si ya existe la asignación
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
        
        // Insertar nueva asignación
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
   * Asigna un permiso específico a un rol (método individual)
   * @param roleId ID del rol
   * @param permissionId ID del permiso
   */
  async assignPermissionToRole(roleId: string, permissionId: string): Promise<PermissionResult> {
    return this.assignPermissionsToRole(roleId, [permissionId]);
  }

  /**
   * Remueve permisos de un rol
   * @param roleId ID del rol
   * @param permissionIds Array de IDs de permisos
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

      console.log(`✅ Permisos removidos del rol: ${roleId}`);
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
   * Actualiza un permiso existente
   * @param id ID del permiso
   * @param data Datos de actualización
   */
  async updatePermission(id: string, data: UpdatePermissionData): Promise<PermissionResult> {
    try {
      const db = getDatabase();

      // Verificar que el permiso existe
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

      // Verificar que el nombre no esté en uso por otro permiso
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
      console.log(`✅ Permiso actualizado: ${updatedPermission?.name}`);
      
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
   * Elimina un permiso
   * @param id ID del permiso
   */
  async deletePermission(id: string): Promise<PermissionResult> {
    try {
      const db = getDatabase();

      // Verificar que el permiso existe
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

      // Eliminar relaciones primero
      const deleteRelationsQuery = db.query(
        "DELETE FROM role_permissions WHERE permission_id = ?"
      );
      deleteRelationsQuery.run(id);

      // Eliminar el permiso
      const deletePermissionQuery = db.query(
        "DELETE FROM permissions WHERE id = ?"
      );
      deletePermissionQuery.run(id);

      console.log(`✅ Permiso eliminado: ${existingPermission.name}`);
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
   * Actualiza un rol existente
   * @param id ID del rol
   * @param data Datos de actualización
   */
  async updateRole(id: string, data: UpdateRoleData): Promise<RoleResult> {
    try {
      const db = getDatabase();

      // Verificar que el rol existe
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

      // Verificar que el nombre no esté en uso por otro rol
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
      console.log(`✅ Rol actualizado: ${updatedRole?.name}`);
      
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
   * Elimina un rol
   * @param id ID del rol
   */
  async deleteRole(id: string): Promise<RoleResult> {
    try {
      const db = getDatabase();

      // Verificar que el rol existe
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

      // Eliminar relaciones con usuarios
      const deleteUserRolesQuery = db.query(
        "DELETE FROM user_roles WHERE role_id = ?"
      );
      deleteUserRolesQuery.run(id);

      // Eliminar relaciones con permisos
      const deleteRolePermissionsQuery = db.query(
        "DELETE FROM role_permissions WHERE role_id = ?"
      );
      deleteRolePermissionsQuery.run(id);

      // Eliminar el rol
      const deleteRoleQuery = db.query(
        "DELETE FROM roles WHERE id = ?"
      );
      deleteRoleQuery.run(id);

      console.log(`✅ Rol eliminado: ${existingRole.name}`);
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
   * Remueve un permiso específico de un rol
   * @param roleId ID del rol
   * @param permissionId ID del permiso
   */
  async removePermissionFromRole(roleId: string, permissionId: string): Promise<PermissionResult> {
    return this.removePermissionsFromRole(roleId, [permissionId]);
  }

  /**
   * Verifica si un usuario tiene un permiso específico
   * @param userId ID del usuario
   * @param permissionName Nombre del permiso
   * @param options Opciones de verificación
   * @returns true si el usuario tiene el permiso
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

      // Verificar permiso exacto
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

      // Verificar permisos wildcard
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
   * Verifica si un usuario tiene un rol específico
   * @param userId ID del usuario
   * @param roleName Nombre del rol
   * @returns true si el usuario tiene el rol
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
   * Verifica si un usuario tiene todos los roles especificados
   * @param userId ID del usuario
   * @param roleNames Array de nombres de roles
   * @returns true si el usuario tiene todos los roles
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
   * Verifica si un usuario tiene al menos uno de los roles especificados
   * @param userId ID del usuario
   * @param roleNames Array de nombres de roles
   * @returns true si el usuario tiene al menos uno de los roles
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
   * Verifica si un usuario tiene todos los permisos especificados
   * @param userId ID del usuario
   * @param permissionNames Array de nombres de permisos
   * @returns true si el usuario tiene todos los permisos
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
   * Verifica si un usuario tiene al menos uno de los permisos especificados
   * @param userId ID del usuario
   * @param permissionNames Array de nombres de permisos
   * @returns true si el usuario tiene al menos uno de los permisos
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
   * Verifica si un usuario puede acceder a un recurso específico
   * @param userId ID del usuario
   * @param resource Nombre del recurso
   * @param action Acción a realizar (read, write, delete, etc.)
   * @returns true si el usuario puede acceder al recurso
   */
  async userCanAccessResource(userId: string, resource: string, action: string): Promise<boolean> {
    try {
      const db = getDatabase();

      // Verificar permiso exacto
      const exactPermissionName = `${resource}:${action}`;
      const hasExactPermission = await this.userHasPermission(userId, exactPermissionName);
      
      if (hasExactPermission) {
        return true;
      }

      // Verificar permisos wildcard específicos para el recurso y acción
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
   * Verifica si un usuario tiene múltiples permisos
   * @param userId ID del usuario
   * @param permissionNames Array de nombres de permisos
   * @param options Opciones de verificación
   * @returns true si cumple con los criterios
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

      // Si requireAll es true, todos los permisos deben estar presentes
      if (options.requireAll) {
        return results.every(result => result);
      }

      // Por defecto, solo se requiere uno (OR)
      return results.some(result => result);
    } catch (error:any) {
      console.error('Error checking user permissions:', error);
      return false;
    }
  }

  /**
   * Obtiene todos los permisos de un usuario
   * @param userId ID del usuario
   * @returns Array de permisos
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
   * Busca un permiso por ID
   * @param id ID del permiso
   * @returns Permiso o null
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
   * Busca un permiso por nombre
   * @param name Nombre del permiso
   * @returns Permiso o null
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
   * Busca un rol por ID
   * @param id ID del rol
   * @param includePermissions Si incluir permisos
   * @returns Rol o null
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
   * Busca un rol por nombre
   * @param name Nombre del rol
   * @param includePermissions Si incluir permisos
   * @returns Rol o null
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
   * Obtiene los permisos de un rol
   * @param roleId ID del rol
   * @returns Array de permisos
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
   * Obtiene todos los roles
   * @param includePermissions Si incluir permisos
   * @returns Array de roles
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
   * Obtiene todos los permisos
   * @returns Array de permisos
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

  // Métodos de validación y utilidad privados

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
 * Instancia singleton del servicio de permisos
 */
let permissionServiceInstance: PermissionService | null = null;

/**
 * Inicializa el servicio de permisos
 * @returns Instancia del servicio de permisos
 */
export function initPermissionService(): PermissionService {
  permissionServiceInstance = new PermissionService();
  return permissionServiceInstance;
}

/**
 * Obtiene la instancia del servicio de permisos
 * @returns Instancia del servicio de permisos
 * @throws Error si no ha sido inicializado
 */
export function getPermissionService(): PermissionService {
  if (!permissionServiceInstance) {
    throw new Error('Permission Service not initialized. Call initPermissionService() first.');
  }
  return permissionServiceInstance;
}