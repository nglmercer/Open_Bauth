// src/services/permissions.ts
import { getDatabase } from '../db/connection';
import type { 
  Role, 
  Permission, 
  CreateRoleData, 
  CreatePermissionData, 
  AssignRoleData, 
  PermissionOptions 
} from '../types/auth';

/**
 * Servicio de permisos y gestión de roles
 * Maneja la creación, asignación y verificación de roles y permisos
 */
export class PermissionService {
  /**
   * Crea un nuevo permiso
   * @param data Datos del permiso
   * @returns Permiso creado
   */
  async createPermission(data: CreatePermissionData): Promise<Permission> {
    try {
      const db = getDatabase();

      // Validar datos
      this.validatePermissionData(data);

      // Verificar si el permiso ya existe
      const existingPermission = await this.findPermissionByName(data.name);
      if (existingPermission) {
        throw new Error(`Permission '${data.name}' already exists`);
      }

      // Crear permiso
      const permissionId = crypto.randomUUID();
      db.query(
        "INSERT INTO permissions (id, name, resource, action, created_at) VALUES (?, ?, ?, ?, datetime('now'))"
      ).run(permissionId, data.name, data.resource, data.action);

      // Obtener el permiso creado
      const permission = await this.findPermissionById(permissionId);
      if (!permission) {
        throw new Error('Failed to create permission');
      }

      console.log(`✅ Permiso creado: ${permission.name}`);
      return permission;
    } catch (error) {
      console.error('Error creating permission:', error);
      throw new Error(`Failed to create permission: ${error.message}`);
    }
  }

  /**
   * Crea un nuevo rol
   * @param data Datos del rol
   * @returns Rol creado
   */
  async createRole(data: CreateRoleData): Promise<Role> {
    try {
      const db = getDatabase();

      // Validar datos
      this.validateRoleData(data);

      // Verificar si el rol ya existe
      const existingRole = await this.findRoleByName(data.name);
      if (existingRole) {
        throw new Error(`Role '${data.name}' already exists`);
      }

      // Crear rol
      const roleId = crypto.randomUUID();
      db.query(
        "INSERT INTO roles (id, name, created_at) VALUES (?, ?, datetime('now'))"
      ).run(roleId, data.name);

      // Asignar permisos si se proporcionan
      if (data.permissionIds && data.permissionIds.length > 0) {
        await this.assignPermissionsToRole(roleId, data.permissionIds);
      }

      // Obtener el rol creado con permisos
      const role = await this.findRoleById(roleId, true);
      if (!role) {
        throw new Error('Failed to create role');
      }

      console.log(`✅ Rol creado: ${role.name}`);
      return role;
    } catch (error) {
      console.error('Error creating role:', error);
      throw new Error(`Failed to create role: ${error.message}`);
    }
  }

  /**
   * Asigna un rol a un usuario
   * @param data Datos de asignación
   */
  async assignRoleToUser(data: AssignRoleData): Promise<void> {
    try {
      const db = getDatabase();

      // Verificar que el usuario y el rol existen
      const userExists = await this.checkUserExists(data.userId);
      if (!userExists) {
        throw new Error('User not found');
      }

      const roleExists = await this.checkRoleExists(data.roleId);
      if (!roleExists) {
        throw new Error('Role not found');
      }

      // Verificar si la asignación ya existe
      const existingAssignment = await db`
        SELECT id FROM user_roles 
        WHERE user_id = ${data.userId} AND role_id = ${data.roleId}
      `;

      if (existingAssignment.length > 0) {
        throw new Error('User already has this role');
      }

      // Crear asignación
      await db`
        INSERT INTO user_roles (id, user_id, role_id, created_at)
        VALUES (${crypto.randomUUID()}, ${data.userId}, ${data.roleId}, datetime('now'))
      `;

      console.log(`✅ Rol asignado al usuario: ${data.userId} -> ${data.roleId}`);
    } catch (error) {
      console.error('Error assigning role to user:', error);
      throw new Error(`Failed to assign role: ${error.message}`);
    }
  }

  /**
   * Remueve un rol de un usuario
   * @param userId ID del usuario
   * @param roleId ID del rol
   */
  async removeRoleFromUser(userId: string, roleId: string): Promise<void> {
    try {
      const db = getDatabase();

      const result = await db`
        DELETE FROM user_roles 
        WHERE user_id = ${userId} AND role_id = ${roleId}
      `;

      console.log(`✅ Rol removido del usuario: ${userId} -> ${roleId}`);
    } catch (error) {
      console.error('Error removing role from user:', error);
      throw new Error(`Failed to remove role: ${error.message}`);
    }
  }

  /**
   * Asigna permisos a un rol
   * @param roleId ID del rol
   * @param permissionIds Array de IDs de permisos
   */
  async assignPermissionsToRole(roleId: string, permissionIds: string[]): Promise<void> {
    try {
      const db = getDatabase();

      // Verificar que el rol existe
      const roleExists = await this.checkRoleExists(roleId);
      if (!roleExists) {
        throw new Error('Role not found');
      }

      // Verificar que todos los permisos existen
      for (const permissionId of permissionIds) {
        const permissionExists = await this.checkPermissionExists(permissionId);
        if (!permissionExists) {
          throw new Error(`Permission not found: ${permissionId}`);
        }
      }

      // Asignar permisos (ignorar duplicados)
      for (const permissionId of permissionIds) {
        try {
          db.query(
            "INSERT INTO role_permissions (id, role_id, permission_id, created_at) VALUES (?, ?, ?, datetime('now'))"
          ).run(crypto.randomUUID(), roleId, permissionId);
        } catch (error) {
          // Ignorar errores de duplicados
          if (!error.message.includes('UNIQUE constraint')) {
            throw error;
          }
        }
      }

      console.log(`✅ Permisos asignados al rol: ${roleId}`);
    } catch (error) {
      console.error('Error assigning permissions to role:', error);
      throw new Error(`Failed to assign permissions: ${error.message}`);
    }
  }

  /**
   * Remueve permisos de un rol
   * @param roleId ID del rol
   * @param permissionIds Array de IDs de permisos
   */
  async removePermissionsFromRole(roleId: string, permissionIds: string[]): Promise<void> {
    try {
      const db = getDatabase();

      for (const permissionId of permissionIds) {
        await db`
          DELETE FROM role_permissions 
          WHERE role_id = ${roleId} AND permission_id = ${permissionId}
        `;
      }

      console.log(`✅ Permisos removidos del rol: ${roleId}`);
    } catch (error) {
      console.error('Error removing permissions from role:', error);
      throw new Error(`Failed to remove permissions: ${error.message}`);
    }
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

      const query = db.query(`
        SELECT COUNT(*) as count
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        INNER JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = ? AND p.name = ?
      `);
      const result = query.all(userId, permissionName);

      return result[0].count > 0;
    } catch (error) {
      console.error('Error checking user permission:', error);
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
    } catch (error) {
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
        SELECT DISTINCT p.id, p.name, p.resource, p.action, p.created_at
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        INNER JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = ?
        ORDER BY p.resource, p.action
      `);
      const result = query.all(userId);

      return result.map(row => ({
        id: row.id,
        name: row.name,
        resource: row.resource,
        action: row.action,
        created_at: new Date(row.created_at)
      }));
    } catch (error) {
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

      const result = db.query(
        "SELECT id, name, resource, action, created_at FROM permissions WHERE id = ?"
      ).all(id);

      if (result.length === 0) {
        return null;
      }

      const row = result[0];
      return {
        id: row.id,
        name: row.name,
        resource: row.resource,
        action: row.action,
        created_at: new Date(row.created_at)
      };
    } catch (error) {
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

      const result = db.query(
        "SELECT id, name, resource, action, created_at FROM permissions WHERE name = ?"
      ).all(name);

      if (result.length === 0) {
        return null;
      }

      const row = result[0];
      return {
        id: row.id,
        name: row.name,
        resource: row.resource,
        action: row.action,
        created_at: new Date(row.created_at)
      };
    } catch (error) {
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

      const result = db.query(
        "SELECT id, name, created_at FROM roles WHERE id = ?"
      ).all(id);

      if (result.length === 0) {
        return null;
      }

      const row = result[0];
      const role: Role = {
        id: row.id,
        name: row.name,
        created_at: new Date(row.created_at),
        permissions: []
      };

      if (includePermissions) {
        role.permissions = await this.getRolePermissions(id);
      }

      return role;
    } catch (error) {
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

      const result = db.query(
        "SELECT id, name, created_at FROM roles WHERE name = ?"
      ).all(name);

      if (result.length === 0) {
        return null;
      }

      const row = result[0];
      const role: Role = {
        id: row.id,
        name: row.name,
        created_at: new Date(row.created_at),
        permissions: []
      };

      if (includePermissions) {
        role.permissions = await this.getRolePermissions(row.id);
      }

      return role;
    } catch (error) {
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
        SELECT p.id, p.name, p.resource, p.action, p.created_at
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = ?
        ORDER BY p.resource, p.action
      `).all(roleId);

      return result.map(row => ({
        id: row.id,
        name: row.name,
        resource: row.resource,
        action: row.action,
        created_at: new Date(row.created_at)
      }));
    } catch (error) {
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
        SELECT id, name, created_at
        FROM roles
        ORDER BY name
      `);
      const result = query.all();

      const roles = [];
      for (const row of result) {
        const role: Role = {
          id: row.id,
          name: row.name,
          created_at: new Date(row.created_at),
          permissions: []
        };

        if (includePermissions) {
          role.permissions = await this.getRolePermissions(row.id);
        }

        roles.push(role);
      }

      return roles;
    } catch (error) {
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
        SELECT id, name, resource, action, created_at
        FROM permissions
        ORDER BY resource, action
      `);
      const result = query.all();

      return result.map(row => ({
        id: row.id,
        name: row.name,
        resource: row.resource,
        action: row.action,
        created_at: new Date(row.created_at)
      }));
    } catch (error) {
      console.error('Error getting all permissions:', error);
      throw new Error(`Failed to get permissions: ${error.message}`);
    }
  }

  // Métodos de validación y utilidad privados

  private validatePermissionData(data: CreatePermissionData): void {
    if (!data.name || !data.resource || !data.action) {
      throw new Error('Name, resource, and action are required');
    }

    if (data.name.length < 3) {
      throw new Error('Permission name must be at least 3 characters long');
    }
  }

  private validateRoleData(data: CreateRoleData): void {
    if (!data.name) {
      throw new Error('Role name is required');
    }

    if (data.name.length < 3) {
      throw new Error('Role name must be at least 3 characters long');
    }
  }

  private async checkUserExists(userId: string): Promise<boolean> {
    try {
      const db = getDatabase();
      const result = await db`SELECT id FROM users WHERE id = ${userId}`;
      return result.length > 0;
    } catch (error) {
      return false;
    }
  }

  private async checkRoleExists(roleId: string): Promise<boolean> {
    try {
      const db = getDatabase();
      const result = db.query("SELECT id FROM roles WHERE id = ?").all(roleId);
      return result.length > 0;
    } catch (error) {
      return false;
    }
  }

  private async checkPermissionExists(permissionId: string): Promise<boolean> {
    try {
      const db = getDatabase();
      const result = db.query("SELECT id FROM permissions WHERE id = ?").all(permissionId);
      return result.length > 0;
    } catch (error) {
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