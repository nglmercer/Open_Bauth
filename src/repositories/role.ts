// src/repositories/role.ts
import { getDatabase } from '../db/connection';
import type { Role } from '../types/auth';
import type { DatabaseTransaction } from '../types/common';
import { DatabaseError, NotFoundError } from '../errors/auth';

/**
 * Database role interface
 */
interface DatabaseRole {
  id: string;
  name: string;
  created_at: string;
  is_active: number;
}

/**
 * Role repository for database operations
 */
export class RoleRepository {
  /**
   * Find role by ID
   */
  async findById(roleId: string, transaction?: DatabaseTransaction): Promise<Role | null> {
    try {
      const db = transaction ? transaction.getDatabase() : getDatabase();
      
      const query = db.query('SELECT id, name, created_at, is_active FROM roles WHERE id = ?');
      const result = query.get(roleId) as DatabaseRole | null;
      
      if (!result) {
        return null;
      }
      
      return this.mapDatabaseRoleToRole(result);
    } catch (error) {
      throw new DatabaseError(`Failed to find role by ID: ${error instanceof Error ? error.message : String(error)}`, 'findById');
    }
  }
  
  /**
   * Find role by name
   */
  async findByName(name: string, transaction?: DatabaseTransaction): Promise<Role | null> {
    try {
      const db = transaction ? transaction.getDatabase() : getDatabase();
      
      const query = db.query('SELECT id, name, created_at, is_active FROM roles WHERE name = ?');
      const result = query.get(name.toLowerCase()) as DatabaseRole | null;
      
      if (!result) {
        return null;
      }
      
      return this.mapDatabaseRoleToRole(result);
    } catch (error) {
      throw new DatabaseError(`Failed to find role by name: ${error instanceof Error ? error.message : String(error)}`, 'findByName');
    }
  }
  
  /**
   * Create a new role
   */
  async create(roleData: {
    id: string;
    name: string;
    isActive?: boolean;
  }, transaction?: DatabaseTransaction): Promise<string> {
    try {
      const db = transaction ? transaction.getDatabase() : getDatabase();
      
      const insertQuery = db.query(`
        INSERT INTO roles (id, name, created_at, is_active)
        VALUES (?, ?, datetime('now'), ?)
      `);
      
      insertQuery.run(
        roleData.id,
        roleData.name.toLowerCase(),
        roleData.isActive !== false ? 1 : 0
      );
      
      return roleData.id;
    } catch (error) {
      throw new DatabaseError(`Failed to create role: ${error instanceof Error ? error.message : String(error)}`, 'create');
    }
  }
  
  /**
   * Check if user has role
   */
  async userHasRole(userId: string, roleId: string, transaction?: DatabaseTransaction): Promise<boolean> {
    try {
      const db = transaction ? transaction.getDatabase() : getDatabase();
      
      const query = db.query('SELECT id FROM user_roles WHERE user_id = ? AND role_id = ?');
      const result = query.get(userId, roleId);
      
      return result !== null;
    } catch (error) {
      throw new DatabaseError(`Failed to check user role: ${error instanceof Error ? error.message : String(error)}`, 'userHasRole');
    }
  }
  
  /**
   * Assign role to user
   */
  async assignToUser(userId: string, roleId: string, transaction?: DatabaseTransaction): Promise<void> {
    try {
      const db = transaction ? transaction.getDatabase() : getDatabase();
      
      // Check if assignment already exists
      const exists = await this.userHasRole(userId, roleId, transaction);
      if (exists) {
        throw new Error('User already has this role');
      }
      
      const insertQuery = db.query(`
        INSERT INTO user_roles (id, user_id, role_id, created_at)
        VALUES (?, ?, ?, datetime('now'))
      `);
      
      insertQuery.run(crypto.randomUUID(), userId, roleId);
    } catch (error) {
      throw new DatabaseError(`Failed to assign role to user: ${error instanceof Error ? error.message : String(error)}`, 'assignToUser');
    }
  }
  
  /**
   * Remove role from user
   */
  async removeFromUser(userId: string, roleId: string, transaction?: DatabaseTransaction): Promise<void> {
    try {
      const db = transaction ? transaction.getDatabase() : getDatabase();
      
      const deleteQuery = db.query('DELETE FROM user_roles WHERE user_id = ? AND role_id = ?');
      deleteQuery.run(userId, roleId);
    } catch (error) {
      throw new DatabaseError(`Failed to remove role from user: ${error instanceof Error ? error.message : String(error)}`, 'removeFromUser');
    }
  }
  
  /**
   * Get or create default user role
   */
  async getOrCreateDefaultRole(transaction?: DatabaseTransaction): Promise<Role> {
    try {
      // Try to find existing 'user' role
      let role = await this.findByName('user', transaction);
      
      if (!role) {
        // Create default 'user' role
        const roleId = crypto.randomUUID();
        await this.create({
          id: roleId,
          name: 'user',
          isActive: true
        }, transaction);
        
        role = await this.findById(roleId, transaction);
        if (!role) {
          throw new Error('Failed to create default role');
        }
      }
      
      return role;
    } catch (error) {
      throw new DatabaseError(`Failed to get or create default role: ${error instanceof Error ? error.message : String(error)}`, 'getOrCreateDefaultRole');
    }
  }
  
  /**
   * Get all roles
   */
  async getAll(activeOnly: boolean = false): Promise<Role[]> {
    try {
      const db = getDatabase();
      
      let query = 'SELECT id, name, created_at, is_active FROM roles';
      const params: any[] = [];
      
      if (activeOnly) {
        query += ' WHERE is_active = 1';
      }
      
      query += ' ORDER BY name';
      
      const rolesQuery = db.query(query);
      const results = rolesQuery.all(...params) as DatabaseRole[];
      
      return results.map(result => this.mapDatabaseRoleToRole(result));
    } catch (error) {
      throw new DatabaseError(`Failed to get all roles: ${error instanceof Error ? error.message : String(error)}`, 'getAll');
    }
  }
  
  /**
   * Map database role to Role interface
   */
  private mapDatabaseRoleToRole(roleData: DatabaseRole): Role {
    return {
      id: roleData.id,
      name: roleData.name,
      createdAt: new Date(roleData.created_at),
      updatedAt: new Date(roleData.created_at),
      permissions: [],
      isActive: roleData.is_active === 1
    };
  }
}