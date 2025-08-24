// src/repositories/user.ts
import { getDatabase } from '../db/connection';
import type { User, Role, Permission, UserQueryOptions } from '../types/auth';
import type { DatabaseTransaction } from '../types/common';
import { DatabaseError, UserNotFoundError } from '../errors/auth';

/**
 * Database user interface (raw database result)
 */
interface DatabaseUser {
  id: string;
  email: string;
  password_hash: string;
  first_name?: string;
  last_name?: string;
  created_at: string;
  updated_at: string;
  is_active: number;
  last_login_at?: string;
}

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
 * Database permission interface
 */
interface DatabasePermission {
  id: string;
  name: string;
  resource: string;
  action: string;
  created_at: string;
}

/**
 * User repository for database operations
 */
export class UserRepository {
  /**
   * Find user by ID
   */
  async findById(id: string, options: UserQueryOptions = {}, transaction?: DatabaseTransaction): Promise<User | null> {
    try {
      const db = getDatabase();
      
      const activeCondition = options.activeOnly ? ' AND is_active = 1' : '';
      const query = db.query(`
        SELECT id, email, password_hash, first_name, last_name, created_at, updated_at, is_active, last_login_at
        FROM users
        WHERE id = ?${activeCondition}
      `);
      
      const userResult = query.all(id) as DatabaseUser[];
      
      if (userResult.length === 0) {
        return null;
      }
      
      const userData = userResult[0];
      const user = this.mapDatabaseUserToSafeUser(userData) as User;
      
      // Include roles if requested
      if (options.includeRoles) {
        user.roles = await this.getUserRoles(id, options.includePermissions, transaction);
      }
      
      return user;
    } catch (error) {
      throw new DatabaseError(`Failed to find user by ID: ${error instanceof Error ? error.message : String(error)}`, 'findById');
    }
  }
  
  /**
   * Find user by email
   */
  async findByEmail(email: string, options: UserQueryOptions = {}, transaction?: DatabaseTransaction): Promise<User | null> {
    try {
      const db = getDatabase();
      
      let query = `
        SELECT id, email, password_hash, first_name, last_name, created_at, updated_at, is_active, last_login_at
        FROM users
        WHERE email = ?
      `;
      
      const params = [email.toLowerCase()];
      
      if (options.activeOnly) {
        query += ` AND is_active = 1`;
      }
      
      const userResult = db.query(query).all(...params) as DatabaseUser[];
      
      if (userResult.length === 0) {
        return null;
      }
      
      const userData = userResult[0];
      const user = this.mapDatabaseUserToSafeUser(userData) as User;
      
      // Include roles if requested
      if (options.includeRoles) {
        user.roles = await this.getUserRoles(userData.id, options.includePermissions, transaction);
      }
      
      return user;
    } catch (error) {
      throw new DatabaseError(`Failed to find user by email: ${error instanceof Error ? error.message : String(error)}`, 'findByEmail');
    }
  }
  
  /**
   * Create a new user
   */
  async create(userData: {
    id: string;
    email: string;
    passwordHash: string;
    firstName?: string | null;
    lastName?: string | null;
    isActive?: boolean;
  }, transaction?: DatabaseTransaction): Promise<User> {
    try {
      const db = getDatabase();
      
      const insertQuery = db.query(`
        INSERT INTO users (id, email, password_hash, first_name, last_name, created_at, updated_at, is_active)
        VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'), ?)
      `);
      
      insertQuery.run(
        userData.id,
        userData.email.toLowerCase(),
        userData.passwordHash,
        userData.firstName || null,
        userData.lastName || null,
        userData.isActive !== false ? 1 : 0
      );
      
      // Fetch the created user and return it properly mapped
      const createdUser = await this.findById(userData.id, { includeRoles: true });
      if (!createdUser) {
        throw new DatabaseError('Failed to retrieve created user', 'create');
      }
      
      return createdUser;
    } catch (error) {
      throw new DatabaseError(`Failed to create user: ${error instanceof Error ? error.message : String(error)}`, 'create');
    }
  }
  
  /**
   * Update user data
   */
  async update(userId: string, updateData: {
    email?: string;
    passwordHash?: string;
    firstName?: string | null;
    lastName?: string | null;
    isActive?: boolean;
    lastLoginAt?: Date;
  }, transaction?: DatabaseTransaction): Promise<void> {
    try {
      const db = getDatabase();
      
      const updateFields: string[] = [];
      const updateValues: any[] = [];
      
      if (updateData.email !== undefined) {
        updateFields.push('email = ?');
        updateValues.push(updateData.email.toLowerCase());
      }
      
      if (updateData.passwordHash !== undefined) {
        updateFields.push('password_hash = ?');
        updateValues.push(updateData.passwordHash);
      }
      
      if (updateData.firstName !== undefined) {
        updateFields.push('first_name = ?');
        updateValues.push(updateData.firstName);
      }
      
      if (updateData.lastName !== undefined) {
        updateFields.push('last_name = ?');
        updateValues.push(updateData.lastName);
      }
      
      if (updateData.isActive !== undefined) {
        updateFields.push('is_active = ?');
        updateValues.push(updateData.isActive ? 1 : 0);
      }
      
      if (updateData.lastLoginAt !== undefined) {
        updateFields.push('last_login_at = ?');
        // Ensure lastLoginAt is a valid Date object
        const lastLoginDate = updateData.lastLoginAt instanceof Date 
          ? updateData.lastLoginAt 
          : new Date(updateData.lastLoginAt);
        updateValues.push(lastLoginDate.toISOString());
      }
      
      updateFields.push("updated_at = datetime('now')");
      updateValues.push(userId);
      
      if (updateFields.length === 1) { // Only updated_at was added
        return;
      }
      
      const updateQuery = db.query(
        `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`
      );
      
      updateQuery.run(...updateValues);
    } catch (error) {
      throw new DatabaseError(`Failed to update user: ${error instanceof Error ? error.message : String(error)}`, 'update');
    }
  }
  
  /**
   * Delete user
   */
  async delete(userId: string, transaction?: DatabaseTransaction): Promise<void> {
    try {
      const db = getDatabase();
      
      // First remove user roles
      const deleteRolesQuery = db.query('DELETE FROM user_roles WHERE user_id = ?');
      deleteRolesQuery.run(userId);
      
      // Then delete user
      const deleteUserQuery = db.query('DELETE FROM users WHERE id = ?');
      deleteUserQuery.run(userId);
    } catch (error) {
      throw new DatabaseError(`Failed to delete user: ${error instanceof Error ? error.message : String(error)}`, 'delete');
    }
  }
  
  /**
   * Get users with pagination and filtering
   */
  async getUsers(options: {
    page?: number;
    limit?: number;
    activeOnly?: boolean;
    search?: string;
    sortBy?: 'email' | 'created_at' | 'last_login_at';
    sortOrder?: 'asc' | 'desc';
    includeRoles?: boolean;
    includePermissions?: boolean;
  } = {}): Promise<{
    users: User[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  }> {
    try {
      const db = getDatabase();
      
      const page = Math.max(1, options.page || 1);
      const limit = Math.min(100, Math.max(1, options.limit || 10));
      const offset = (page - 1) * limit;
      
      // Build WHERE clause
      const whereConditions: string[] = [];
      const whereParams: any[] = [];
      
      if (options.activeOnly !== undefined) {
        whereConditions.push(`is_active = ${options.activeOnly ? 1 : 0}`);
      }
      
      if (options.search) {
        whereConditions.push('(email LIKE ? OR first_name LIKE ? OR last_name LIKE ?)');
        const searchPattern = `%${options.search}%`;
        whereParams.push(searchPattern, searchPattern, searchPattern);
      }
      
      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';
      
      // Build ORDER BY clause
      const sortBy = options.sortBy || 'created_at';
      const sortOrder = options.sortOrder || 'desc';
      const orderClause = `ORDER BY ${sortBy} ${sortOrder.toUpperCase()}`;
      
      // Get total count
      const countQuery = db.query(`SELECT COUNT(*) as count FROM users ${whereClause}`);
      const countResult = countQuery.get(...whereParams) as { count: number };
      const total = countResult.count;
      
      // Get users
      const usersQuery = db.query(`
        SELECT id, email, password_hash, first_name, last_name, created_at, updated_at, is_active, last_login_at
        FROM users
        ${whereClause}
        ${orderClause}
        LIMIT ? OFFSET ?
      `);
      
      const usersResult = usersQuery.all(...whereParams, limit, offset) as DatabaseUser[];
      
      const users: User[] = [];
      for (const userData of usersResult) {
        const user = this.mapDatabaseUserToSafeUser(userData) as User;
        
        if (options.includeRoles) {
          user.roles = await this.getUserRoles(userData.id, options.includePermissions);
        }
        
        users.push(user);
      }
      
      return {
        users,
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      };
    } catch (error) {
      throw new DatabaseError(`Failed to get users: ${error instanceof Error ? error.message : String(error)}`, 'getUsers');
    }
  }
  
  /**
   * Get user roles
   */
  async getUserRoles(userId: string, includePermissions: boolean = false, transaction?: DatabaseTransaction): Promise<Role[]> {
    try {
      const db = getDatabase();
      
      const rolesQuery = db.query(`
        SELECT r.id, r.name, r.created_at, r.is_active
        FROM roles r
        INNER JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ?
        ORDER BY r.name
      `);
      
      const rolesResult = rolesQuery.all(userId) as DatabaseRole[];
      
      const roles: Role[] = [];
      for (const roleData of rolesResult) {
        const role: Role = {
          id: roleData.id,
          name: roleData.name,
          createdAt: new Date(roleData.created_at),
          updatedAt: new Date(roleData.created_at), // Use created_at as fallback since updated_at is not available
          created_at: new Date(roleData.created_at), // For test compatibility
          isActive: Boolean(roleData.is_active), // For test compatibility
          description: undefined,
          permissions: [],
          metadata: undefined
        } as any;
        
        if (includePermissions) {
          role.permissions = await this.getRolePermissions(role.id, transaction);
        }
        
        roles.push(role);
      }
      
      return roles;
    } catch (error) {
      throw new DatabaseError(`Failed to get user roles: ${error instanceof Error ? error.message : String(error)}`, 'getUserRoles');
    }
  }
  
  /**
   * Get role permissions
   */
  async getRolePermissions(roleId: string, transaction?: DatabaseTransaction): Promise<Permission[]> {
    try {
      const db = getDatabase();
      
      const permissionsQuery = db.query(`
        SELECT p.id, p.name, p.resource, p.action, p.created_at
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = ?
        ORDER BY p.resource, p.action
      `);
      
      const permissionsResult = permissionsQuery.all(roleId) as DatabasePermission[];
      
      return permissionsResult.map((permData): Permission => ({
        id: permData.id,
        name: permData.name,
        resource: permData.resource,
        action: permData.action,
        createdAt: new Date(permData.created_at),
        updatedAt: new Date()
      }));
    } catch (error) {
      throw new DatabaseError(`Failed to get role permissions: ${error instanceof Error ? error.message : String(error)}`, 'getRolePermissions');
    }
  }
  
  /**
   * Map database user to User interface
   */
  private mapDatabaseUserToUser(userData: DatabaseUser): User {
    return {
      id: userData.id,
      email: userData.email,
      passwordHash: userData.password_hash,
      firstName: userData.first_name || undefined,
      lastName: userData.last_name || undefined,
      createdAt: new Date(userData.created_at),
      updatedAt: new Date(userData.updated_at),
      isActive: Boolean(userData.is_active),
      lastLoginAt: userData.last_login_at ? new Date(userData.last_login_at) : undefined,
      roles: []
    };
  }

  /**
   * Map database user to User interface without password
   */
  private mapDatabaseUserToSafeUser(userData: DatabaseUser): Omit<User, 'passwordHash'> {
    return {
      id: userData.id,
      email: userData.email,
      firstName: userData.first_name || undefined,
      lastName: userData.last_name || undefined,
      createdAt: new Date(userData.created_at),
      updatedAt: new Date(userData.updated_at),
      isActive: Boolean(userData.is_active),
      lastLoginAt: userData.last_login_at ? new Date(userData.last_login_at) : undefined,
      roles: []
    };
  }

  /**
   * Find user by email for authentication (includes password hash)
   */
  async findByEmailForAuth(email: string, options: UserQueryOptions = {}, transaction?: DatabaseTransaction): Promise<User | null> {
    try {
      const db = getDatabase();
      
      let query = `
        SELECT id, email, password_hash, first_name, last_name, created_at, updated_at, is_active, last_login_at
        FROM users
        WHERE email = ?
      `;
      
      const params = [email.toLowerCase()];
      
      if (options.activeOnly) {
        query += ` AND is_active = 1`;
      }
      
      const userResult = db.query(query).all(...params) as DatabaseUser[];
      
      if (userResult.length === 0) {
        return null;
      }
      
      const userData = userResult[0];
      const user = this.mapDatabaseUserToUser(userData);
      
      // Include roles if requested
      if (options.includeRoles) {
        user.roles = await this.getUserRoles(userData.id, options.includePermissions, transaction);
      }
      
      return user;
    } catch (error) {
      throw new DatabaseError(`Failed to find user by email for auth: ${error instanceof Error ? error.message : String(error)}`, 'findByEmailForAuth');
    }
  }
}