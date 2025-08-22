// src/services/auth.ts
import { getDatabase } from '../db/connection';
import { getJWTService } from './jwt';
import type { 
  User, 
  RegisterData, 
  LoginData, 
  AuthResult, 
  UserQueryOptions,
  UpdateUserData,
  AuthError,
  AuthErrorType,
  Role,
  Permission 
} from '../types/auth';

/**
 * Servicio de autenticación
 * Maneja registro, login y operaciones de usuario
 */
export class AuthService {
  /**
   * Registra un nuevo usuario
   * @param data Datos de registro
   * @returns Usuario creado y token
   */
  async register(data: RegisterData): Promise<AuthResult> {
    try {
      const db = getDatabase();
      const jwtService = getJWTService();

      // Validar datos de entrada
      try {
        this.validateRegisterData(data);
      } catch (validationError: any) {
        return {
          success: false,
          error: {
            type: validationError.type || 'VALIDATION_ERROR' as AuthErrorType,
            message: validationError.message
          }
        };
      }

      // Verificar si el usuario ya existe
      const existingUser = await this.findUserByEmail(data.email);
      if (existingUser) {
        return {
          success: false,
          error: {
            type: 'VALIDATION_ERROR' as AuthErrorType,
            message: 'User already exists with this email'
          }
        };
      }

      // Hash de la contraseña usando Bun
      const passwordHash = await Bun.password.hash(data.password, {
        algorithm: 'bcrypt',
        cost: 12
      });

      // Crear usuario en la base de datos
      const userId = crypto.randomUUID();
      const isActive = data.isActive !== undefined ? data.isActive : true;
      const insertQuery = db.query(`
        INSERT INTO users (id, email, password_hash, first_name, last_name, created_at, updated_at, is_active)
        VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'), ?)
      `);
      insertQuery.run(userId, data.email.toLowerCase(), passwordHash, data.firstName || null, data.lastName || null, isActive ? 1 : 0);

      // Asignar rol por defecto (user)
      await this.assignDefaultRole(userId);

      // Obtener el usuario completo con roles
      const user = await this.findUserById(userId, { includeRoles: true, includePermissions: true });
      if (!user) {
        throw new Error('Failed to create user');
      }

      // Update lastLoginAt
      const updateLoginQuery = db.query(
        "UPDATE users SET last_login_at = datetime('now') WHERE id = ?"
      );
      updateLoginQuery.run(user.id);

      // Generar token JWT
      const token = await jwtService.generateToken(user);
      const refreshToken = await jwtService.generateRefreshToken(Number(user.id));

      // Get updated user with lastLoginAt
      const updatedUser = await this.findUserById(user.id, { includeRoles: true, includePermissions: true });

      return { 
        success: true, 
        user: updatedUser || user, 
        token, 
        refreshToken 
      };
    } catch (error:any) {
      console.error('Error registering user:', error);
      return {
        success: false,
        error: {
          type: (error.type as AuthErrorType) || 'SERVER_ERROR' as AuthErrorType,
          message: error.message || 'Registration failed'
        }
      };
    }
  }

  /**
   * Autentica un usuario
   * @param data Datos de login
   * @returns Usuario y token si la autenticación es exitosa
   */
  async login(data: LoginData): Promise<AuthResult> {
    try {
      const db = getDatabase();
      const jwtService = getJWTService();

      // Validar datos de entrada
      this.validateLoginData(data);

      // Buscar usuario por email
      const user = await this.findUserByEmail(data.email, { 
        includeRoles: true, 
        includePermissions: true 
      });

      if (!user) {
        return {
          success: false,
          error: {
            type: 'AUTHENTICATION_ERROR' as AuthErrorType,
            message: 'Invalid credentials'
          }
        };
      }

      // Verificar si el usuario está activo
      if (!user.is_active) {
        return {
          success: false,
          error: {
            type: 'AUTHENTICATION_ERROR' as AuthErrorType,
            message: 'Account is inactive'
          }
        };
      }

      // Verificar contraseña
      const isValidPassword = await Bun.password.verify(data.password, user.password_hash);
      if (!isValidPassword) {
        return {
          success: false,
          error: {
            type: 'AUTHENTICATION_ERROR' as AuthErrorType,
            message: 'Invalid credentials'
          }
        };
      }

      // Actualizar última actividad y last_login_at
      const updateQuery = db.query(
        "UPDATE users SET updated_at = datetime('now'), last_login_at = datetime('now') WHERE id = ?"
      );
      updateQuery.run(user.id);

      // Obtener usuario actualizado con lastLoginAt
      const updatedUser = await this.findUserById(user.id, { includeRoles: true, includePermissions: true });
      if (!updatedUser) {
        return {
          success: false,
          error: {
            type: 'DATABASE_ERROR' as AuthErrorType,
            message: 'User not found after update'
          }
        };
      }

      // Generar token JWT
      const token = await jwtService.generateToken(updatedUser);
      const refreshToken = await jwtService.generateRefreshToken(Number(updatedUser.id));

      console.log(`✅ Usuario autenticado: ${updatedUser.email}`);

      return { 
        success: true, 
        user: updatedUser, 
        token, 
        refreshToken 
      };
    } catch (error:any) {
      console.error('Error during login:', error);
      return {
        success: false,
        error: {
          type: (error.type as AuthErrorType) || 'AUTHENTICATION_ERROR' as AuthErrorType,
          message: error.message || 'Login failed'
        }
      };
    }
  }

  /**
   * Busca un usuario por ID
   * @param id ID del usuario
   * @param options Opciones de consulta
   * @returns Usuario o null si no se encuentra
   */
  async findUserById(id: string, options: UserQueryOptions = {}): Promise<User | null> {
    try {
      const db = getDatabase();

      // Consulta base del usuario
      const activeCondition = options.activeOnly ? ' AND is_active = 1' : '';
      const query = db.query(`
        SELECT id, email, password_hash, first_name, last_name, created_at, updated_at, is_active, last_login_at
        FROM users
        WHERE id = ?${activeCondition}
      `);
      const userResult = query.all(id) as Array<{
        id: string;
        email: string;
        password_hash: string;
        first_name?: string;
        last_name?: string;
        created_at: string;
        updated_at: string;
        is_active: number;
        last_login_at?: string;
      }>;

      if (userResult.length === 0) {
        return null;
      }

      const userData = userResult[0];
      const user = this.mapDatabaseUserToUser(userData);

      // Incluir roles si se solicita
      if (options.includeRoles) {
        user.roles = await this.getUserRoles(id, options.includePermissions);
      }

      return user;
    } catch (error:any) {
      console.error('Error finding user by ID:', error);
      throw new Error(`Failed to find user: ${error.message}`);
    }
  }

  /**
   * Busca un usuario por email
   * @param email Email del usuario
   * @param options Opciones de consulta
   * @returns Usuario o null si no se encuentra
   */
  async findUserByEmail(email: string, options: UserQueryOptions = {}): Promise<User | null> {
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

      const userResult = db.query(query).all(...params) as Array<{
        id: string;
        email: string;
        password_hash: string;
        first_name?: string;
        last_name?: string;
        created_at: string;
        updated_at: string;
        is_active: number;
        last_login_at?: string;
      }>;

      if (userResult.length === 0) {
        return null;
      }

      const userData = userResult[0];
      const user = this.mapDatabaseUserToUser(userData);

      // Incluir roles si se solicita
      if (options.includeRoles) {
        user.roles = await this.getUserRoles(userData.id, options.includePermissions);
      }

      return user;
    } catch (error:any) {
      console.error('Error finding user by email:', error);
      throw new Error(`Failed to find user: ${error.message}`);
    }
  }

  /**
   * Obtiene los roles de un usuario
   * @param userId ID del usuario
   * @param includePermissions Si incluir permisos de los roles
   * @returns Array de roles
   */
  async getUserRoles(userId: string, includePermissions: boolean = false): Promise<Role[]> {
    try {
      const db = getDatabase();

      const rolesQuery = db.query(`
        SELECT r.id, r.name, r.created_at, r.is_active
        FROM roles r
        INNER JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ?
        ORDER BY r.name
      `);
      const rolesResult = rolesQuery.all(userId) as Array<{
        id: string;
        name: string;
        created_at: string;
        is_active: number;
      }>;

      const roles: Role[] = [];
      for (const roleData of rolesResult) {
        const role: Role = {
          id: roleData.id,
          name: roleData.name,
          created_at: new Date(roleData.created_at),
          isActive: Boolean(roleData.is_active),
          permissions: [] as Permission[]
        };

        // Incluir permisos si se solicita
        if (includePermissions) {
          const permissionsQuery = db.query(`
            SELECT p.id, p.name, p.resource, p.action, p.created_at
            FROM permissions p
            INNER JOIN role_permissions rp ON p.id = rp.permission_id
            WHERE rp.role_id = ?
            ORDER BY p.resource, p.action
          `);
          const permissionsResult = permissionsQuery.all(role.id) as Array<{
            id: string;
            name: string;
            resource: string;
            action: string;
            created_at: string;
          }>;

          role.permissions = permissionsResult.map((permData): Permission => ({
            id: permData.id,
            name: permData.name,
            resource: permData.resource,
            action: permData.action,
            created_at: new Date(permData.created_at)
          }));
        }

        roles.push(role);
      }

      return roles;
    } catch (error:any) {
      console.error('Error getting user roles:', error);
      throw new Error(`Failed to get user roles: ${error.message}`);
    }
  }

  /**
   * Asigna un rol específico a un usuario
   * @param userId ID del usuario
   * @param roleName Nombre del rol a asignar
   */
  async assignRole(userId: string, roleName: string): Promise<{ success: boolean; error?: { type: AuthErrorType; message: string } }> {
    try {
      const db = getDatabase();

      // Verificar que el usuario existe
      const user = await this.findUserById(userId);
      if (!user) {
        return {
          success: false,
          error: {
            type: 'USER_NOT_FOUND' as AuthErrorType,
            message: 'User not found'
          }
        };
      }

      // Buscar el rol por nombre
      const findRoleQuery = db.query("SELECT id FROM roles WHERE name = ?");
      const roleResult = findRoleQuery.get(roleName) as { id: string } | null;

      if (!roleResult) {
        return {
          success: false,
          error: {
            type: 'NOT_FOUND_ERROR' as AuthErrorType,
            message: `Role '${roleName}' not found`
          }
        };
      }

      // Verificar si el usuario ya tiene este rol
      const existingQuery = db.query(
        "SELECT id FROM user_roles WHERE user_id = ? AND role_id = ?"
      );
      const existing = existingQuery.get(userId, roleResult.id);

      if (existing) {
        return {
          success: false,
          error: {
            type: 'VALIDATION_ERROR' as AuthErrorType,
            message: 'User already has this role'
          }
        };
      }

      // Asignar rol al usuario
      const assignRoleQuery = db.query(
        "INSERT INTO user_roles (id, user_id, role_id, created_at) VALUES (?, ?, ?, datetime('now'))"
      );
      assignRoleQuery.run(crypto.randomUUID(), userId, roleResult.id);

      console.log(`✅ Rol ${roleName} asignado al usuario: ${userId}`);
      return { success: true };
    } catch (error: any) {
      console.error('Error assigning role:', error);
      return {
        success: false,
        error: {
          type: 'DATABASE_ERROR' as AuthErrorType,
          message: error.message || 'Failed to assign role'
        }
      };
    }
  }

  /**
   * Asigna el rol por defecto a un usuario
   * @param userId ID del usuario
   */
  private async assignDefaultRole(userId: string): Promise<void> {
    try {
      const db = getDatabase();

      // Buscar o crear el rol 'user'
      const findRoleQuery = db.query("SELECT id FROM roles WHERE name = 'user'");
      let userRole = findRoleQuery.all() as { id: string }[];

      if (userRole.length === 0) {
        // Crear rol 'user' si no existe
        const roleId = crypto.randomUUID();
        const createRoleQuery = db.query(
          "INSERT INTO roles (id, name, created_at) VALUES (?, ?, datetime('now'))"
        );
        createRoleQuery.run(roleId, 'user');
        userRole = [{ id: roleId }];
      }

      // Asignar rol al usuario
      const assignRoleQuery = db.query(
        "INSERT INTO user_roles (id, user_id, role_id, created_at) VALUES (?, ?, ?, datetime('now'))"
      );
      assignRoleQuery.run(crypto.randomUUID(), userId, userRole[0].id);
    } catch (error:any) {
      console.error('Error assigning default role:', error);
      throw error;
    }
  }

  /**
   * Valida los datos de registro
   * @param data Datos de registro
   */
  private validateRegisterData(data: RegisterData): void {
    if (!data.email || !data.password) {
      const error = new Error('Email and password are required');
      (error as any).type = 'VALIDATION_ERROR';
      throw error;
    }

    // Validar formato de email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(data.email)) {
      const error = new Error('Invalid email format');
      (error as any).type = 'VALIDATION_ERROR';
      throw error;
    }

    // Validar contraseña
    if (data.password.length < 8) {
      const error = new Error('Invalid password strength');
      (error as any).type = 'VALIDATION_ERROR';
      throw error;
    }

    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(data.password)) {
      const error = new Error('Password must contain at least one uppercase letter, one lowercase letter, and one number');
      (error as any).type = 'VALIDATION_ERROR';
      throw error;
    }
  }

  /**
   * Valida los datos de login
   * @param data Datos de login
   */
  private validateLoginData(data: LoginData): void {
    if (!data.email || !data.password) {
      throw new Error('Email and password are required');
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(data.email)) {
      throw new Error('Invalid email format');
    }
  }

  /**
   * Actualiza la contraseña de un usuario
   * @param userId ID del usuario
   * @param newPassword Nueva contraseña
   */
  async updatePassword(userId: string, newPassword: string): Promise<{ success: boolean; error?: { type: AuthErrorType; message: string } }> {
    try {
      const db = getDatabase();

      // Validar nueva contraseña
      if (newPassword.length < 8) {
        return {
          success: false,
          error: {
            type: 'VALIDATION_ERROR' as AuthErrorType,
            message: 'Password must be at least 8 characters long'
          }
        };
      }

      // Hash de la nueva contraseña
      const passwordHash = await Bun.password.hash(newPassword, {
        algorithm: 'bcrypt',
        cost: 12
      });

      // Actualizar en la base de datos
      const updatePasswordQuery = db.query(
        "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?"
      );
      updatePasswordQuery.run(passwordHash, userId);

      console.log(`✅ Contraseña actualizada para usuario: ${userId}`);
      return { success: true };
    } catch (error:any) {
      console.error('Error updating password:', error);
      return {
        success: false,
        error: {
          type: 'DATABASE_ERROR' as AuthErrorType,
          message: `Failed to update password: ${error.message}`
        }
      };
    }
  }

  /**
   * Actualiza los datos de un usuario
   * @param userId ID del usuario
   * @param data Datos de actualización
   */
  async updateUser(userId: string, data: UpdateUserData): Promise<{ success: boolean; user?: User; error?: { type: AuthErrorType; message: string } }> {
    try {
      const db = getDatabase();

      // Verificar que el usuario existe
      const existingUser = await this.findUserById(userId);
      if (!existingUser) {
        return {
          success: false,
          error: {
            type: 'USER_NOT_FOUND' as AuthErrorType,
            message: 'User not found'
          }
        };
      }

      // Verificar que el email no esté en uso por otro usuario
      if (data.email && data.email !== existingUser.email) {
        const existingByEmail = await this.findUserByEmail(data.email);
        if (existingByEmail && existingByEmail.id !== userId) {
          return {
            success: false,
            error: {
              type: 'VALIDATION_ERROR' as AuthErrorType,
              message: 'Email already exists'
            }
          };
        }
      }

      // Update lastLoginAt if provided
      let updateFields = [];
      let updateValues = [];
      
      if (data.email) {
        updateFields.push('email = ?');
        updateValues.push(data.email);
      }
      if (data.firstName !== undefined) {
        updateFields.push('first_name = ?');
        updateValues.push(data.firstName);
      }
      if (data.lastName !== undefined) {
        updateFields.push('last_name = ?');
        updateValues.push(data.lastName);
      }
      if (data.is_active !== undefined || data.isActive !== undefined) {
        updateFields.push('is_active = ?');
        const activeValue = data.is_active !== undefined ? data.is_active : data.isActive;
        updateValues.push(activeValue ? 1 : 0);
      }
      if (data.password) {
        const passwordHash = await Bun.password.hash(data.password, {
          algorithm: 'bcrypt',
          cost: 12
        });
        updateFields.push('password_hash = ?');
        updateValues.push(passwordHash);
      }
      
      updateFields.push("updated_at = datetime('now')");
      updateValues.push(userId);

      // Actualizar en la base de datos
      const updateQuery = db.query(
        `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`
      );
      updateQuery.run(...updateValues);

      // Update lastLoginAt if this is a login update
      if (data.lastLoginAt) {
        const loginUpdateQuery = db.query(
          "UPDATE users SET last_login_at = datetime('now') WHERE id = ?"
        );
        loginUpdateQuery.run(userId);
      }

      // Obtener el usuario actualizado
      const updatedUser = await this.findUserById(userId, { includeRoles: true, includePermissions: true });
      if (!updatedUser) {
        return {
          success: false,
          error: {
            type: 'DATABASE_ERROR' as AuthErrorType,
            message: 'Failed to retrieve updated user'
          }
        };
      }

      console.log(`✅ Usuario actualizado: ${updatedUser.email}`);
      return { success: true, user: updatedUser };
    } catch (error:any) {
      console.error('Error updating user:', error);
      return {
        success: false,
        error: {
          type: 'DATABASE_ERROR' as AuthErrorType,
          message: error.message || 'Failed to update user'
        }
      };
    }
  }

  /**
   * Desactiva un usuario
   * @param userId ID del usuario
   */
  async deactivateUser(userId: string): Promise<{ success: boolean; error?: { type: AuthErrorType; message: string } }> {
    try {
      const db = getDatabase();

      const deactivateQuery = db.query(
        "UPDATE users SET is_active = 0, updated_at = datetime('now') WHERE id = ?"
      );
      deactivateQuery.run(userId);

      console.log(`✅ Usuario desactivado: ${userId}`);
      return { success: true };
    } catch (error:any) {
      console.error('Error deactivating user:', error);
      return {
        success: false,
        error: {
          type: 'DATABASE_ERROR' as AuthErrorType,
          message: `Failed to deactivate user: ${error.message}`
        }
      };
    }
  }

  /**
   * Activa un usuario
   * @param userId ID del usuario
   */
  async activateUser(userId: string): Promise<{ success: boolean; error?: { type: AuthErrorType; message: string } }> {
    try {
      const db = getDatabase();

      const activateQuery = db.query(
        "UPDATE users SET is_active = 1, updated_at = datetime('now') WHERE id = ?"
      );
      activateQuery.run(userId);

      console.log(`✅ Usuario activado: ${userId}`);
      return { success: true };
    } catch (error:any) {
      console.error('Error activating user:', error);
      return {
        success: false,
        error: {
          type: 'DATABASE_ERROR' as AuthErrorType,
          message: `Failed to activate user: ${error.message}`
        }
      };
    }
  }

  /**
   * Elimina un usuario
   * @param userId ID del usuario
   */
  async deleteUser(userId: string): Promise<{ success: boolean; error?: { type: AuthErrorType; message: string } }> {
    try {
      const db = getDatabase();

      // Verificar que el usuario existe
      const existingUser = await this.findUserById(userId);
      if (!existingUser) {
        return {
          success: false,
          error: {
            type: 'USER_NOT_FOUND' as AuthErrorType,
            message: 'User not found'
          }
        };
      }

      // Eliminar roles del usuario
      const deleteUserRolesQuery = db.query(
        "DELETE FROM user_roles WHERE user_id = ?"
      );
      deleteUserRolesQuery.run(userId);

      // Eliminar usuario
      const deleteUserQuery = db.query(
        "DELETE FROM users WHERE id = ?"
      );
      deleteUserQuery.run(userId);

      console.log(`✅ Usuario eliminado: ${userId}`);
      return { success: true };
    } catch (error:any) {
      console.error('Error deleting user:', error);
      return {
        success: false,
        error: {
          type: 'DATABASE_ERROR' as AuthErrorType,
          message: error.message || 'Failed to delete user'
        }
      };
    }
  }

  /**
   * Remueve un rol de un usuario
   * @param userId ID del usuario
   * @param roleName Nombre del rol
   */
  async removeRole(userId: string, roleName: string): Promise<{ success: boolean; error?: { type: AuthErrorType; message: string } }> {
    try {
      const db = getDatabase();

      // Verificar que el usuario existe
      const existingUser = await this.findUserById(userId);
      if (!existingUser) {
        return {
          success: false,
          error: {
            type: 'USER_NOT_FOUND' as AuthErrorType,
            message: 'User not found'
          }
        };
      }

      // Verificar que el rol existe
      const roleQuery = db.query("SELECT id FROM roles WHERE name = ?");
      const role = roleQuery.get(roleName) as { id: string } | undefined;
      if (!role) {
        return {
          success: false,
          error: {
            type: 'NOT_FOUND_ERROR' as AuthErrorType,
            message: 'Role not found'
          }
        };
      }

      // Verificar que el usuario tiene el rol
      const userRoleQuery = db.query(
        "SELECT id FROM user_roles WHERE user_id = ? AND role_id = ?"
      );
      const userRole = userRoleQuery.get(userId, role.id);
      if (!userRole) {
        return {
          success: false,
          error: {
            type: 'NOT_FOUND_ERROR' as AuthErrorType,
            message: 'User does not have this role'
          }
        };
      }

      // Remover el rol
      const removeRoleQuery = db.query(
        "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?"
      );
      removeRoleQuery.run(userId, role.id);

      console.log(`✅ Rol ${roleName} removido del usuario: ${userId}`);
      return { success: true };
    } catch (error:any) {
      console.error('Error removing role:', error);
      return {
        success: false,
        error: {
          type: 'DATABASE_ERROR' as AuthErrorType,
          message: error.message || 'Failed to remove role'
        }
      };
    }
  }

  /**
   * Obtiene todos los usuarios con paginación
   * @param page Página (empezando en 1)
   * @param limit Límite por página
   * @param options Opciones de consulta
   * @returns Array de usuarios y total
   */
  async getUsers(
    page: number = 1, 
    limit: number = 10, 
    options: UserQueryOptions = {}
  ): Promise<{ users: User[], total: number }> {
    try {
      const db = getDatabase();
      const offset = (page - 1) * limit;

      // Build WHERE conditions
      let whereConditions = [];
      let queryParams = [];
      
      if (options.activeOnly) {
        whereConditions.push('is_active = ?');
        queryParams.push(1);
      }
      
      if (options.isActive !== undefined) {
        whereConditions.push('is_active = ?');
        queryParams.push(options.isActive ? 1 : 0);
      }
      
      if (options.search) {
        whereConditions.push('(email LIKE ? OR first_name LIKE ? OR last_name LIKE ?)');
        const searchTerm = `%${options.search}%`;
        queryParams.push(searchTerm, searchTerm, searchTerm);
      }
      
      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';
      
      // Build ORDER BY clause
      let orderBy = 'ORDER BY created_at DESC';
      if (options.sortBy) {
        const sortDirection = options.sortOrder === 'asc' ? 'ASC' : 'DESC';
        switch (options.sortBy) {
          case 'email':
            orderBy = `ORDER BY email ${sortDirection}`;
            break;
          case 'created_at':
            orderBy = `ORDER BY created_at ${sortDirection}`;
            break;
          case 'name':
            orderBy = `ORDER BY first_name ${sortDirection}, last_name ${sortDirection}`;
            break;
          default:
            orderBy = 'ORDER BY created_at DESC';
        }
      }

      // Contar total de usuarios
      const countQuery = db.query(`SELECT COUNT(*) as total FROM users ${whereClause}`);
      const countResult = countQuery.get(...queryParams) as { total: number } | { 'COUNT(*)': number } | undefined;
      const total = (countResult as any)?.total || (countResult as any)?.["COUNT(*)"] || 0;

      // Obtener usuarios con paginación
      const usersQuery = db.query(
        `SELECT id, email, password_hash, first_name, last_name, created_at, updated_at, is_active, last_login_at FROM users ${whereClause} ${orderBy} LIMIT ? OFFSET ?`
      );
      const usersResult = usersQuery.all(...queryParams, limit, offset) as Array<{
        id: string;
        email: string;
        password_hash: string;
        first_name?: string;
        last_name?: string;
        created_at: string;
        updated_at: string;
        is_active: number;
        last_login_at?: string;
      }>;

      const users: User[] = [];
      for (const userData of usersResult) {
        const user = this.mapDatabaseUserToUser(userData);

        // Incluir roles si se solicita
        if (options.includeRoles) {
          user.roles = await this.getUserRoles(userData.id, options.includePermissions);
        }

        users.push(user);
      }

      return { users, total };
    } catch (error:any) {
      console.error('Error getting users:', error);
      throw new Error(`Failed to get users: ${error.message}`);
    }
  }

  /**
   * Maps database user object to User interface with proper camelCase properties
   * @param userData Raw user data from database
   * @returns User object with proper property names
   */
  private mapDatabaseUserToUser(userData: {
    id: string;
    email: string;
    password_hash: string;
    first_name?: string;
    last_name?: string;
    created_at: string;
    updated_at: string;
    is_active: number;
    last_login_at?: string;
  }): User {
    const createdAt = new Date(userData.created_at);
    const updatedAt = new Date(userData.updated_at);
    
    return {
      id: userData.id,
      email: userData.email,
      password_hash: userData.password_hash,
      firstName: userData.first_name,
      lastName: userData.last_name,
      created_at: createdAt,
      updated_at: updatedAt,
      createdAt: createdAt,
      updatedAt: updatedAt,
      is_active: Boolean(userData.is_active),
      isActive: Boolean(userData.is_active),
      lastLoginAt: userData.last_login_at ? new Date(userData.last_login_at) : undefined,
      roles: [] as Role[]
    };
  }
}

/**
 * Instancia singleton del servicio de autenticación
 */
let authServiceInstance: AuthService | null = null;

/**
 * Inicializa el servicio de autenticación
 * @returns Instancia del servicio de autenticación
 */
export function initAuthService(): AuthService {
  authServiceInstance = new AuthService();
  return authServiceInstance;
}

/**
 * Obtiene la instancia del servicio de autenticación
 * @returns Instancia del servicio de autenticación
 * @throws Error si no ha sido inicializado
 */
export function getAuthService(): AuthService {
  if (!authServiceInstance) {
    throw new Error('Auth Service not initialized. Call initAuthService() first.');
  }
  return authServiceInstance;
}