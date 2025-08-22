// src/services/auth.ts
import { getDatabase } from '../db/connection';
import { getJWTService } from './jwt';
import type { 
  User, 
  RegisterData, 
  LoginData, 
  AuthResult, 
  UserQueryOptions,
  AuthError,
  AuthErrorType 
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
      this.validateRegisterData(data);

      // Verificar si el usuario ya existe
      const existingUser = await this.findUserByEmail(data.email);
      if (existingUser) {
        throw new Error('User already exists with this email');
      }

      // Hash de la contraseña usando Bun
      const passwordHash = await Bun.password.hash(data.password, {
        algorithm: 'bcrypt',
        cost: 12
      });

      // Crear usuario en la base de datos
      const userId = crypto.randomUUID();
      const insertQuery = db.query(`
        INSERT INTO users (id, email, password_hash, created_at, updated_at, is_active)
        VALUES (?, ?, ?, datetime('now'), datetime('now'), 1)
      `);
      insertQuery.run(userId, data.email.toLowerCase(), passwordHash);

      // Asignar rol por defecto (user)
      await this.assignDefaultRole(userId);

      // Obtener el usuario completo con roles
      const user = await this.findUserById(userId, { includeRoles: true, includePermissions: true });
      if (!user) {
        throw new Error('Failed to create user');
      }

      // Generar token JWT
      const token = await jwtService.generateToken(user);

      console.log(`✅ Usuario registrado: ${user.email}`);

      return { user, token };
    } catch (error) {
      console.error('Error registering user:', error);
      throw new Error(`Registration failed: ${error.message}`);
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
        throw new Error('Invalid credentials');
      }

      // Verificar si el usuario está activo
      if (!user.is_active) {
        throw new Error('Account is deactivated');
      }

      // Verificar contraseña
      const isValidPassword = await Bun.password.verify(data.password, user.password_hash);
      if (!isValidPassword) {
        throw new Error('Invalid credentials');
      }

      // Actualizar última actividad
      await db`
        UPDATE users 
        SET updated_at = datetime('now')
        WHERE id = ${user.id}
      `;

      // Generar token JWT
      const token = await jwtService.generateToken(user);

      console.log(`✅ Usuario autenticado: ${user.email}`);

      return { user, token };
    } catch (error) {
      console.error('Error during login:', error);
      throw new Error(`Login failed: ${error.message}`);
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
        SELECT id, email, password_hash, created_at, updated_at, is_active
        FROM users
        WHERE id = ?${activeCondition}
      `);
      const userResult = query.all(id);

      if (userResult.length === 0) {
        return null;
      }

      const userData = userResult[0];
      const user: User = {
        id: userData.id,
        email: userData.email,
        password_hash: userData.password_hash,
        created_at: new Date(userData.created_at),
        updated_at: new Date(userData.updated_at),
        is_active: Boolean(userData.is_active),
        roles: []
      };

      // Incluir roles si se solicita
      if (options.includeRoles) {
        user.roles = await this.getUserRoles(id, options.includePermissions);
      }

      return user;
    } catch (error) {
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
        SELECT id, email, password_hash, created_at, updated_at, is_active
        FROM users
        WHERE email = ?
      `;
      
      const params = [email.toLowerCase()];
      
      if (options.activeOnly) {
        query += ` AND is_active = 1`;
      }

      const userResult = db.query(query).all(...params);

      if (userResult.length === 0) {
        return null;
      }

      const userData = userResult[0];
      const user: User = {
        id: userData.id,
        email: userData.email,
        password_hash: userData.password_hash,
        created_at: new Date(userData.created_at),
        updated_at: new Date(userData.updated_at),
        is_active: Boolean(userData.is_active),
        roles: []
      };

      // Incluir roles si se solicita
      if (options.includeRoles) {
        user.roles = await this.getUserRoles(userData.id, options.includePermissions);
      }

      return user;
    } catch (error) {
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
  async getUserRoles(userId: string, includePermissions: boolean = false) {
    try {
      const db = getDatabase();

      const rolesQuery = db.query(`
        SELECT r.id, r.name, r.created_at
        FROM roles r
        INNER JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ?
        ORDER BY r.name
      `);
      const rolesResult = rolesQuery.all(userId);

      const roles = [];
      for (const roleData of rolesResult) {
        const role = {
          id: roleData.id,
          name: roleData.name,
          created_at: new Date(roleData.created_at),
          permissions: []
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
          const permissionsResult = permissionsQuery.all(role.id);

          role.permissions = permissionsResult.map(permData => ({
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
    } catch (error) {
      console.error('Error getting user roles:', error);
      throw new Error(`Failed to get user roles: ${error.message}`);
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
      let userRole = await db`
        SELECT id FROM roles WHERE name = 'user'
      `;

      if (userRole.length === 0) {
        // Crear rol 'user' si no existe
        const roleId = crypto.randomUUID();
        await db`
          INSERT INTO roles (id, name, created_at)
          VALUES (${roleId}, 'user', datetime('now'))
        `;
        userRole = [{ id: roleId }];
      }

      // Asignar rol al usuario
      await db`
        INSERT INTO user_roles (id, user_id, role_id, created_at)
        VALUES (${crypto.randomUUID()}, ${userId}, ${userRole[0].id}, datetime('now'))
      `;
    } catch (error) {
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
      throw new Error('Email and password are required');
    }

    // Validar formato de email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(data.email)) {
      throw new Error('Invalid email format');
    }

    // Validar contraseña
    if (data.password.length < 8) {
      throw new Error('Password must be at least 8 characters long');
    }

    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(data.password)) {
      throw new Error('Password must contain at least one uppercase letter, one lowercase letter, and one number');
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
  async updatePassword(userId: string, newPassword: string): Promise<void> {
    try {
      const db = getDatabase();

      // Validar nueva contraseña
      if (newPassword.length < 8) {
        throw new Error('Password must be at least 8 characters long');
      }

      // Hash de la nueva contraseña
      const passwordHash = await Bun.password.hash(newPassword, {
        algorithm: 'bcrypt',
        cost: 12
      });

      // Actualizar en la base de datos
      await db`
        UPDATE users 
        SET password_hash = ${passwordHash}, updated_at = datetime('now')
        WHERE id = ${userId}
      `;

      console.log(`✅ Contraseña actualizada para usuario: ${userId}`);
    } catch (error) {
      console.error('Error updating password:', error);
      throw new Error(`Failed to update password: ${error.message}`);
    }
  }

  /**
   * Desactiva un usuario
   * @param userId ID del usuario
   */
  async deactivateUser(userId: string): Promise<void> {
    try {
      const db = getDatabase();

      await db`
        UPDATE users 
        SET is_active = 0, updated_at = datetime('now')
        WHERE id = ${userId}
      `;

      console.log(`✅ Usuario desactivado: ${userId}`);
    } catch (error) {
      console.error('Error deactivating user:', error);
      throw new Error(`Failed to deactivate user: ${error.message}`);
    }
  }

  /**
   * Activa un usuario
   * @param userId ID del usuario
   */
  async activateUser(userId: string): Promise<void> {
    try {
      const db = getDatabase();

      await db`
        UPDATE users 
        SET is_active = 1, updated_at = datetime('now')
        WHERE id = ${userId}
      `;

      console.log(`✅ Usuario activado: ${userId}`);
    } catch (error) {
      console.error('Error activating user:', error);
      throw new Error(`Failed to activate user: ${error.message}`);
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

      // Contar total de usuarios
      const countResult = await db`
        SELECT COUNT(*) as total
        FROM users
        ${options.activeOnly ? db`WHERE is_active = 1` : db``}
      `;
      const total = countResult[0].total;

      // Obtener usuarios con paginación
      const usersResult = await db`
        SELECT id, email, password_hash, created_at, updated_at, is_active
        FROM users
        ${options.activeOnly ? db`WHERE is_active = 1` : db``}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;

      const users = [];
      for (const userData of usersResult) {
        const user: User = {
          id: userData.id,
          email: userData.email,
          password_hash: userData.password_hash,
          created_at: new Date(userData.created_at),
          updated_at: new Date(userData.updated_at),
          is_active: Boolean(userData.is_active),
          roles: []
        };

        // Incluir roles si se solicita
        if (options.includeRoles) {
          user.roles = await this.getUserRoles(userData.id, options.includePermissions);
        }

        users.push(user);
      }

      return { users, total };
    } catch (error) {
      console.error('Error getting users:', error);
      throw new Error(`Failed to get users: ${error.message}`);
    }
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