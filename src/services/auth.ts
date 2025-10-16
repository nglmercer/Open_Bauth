import type { DatabaseInitializer } from "../database/database-initializer";
import type { BaseController } from "../database/base-controller";
import type { JWTService } from "./jwt";
import {
  AuthResult,
  LoginData,
  RegisterData,
  UpdateUserData,
  User,
  Role,
  UserQueryOptions,
  AuthErrorType,
} from "../types/auth";

/**
 * Main service for authentication, registration, and user management.
 */
export class AuthService {
  private userController: BaseController<User>;
  private roleController: BaseController<Role>;
  private userRoleController: BaseController<{
    id: string;
    user_id: string;
    role_id: string;
  }>;
  private jwtService: JWTService;

  constructor(dbInitializer: DatabaseInitializer, jwtService: JWTService) {
    // Use configured table names instead of hardcoded ones
    this.userController = dbInitializer.createControllerByKey<User>("users");
    this.roleController = dbInitializer.createControllerByKey<Role>("roles");
    this.userRoleController = dbInitializer.createControllerByKey("userRoles");
    this.jwtService = jwtService;
  }

  private sanitizeUser(user: User): User {
    const { password_hash, ...sanitizedUser } = user;
    return sanitizedUser as User;
  }

  private async attachRolesToUser(user: User): Promise<User> {
    if (!user || !user.id) {
      return { ...user, roles: [] };
    }
    const assignments = await this.userRoleController.search({
      user_id: user.id,
    });
    if (!assignments.data || assignments.data.length === 0) {
      return { ...user, roles: [] };
    }

    const roleIds = assignments.data.map((a) => a.role_id);
    const roles = await Promise.all(
      roleIds.map(async (id) => {
        const role = await this.roleController.findById(id);
        return role.data;
      }),
    );

    return { ...user, roles: roles.filter((r): r is Role => r !== null) };
  }

  async getRoleByName(roleName: string): Promise<Role | null> {
    const result = await this.roleController.findFirst({ name: roleName });
    return result.data || null;
  }

  // --- Core Authentication Methods ---

  async register(data: RegisterData): Promise<AuthResult> {
    if (typeof data.email !== "string" || !data.email) {
      return {
        success: false,
        error: {
          type: AuthErrorType.VALIDATION_ERROR,
          message: "Email is required",
        },
      };
    }
    if (typeof data.password !== "string" || !data.password) {
      return {
        success: false,
        error: {
          type: AuthErrorType.VALIDATION_ERROR,
          message: "Password is required",
        },
      };
    }

    try {
      const existingUser = await this.userController.findFirst({
        email: data.email.toLowerCase(),
      });
      if (existingUser.data) {
        return {
          success: false,
          error: {
            type: AuthErrorType.USER_ALREADY_EXISTS,
            message: "A user with this email already exists",
          },
        };
      }

      const password_hash = await Bun.password.hash(data.password);

      const createResult = await this.userController.create({
        email: data.email.toLowerCase(),
        password_hash,
        first_name: data.first_name,
        last_name: data.last_name,
        is_active: data.is_active !== undefined ? data.is_active : true,
      });

      if (!createResult.success || !createResult.data) {
        return {
          success: false,
          error: {
            type: AuthErrorType.DATABASE_ERROR,
            message: createResult.error || "Failed to create user",
          },
        };
      }

      const newUser = createResult.data;
      const userWithRoles = await this.attachRolesToUser(newUser);
      const token = await this.jwtService.generateToken(userWithRoles);

      return {
        success: true,
        user: this.sanitizeUser(userWithRoles),
        token,
      };
    } catch (error: any) {
      return {
        success: false,
        error: { type: AuthErrorType.DATABASE_ERROR, message: error.message },
      };
    }
  }

  async login(data: LoginData): Promise<AuthResult> {
    if (typeof data.email !== "string" || !data.email) {
      return {
        success: false,
        error: {
          type: AuthErrorType.VALIDATION_ERROR,
          message: "Email is required",
        },
      };
    }
    if (typeof data.password !== "string" || !data.password) {
      return {
        success: false,
        error: {
          type: AuthErrorType.VALIDATION_ERROR,
          message: "Password is required",
        },
      };
    }

    try {
      const userResult = await this.userController.findFirst({
        email: data.email.toLowerCase(),
      });
      const user = userResult.data;

      if (!user || !user.password_hash) {
        return {
          success: false,
          error: {
            type: AuthErrorType.INVALID_CREDENTIALS,
            message: "Invalid credentials",
          },
        };
      }

      if (!user.is_active) {
        return {
          success: false,
          error: {
            type: AuthErrorType.ACCOUNT_INACTIVE,
            message: "User account is deactivated",
          },
        };
      }

      const isPasswordValid = await Bun.password.verify(
        data.password,
        user.password_hash,
      );
      if (!isPasswordValid) {
        return {
          success: false,
          error: {
            type: AuthErrorType.INVALID_CREDENTIALS,
            message: "Invalid credentials",
          },
        };
      }

      const userWithRoles = await this.attachRolesToUser(user);
      const token = await this.jwtService.generateToken(userWithRoles);

      this.userController.update(user.id, {
        last_login_at: new Date().toISOString(),
      });

      return {
        success: true,
        user: this.sanitizeUser(userWithRoles),
        token,
      };
    } catch (error: any) {
      return {
        success: false,
        error: { type: AuthErrorType.DATABASE_ERROR, message: error.message },
      };
    }
  }

  // --- User Management Methods ---

  async findUserById(
    id: string,
    options: UserQueryOptions = {},
  ): Promise<User | null> {
    const userResult = await this.userController.findById(id);
    if (!userResult.data) return null;

    let user = userResult.data;
    if (options.includeRoles) {
      user = await this.attachRolesToUser(user);
    }

    return this.sanitizeUser(user);
  }

  async findUserByEmail(
    email: string,
    options: UserQueryOptions = {},
  ): Promise<User | null> {
    const userResult = await this.userController.findFirst({
      email: email.toLowerCase(),
    });
    if (!userResult.data) return null;

    let user = userResult.data;
    if (options.includeRoles) {
      user = await this.attachRolesToUser(user);
    }

    return this.sanitizeUser(user);
  }

  async updateUser(
    userId: string,
    data: UpdateUserData,
  ): Promise<{ success: boolean; user?: User; error?: any }> {
    const result = await this.userController.update(userId, data);
    if (!result.success || !result.data) {
      return {
        success: false,
        error: {
          type: AuthErrorType.DATABASE_ERROR,
          message: result.error || "Failed to update user",
        },
      };
    }
    return { success: true, user: this.sanitizeUser(result.data) };
  }

  async updatePassword(
    userId: string,
    newPassword: string,
  ): Promise<{ success: boolean; error?: any }> {
    if (typeof newPassword !== "string" || !newPassword) {
      return {
        success: false,
        error: {
          type: AuthErrorType.VALIDATION_ERROR,
          message: "New password cannot be empty",
        },
      };
    }
    const password_hash = await Bun.password.hash(newPassword);
    const result = await this.userController.update(userId, { password_hash });
    if (!result.success) {
      return {
        success: false,
        error: { type: AuthErrorType.DATABASE_ERROR, message: result.error },
      };
    }
    return { success: true };
  }

  async deactivateUser(
    userId: string,
  ): Promise<{ success: boolean; error?: any }> {
    const result = await this.userController.update(userId, {
      is_active: false,
    });
    if (!result.success) {
      return {
        success: false,
        error: { type: AuthErrorType.DATABASE_ERROR, message: result.error },
      };
    }
    return { success: true };
  }

  async activateUser(
    userId: string,
  ): Promise<{ success: boolean; error?: any }> {
    const result = await this.userController.update(userId, {
      is_active: true,
    });
    if (!result.success) {
      return {
        success: false,
        error: { type: AuthErrorType.DATABASE_ERROR, message: result.error },
      };
    }
    return { success: true };
  }

  async deleteUser(userId: string): Promise<{ success: boolean; error?: any }> {
    try {
      // Idealmente, esto debería estar en una transacción.
      const assignments = await this.userRoleController.search(
        { user_id: userId },
        { limit: 1000 },
      );
      if (assignments.data) {
        for (const assignment of assignments.data) {
          await this.userRoleController.delete(assignment.id);
        }
      }

      const result = await this.userController.delete(userId);
      if (!result.success) {
        return {
          success: false,
          error: { type: AuthErrorType.DATABASE_ERROR, message: result.error },
        };
      }
      return { success: true };
    } catch (error: any) {
      return {
        success: false,
        error: { type: AuthErrorType.DATABASE_ERROR, message: error.message },
      };
    }
  }

  // --- Role Management Methods ---

  async assignRole(
    userId: string,
    roleName: string,
  ): Promise<{ success: boolean; error?: any }> {
    try {
      const roleResult = await this.roleController.findFirst({
        name: roleName,
      });
      if (!roleResult.data) {
        return {
          success: false,
          error: {
            type: AuthErrorType.NOT_FOUND_ERROR,
            message: `Role '${roleName}' not found`,
          },
        };
      }

      const userResult = await this.userController.findById(userId);
      if (!userResult.data) {
        return {
          success: false,
          error: {
            type: AuthErrorType.USER_NOT_FOUND,
            message: "User not found",
          },
        };
      }

      const existing = await this.userRoleController.findFirst({
        user_id: userId,
        role_id: roleResult.data.id,
      });
      if (existing.data) {
        return { success: true }; // El rol ya está asignado, operación exitosa.
      }

      const result = await this.userRoleController.create({
        user_id: userId,
        role_id: roleResult.data.id,
      });
      if (!result.success) {
        return {
          success: false,
          error: { type: AuthErrorType.DATABASE_ERROR, message: result.error },
        };
      }
      return { success: true };
    } catch (error: any) {
      return {
        success: false,
        error: { type: AuthErrorType.DATABASE_ERROR, message: error.message },
      };
    }
  }

  async removeRole(
    userId: string,
    roleName: string,
  ): Promise<{ success: boolean; error?: any }> {
    try {
      const roleResult = await this.roleController.findFirst({
        name: roleName,
      });
      if (!roleResult.data) {
        return {
          success: false,
          error: {
            type: AuthErrorType.NOT_FOUND_ERROR,
            message: `Role '${roleName}' not found`,
          },
        };
      }

      const assignment = await this.userRoleController.findFirst({
        user_id: userId,
        role_id: roleResult.data.id,
      });
      if (!assignment.data) {
        return {
          success: false,
          error: {
            type: AuthErrorType.NOT_FOUND_ERROR,
            message: "User does not have this role",
          },
        };
      }

      const result = await this.userRoleController.delete(assignment.data.id);
      if (!result.success) {
        return {
          success: false,
          error: { type: AuthErrorType.DATABASE_ERROR, message: result.error },
        };
      }
      return { success: true };
    } catch (error: any) {
      return {
        success: false,
        error: { type: AuthErrorType.DATABASE_ERROR, message: error.message },
      };
    }
  }

  // --- Data Retrieval Methods ---

  async getUsers(
    page: number = 1,
    limit: number = 20,
    options: UserQueryOptions = {},
  ): Promise<{ users: User[]; total: number }> {
    const offset = (page - 1) * limit;
    const result = await this.userController.findAll({ limit, offset });

    let users = result.data || [];
    const total = result.total || 0;

    if (options.includeRoles && users.length > 0) {
      users = await Promise.all(
        users.map((user) => this.attachRolesToUser(user)),
      );
    }

    return { users: users.map(this.sanitizeUser), total };
  }

  async getUserRoles(userId: string): Promise<Role[]> {
    const user = await this.userController.findById(userId);
    if (!user.data) {
      return [];
    }

    const userWithRoles = await this.attachRolesToUser(user.data);
    return userWithRoles.roles || [];
  }
}
