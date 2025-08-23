// @bun
// src/db/connection.ts
import { Database } from "bun:sqlite";
var db;
function initDatabase(dbPath = "./auth.db") {
  if (!db) {
    try {
      db = new Database(dbPath);
      db.exec("PRAGMA journal_mode = WAL;");
      db.exec("PRAGMA synchronous = NORMAL;");
      db.exec("PRAGMA cache_size = 1000;");
      db.exec("PRAGMA temp_store = memory;");
      db.exec("PRAGMA busy_timeout = 5000;");
      console.log(`\u2705 Base de datos SQLite inicializada: ${dbPath}`);
    } catch (error) {
      console.error(`\u274C Error al inicializar la base de datos: ${error}`);
      throw new Error(`Failed to initialize database: ${error}`);
    }
  }
  return db;
}
function getDatabase() {
  if (!db) {
    console.log("\u26A0\uFE0F Database not initialized, auto-initializing with test.db");
    initDatabase("./test.db");
  }
  try {
    if (!db) {
      throw new Error("Database not initialized");
    }
    db.query("SELECT 1").get();
  } catch (error) {
    if (error.message && error.message.includes("closed database")) {
      console.log("\u26A0\uFE0F Database connection closed, reinitializing...");
      db = null;
      initDatabase("./test.db");
    } else {
      throw error;
    }
  }
  if (!db) {
    throw new Error("Failed to initialize database");
  }
  return db;
}
function forceReinitDatabase() {
  console.log("\uD83D\uDD04 Force reinitializing database...");
  db = null;
  initDatabase("./test.db");
  if (!db) {
    throw new Error("Failed to reinitialize database");
  }
  return db;
}
async function closeDatabase() {
  if (db) {
    try {
      db.close();
      db = null;
      console.log("\u2705 Conexi\xF3n a la base de datos cerrada");
    } catch (error) {
      console.error(`\u274C Error al cerrar la base de datos: ${error}`);
      throw error;
    }
  }
}
function isDatabaseInitialized() {
  return db !== undefined && db !== null;
}
async function testConnection() {
  try {
    const db2 = getDatabase();
    db2.query("SELECT 1 as test").get();
    console.log("\u2705 Conexi\xF3n a la base de datos verificada");
    return true;
  } catch (error) {
    console.error(`\u274C Error en la conexi\xF3n a la base de datos: ${error}`);
    return false;
  }
}
async function getDatabaseInfo() {
  try {
    const db2 = getDatabase();
    const versionResult = db2.query("PRAGMA user_version").get();
    const pageSizeResult = db2.query("PRAGMA page_size").get();
    const encodingResult = db2.query("PRAGMA encoding").get();
    const journalModeResult = db2.query("PRAGMA journal_mode").get();
    return {
      version: (versionResult?.user_version || 0).toString(),
      pageSize: pageSizeResult?.page_size || 0,
      encoding: encodingResult?.encoding || "unknown",
      journalMode: journalModeResult?.journal_mode || "unknown"
    };
  } catch (error) {
    console.error(`\u274C Error al obtener informaci\xF3n de la base de datos: ${error}`);
    throw error;
  }
}

// src/services/jwt.ts
class JWTService {
  secret;
  expiresIn;
  constructor(secret, expiresIn = "24h") {
    if (!secret) {
      throw new Error("JWT secret is required");
    }
    this.secret = secret;
    this.expiresIn = expiresIn;
  }
  async generateToken(user) {
    try {
      const now = Math.floor(Date.now() / 1000);
      const expirationTime = this.parseExpirationTime(this.expiresIn);
      const payload = {
        userId: user.id,
        email: user.email,
        roles: user.roles.map((role) => role.name),
        iat: now,
        exp: now + expirationTime
      };
      const header = {
        alg: "HS256",
        typ: "JWT"
      };
      const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
      const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));
      const signature = await this.createSignature(`${encodedHeader}.${encodedPayload}`);
      return `${encodedHeader}.${encodedPayload}.${signature}`;
    } catch (error) {
      console.error("Error generating JWT token:", error);
      throw new Error("Failed to generate token");
    }
  }
  async verifyToken(token) {
    return Promise.resolve().then(async () => {
      if (!token) {
        throw new Error("Token is required");
      }
      const parts = token.split(".");
      if (parts.length !== 3) {
        throw new Error("Invalid token format");
      }
      const [encodedHeader, encodedPayload, signature] = parts;
      const expectedSignature = await this.createSignature(`${encodedHeader}.${encodedPayload}`);
      if (signature !== expectedSignature) {
        throw new Error("Invalid token signature");
      }
      const payload = JSON.parse(this.base64UrlDecode(encodedPayload));
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < now) {
        throw new Error("Token has expired");
      }
      return payload;
    }).catch((error) => {
      console.error("Error verifying JWT token:", error);
      throw new Error(`Invalid token: ${error.message}`);
    });
  }
  extractTokenFromHeader(authHeader) {
    if (!authHeader) {
      return null;
    }
    const parts = authHeader.split(" ");
    if (parts.length !== 2 || parts[0] !== "Bearer") {
      return null;
    }
    return parts[1];
  }
  isTokenExpired(token) {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) {
        return true;
      }
      const payload = JSON.parse(this.base64UrlDecode(parts[1]));
      const now = Math.floor(Date.now() / 1000);
      return payload.exp ? payload.exp < now : false;
    } catch (error) {
      return true;
    }
  }
  getTokenRemainingTime(token) {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) {
        return 0;
      }
      const payload = JSON.parse(this.base64UrlDecode(parts[1]));
      const now = Math.floor(Date.now() / 1000);
      if (!payload.exp) {
        return Infinity;
      }
      const remaining = payload.exp - now;
      return Math.max(0, remaining);
    } catch (error) {
      return 0;
    }
  }
  async refreshTokenIfNeeded(token, user, refreshThreshold = 3600) {
    const remainingTime = this.getTokenRemainingTime(token);
    if (remainingTime <= refreshThreshold) {
      return await this.generateToken(user);
    }
    return token;
  }
  base64UrlEncode(str) {
    const base64 = Buffer.from(str).toString("base64");
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }
  base64UrlDecode(str) {
    let padded = str;
    while (padded.length % 4) {
      padded += "=";
    }
    const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
    return Buffer.from(base64, "base64").toString("utf-8");
  }
  async createSignature(data) {
    const encoder = new TextEncoder;
    const keyData = encoder.encode(this.secret);
    const messageData = encoder.encode(data);
    const key = await crypto.subtle.importKey("raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const signature = await crypto.subtle.sign("HMAC", key, messageData);
    const signatureArray = new Uint8Array(signature);
    const base64 = Buffer.from(signatureArray).toString("base64");
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }
  parseExpirationTime(expiresIn) {
    const units = {
      s: 1,
      m: 60,
      h: 3600,
      d: 86400,
      w: 604800
    };
    const match = expiresIn.match(/^(-?\d+)([smhdw])$/);
    if (!match) {
      throw new Error(`Invalid expiration format: ${expiresIn}`);
    }
    const [, value, unit] = match;
    const multiplier = units[unit];
    if (!multiplier) {
      throw new Error(`Invalid time unit: ${unit}`);
    }
    return parseInt(value) * multiplier;
  }
  async generateRefreshToken(userId) {
    const payload = {
      userId,
      type: "refresh",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60
    };
    const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));
    const signature = await this.createSignature(encodedPayload);
    return `${encodedPayload}.${signature}`;
  }
  async verifyRefreshToken(refreshToken) {
    try {
      const parts = refreshToken.split(".");
      if (parts.length !== 2) {
        throw new Error("Invalid refresh token format");
      }
      const [encodedPayload, signature] = parts;
      const expectedSignature = await this.createSignature(encodedPayload);
      if (signature !== expectedSignature) {
        throw new Error("Invalid refresh token signature");
      }
      const payload = JSON.parse(this.base64UrlDecode(encodedPayload));
      if (payload.type !== "refresh") {
        throw new Error("Invalid token type");
      }
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < now) {
        throw new Error("Refresh token has expired");
      }
      return payload.userId;
    } catch (error) {
      throw new Error(`Invalid refresh token: ${error.message}`);
    }
  }
}
var jwtServiceInstance = null;
function initJWTService(secret, expiresIn) {
  jwtServiceInstance = new JWTService(secret, expiresIn);
  return jwtServiceInstance;
}
function getJWTService() {
  if (!jwtServiceInstance) {
    throw new Error("JWT Service not initialized. Call initJWTService() first.");
  }
  return jwtServiceInstance;
}

// src/services/auth.ts
class AuthService {
  async register(data) {
    try {
      const db2 = getDatabase();
      const jwtService = getJWTService();
      try {
        this.validateRegisterData(data);
      } catch (validationError) {
        return {
          success: false,
          error: {
            type: validationError.type || "VALIDATION_ERROR",
            message: validationError.message
          }
        };
      }
      const existingUser = await this.findUserByEmail(data.email);
      if (existingUser) {
        return {
          success: false,
          error: {
            type: "VALIDATION_ERROR",
            message: "User already exists with this email"
          }
        };
      }
      const passwordHash = await Bun.password.hash(data.password, {
        algorithm: "bcrypt",
        cost: 12
      });
      const userId = crypto.randomUUID();
      const isActive = data.isActive !== undefined ? data.isActive : true;
      const insertQuery = db2.query(`
        INSERT INTO users (id, email, password_hash, first_name, last_name, created_at, updated_at, is_active)
        VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'), ?)
      `);
      insertQuery.run(userId, data.email.toLowerCase(), passwordHash, data.firstName || null, data.lastName || null, isActive ? 1 : 0);
      await this.assignDefaultRole(userId);
      const user = await this.findUserById(userId, { includeRoles: true, includePermissions: true });
      if (!user) {
        throw new Error("Failed to create user");
      }
      const updateLoginQuery = db2.query("UPDATE users SET last_login_at = datetime('now') WHERE id = ?");
      updateLoginQuery.run(user.id);
      const token = await jwtService.generateToken(user);
      const refreshToken = await jwtService.generateRefreshToken(Number(user.id));
      const updatedUser = await this.findUserById(user.id, { includeRoles: true, includePermissions: true });
      return {
        success: true,
        user: updatedUser || user,
        token,
        refreshToken
      };
    } catch (error) {
      console.error("Error registering user:", error);
      return {
        success: false,
        error: {
          type: error.type || "SERVER_ERROR",
          message: error.message || "Registration failed"
        }
      };
    }
  }
  async login(data) {
    try {
      const db2 = getDatabase();
      const jwtService = getJWTService();
      this.validateLoginData(data);
      const user = await this.findUserByEmail(data.email, {
        includeRoles: true,
        includePermissions: true
      });
      if (!user) {
        return {
          success: false,
          error: {
            type: "AUTHENTICATION_ERROR",
            message: "Invalid credentials"
          }
        };
      }
      if (!user.is_active) {
        return {
          success: false,
          error: {
            type: "AUTHENTICATION_ERROR",
            message: "Account is inactive"
          }
        };
      }
      const isValidPassword = await Bun.password.verify(data.password, user.password_hash);
      if (!isValidPassword) {
        return {
          success: false,
          error: {
            type: "AUTHENTICATION_ERROR",
            message: "Invalid credentials"
          }
        };
      }
      const updateQuery = db2.query("UPDATE users SET updated_at = datetime('now'), last_login_at = datetime('now') WHERE id = ?");
      updateQuery.run(user.id);
      const updatedUser = await this.findUserById(user.id, { includeRoles: true, includePermissions: true });
      if (!updatedUser) {
        return {
          success: false,
          error: {
            type: "DATABASE_ERROR",
            message: "User not found after update"
          }
        };
      }
      const token = await jwtService.generateToken(updatedUser);
      const refreshToken = await jwtService.generateRefreshToken(Number(updatedUser.id));
      console.log(`\u2705 Usuario autenticado: ${updatedUser.email}`);
      return {
        success: true,
        user: updatedUser,
        token,
        refreshToken
      };
    } catch (error) {
      console.error("Error during login:", error);
      return {
        success: false,
        error: {
          type: error.type || "AUTHENTICATION_ERROR",
          message: error.message || "Login failed"
        }
      };
    }
  }
  async findUserById(id, options = {}) {
    try {
      const db2 = getDatabase();
      const activeCondition = options.activeOnly ? " AND is_active = 1" : "";
      const query = db2.query(`
        SELECT id, email, password_hash, first_name, last_name, created_at, updated_at, is_active, last_login_at
        FROM users
        WHERE id = ?${activeCondition}
      `);
      const userResult = query.all(id);
      if (userResult.length === 0) {
        return null;
      }
      const userData = userResult[0];
      const user = this.mapDatabaseUserToUser(userData);
      if (options.includeRoles) {
        user.roles = await this.getUserRoles(id, options.includePermissions);
      }
      return user;
    } catch (error) {
      console.error("Error finding user by ID:", error);
      throw new Error(`Failed to find user: ${error.message}`);
    }
  }
  async findUserByEmail(email, options = {}) {
    try {
      const db2 = getDatabase();
      let query = `
        SELECT id, email, password_hash, first_name, last_name, created_at, updated_at, is_active, last_login_at
        FROM users
        WHERE email = ?
      `;
      const params = [email.toLowerCase()];
      if (options.activeOnly) {
        query += ` AND is_active = 1`;
      }
      const userResult = db2.query(query).all(...params);
      if (userResult.length === 0) {
        return null;
      }
      const userData = userResult[0];
      const user = this.mapDatabaseUserToUser(userData);
      if (options.includeRoles) {
        user.roles = await this.getUserRoles(userData.id, options.includePermissions);
      }
      return user;
    } catch (error) {
      console.error("Error finding user by email:", error);
      throw new Error(`Failed to find user: ${error.message}`);
    }
  }
  async getUserRoles(userId, includePermissions = false) {
    try {
      const db2 = getDatabase();
      const rolesQuery = db2.query(`
        SELECT r.id, r.name, r.created_at, r.is_active
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
          isActive: Boolean(roleData.is_active),
          permissions: []
        };
        if (includePermissions) {
          const permissionsQuery = db2.query(`
            SELECT p.id, p.name, p.resource, p.action, p.created_at
            FROM permissions p
            INNER JOIN role_permissions rp ON p.id = rp.permission_id
            WHERE rp.role_id = ?
            ORDER BY p.resource, p.action
          `);
          const permissionsResult = permissionsQuery.all(role.id);
          role.permissions = permissionsResult.map((permData) => ({
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
      console.error("Error getting user roles:", error);
      throw new Error(`Failed to get user roles: ${error.message}`);
    }
  }
  async assignRole(userId, roleName) {
    try {
      const db2 = getDatabase();
      const user = await this.findUserById(userId);
      if (!user) {
        return {
          success: false,
          error: {
            type: "USER_NOT_FOUND",
            message: "User not found"
          }
        };
      }
      const findRoleQuery = db2.query("SELECT id FROM roles WHERE name = ?");
      const roleResult = findRoleQuery.get(roleName);
      if (!roleResult) {
        return {
          success: false,
          error: {
            type: "NOT_FOUND_ERROR",
            message: `Role '${roleName}' not found`
          }
        };
      }
      const existingQuery = db2.query("SELECT id FROM user_roles WHERE user_id = ? AND role_id = ?");
      const existing = existingQuery.get(userId, roleResult.id);
      if (existing) {
        return {
          success: false,
          error: {
            type: "VALIDATION_ERROR",
            message: "User already has this role"
          }
        };
      }
      const assignRoleQuery = db2.query("INSERT INTO user_roles (id, user_id, role_id, created_at) VALUES (?, ?, ?, datetime('now'))");
      assignRoleQuery.run(crypto.randomUUID(), userId, roleResult.id);
      console.log(`\u2705 Rol ${roleName} asignado al usuario: ${userId}`);
      return { success: true };
    } catch (error) {
      console.error("Error assigning role:", error);
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: error.message || "Failed to assign role"
        }
      };
    }
  }
  async assignDefaultRole(userId) {
    try {
      const db2 = getDatabase();
      const findRoleQuery = db2.query("SELECT id FROM roles WHERE name = 'user'");
      let userRole = findRoleQuery.all();
      if (userRole.length === 0) {
        const roleId = crypto.randomUUID();
        const createRoleQuery = db2.query("INSERT INTO roles (id, name, created_at) VALUES (?, ?, datetime('now'))");
        createRoleQuery.run(roleId, "user");
        userRole = [{ id: roleId }];
      }
      const assignRoleQuery = db2.query("INSERT INTO user_roles (id, user_id, role_id, created_at) VALUES (?, ?, ?, datetime('now'))");
      assignRoleQuery.run(crypto.randomUUID(), userId, userRole[0].id);
    } catch (error) {
      console.error("Error assigning default role:", error);
      throw error;
    }
  }
  validateRegisterData(data) {
    if (!data.email || !data.password) {
      const error = new Error("Email and password are required");
      error.type = "VALIDATION_ERROR";
      throw error;
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(data.email)) {
      const error = new Error("Invalid email format");
      error.type = "VALIDATION_ERROR";
      throw error;
    }
    if (data.password.length < 8) {
      const error = new Error("Invalid password strength");
      error.type = "VALIDATION_ERROR";
      throw error;
    }
    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(data.password)) {
      const error = new Error("Password must contain at least one uppercase letter, one lowercase letter, and one number");
      error.type = "VALIDATION_ERROR";
      throw error;
    }
  }
  validateLoginData(data) {
    if (!data.email || !data.password) {
      throw new Error("Email and password are required");
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(data.email)) {
      throw new Error("Invalid email format");
    }
  }
  async updatePassword(userId, newPassword) {
    try {
      const db2 = getDatabase();
      if (newPassword.length < 8) {
        return {
          success: false,
          error: {
            type: "VALIDATION_ERROR",
            message: "Password must be at least 8 characters long"
          }
        };
      }
      const passwordHash = await Bun.password.hash(newPassword, {
        algorithm: "bcrypt",
        cost: 12
      });
      const updatePasswordQuery = db2.query("UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?");
      updatePasswordQuery.run(passwordHash, userId);
      console.log(`\u2705 Contrase\xF1a actualizada para usuario: ${userId}`);
      return { success: true };
    } catch (error) {
      console.error("Error updating password:", error);
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: `Failed to update password: ${error.message}`
        }
      };
    }
  }
  async updateUser(userId, data) {
    try {
      const db2 = getDatabase();
      const existingUser = await this.findUserById(userId);
      if (!existingUser) {
        return {
          success: false,
          error: {
            type: "USER_NOT_FOUND",
            message: "User not found"
          }
        };
      }
      if (data.email && data.email !== existingUser.email) {
        const existingByEmail = await this.findUserByEmail(data.email);
        if (existingByEmail && existingByEmail.id !== userId) {
          return {
            success: false,
            error: {
              type: "VALIDATION_ERROR",
              message: "Email already exists"
            }
          };
        }
      }
      let updateFields = [];
      let updateValues = [];
      if (data.email) {
        updateFields.push("email = ?");
        updateValues.push(data.email);
      }
      if (data.firstName !== undefined) {
        updateFields.push("first_name = ?");
        updateValues.push(data.firstName);
      }
      if (data.lastName !== undefined) {
        updateFields.push("last_name = ?");
        updateValues.push(data.lastName);
      }
      if (data.is_active !== undefined || data.isActive !== undefined) {
        updateFields.push("is_active = ?");
        const activeValue = data.is_active !== undefined ? data.is_active : data.isActive;
        updateValues.push(activeValue ? 1 : 0);
      }
      if (data.password) {
        const passwordHash = await Bun.password.hash(data.password, {
          algorithm: "bcrypt",
          cost: 12
        });
        updateFields.push("password_hash = ?");
        updateValues.push(passwordHash);
      }
      updateFields.push("updated_at = datetime('now')");
      updateValues.push(userId);
      const updateQuery = db2.query(`UPDATE users SET ${updateFields.join(", ")} WHERE id = ?`);
      updateQuery.run(...updateValues);
      if (data.lastLoginAt) {
        const loginUpdateQuery = db2.query("UPDATE users SET last_login_at = datetime('now') WHERE id = ?");
        loginUpdateQuery.run(userId);
      }
      const updatedUser = await this.findUserById(userId, { includeRoles: true, includePermissions: true });
      if (!updatedUser) {
        return {
          success: false,
          error: {
            type: "DATABASE_ERROR",
            message: "Failed to retrieve updated user"
          }
        };
      }
      console.log(`\u2705 Usuario actualizado: ${updatedUser.email}`);
      return { success: true, user: updatedUser };
    } catch (error) {
      console.error("Error updating user:", error);
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: error.message || "Failed to update user"
        }
      };
    }
  }
  async deactivateUser(userId) {
    try {
      const db2 = getDatabase();
      const deactivateQuery = db2.query("UPDATE users SET is_active = 0, updated_at = datetime('now') WHERE id = ?");
      deactivateQuery.run(userId);
      console.log(`\u2705 Usuario desactivado: ${userId}`);
      return { success: true };
    } catch (error) {
      console.error("Error deactivating user:", error);
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: `Failed to deactivate user: ${error.message}`
        }
      };
    }
  }
  async activateUser(userId) {
    try {
      const db2 = getDatabase();
      const activateQuery = db2.query("UPDATE users SET is_active = 1, updated_at = datetime('now') WHERE id = ?");
      activateQuery.run(userId);
      console.log(`\u2705 Usuario activado: ${userId}`);
      return { success: true };
    } catch (error) {
      console.error("Error activating user:", error);
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: `Failed to activate user: ${error.message}`
        }
      };
    }
  }
  async deleteUser(userId) {
    try {
      const db2 = getDatabase();
      const existingUser = await this.findUserById(userId);
      if (!existingUser) {
        return {
          success: false,
          error: {
            type: "USER_NOT_FOUND",
            message: "User not found"
          }
        };
      }
      const deleteUserRolesQuery = db2.query("DELETE FROM user_roles WHERE user_id = ?");
      deleteUserRolesQuery.run(userId);
      const deleteUserQuery = db2.query("DELETE FROM users WHERE id = ?");
      deleteUserQuery.run(userId);
      console.log(`\u2705 Usuario eliminado: ${userId}`);
      return { success: true };
    } catch (error) {
      console.error("Error deleting user:", error);
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: error.message || "Failed to delete user"
        }
      };
    }
  }
  async removeRole(userId, roleName) {
    try {
      const db2 = getDatabase();
      const existingUser = await this.findUserById(userId);
      if (!existingUser) {
        return {
          success: false,
          error: {
            type: "USER_NOT_FOUND",
            message: "User not found"
          }
        };
      }
      const roleQuery = db2.query("SELECT id FROM roles WHERE name = ?");
      const role = roleQuery.get(roleName);
      if (!role) {
        return {
          success: false,
          error: {
            type: "NOT_FOUND_ERROR",
            message: "Role not found"
          }
        };
      }
      const userRoleQuery = db2.query("SELECT id FROM user_roles WHERE user_id = ? AND role_id = ?");
      const userRole = userRoleQuery.get(userId, role.id);
      if (!userRole) {
        return {
          success: false,
          error: {
            type: "NOT_FOUND_ERROR",
            message: "User does not have this role"
          }
        };
      }
      const removeRoleQuery = db2.query("DELETE FROM user_roles WHERE user_id = ? AND role_id = ?");
      removeRoleQuery.run(userId, role.id);
      console.log(`\u2705 Rol ${roleName} removido del usuario: ${userId}`);
      return { success: true };
    } catch (error) {
      console.error("Error removing role:", error);
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: error.message || "Failed to remove role"
        }
      };
    }
  }
  async getUsers(page = 1, limit = 10, options = {}) {
    try {
      const db2 = getDatabase();
      const offset = (page - 1) * limit;
      let whereConditions = [];
      let queryParams = [];
      if (options.activeOnly) {
        whereConditions.push("is_active = ?");
        queryParams.push(1);
      }
      if (options.isActive !== undefined) {
        whereConditions.push("is_active = ?");
        queryParams.push(options.isActive ? 1 : 0);
      }
      if (options.search) {
        whereConditions.push("(email LIKE ? OR first_name LIKE ? OR last_name LIKE ?)");
        const searchTerm = `%${options.search}%`;
        queryParams.push(searchTerm, searchTerm, searchTerm);
      }
      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
      let orderBy = "ORDER BY created_at DESC";
      if (options.sortBy) {
        const sortDirection = options.sortOrder === "asc" ? "ASC" : "DESC";
        switch (options.sortBy) {
          case "email":
            orderBy = `ORDER BY email ${sortDirection}`;
            break;
          case "created_at":
            orderBy = `ORDER BY created_at ${sortDirection}`;
            break;
          case "name":
            orderBy = `ORDER BY first_name ${sortDirection}, last_name ${sortDirection}`;
            break;
          default:
            orderBy = "ORDER BY created_at DESC";
        }
      }
      const countQuery = db2.query(`SELECT COUNT(*) as total FROM users ${whereClause}`);
      const countResult = countQuery.get(...queryParams);
      const total = countResult?.total || countResult?.["COUNT(*)"] || 0;
      const usersQuery = db2.query(`SELECT id, email, password_hash, first_name, last_name, created_at, updated_at, is_active, last_login_at FROM users ${whereClause} ${orderBy} LIMIT ? OFFSET ?`);
      const usersResult = usersQuery.all(...queryParams, limit, offset);
      const users = [];
      for (const userData of usersResult) {
        const user = this.mapDatabaseUserToUser(userData);
        if (options.includeRoles) {
          user.roles = await this.getUserRoles(userData.id, options.includePermissions);
        }
        users.push(user);
      }
      return { users, total };
    } catch (error) {
      console.error("Error getting users:", error);
      throw new Error(`Failed to get users: ${error.message}`);
    }
  }
  mapDatabaseUserToUser(userData) {
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
      createdAt,
      updatedAt,
      is_active: Boolean(userData.is_active),
      isActive: Boolean(userData.is_active),
      lastLoginAt: userData.last_login_at ? new Date(userData.last_login_at) : undefined,
      roles: []
    };
  }
}
var authServiceInstance = null;
function initAuthService() {
  authServiceInstance = new AuthService;
  return authServiceInstance;
}
function getAuthService() {
  if (!authServiceInstance) {
    throw new Error("Auth Service not initialized. Call initAuthService() first.");
  }
  return authServiceInstance;
}
// src/services/permissions.ts
class PermissionService {
  async createPermission(data) {
    try {
      const db2 = getDatabase();
      const validation = this.validatePermissionData(data);
      if (!validation.isValid) {
        return {
          success: false,
          error: {
            type: "VALIDATION_ERROR",
            message: validation.error
          }
        };
      }
      const existingPermission = await this.findPermissionByName(data.name);
      if (existingPermission) {
        return {
          success: false,
          error: {
            type: "VALIDATION_ERROR",
            message: `Permission '${data.name}' already exists`
          }
        };
      }
      const permissionId = crypto.randomUUID();
      const query = db2.query("INSERT INTO permissions (id, name, resource, action, description, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))");
      query.run(permissionId, data.name, data.resource || "default", data.action || "read", data.description || null);
      const permission = await this.findPermissionById(permissionId);
      if (!permission) {
        return {
          success: false,
          error: {
            type: "DATABASE_ERROR",
            message: "Failed to create permission"
          }
        };
      }
      return {
        success: true,
        permission
      };
    } catch (error) {
      console.error("Error creating permission:", error);
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: `Failed to create permission: ${error.message}`
        }
      };
    }
  }
  async createRole(data) {
    try {
      const db2 = getDatabase();
      const validation = this.validateRoleData(data);
      if (!validation.isValid) {
        return {
          success: false,
          error: {
            type: "VALIDATION_ERROR",
            message: validation.error
          }
        };
      }
      const existingRole = await this.findRoleByName(data.name);
      if (existingRole) {
        return {
          success: false,
          error: {
            type: "VALIDATION_ERROR",
            message: `Role '${data.name}' already exists`
          }
        };
      }
      const roleId = crypto.randomUUID();
      const query = db2.query("INSERT INTO roles (id, name, description, is_active, created_at) VALUES (?, ?, ?, ?, datetime('now'))");
      query.run(roleId, data.name, data.description || null, 1);
      if (data.permissionIds && data.permissionIds.length > 0) {
        const assignResult = await this.assignPermissionsToRole(roleId, data.permissionIds);
        if (!assignResult.success) {
          return assignResult;
        }
      }
      const role = await this.findRoleById(roleId, true);
      if (!role) {
        return {
          success: false,
          error: {
            type: "DATABASE_ERROR",
            message: "Failed to create role"
          }
        };
      }
      return {
        success: true,
        role
      };
    } catch (error) {
      console.error("Error creating role:", error);
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: `Failed to create role: ${error.message}`
        }
      };
    }
  }
  async assignRoleToUser(data) {
    try {
      const db2 = getDatabase();
      const userExists = await this.checkUserExists(data.userId);
      if (!userExists) {
        return {
          success: false,
          error: {
            type: "NOT_FOUND_ERROR",
            message: "User not found"
          }
        };
      }
      const roleExists = await this.checkRoleExists(data.roleId);
      if (!roleExists) {
        return {
          success: false,
          error: {
            type: "NOT_FOUND_ERROR",
            message: "Role not found"
          }
        };
      }
      const existingQuery = db2.query("SELECT id FROM user_roles WHERE user_id = ? AND role_id = ?");
      const existingAssignment = existingQuery.all(data.userId, data.roleId);
      if (existingAssignment.length > 0) {
        return {
          success: false,
          error: {
            type: "VALIDATION_ERROR",
            message: "User already has this role"
          }
        };
      }
      const insertQuery = db2.query("INSERT INTO user_roles (id, user_id, role_id, created_at) VALUES (?, ?, ?, datetime('now'))");
      insertQuery.run(crypto.randomUUID(), data.userId, data.roleId);
      console.log(`\u2705 Rol asignado al usuario: ${data.userId} -> ${data.roleId}`);
      return { success: true };
    } catch (error) {
      console.error("Error assigning role to user:", error);
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: `Failed to assign role: ${error.message}`
        }
      };
    }
  }
  async removeRoleFromUser(userId, roleId) {
    try {
      const db2 = getDatabase();
      const query = db2.query("DELETE FROM user_roles WHERE user_id = ? AND role_id = ?");
      query.run(userId, roleId);
      console.log(`\u2705 Rol removido del usuario: ${userId} -> ${roleId}`);
      return { success: true };
    } catch (error) {
      console.error("Error removing role from user:", error);
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: `Failed to remove role: ${error.message}`
        }
      };
    }
  }
  async assignPermissionsToRole(roleId, permissionIds) {
    try {
      const db2 = getDatabase();
      const roleExists = await this.checkRoleExists(roleId);
      if (!roleExists) {
        return {
          success: false,
          error: {
            type: "NOT_FOUND_ERROR",
            message: "Role not found"
          }
        };
      }
      for (const permissionId of permissionIds) {
        const permissionExists = await this.checkPermissionExists(permissionId);
        if (!permissionExists) {
          return {
            success: false,
            error: {
              type: "NOT_FOUND_ERROR",
              message: `Permission not found: ${permissionId}`
            }
          };
        }
      }
      for (const permissionId of permissionIds) {
        const existingQuery = db2.query("SELECT id FROM role_permissions WHERE role_id = ? AND permission_id = ?");
        const existing = existingQuery.get(roleId, permissionId);
        if (existing) {
          return {
            success: false,
            error: {
              type: "VALIDATION_ERROR",
              message: `Permission ${permissionId} is already assigned to role ${roleId}`
            }
          };
        }
        const insertQuery = db2.query("INSERT INTO role_permissions (id, role_id, permission_id, created_at) VALUES (?, ?, ?, datetime('now'))");
        insertQuery.run(crypto.randomUUID(), roleId, permissionId);
      }
      return { success: true };
    } catch (error) {
      console.error("Error assigning permissions to role:", error);
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: `Failed to assign permissions: ${error.message}`
        }
      };
    }
  }
  async assignPermissionToRole(roleId, permissionId) {
    return this.assignPermissionsToRole(roleId, [permissionId]);
  }
  async removePermissionsFromRole(roleId, permissionIds) {
    try {
      const db2 = getDatabase();
      for (const permissionId of permissionIds) {
        const query = db2.query("DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?");
        query.run(roleId, permissionId);
      }
      console.log(`\u2705 Permisos removidos del rol: ${roleId}`);
      return { success: true };
    } catch (error) {
      console.error("Error removing permissions from role:", error);
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: `Failed to remove permissions: ${error.message}`
        }
      };
    }
  }
  async updatePermission(id, data) {
    try {
      const db2 = getDatabase();
      const existingPermission = await this.findPermissionById(id);
      if (!existingPermission) {
        return {
          success: false,
          error: {
            type: "NOT_FOUND_ERROR",
            message: "Permission not found"
          }
        };
      }
      if (data.name && data.name !== existingPermission.name) {
        const existingByName = await this.findPermissionByName(data.name);
        if (existingByName && existingByName.id !== id) {
          return {
            success: false,
            error: {
              type: "VALIDATION_ERROR",
              message: "Permission name already exists"
            }
          };
        }
      }
      const query = db2.query("UPDATE permissions SET name = ?, resource = ?, action = ?, description = ? WHERE id = ?");
      query.run(data.name || existingPermission.name, data.resource || existingPermission.resource, data.action || existingPermission.action, data.description !== undefined ? data.description : existingPermission.description || null, id);
      const updatedPermission = await this.findPermissionById(id);
      console.log(`\u2705 Permiso actualizado: ${updatedPermission?.name}`);
      return {
        success: true,
        permission: updatedPermission
      };
    } catch (error) {
      console.error("Error updating permission:", error);
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: `Failed to update permission: ${error.message}`
        }
      };
    }
  }
  async deletePermission(id) {
    try {
      const db2 = getDatabase();
      const existingPermission = await this.findPermissionById(id);
      if (!existingPermission) {
        return {
          success: false,
          error: {
            type: "NOT_FOUND_ERROR",
            message: "Permission not found"
          }
        };
      }
      const deleteRelationsQuery = db2.query("DELETE FROM role_permissions WHERE permission_id = ?");
      deleteRelationsQuery.run(id);
      const deletePermissionQuery = db2.query("DELETE FROM permissions WHERE id = ?");
      deletePermissionQuery.run(id);
      console.log(`\u2705 Permiso eliminado: ${existingPermission.name}`);
      return { success: true };
    } catch (error) {
      console.error("Error deleting permission:", error);
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: `Failed to delete permission: ${error.message}`
        }
      };
    }
  }
  async updateRole(id, data) {
    try {
      const db2 = getDatabase();
      const existingRole = await this.findRoleById(id);
      if (!existingRole) {
        return {
          success: false,
          error: {
            type: "NOT_FOUND_ERROR",
            message: "Role not found"
          }
        };
      }
      if (data.name && data.name !== existingRole.name) {
        const existingByName = await this.findRoleByName(data.name);
        if (existingByName && existingByName.id !== id) {
          return {
            success: false,
            error: {
              type: "VALIDATION_ERROR",
              message: "Role name already exists"
            }
          };
        }
      }
      const query = db2.query("UPDATE roles SET name = ?, description = ?, is_active = ? WHERE id = ?");
      query.run(data.name || existingRole.name, data.description !== undefined ? data.description : existingRole.description || null, data.isActive !== undefined ? data.isActive ? 1 : 0 : existingRole.isActive ? 1 : 0, id);
      const updatedRole = await this.findRoleById(id);
      console.log(`\u2705 Rol actualizado: ${updatedRole?.name}`);
      return {
        success: true,
        role: updatedRole || undefined
      };
    } catch (error) {
      console.error("Error updating role:", error);
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: `Failed to update role: ${error.message}`
        }
      };
    }
  }
  async deleteRole(id) {
    try {
      const db2 = getDatabase();
      const existingRole = await this.findRoleById(id);
      if (!existingRole) {
        return {
          success: false,
          error: {
            type: "NOT_FOUND_ERROR",
            message: "Role not found"
          }
        };
      }
      const deleteUserRolesQuery = db2.query("DELETE FROM user_roles WHERE role_id = ?");
      deleteUserRolesQuery.run(id);
      const deleteRolePermissionsQuery = db2.query("DELETE FROM role_permissions WHERE role_id = ?");
      deleteRolePermissionsQuery.run(id);
      const deleteRoleQuery = db2.query("DELETE FROM roles WHERE id = ?");
      deleteRoleQuery.run(id);
      console.log(`\u2705 Rol eliminado: ${existingRole.name}`);
      return { success: true };
    } catch (error) {
      console.error("Error deleting role:", error);
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: `Failed to delete role: ${error.message}`
        }
      };
    }
  }
  async removePermissionFromRole(roleId, permissionId) {
    return this.removePermissionsFromRole(roleId, [permissionId]);
  }
  async userHasPermission(userId, permissionName, options = {}) {
    try {
      const db2 = getDatabase();
      const userQuery = db2.query(`
        SELECT is_active
        FROM users
        WHERE id = ?
      `);
      const userResult = userQuery.get(userId);
      if (!userResult || !userResult.is_active) {
        return false;
      }
      const exactQuery = db2.query(`
        SELECT COUNT(*) as count
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        INNER JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = ? AND p.name = ?
      `);
      const exactResult = exactQuery.get(userId, permissionName);
      if (exactResult?.count > 0) {
        return true;
      }
      const wildcardQuery = db2.query(`
        SELECT COUNT(*) as count
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        INNER JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = ? AND (p.name = '*:*' OR p.name = 'admin:*' OR p.resource = '*' OR p.action = '*')
      `);
      const wildcardResult = wildcardQuery.get(userId);
      return wildcardResult?.count > 0;
    } catch (error) {
      console.error("Error checking user permission:", error);
      return false;
    }
  }
  async userHasRole(userId, roleName) {
    try {
      const db2 = getDatabase();
      const query = db2.query(`
        SELECT COUNT(*) as count
        FROM user_roles ur
        INNER JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = ? AND r.name = ?
      `);
      const result = query.get(userId, roleName);
      return result?.count > 0;
    } catch (error) {
      console.error("Error checking user role:", error);
      return false;
    }
  }
  async userHasAllRoles(userId, roleNames) {
    try {
      for (const roleName of roleNames) {
        const hasRole = await this.userHasRole(userId, roleName);
        if (!hasRole) {
          return false;
        }
      }
      return true;
    } catch (error) {
      console.error("Error checking user roles:", error);
      return false;
    }
  }
  async userHasAnyRole(userId, roleNames) {
    try {
      for (const roleName of roleNames) {
        const hasRole = await this.userHasRole(userId, roleName);
        if (hasRole) {
          return true;
        }
      }
      return false;
    } catch (error) {
      console.error("Error checking user roles:", error);
      return false;
    }
  }
  async userHasAllPermissions(userId, permissionNames) {
    try {
      for (const permissionName of permissionNames) {
        const hasPermission = await this.userHasPermission(userId, permissionName);
        if (!hasPermission) {
          return false;
        }
      }
      return true;
    } catch (error) {
      console.error("Error checking user permissions:", error);
      return false;
    }
  }
  async userHasAnyPermission(userId, permissionNames) {
    try {
      for (const permissionName of permissionNames) {
        const hasPermission = await this.userHasPermission(userId, permissionName);
        if (hasPermission) {
          return true;
        }
      }
      return false;
    } catch (error) {
      console.error("Error checking user permissions:", error);
      return false;
    }
  }
  async userCanAccessResource(userId, resource, action) {
    try {
      const db2 = getDatabase();
      const exactPermissionName = `${resource}:${action}`;
      const hasExactPermission = await this.userHasPermission(userId, exactPermissionName);
      if (hasExactPermission) {
        return true;
      }
      const wildcardQuery = db2.query(`
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
      const wildcardResult = wildcardQuery.get(userId, `${resource}:*`, `*:${action}`, resource, action);
      return wildcardResult?.count > 0;
    } catch (error) {
      console.error("Error checking resource access:", error);
      return false;
    }
  }
  async userHasPermissions(userId, permissionNames, options = {}) {
    try {
      if (permissionNames.length === 0) {
        return true;
      }
      const results = await Promise.all(permissionNames.map((permission) => this.userHasPermission(userId, permission, options)));
      if (options.requireAll) {
        return results.every((result) => result);
      }
      return results.some((result) => result);
    } catch (error) {
      console.error("Error checking user permissions:", error);
      return false;
    }
  }
  async getUserPermissions(userId) {
    try {
      const db2 = getDatabase();
      const query = db2.query(`
        SELECT DISTINCT p.id, p.name, p.resource, p.action, p.description, p.created_at
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        INNER JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = ?
        ORDER BY p.resource, p.action
      `);
      const result = query.all(userId);
      return result.map((row) => ({
        id: row.id,
        name: row.name,
        resource: row.resource,
        action: row.action,
        description: row.description,
        created_at: new Date(row.created_at)
      }));
    } catch (error) {
      console.error("Error getting user permissions:", error);
      throw new Error(`Failed to get user permissions: ${error.message}`);
    }
  }
  async findPermissionById(id) {
    try {
      const db2 = getDatabase();
      const query = db2.query("SELECT id, name, resource, action, description, created_at FROM permissions WHERE id = ?");
      const result = query.get(id);
      if (!result) {
        return null;
      }
      return {
        id: result.id,
        name: result.name,
        resource: result.resource,
        action: result.action,
        description: result.description,
        created_at: new Date(result.created_at)
      };
    } catch (error) {
      console.error("Error finding permission by ID:", error);
      return null;
    }
  }
  async findPermissionByName(name) {
    try {
      const db2 = getDatabase();
      const query = db2.query("SELECT id, name, resource, action, description, created_at FROM permissions WHERE name = ?");
      const result = query.get(name);
      if (!result) {
        return null;
      }
      return {
        id: result.id,
        name: result.name,
        resource: result.resource,
        action: result.action,
        description: result.description,
        created_at: new Date(result.created_at)
      };
    } catch (error) {
      console.error("Error finding permission by name:", error);
      return null;
    }
  }
  async findRoleById(id, includePermissions = false) {
    try {
      const db2 = getDatabase();
      const query = db2.query("SELECT id, name, description, created_at, is_active FROM roles WHERE id = ?");
      const result = query.get(id);
      if (!result) {
        return null;
      }
      const role = {
        id: result.id,
        name: result.name,
        description: result.description,
        created_at: new Date(result.created_at),
        isActive: Boolean(result.is_active),
        permissions: []
      };
      if (includePermissions) {
        role.permissions = await this.getRolePermissions(id);
      }
      return role;
    } catch (error) {
      console.error("Error finding role by ID:", error);
      return null;
    }
  }
  async findRoleByName(name, includePermissions = false) {
    try {
      const db2 = getDatabase();
      const query = db2.query("SELECT id, name, description, created_at, is_active FROM roles WHERE name = ?");
      const result = query.get(name);
      if (!result) {
        return null;
      }
      const role = {
        id: result.id,
        name: result.name,
        description: result.description,
        created_at: new Date(result.created_at),
        isActive: Boolean(result.is_active),
        permissions: []
      };
      if (includePermissions) {
        role.permissions = await this.getRolePermissions(result.id);
      }
      return role;
    } catch (error) {
      console.error("Error finding role by name:", error);
      return null;
    }
  }
  async getRolePermissions(roleId) {
    try {
      const db2 = getDatabase();
      const result = db2.query(`
        SELECT p.id, p.name, p.resource, p.action, p.description, p.created_at
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = ?
        ORDER BY p.resource, p.action
      `).all(roleId);
      return result.map((row) => ({
        id: row.id,
        name: row.name,
        resource: row.resource,
        action: row.action,
        description: row.description,
        created_at: new Date(row.created_at)
      }));
    } catch (error) {
      console.error("Error getting role permissions:", error);
      return [];
    }
  }
  async getAllRoles(includePermissions = false) {
    try {
      const db2 = getDatabase();
      const query = db2.query(`
        SELECT id, name, description, created_at, is_active
        FROM roles
        ORDER BY name
      `);
      const result = query.all();
      const roles = [];
      for (const row of result) {
        const role = {
          id: row.id,
          name: row.name,
          description: row.description,
          created_at: new Date(row.created_at),
          isActive: Boolean(row.is_active),
          permissions: []
        };
        if (includePermissions) {
          role.permissions = await this.getRolePermissions(row.id);
        }
        roles.push(role);
      }
      return roles;
    } catch (error) {
      console.error("Error getting all roles:", error);
      throw new Error(`Failed to get roles: ${error.message}`);
    }
  }
  async getAllPermissions() {
    try {
      const db2 = getDatabase();
      const query = db2.query(`
        SELECT id, name, resource, action, description, created_at
        FROM permissions
        ORDER BY resource, action
      `);
      const result = query.all();
      return result.map((row) => ({
        id: row.id,
        name: row.name,
        resource: row.resource,
        action: row.action,
        description: row.description,
        created_at: new Date(row.created_at)
      }));
    } catch (error) {
      console.error("Error getting all permissions:", error);
      throw new Error(`Failed to get permissions: ${error.message}`);
    }
  }
  validatePermissionData(data) {
    if (!data.name || !data.resource || !data.action) {
      return {
        isValid: false,
        error: "Name, resource, and action are required"
      };
    }
    if (data.name.length < 3) {
      return {
        isValid: false,
        error: "Permission name must be at least 3 characters long"
      };
    }
    return { isValid: true };
  }
  validateRoleData(data) {
    if (!data.name) {
      return {
        isValid: false,
        error: "Role name is required"
      };
    }
    if (data.name.length < 3) {
      return {
        isValid: false,
        error: "Role name must be at least 3 characters long"
      };
    }
    return { isValid: true };
  }
  async checkUserExists(userId) {
    try {
      const db2 = getDatabase();
      const query = db2.query("SELECT id FROM users WHERE id = ?");
      const result = query.get(userId);
      return !!result;
    } catch (error) {
      console.error("Error checking user existence:", error);
      return false;
    }
  }
  async checkRoleExists(roleId) {
    try {
      const db2 = getDatabase();
      const query = db2.query("SELECT id FROM roles WHERE id = ?");
      const result = query.get(roleId);
      return !!result;
    } catch (error) {
      console.error("Error checking role existence:", error);
      return false;
    }
  }
  async checkPermissionExists(permissionId) {
    try {
      const db2 = getDatabase();
      const query = db2.query("SELECT id FROM permissions WHERE id = ?");
      const result = query.get(permissionId);
      return !!result;
    } catch (error) {
      console.error("Error checking permission existence:", error);
      return false;
    }
  }
}
var permissionServiceInstance = null;
function initPermissionService() {
  permissionServiceInstance = new PermissionService;
  return permissionServiceInstance;
}
function getPermissionService() {
  if (!permissionServiceInstance) {
    throw new Error("Permission Service not initialized. Call initPermissionService() first.");
  }
  return permissionServiceInstance;
}
// src/config/auth.ts
var DEFAULT_AUTH_CONFIG = {
  jwtSecret: process.env.JWT_SECRET || "change-this-secret-in-production",
  jwtExpiration: process.env.JWT_EXPIRATION || "1h",
  refreshTokenExpiration: process.env.REFRESH_TOKEN_EXPIRATION || "7d",
  database: {
    path: process.env.DATABASE_PATH || "./data/auth.db",
    enableWAL: process.env.DATABASE_WAL === "true",
    enableForeignKeys: true,
    busyTimeout: 5000
  },
  security: {
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS || "12"),
    maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS || "5"),
    lockoutDuration: parseInt(process.env.LOCKOUT_DURATION || "900000"),
    sessionTimeout: parseInt(process.env.SESSION_TIMEOUT || "3600000"),
    requireEmailVerification: process.env.REQUIRE_EMAIL_VERIFICATION === "true",
    allowMultipleSessions: process.env.ALLOW_MULTIPLE_SESSIONS !== "false",
    passwordMinLength: parseInt(process.env.PASSWORD_MIN_LENGTH || "8"),
    passwordRequireUppercase: process.env.PASSWORD_REQUIRE_UPPERCASE !== "false",
    passwordRequireLowercase: process.env.PASSWORD_REQUIRE_LOWERCASE !== "false",
    passwordRequireNumbers: process.env.PASSWORD_REQUIRE_NUMBERS !== "false",
    passwordRequireSymbols: process.env.PASSWORD_REQUIRE_SYMBOLS !== "false"
  },
  cors: {
    origins: process.env.CORS_ORIGINS?.split(",") || ["http://localhost:3000"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    headers: ["Content-Type", "Authorization"]
  },
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || "900000"),
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX || "100"),
    skipSuccessfulRequests: false,
    skipFailedRequests: false
  },
  logging: {
    level: process.env.LOG_LEVEL || "info",
    enableConsole: process.env.LOG_CONSOLE !== "false",
    enableFile: process.env.LOG_FILE === "true",
    filePath: process.env.LOG_FILE_PATH || "./logs/auth.log",
    enableDatabase: process.env.LOG_DATABASE === "true"
  }
};
var SECURITY_CONFIG = {
  securityHeaders: {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Referrer-Policy": "strict-origin-when-cross-origin"
  },
  cookies: {
    httpOnly: true,
    secure: false,
    sameSite: "strict",
    maxAge: 24 * 60 * 60 * 1000
  },
  validation: {
    maxEmailLength: 254,
    maxNameLength: 100,
    maxPasswordLength: 128,
    allowedEmailDomains: process.env.ALLOWED_EMAIL_DOMAINS?.split(","),
    blockedEmailDomains: process.env.BLOCKED_EMAIL_DOMAINS?.split(",") || [
      "tempmail.org",
      "10minutemail.com",
      "guerrillamail.com"
    ]
  },
  ipSecurity: {
    enableGeoBlocking: process.env.ENABLE_GEO_BLOCKING === "true",
    blockedCountries: process.env.BLOCKED_COUNTRIES?.split(",") || [],
    enableIPWhitelist: process.env.ENABLE_IP_WHITELIST === "true",
    ipWhitelist: process.env.IP_WHITELIST?.split(",") || [],
    enableIPBlacklist: process.env.ENABLE_IP_BLACKLIST === "true",
    ipBlacklist: process.env.IP_BLACKLIST?.split(",") || []
  }
};
var DEV_CONFIG = {
  jwtSecret: "dev-secret-key-not-for-production",
  jwtExpiration: "24h",
  refreshTokenExpiration: "30d",
  security: {
    bcryptRounds: 4,
    maxLoginAttempts: 10,
    lockoutDuration: 60000,
    sessionTimeout: 24 * 60 * 60 * 1000,
    requireEmailVerification: false,
    allowMultipleSessions: true,
    passwordMinLength: 6,
    passwordRequireUppercase: false,
    passwordRequireLowercase: false,
    passwordRequireNumbers: false,
    passwordRequireSymbols: false
  },
  logging: {
    level: "debug",
    enableConsole: true,
    enableFile: false,
    filePath: "./logs/auth.log",
    enableDatabase: false
  }
};
var PROD_CONFIG = {
  security: {
    bcryptRounds: 14,
    maxLoginAttempts: 3,
    lockoutDuration: 30 * 60 * 1000,
    sessionTimeout: 60 * 60 * 1000,
    requireEmailVerification: true,
    allowMultipleSessions: false,
    passwordMinLength: 12,
    passwordRequireUppercase: true,
    passwordRequireLowercase: true,
    passwordRequireNumbers: true,
    passwordRequireSymbols: true
  },
  logging: {
    level: "warn",
    enableConsole: false,
    enableFile: true,
    filePath: "./logs/auth.log",
    enableDatabase: true
  }
};
function getAuthConfig(environment) {
  const env = environment || "development";
  let config = { ...DEFAULT_AUTH_CONFIG };
  switch (env) {
    case "development":
      config = mergeConfig(config, DEV_CONFIG);
      break;
    case "production":
      config = mergeConfig(config, PROD_CONFIG);
      break;
    case "test":
      config = mergeConfig(config, {
        database: {
          path: ":memory:",
          enableWAL: false,
          enableForeignKeys: true,
          busyTimeout: 5000
        },
        logging: {
          level: "error",
          enableConsole: false,
          enableFile: false,
          filePath: "./logs/auth.log",
          enableDatabase: false
        }
      });
      break;
  }
  return config;
}
function validateAuthConfig(config) {
  const errors = [];
  if (!config.jwtSecret || config.jwtSecret === "change-this-secret-in-production") {
    if (false) {}
  }
  if (config.jwtSecret && config.jwtSecret.length < 32) {
    errors.push("JWT secret debe tener al menos 32 caracteres");
  }
  if (!config.database?.path) {
    errors.push("Ruta de base de datos es requerida");
  }
  if (config.security) {
    if (config.security.bcryptRounds < 4 || config.security.bcryptRounds > 20) {
      errors.push("bcryptRounds debe estar entre 4 y 20");
    }
    if (config.security.passwordMinLength < 6) {
      errors.push("passwordMinLength debe ser al menos 6");
    }
    if (config.security.maxLoginAttempts < 1) {
      errors.push("maxLoginAttempts debe ser al menos 1");
    }
  }
  if (config.cors?.origins && config.cors.origins.length === 0) {
    errors.push("Al menos un origen CORS debe ser especificado");
  }
  return {
    valid: errors.length === 0,
    errors
  };
}
function getRequiredEnvVars() {
  return {
    JWT_SECRET: process.env.JWT_SECRET,
    DATABASE_PATH: process.env.DATABASE_PATH,
    NODE_ENV: "development",
    BCRYPT_ROUNDS: process.env.BCRYPT_ROUNDS,
    MAX_LOGIN_ATTEMPTS: process.env.MAX_LOGIN_ATTEMPTS,
    CORS_ORIGINS: process.env.CORS_ORIGINS
  };
}
function generateEnvExample() {
  return `# Configuraci\xF3n de Autenticaci\xF3n

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRATION=1h
REFRESH_TOKEN_EXPIRATION=7d

# Database Configuration
DATABASE_PATH=./data/auth.db
DATABASE_WAL=true

# Security Configuration
BCRYPT_ROUNDS=12
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=900000
SESSION_TIMEOUT=3600000
REQUIRE_EMAIL_VERIFICATION=false
ALLOW_MULTIPLE_SESSIONS=true

# Password Policy
PASSWORD_MIN_LENGTH=8
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_SYMBOLS=true

# CORS Configuration
CORS_ORIGINS=http://localhost:3000,http://localhost:3001

# Rate Limiting
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100

# Logging
LOG_LEVEL=info
LOG_CONSOLE=true
LOG_FILE=false
LOG_FILE_PATH=./logs/auth.log
LOG_DATABASE=false

# Email Validation
ALLOWED_EMAIL_DOMAINS=
BLOCKED_EMAIL_DOMAINS=tempmail.org,10minutemail.com

# IP Security
ENABLE_GEO_BLOCKING=false
BLOCKED_COUNTRIES=
ENABLE_IP_WHITELIST=false
IP_WHITELIST=
ENABLE_IP_BLACKLIST=false
IP_BLACKLIST=

# Environment
NODE_ENV=development
`;
}
function mergeConfig(base, override) {
  const result = { ...base };
  Object.keys(override).forEach((key) => {
    const value = override[key];
    if (value !== undefined) {
      if (typeof value === "object" && value !== null && !Array.isArray(value)) {
        const baseValue = result[key];
        if (typeof baseValue === "object" && baseValue !== null && !Array.isArray(baseValue)) {
          result[key] = {
            ...baseValue,
            ...value
          };
        } else {
          result[key] = value;
        }
      } else {
        result[key] = value;
      }
    }
  });
  return result;
}
function printConfig(config) {
  const safeConfig = { ...config };
  if (safeConfig.jwtSecret) {
    safeConfig.jwtSecret = "***HIDDEN***";
  }
  console.log("\uD83D\uDD27 Configuraci\xF3n de autenticaci\xF3n:");
  console.log(JSON.stringify(safeConfig, null, 2));
}
var auth_default = getAuthConfig();

// src/middleware/auth.ts
async function authenticateRequest(request, config = {}) {
  const {
    required = true,
    permissions = [],
    permissionOptions = {},
    tokenHeader = "authorization",
    extractToken
  } = config;
  let token = null;
  if (extractToken) {
    token = extractToken(request);
  } else {
    const authHeader = request.headers[tokenHeader] || request.headers[tokenHeader.toLowerCase()];
    if (!authHeader) {
      if (!required) {
        return { success: true, context: { permissions: [], isAuthenticated: false } };
      }
      return {
        success: false,
        error: "Authorization header is required",
        statusCode: 401
      };
    }
    const jwtService2 = config.jwtService || getJWTService();
    if (tokenHeader === "authorization") {
      token = jwtService2.extractTokenFromHeader(authHeader);
    } else {
      token = authHeader;
    }
  }
  if (!token) {
    if (!required) {
      return { success: true, context: { permissions: [], isAuthenticated: false } };
    }
    return {
      success: false,
      error: extractToken ? "Token not found" : "Invalid authorization header format. Use: Bearer <token>",
      statusCode: 401
    };
  }
  const jwtService = config.jwtService || getJWTService();
  const result = await jwtService.verifyToken(token).then((payload2) => ({ success: true, payload: payload2 })).catch((error) => ({ success: false, error: error.message }));
  if (!result.success) {
    if (!required) {
      return { success: true, context: { permissions: [], isAuthenticated: false } };
    }
    return {
      success: false,
      error: "Invalid or expired token",
      statusCode: 401
    };
  }
  const payload = result.payload;
  const authService = config.authService || getAuthService();
  const user = await authService.findUserById(payload.userId, {
    includeRoles: true,
    includePermissions: true,
    activeOnly: true
  });
  if (!user) {
    return {
      success: false,
      error: "User not found or inactive",
      statusCode: 401
    };
  }
  const permissionService = config.permissionService || getPermissionService();
  const userPermissions = await permissionService.getUserPermissions(user.id);
  const permissionNames = userPermissions.map((p) => p.name);
  const authContext = {
    user,
    token,
    permissions: permissionNames,
    isAuthenticated: true
  };
  if (permissions.length > 0) {
    const hasPermissions = await permissionService.userHasPermissions(user.id, permissions, permissionOptions);
    if (!hasPermissions) {
      return {
        success: false,
        error: `Insufficient permissions. Required: ${permissions.join(", ")}`,
        statusCode: 403
      };
    }
  }
  return { success: true, context: authContext };
}
async function authorizeRequest(authContext, requiredPermissions, options = {}) {
  try {
    if (!authContext.user) {
      return {
        success: false,
        error: "User not authenticated",
        statusCode: 401
      };
    }
    if (requiredPermissions.length === 0) {
      return { success: true };
    }
    const permissionService = getPermissionService();
    const hasPermissions = await permissionService.userHasPermissions(authContext.user.id, requiredPermissions, options);
    if (!hasPermissions) {
      return {
        success: false,
        error: `Insufficient permissions. Required: ${requiredPermissions.join(", ")}`,
        statusCode: 403
      };
    }
    return { success: true };
  } catch (error) {
    console.error("Authorization error:", error);
    return {
      success: false,
      error: "Internal authorization error",
      statusCode: 500
    };
  }
}
function getCurrentUser(authContext) {
  return authContext?.user || null;
}
function createEmptyAuthContext() {
  return {
    permissions: [],
    isAuthenticated: false
  };
}
function logAuthEvent(event, userId, metadata) {
  const logData = {
    event,
    userId,
    timestamp: new Date().toISOString(),
    metadata
  };
  console.log(`\uD83D\uDD10 Auth Event: ${JSON.stringify(logData)}`);
}
function extractClientIP(headers) {
  return headers["x-forwarded-for"] || headers["x-real-ip"] || headers["x-client-ip"] || headers["cf-connecting-ip"] || "unknown";
}
function extractUserAgent(headers) {
  return headers["user-agent"] || headers["User-Agent"] || "Unknown";
}

// src/adapters/websocket.ts
var activeConnections = new Map;
var connectionsBySession = new Map;
async function authenticateWebSocket(ws, request, config = {}) {
  try {
    const url = new URL(request.url, "http://localhost");
    let token = url.searchParams.get("token");
    if (!token && request.headers.authorization) {
      const authHeader = request.headers.authorization;
      if (authHeader.startsWith("Bearer ")) {
        token = authHeader.replace("Bearer ", "");
      }
    }
    if (!token && config.required !== false) {
      ws.close(1008, "Authentication required");
      return false;
    }
    const authRequest = {
      headers: {
        ...request.headers,
        ...token && { authorization: `Bearer ${token}` }
      }
    };
    const result = await authenticateRequest(authRequest, config);
    if (!result.success) {
      logAuthEvent("websocket.auth.failed", undefined, {
        ip: extractClientIP(authRequest.headers),
        userAgent: extractUserAgent(authRequest.headers),
        error: result.error
      });
      ws.close(1008, result.error || "Authentication failed");
      return false;
    }
    ws.auth = result.context;
    ws.userId = result.context?.user?.id;
    ws.sessionId = generateSessionId();
    ws.lastActivity = new Date;
    if (ws.userId && config.maxConnections) {
      const userConnections = activeConnections.get(ws.userId) || new Set;
      if (userConnections.size >= config.maxConnections) {
        ws.close(1008, "Maximum connections exceeded");
        return false;
      }
    }
    if (ws.userId) {
      registerConnection(ws);
      logAuthEvent("websocket.connected", ws.userId, {
        sessionId: ws.sessionId,
        ip: extractClientIP(authRequest.headers),
        userAgent: extractUserAgent(authRequest.headers)
      });
    }
    if (config.heartbeatInterval) {
      setupHeartbeat(ws, config.heartbeatInterval);
    }
    if (config.sessionTimeout) {
      setupSessionTimeout(ws, config.sessionTimeout);
    }
    return true;
  } catch (error) {
    console.error("WebSocket authentication error:", error);
    ws.close(1011, "Internal authentication error");
    return false;
  }
}
function checkWebSocketPermissions(ws, permissions, requireAll = false) {
  if (!ws.auth?.user) {
    return false;
  }
  const userPermissions = ws.auth.user.roles.flatMap((role) => role.permissions.map((p) => p.name));
  if (requireAll) {
    return permissions.every((permission) => userPermissions.includes(permission));
  } else {
    return permissions.some((permission) => userPermissions.includes(permission));
  }
}
function checkWebSocketRoles(ws, roles) {
  if (!ws.auth?.user) {
    return false;
  }
  const userRoles = ws.auth.user.roles.map((role) => role.name);
  return roles.some((role) => userRoles.includes(role));
}
function getWebSocketCurrentUser(ws) {
  return getCurrentUser(ws.auth);
}
function isWebSocketAuthenticated(ws) {
  return !!ws.auth?.user;
}
function getWebSocketAuthContext(ws) {
  return ws.auth || createEmptyAuthContext();
}
function sendToUser(userId, message, excludeSession) {
  const userConnections = activeConnections.get(userId);
  if (!userConnections)
    return;
  const messageStr = typeof message === "string" ? message : JSON.stringify(message);
  userConnections.forEach((ws) => {
    if (excludeSession && ws.sessionId === excludeSession)
      return;
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(messageStr);
    }
  });
}
function sendToUsersWithPermissions(permissions, message, requireAll = false) {
  const messageStr = typeof message === "string" ? message : JSON.stringify(message);
  activeConnections.forEach((connections, userId) => {
    connections.forEach((ws) => {
      if (ws.readyState === WebSocket.OPEN && checkWebSocketPermissions(ws, permissions, requireAll)) {
        ws.send(messageStr);
      }
    });
  });
}
function sendToUsersWithRoles(roles, message) {
  const messageStr = typeof message === "string" ? message : JSON.stringify(message);
  activeConnections.forEach((connections, userId) => {
    connections.forEach((ws) => {
      if (ws.readyState === WebSocket.OPEN && checkWebSocketRoles(ws, roles)) {
        ws.send(messageStr);
      }
    });
  });
}
function broadcastToAuthenticated(message, excludeUser) {
  const messageStr = typeof message === "string" ? message : JSON.stringify(message);
  activeConnections.forEach((connections, userId) => {
    if (excludeUser && userId === excludeUser)
      return;
    connections.forEach((ws) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(messageStr);
      }
    });
  });
}
function getConnectionStats() {
  let totalConnections = 0;
  const userStats = {};
  activeConnections.forEach((connections, userId) => {
    const activeCount = Array.from(connections).filter((ws) => ws.readyState === WebSocket.OPEN).length;
    totalConnections += activeCount;
    userStats[userId] = activeCount;
  });
  return {
    totalConnections,
    uniqueUsers: activeConnections.size,
    userStats
  };
}
function disconnectUser(userId, reason = "User disconnected") {
  const userConnections = activeConnections.get(userId);
  if (!userConnections)
    return;
  userConnections.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.close(1000, reason);
    }
  });
  logAuthEvent("websocket.user_disconnected", userId, { reason });
}
function cleanupInactiveConnections() {
  const now = new Date;
  const inactiveThreshold = 30 * 60 * 1000;
  activeConnections.forEach((connections, userId) => {
    connections.forEach((ws) => {
      if (ws.readyState !== WebSocket.OPEN || ws.lastActivity && now.getTime() - ws.lastActivity.getTime() > inactiveThreshold) {
        unregisterConnection(ws);
      }
    });
  });
}
function registerConnection(ws) {
  if (!ws.userId || !ws.sessionId)
    return;
  if (!activeConnections.has(ws.userId)) {
    activeConnections.set(ws.userId, new Set);
  }
  activeConnections.get(ws.userId).add(ws);
  connectionsBySession.set(ws.sessionId, ws);
  ws.on("close", () => unregisterConnection(ws));
  ws.on("error", () => unregisterConnection(ws));
}
function unregisterConnection(ws) {
  if (ws.userId) {
    const userConnections = activeConnections.get(ws.userId);
    if (userConnections) {
      userConnections.delete(ws);
      if (userConnections.size === 0) {
        activeConnections.delete(ws.userId);
      }
    }
    logAuthEvent("websocket.disconnected", ws.userId, {
      sessionId: ws.sessionId
    });
  }
  if (ws.sessionId) {
    connectionsBySession.delete(ws.sessionId);
  }
}
function setupHeartbeat(ws, interval) {
  const heartbeatTimer = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.ping();
      ws.lastActivity = new Date;
    } else {
      clearInterval(heartbeatTimer);
    }
  }, interval);
  ws.on("pong", () => {
    ws.lastActivity = new Date;
  });
  ws.on("close", () => {
    clearInterval(heartbeatTimer);
  });
}
function setupSessionTimeout(ws, timeout) {
  const timeoutTimer = setTimeout(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.close(1000, "Session timeout");
    }
  }, timeout);
  ws.on("message", () => {
    ws.lastActivity = new Date;
  });
  ws.on("close", () => {
    clearTimeout(timeoutTimer);
  });
}
function generateSessionId() {
  return `ws_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}
function handleAuthenticatedMessage(ws, message, permissions) {
  ws.lastActivity = new Date;
  if (!isWebSocketAuthenticated(ws)) {
    ws.send(JSON.stringify({
      type: "error",
      message: "Authentication required",
      timestamp: new Date().toISOString()
    }));
    return false;
  }
  if (permissions && !checkWebSocketPermissions(ws, permissions)) {
    ws.send(JSON.stringify({
      type: "error",
      message: "Insufficient permissions",
      timestamp: new Date().toISOString()
    }));
    logAuthEvent("websocket.insufficient_permissions", ws.userId, {
      requiredPermissions: permissions,
      sessionId: ws.sessionId
    });
    return false;
  }
  return true;
}
function createWebSocketResponse(type, data, message) {
  return {
    type,
    data,
    message,
    timestamp: new Date().toISOString()
  };
}
function initializeConnectionCleanup(interval = 5 * 60 * 1000) {
  setInterval(() => {
    cleanupInactiveConnections();
  }, interval);
}

// src/db/migrations.ts
var migrations = [
  {
    version: 1,
    name: "create_users_table",
    up: async (db2) => {
      db2.exec(`
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          is_active BOOLEAN DEFAULT 1
        )
      `);
      db2.exec("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)");
      db2.exec("CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active)");
      console.log("\u2705 Tabla users creada");
    },
    down: async (db2) => {
      db2.exec("DROP TABLE IF EXISTS users");
      console.log("\u2705 Tabla users eliminada");
    }
  },
  {
    version: 2,
    name: "create_roles_table",
    up: async (db2) => {
      db2.exec(`
        CREATE TABLE IF NOT EXISTS roles (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          name TEXT UNIQUE NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);
      db2.exec("CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name)");
      console.log("\u2705 Tabla roles creada");
    },
    down: async (db2) => {
      db2.exec("DROP TABLE IF EXISTS roles");
      console.log("\u2705 Tabla roles eliminada");
    }
  },
  {
    version: 3,
    name: "create_permissions_table",
    up: async (db2) => {
      db2.exec(`
        CREATE TABLE IF NOT EXISTS permissions (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          name TEXT UNIQUE NOT NULL,
          resource TEXT NOT NULL,
          action TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);
      db2.exec("CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name)");
      db2.exec("CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource)");
      db2.exec("CREATE INDEX IF NOT EXISTS idx_permissions_action ON permissions(action)");
      console.log("\u2705 Tabla permissions creada");
    },
    down: async (db2) => {
      db2.exec("DROP TABLE IF EXISTS permissions");
      console.log("\u2705 Tabla permissions eliminada");
    }
  },
  {
    version: 4,
    name: "create_user_roles_table",
    up: async (db2) => {
      db2.exec(`
        CREATE TABLE IF NOT EXISTS user_roles (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          user_id TEXT NOT NULL,
          role_id TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
          UNIQUE(user_id, role_id)
        )
      `);
      db2.exec("CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id)");
      db2.exec("CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id)");
      console.log("\u2705 Tabla user_roles creada");
    },
    down: async (db2) => {
      db2.exec("DROP TABLE IF EXISTS user_roles");
      console.log("\u2705 Tabla user_roles eliminada");
    }
  },
  {
    version: 5,
    name: "create_role_permissions_table",
    up: async (db2) => {
      db2.exec(`
        CREATE TABLE IF NOT EXISTS role_permissions (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          role_id TEXT NOT NULL,
          permission_id TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
          FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
          UNIQUE(role_id, permission_id)
        )
      `);
      db2.exec("CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id)");
      db2.exec("CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id)");
      console.log("\u2705 Tabla role_permissions creada");
    },
    down: async (db2) => {
      db2.exec("DROP TABLE IF EXISTS role_permissions");
      console.log("\u2705 Tabla role_permissions eliminada");
    }
  },
  {
    version: 6,
    name: "create_sessions_table",
    up: async (db2) => {
      db2.exec(`
        CREATE TABLE IF NOT EXISTS sessions (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          user_id TEXT NOT NULL,
          token TEXT UNIQUE NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          expires_at DATETIME NOT NULL,
          last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
          ip_address TEXT,
          user_agent TEXT,
          is_active BOOLEAN DEFAULT 1,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);
      db2.exec("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)");
      db2.exec("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)");
      db2.exec("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)");
      db2.exec("CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(is_active)");
      console.log("\u2705 Tabla sessions creada");
    },
    down: async (db2) => {
      db2.exec("DROP TABLE IF EXISTS sessions");
      console.log("\u2705 Tabla sessions eliminada");
    }
  },
  {
    version: 7,
    name: "create_migration_history_table",
    up: async (db2) => {
      db2.exec(`
        CREATE TABLE IF NOT EXISTS migration_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          version INTEGER UNIQUE NOT NULL,
          name TEXT NOT NULL,
          executed_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);
      console.log("\u2705 Tabla migration_history creada");
    },
    down: async (db2) => {
      db2.exec("DROP TABLE IF EXISTS migration_history");
      console.log("\u2705 Tabla migration_history eliminada");
    }
  },
  {
    version: 8,
    name: "add_description_fields",
    up: async (db2) => {
      db2.exec(`
        ALTER TABLE roles ADD COLUMN description TEXT
      `);
      db2.exec(`
        ALTER TABLE permissions ADD COLUMN description TEXT
      `);
      console.log("\u2705 Campos description agregados a roles y permissions");
    },
    down: async (db2) => {
      db2.exec(`
        CREATE TABLE roles_backup AS SELECT id, name, created_at FROM roles;
        DROP TABLE roles;
        CREATE TABLE roles (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          name TEXT UNIQUE NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO roles SELECT * FROM roles_backup;
        DROP TABLE roles_backup;
      `);
      db2.exec(`
        CREATE TABLE permissions_backup AS SELECT id, name, resource, action, created_at FROM permissions;
        DROP TABLE permissions;
        CREATE TABLE permissions (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          name TEXT UNIQUE NOT NULL,
          resource TEXT NOT NULL,
          action TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO permissions SELECT * FROM permissions_backup;
        DROP TABLE permissions_backup;
      `);
      console.log("\u2705 Campos description removidos de roles y permissions");
    }
  },
  {
    version: 9,
    name: "add_user_name_fields",
    up: async (db2) => {
      db2.exec(`
        ALTER TABLE users ADD COLUMN first_name TEXT
      `);
      db2.exec(`
        ALTER TABLE users ADD COLUMN last_name TEXT
      `);
      console.log("\u2705 Campos first_name y last_name agregados a users");
    },
    down: async (db2) => {
      db2.exec(`
        CREATE TABLE users_backup AS SELECT id, email, password_hash, created_at, updated_at, is_active FROM users;
        DROP TABLE users;
        CREATE TABLE users (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          is_active BOOLEAN DEFAULT 1
        );
        INSERT INTO users SELECT * FROM users_backup;
        DROP TABLE users_backup;
      `);
      db2.exec("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)");
      db2.exec("CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active)");
      console.log("\u2705 Campos first_name y last_name removidos de users");
    }
  },
  {
    version: 10,
    name: "add_last_login_at_field",
    up: async (db2) => {
      db2.exec(`
        ALTER TABLE users ADD COLUMN last_login_at DATETIME
      `);
      console.log("\u2705 Campo last_login_at agregado a users");
    },
    down: async (db2) => {
      db2.exec(`
        CREATE TABLE users_backup AS SELECT id, email, password_hash, first_name, last_name, created_at, updated_at, is_active FROM users;
        DROP TABLE users;
        CREATE TABLE users (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          first_name TEXT,
          last_name TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          is_active BOOLEAN DEFAULT 1
        );
        INSERT INTO users SELECT * FROM users_backup;
        DROP TABLE users_backup;
      `);
      db2.exec("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)");
      db2.exec("CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active)");
      console.log("\u2705 Campo last_login_at removido de users");
    }
  },
  {
    version: 11,
    name: "add_roles_is_active_field",
    up: async (db2) => {
      db2.exec(`
        ALTER TABLE roles ADD COLUMN is_active BOOLEAN DEFAULT 1
      `);
      console.log("\u2705 Campo is_active agregado a roles");
    },
    down: async (db2) => {
      db2.exec(`
        CREATE TABLE roles_backup AS SELECT id, name, description, created_at FROM roles;
        DROP TABLE roles;
        CREATE TABLE roles (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          name TEXT UNIQUE NOT NULL,
          description TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO roles SELECT * FROM roles_backup;
        DROP TABLE roles_backup;
      `);
      db2.exec("CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name)");
      console.log("\u2705 Campo is_active removido de roles");
    }
  }
];
async function getCurrentVersion() {
  try {
    const db2 = getDatabase();
    const result = db2.query("SELECT MAX(version) as version FROM migration_history").get();
    return result?.version || 0;
  } catch (error) {
    return 0;
  }
}
async function recordMigration(version, name) {
  const db2 = getDatabase();
  db2.query("INSERT INTO migration_history (version, name) VALUES (?, ?)").run(version, name);
}
async function runMigrations() {
  console.log("\uD83D\uDD04 Iniciando migraciones...");
  const db2 = getDatabase();
  db2.exec(`
    CREATE TABLE IF NOT EXISTS migration_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      version INTEGER UNIQUE NOT NULL,
      name TEXT NOT NULL,
      executed_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  const currentVersion = await getCurrentVersion();
  console.log(`\uD83D\uDCCA Versi\xF3n actual de la base de datos: ${currentVersion}`);
  const pendingMigrations = migrations.filter((m) => m.version > currentVersion);
  if (pendingMigrations.length === 0) {
    console.log("\u2705 No hay migraciones pendientes");
    return;
  }
  console.log(`\uD83D\uDCCB ${pendingMigrations.length} migraciones pendientes`);
  try {
    db2.exec("BEGIN TRANSACTION");
    for (const migration of pendingMigrations) {
      console.log(`\u26A1 Ejecutando migraci\xF3n ${migration.version}: ${migration.name}`);
      await migration.up(db2);
      if (migration.name !== "create_migration_history_table") {
        await recordMigration(migration.version, migration.name);
      }
      console.log(`\u2705 Migraci\xF3n ${migration.version} completada`);
    }
    db2.exec("COMMIT");
    console.log("\uD83C\uDF89 Todas las migraciones completadas exitosamente");
  } catch (error) {
    db2.exec("ROLLBACK");
    console.error("\u274C Error durante las migraciones:", error);
    throw error;
  }
}
async function rollbackMigrations(targetVersion) {
  console.log(`\uD83D\uDD04 Revirtiendo migraciones hasta la versi\xF3n ${targetVersion}...`);
  const db2 = getDatabase();
  const currentVersion = await getCurrentVersion();
  if (targetVersion >= currentVersion) {
    console.log("\u2705 No hay migraciones para revertir");
    return;
  }
  const migrationsToRollback = migrations.filter((m) => m.version > targetVersion && m.version <= currentVersion).sort((a, b) => b.version - a.version);
  console.log(`\uD83D\uDCCB ${migrationsToRollback.length} migraciones a revertir`);
  try {
    db2.exec("BEGIN TRANSACTION");
    for (const migration of migrationsToRollback) {
      console.log(`\u26A1 Revirtiendo migraci\xF3n ${migration.version}: ${migration.name}`);
      await migration.down(db2);
      db2.query("DELETE FROM migration_history WHERE version = ?").run(migration.version);
      console.log(`\u2705 Migraci\xF3n ${migration.version} revertida`);
    }
    db2.exec("COMMIT");
    console.log("\uD83C\uDF89 Rollback completado exitosamente");
  } catch (error) {
    db2.exec("ROLLBACK");
    console.error("\u274C Error durante el rollback:", error);
    throw error;
  }
}
async function getMigrationStatus() {
  const currentVersion = await getCurrentVersion();
  const availableVersion = Math.max(...migrations.map((m) => m.version));
  const pendingMigrations = migrations.filter((m) => m.version > currentVersion).length;
  const executedMigrations = migrations.filter((m) => m.version <= currentVersion);
  return {
    currentVersion,
    availableVersion,
    pendingMigrations,
    executedMigrations
  };
}
async function resetDatabase() {
  console.log("\uD83D\uDD04 Reseteando base de datos...");
  const db2 = getDatabase();
  try {
    db2.exec("BEGIN TRANSACTION");
    const allMigrations = [...migrations].reverse();
    for (const migration of allMigrations) {
      try {
        await migration.down(db2);
      } catch (error) {
        console.warn(`\u26A0\uFE0F Error al revertir ${migration.name}:`, error);
      }
    }
    db2.exec("DROP TABLE IF EXISTS migration_history");
    db2.exec("COMMIT");
    console.log("\u2705 Base de datos reseteada");
    await runMigrations();
  } catch (error) {
    db2.exec("ROLLBACK");
    console.error("\u274C Error al resetear la base de datos:", error);
    throw error;
  }
}

// src/scripts/seed.ts
var initialPermissions = [
  { name: "users.read", resource: "users", action: "read" },
  { name: "users.create", resource: "users", action: "create" },
  { name: "users.update", resource: "users", action: "update" },
  { name: "users.delete", resource: "users", action: "delete" },
  { name: "users.manage", resource: "users", action: "manage" },
  { name: "roles.read", resource: "roles", action: "read" },
  { name: "roles.create", resource: "roles", action: "create" },
  { name: "roles.update", resource: "roles", action: "update" },
  { name: "roles.delete", resource: "roles", action: "delete" },
  { name: "roles.manage", resource: "roles", action: "manage" },
  { name: "permissions.read", resource: "permissions", action: "read" },
  { name: "permissions.create", resource: "permissions", action: "create" },
  { name: "permissions.update", resource: "permissions", action: "update" },
  { name: "permissions.delete", resource: "permissions", action: "delete" },
  { name: "permissions.manage", resource: "permissions", action: "manage" },
  { name: "content.read", resource: "content", action: "read" },
  { name: "content.create", resource: "content", action: "create" },
  { name: "content.update", resource: "content", action: "update" },
  { name: "content.delete", resource: "content", action: "delete" },
  { name: "content.publish", resource: "content", action: "publish" },
  { name: "content.moderate", resource: "content", action: "moderate" },
  { name: "system.admin", resource: "system", action: "admin" },
  { name: "system.settings", resource: "system", action: "settings" },
  { name: "system.logs", resource: "system", action: "logs" },
  { name: "system.backup", resource: "system", action: "backup" },
  { name: "system.maintenance", resource: "system", action: "maintenance" },
  { name: "reports.view", resource: "reports", action: "view" },
  { name: "reports.create", resource: "reports", action: "create" },
  { name: "reports.export", resource: "reports", action: "export" },
  { name: "api.read", resource: "api", action: "read" },
  { name: "api.write", resource: "api", action: "write" },
  { name: "api.admin", resource: "api", action: "admin" }
];
var initialRoles = [
  {
    name: "admin",
    description: "Administrador del sistema con acceso completo",
    permissions: [
      "users.manage",
      "roles.manage",
      "permissions.manage",
      "content.read",
      "content.create",
      "content.update",
      "content.delete",
      "content.publish",
      "content.moderate",
      "system.admin",
      "system.settings",
      "system.logs",
      "system.backup",
      "system.maintenance",
      "reports.view",
      "reports.create",
      "reports.export",
      "api.admin"
    ]
  },
  {
    name: "moderator",
    description: "Moderador con permisos de gesti\xF3n de contenido",
    permissions: [
      "users.read",
      "users.update",
      "content.read",
      "content.create",
      "content.update",
      "content.delete",
      "content.moderate",
      "reports.view",
      "api.read",
      "api.write"
    ]
  },
  {
    name: "editor",
    description: "Editor con permisos de creaci\xF3n y edici\xF3n de contenido",
    permissions: [
      "content.read",
      "content.create",
      "content.update",
      "content.publish",
      "api.read",
      "api.write"
    ]
  },
  {
    name: "author",
    description: "Autor con permisos b\xE1sicos de creaci\xF3n de contenido",
    permissions: [
      "content.read",
      "content.create",
      "content.update",
      "api.read"
    ]
  },
  {
    name: "user",
    description: "Usuario b\xE1sico con permisos de lectura",
    permissions: [
      "content.read",
      "api.read"
    ]
  },
  {
    name: "guest",
    description: "Invitado con acceso muy limitado",
    permissions: [
      "content.read"
    ]
  }
];
var initialUsers = [
  {
    email: "admin@example.com",
    password: "Admin123!@#",
    firstName: "System",
    lastName: "Administrator",
    roles: ["admin"]
  },
  {
    email: "moderator@example.com",
    password: "Moderator123!",
    firstName: "Content",
    lastName: "Moderator",
    roles: ["moderator"]
  },
  {
    email: "editor@example.com",
    password: "Editor123!",
    firstName: "Content",
    lastName: "Editor",
    roles: ["editor"]
  },
  {
    email: "author@example.com",
    password: "Author123!",
    firstName: "Content",
    lastName: "Author",
    roles: ["author"]
  },
  {
    email: "user@example.com",
    password: "User123!",
    firstName: "Regular",
    lastName: "User",
    roles: ["user"]
  }
];
async function seedDatabase() {
  try {
    console.log("\uD83C\uDF31 Iniciando seeding de la base de datos...");
    initDatabase();
    await runMigrations();
    const permissionService = new PermissionService;
    const authService = new AuthService;
    console.log("\uD83D\uDCDD Creando permisos iniciales...");
    const createdPermissions = new Map;
    for (const permission of initialPermissions) {
      try {
        const result = await permissionService.createPermission(permission);
        if (result && result.role) {
          createdPermissions.set(permission.name, result.role.id);
        }
      } catch (error) {
        console.log(`  \u26A0\uFE0F  Permiso ya existe: ${permission.name}`);
      }
    }
    console.log("\uD83D\uDC65 Creando roles iniciales...");
    const createdRoles = new Map;
    for (const role of initialRoles) {
      try {
        const result = await permissionService.createRole({
          name: role.name,
          description: role.description
        });
        if (result && result.role) {
          createdRoles.set(role.name, result.role?.id);
          for (const permissionName of role.permissionIds || []) {
            const permissionId = createdPermissions.get(permissionName);
            if (permissionId) {
              await permissionService.assignPermissionsToRole(result.role?.id, [permissionId]);
            }
          }
        }
      } catch (error) {
        console.log(`  \u26A0\uFE0F  Rol ya existe: ${role.name}`);
      }
    }
    console.log("\uD83D\uDC64 Creando usuarios iniciales...");
    for (const user of initialUsers) {
      try {
        const result = await authService.register({
          email: user.email,
          password: user.password
        });
        if (result) {
          console.log(`  \u2705 Usuario creado: ${user.email}`);
          for (const roleName of user.roles) {
            const roleId = createdRoles.get(roleName);
            if (roleId && result.user) {
              await permissionService.assignRoleToUser({
                roleId,
                userId: result.user?.id
              });
            }
          }
          console.log(`    \uD83C\uDFAD Roles asignados al usuario ${user.email}`);
        }
      } catch (error) {
        console.log(`  \u26A0\uFE0F  Usuario ya existe: ${user.email}`);
        if (true) {}
      }
    }
    console.log("\u2728 Seeding completado exitosamente!");
    console.log(`
\uD83D\uDCCA Resumen:`);
    console.log(`  - Permisos: ${initialPermissions.length}`);
    console.log(`  - Roles: ${initialRoles.length}`);
    console.log(`  - Usuarios: ${initialUsers.length}`);
    console.log(`
\uD83D\uDD10 Credenciales de acceso:`);
    console.log("  Admin: admin@example.com / Admin123!@#");
    console.log("  Moderator: moderator@example.com / Moderator123!");
    console.log("  Editor: editor@example.com / Editor123!");
    console.log("  Author: author@example.com / Author123!");
    console.log("  User: user@example.com / User123!");
  } catch (error) {
    console.error("\u274C Error durante el seeding:", error);
    if (true) {
      throw error;
    }
  }
}
async function cleanDatabase() {
  console.log("\uD83E\uDDF9 Limpiando base de datos...");
  try {
    if (!isDatabaseInitialized()) {
      initDatabase("./test.db");
    }
    let db2 = getDatabase();
    try {
      db2.exec("PRAGMA foreign_keys = OFF");
    } catch (error) {
      if (error instanceof Error && (error.message.includes("Database has closed") || error.message.includes("Cannot use a closed database"))) {
        console.log("\uD83D\uDD04 Database was closed during operation, force reinitializing...");
        db2 = forceReinitDatabase();
        db2.exec("PRAGMA foreign_keys = OFF");
      } else {
        throw error;
      }
    }
    const tables = [
      "user_roles",
      "role_permissions",
      "sessions",
      "users",
      "roles",
      "permissions"
    ];
    for (const table of tables) {
      try {
        db2.exec(`DELETE FROM ${table}`);
      } catch (error) {
        console.log(`  \u26A0\uFE0F  Error limpiando tabla ${table}:`, error);
      }
    }
    db2.exec("PRAGMA foreign_keys = ON");
    console.log("\u2705 Base de datos limpiada correctamente");
  } catch (error) {
    console.error("\u274C Error durante la limpieza:", error);
    if (true) {
      throw error;
    }
  }
}
async function resetDatabase2() {
  try {
    console.log("\uD83D\uDD04 Reseteando base de datos...");
    await cleanDatabase();
    await seedDatabase();
    console.log("\u2728 Base de datos reseteada exitosamente!");
  } catch (error) {
    console.error("\u274C Error durante el reseteo:", error);
    throw error;
  }
}
async function checkDatabaseStatus() {
  try {
    console.log("\uD83D\uDD0D Verificando estado de la base de datos...");
    const db2 = getDatabase();
    const tables = ["users", "roles", "permissions", "user_roles", "role_permissions", "sessions"];
    console.log(`
\uD83D\uDCCA Estado actual:`);
    for (const table of tables) {
      try {
        const result = db2.query(`SELECT COUNT(*) as count FROM ${table}`).get();
        console.log(`  ${table}: ${result.count} registros`);
      } catch (error) {
        console.log(`  ${table}: Tabla no existe`);
      }
    }
    try {
      const usersWithRoles = db2.query(`
        SELECT u.email, GROUP_CONCAT(r.name) as roles
        FROM users u
        LEFT JOIN user_roles ur ON u.id = ur.user_id
        LEFT JOIN roles r ON ur.role_id = r.id
        GROUP BY u.id, u.email
        ORDER BY u.email
      `).all();
      if (usersWithRoles.length > 0) {
        console.log(`
\uD83D\uDC65 Usuarios y sus roles:`);
        usersWithRoles.forEach((user) => {
          console.log(`  ${user.email}: ${user.roles || "Sin roles"}`);
        });
      }
    } catch (error) {
      console.log("  \u26A0\uFE0F  No se pudieron obtener usuarios con roles");
    }
  } catch (error) {
    console.error("\u274C Error verificando estado:", error);
    throw error;
  }
}
async function main() {
  const command = process.argv[2];
  switch (command) {
    case "seed":
      await seedDatabase();
      break;
    case "clean":
      await cleanDatabase();
      break;
    case "reset":
      await resetDatabase2();
      break;
    case "status":
      await checkDatabaseStatus();
      break;
    default:
      console.log("Uso: bun run src/scripts/seed.ts [seed|clean|reset|status]");
      console.log("  seed   - Poblar base de datos con datos iniciales");
      console.log("  clean  - Limpiar todos los datos");
      console.log("  reset  - Limpiar y volver a poblar");
      console.log("  status - Verificar estado actual");
  }
}
if (process.argv[1] && process.argv[1].endsWith("seed.ts") && true) {
  main().catch(console.error);
}

// src/adapters/hono.ts
function honoAuthMiddleware(config = {}) {
  return async (c, next) => {
    try {
      if (config.skipPaths && config.skipPaths.includes(c.req.path)) {
        c.set("auth", createEmptyAuthContext());
        await next();
        return;
      }
      const headers = {};
      c.req.raw.headers.forEach((value, key) => {
        headers[key] = value;
      });
      const authRequest = {
        headers
      };
      const result = await authenticateRequest(authRequest, config);
      if (!result.success) {
        logAuthEvent("auth.failed", undefined, {
          path: c.req.path,
          method: c.req.method,
          ip: extractClientIP(authRequest.headers),
          userAgent: extractUserAgent(authRequest.headers),
          error: result.error
        });
        return c.json({
          error: result.error,
          timestamp: new Date().toISOString()
        }, result.statusCode || 401);
      }
      c.set("auth", result.context);
      if (result.context?.user) {
        logAuthEvent("auth.success", result.context.user.id, {
          path: c.req.path,
          method: c.req.method,
          ip: extractClientIP(authRequest.headers),
          userAgent: extractUserAgent(authRequest.headers)
        });
      }
      await next();
    } catch (error) {
      console.error("Hono auth middleware error:", error);
      return c.json({
        error: "Internal authentication error",
        timestamp: new Date().toISOString()
      }, 500);
    }
  };
}
function honoOptionalAuth() {
  return honoAuthMiddleware({ required: false });
}
function honoRequireAuth() {
  return honoAuthMiddleware({ required: true });
}
function honoRequirePermissions(permissions, requireAll = false) {
  return honoAuthMiddleware({
    required: true,
    permissions,
    permissionOptions: { requireAll }
  });
}
function honoRequireRoles(roles) {
  return async (c, next) => {
    const authContext = c.get("auth");
    if (!authContext?.user) {
      return c.json({
        error: "Authentication required",
        timestamp: new Date().toISOString()
      }, 401);
    }
    const userRoles = authContext.user.roles.map((role) => role.name);
    const hasRequiredRole = roles.some((role) => userRoles.includes(role));
    if (!hasRequiredRole) {
      logAuthEvent("auth.insufficient_roles", authContext.user.id, {
        requiredRoles: roles,
        userRoles,
        path: c.req.path
      });
      return c.json({
        error: `Insufficient roles. Required: ${roles.join(", ")}`,
        timestamp: new Date().toISOString()
      }, 403);
    }
    await next();
  };
}
function honoRequireAdmin() {
  return honoRequireRoles(["admin", "administrator"]);
}
function honoRequireModerator() {
  return honoRequireRoles(["moderator", "admin", "administrator"]);
}
function getHonoCurrentUser(c) {
  const authContext = c.get("auth");
  return getCurrentUser(authContext);
}
function isHonoAuthenticated(c) {
  const authContext = c.get("auth");
  return !!authContext?.user;
}
function getHonoAuthContext(c) {
  return c.get("auth") || createEmptyAuthContext();
}
function honoRequireOwnership(getUserIdFromParams) {
  return async (c, next) => {
    const authContext = c.get("auth");
    if (!authContext?.user) {
      return c.json({
        error: "Authentication required",
        timestamp: new Date().toISOString()
      }, 401);
    }
    const resourceUserId = getUserIdFromParams(c);
    const isOwner = authContext.user.id === resourceUserId;
    const isAdmin = authContext.user.roles.some((role) => ["admin", "administrator"].includes(role.name));
    if (!isOwner && !isAdmin) {
      logAuthEvent("auth.insufficient_ownership", authContext.user.id, {
        resourceUserId,
        path: c.req.path
      });
      return c.json({
        error: "Insufficient permissions. You can only access your own resources.",
        timestamp: new Date().toISOString()
      }, 403);
    }
    await next();
  };
}
function honoRateLimit(maxRequests = 100, windowMs = 15 * 60 * 1000) {
  const requests = new Map;
  return async (c, next) => {
    const authContext = c.get("auth");
    const headers = {};
    c.req.raw.headers.forEach((value, key) => {
      headers[key] = value;
    });
    const clientId = authContext?.user?.id || extractClientIP(headers);
    const now = Date.now();
    const clientData = requests.get(clientId);
    if (!clientData || now > clientData.resetTime) {
      requests.set(clientId, {
        count: 1,
        resetTime: now + windowMs
      });
    } else {
      clientData.count++;
      if (clientData.count > maxRequests) {
        return c.json({
          error: "Rate limit exceeded",
          retryAfter: Math.ceil((clientData.resetTime - now) / 1000),
          timestamp: new Date().toISOString()
        }, 429);
      }
    }
    await next();
  };
}
function honoCorsAuth(origins = ["*"]) {
  return async (c, next) => {
    const origin = c.req.header("origin");
    if (origins.includes("*") || origin && origins.includes(origin)) {
      c.header("Access-Control-Allow-Origin", origin || "*");
      c.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
      c.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
      c.header("Access-Control-Allow-Credentials", "true");
    }
    if (c.req.method === "OPTIONS") {
      return c.text("", 204);
    }
    await next();
  };
}
function honoErrorResponse(c, error, statusCode = 400) {
  return c.json({
    error,
    timestamp: new Date().toISOString(),
    path: c.req.path,
    method: c.req.method
  }, statusCode);
}
function honoSuccessResponse(c, data, message, statusCode = 200) {
  const response = {
    success: true,
    data,
    timestamp: new Date().toISOString()
  };
  if (message) {
    response.message = message;
  }
  return c.json(response, statusCode);
}
function honoAuthLogger() {
  return async (c, next) => {
    const start = Date.now();
    const authContext = c.get("auth");
    await next();
    const duration = Date.now() - start;
    const headers = {};
    c.req.raw.headers.forEach((value, key) => {
      headers[key] = value;
    });
    const logData = {
      method: c.req.method,
      path: c.req.path,
      status: c.res.status,
      duration: `${duration}ms`,
      userId: authContext?.user?.id,
      ip: extractClientIP(headers),
      userAgent: extractUserAgent(headers)
    };
    console.log(`\uD83D\uDCDD Request: ${JSON.stringify(logData)}`);
  };
}

// src/adapters/express.ts
function expressAuthMiddleware(config = {}) {
  return async (req, res, next) => {
    try {
      if (config.skipPaths && config.skipPaths.includes(req.path)) {
        req.auth = createEmptyAuthContext();
        return next();
      }
      const authRequest = {
        headers: req.headers
      };
      const result = await authenticateRequest(authRequest, config);
      if (!result.success) {
        logAuthEvent("auth.failed", undefined, {
          path: req.path,
          method: req.method,
          ip: extractClientIP(authRequest.headers),
          userAgent: extractUserAgent(authRequest.headers),
          error: result.error
        });
        return res.status(result.statusCode || 401).json({
          error: result.error,
          timestamp: new Date().toISOString()
        });
      }
      req.auth = result.context;
      if (result.context?.user) {
        logAuthEvent("auth.success", result.context.user.id, {
          path: req.path,
          method: req.method,
          ip: extractClientIP(authRequest.headers),
          userAgent: extractUserAgent(authRequest.headers)
        });
      }
      next();
    } catch (error) {
      console.error("Express auth middleware error:", error);
      return res.status(500).json({
        error: "Internal authentication error",
        timestamp: new Date().toISOString()
      });
    }
  };
}
function expressOptionalAuth() {
  return expressAuthMiddleware({ required: false });
}
function expressRequireAuth() {
  return expressAuthMiddleware({ required: true });
}
function expressRequirePermissions(permissions, requireAll = false) {
  return expressAuthMiddleware({
    required: true,
    permissions,
    permissionOptions: { requireAll }
  });
}
function expressRequireRoles(roles) {
  return (req, res, next) => {
    const authContext = req.auth;
    if (!authContext?.user) {
      return res.status(401).json({
        error: "Authentication required",
        timestamp: new Date().toISOString()
      });
    }
    const userRoles = authContext.user.roles.map((role) => role.name);
    const hasRequiredRole = roles.some((role) => userRoles.includes(role));
    if (!hasRequiredRole) {
      logAuthEvent("auth.insufficient_roles", authContext.user.id, {
        requiredRoles: roles,
        userRoles,
        path: req.path
      });
      return res.status(403).json({
        error: `Insufficient roles. Required: ${roles.join(", ")}`,
        timestamp: new Date().toISOString()
      });
    }
    next();
  };
}
function expressRequireAdmin() {
  return expressRequireRoles(["admin", "administrator"]);
}
function expressRequireModerator() {
  return expressRequireRoles(["moderator", "admin", "administrator"]);
}
function getExpressCurrentUser(req) {
  return getCurrentUser(req.auth);
}
function isExpressAuthenticated(req) {
  return !!req.auth?.user;
}
function getExpressAuthContext(req) {
  return req.auth || createEmptyAuthContext();
}
function expressRequireOwnership(getUserIdFromParams) {
  return (req, res, next) => {
    const authContext = req.auth;
    if (!authContext?.user) {
      return res.status(401).json({
        error: "Authentication required",
        timestamp: new Date().toISOString()
      });
    }
    const resourceUserId = getUserIdFromParams(req);
    const isOwner = authContext.user.id === resourceUserId;
    const isAdmin = authContext.user.roles.some((role) => ["admin", "administrator"].includes(role.name));
    if (!isOwner && !isAdmin) {
      logAuthEvent("auth.insufficient_ownership", authContext.user.id, {
        resourceUserId,
        path: req.path
      });
      return res.status(403).json({
        error: "Insufficient permissions. You can only access your own resources.",
        timestamp: new Date().toISOString()
      });
    }
    next();
  };
}
function expressRateLimit(maxRequests = 100, windowMs = 15 * 60 * 1000) {
  const requests = new Map;
  return (req, res, next) => {
    const authContext = req.auth;
    const clientId = authContext?.user?.id || extractClientIP(req.headers);
    const now = Date.now();
    const clientData = requests.get(clientId);
    if (!clientData || now > clientData.resetTime) {
      requests.set(clientId, {
        count: 1,
        resetTime: now + windowMs
      });
    } else {
      clientData.count++;
      if (clientData.count > maxRequests) {
        return res.status(429).json({
          error: "Rate limit exceeded",
          retryAfter: Math.ceil((clientData.resetTime - now) / 1000),
          timestamp: new Date().toISOString()
        });
      }
    }
    next();
  };
}
function expressCorsAuth(origins = ["*"]) {
  return (req, res, next) => {
    const origin = req.headers.origin;
    const originStr = Array.isArray(origin) ? origin[0] : origin;
    if (origins.includes("*") || originStr && origins.includes(originStr)) {
      res.header("Access-Control-Allow-Origin", originStr || "*");
      res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
      res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
      res.header("Access-Control-Allow-Credentials", "true");
    }
    if (req.method === "OPTIONS") {
      return res.sendStatus(204);
    }
    next();
  };
}
function expressErrorResponse(res, error, statusCode = 400) {
  return res.status(statusCode).json({
    error,
    timestamp: new Date().toISOString()
  });
}
function expressSuccessResponse(res, data, message, statusCode = 200) {
  const response = {
    success: true,
    data,
    timestamp: new Date().toISOString()
  };
  if (message) {
    response.message = message;
  }
  return res.status(statusCode).json(response);
}
function expressAuthLogger() {
  return (req, res, next) => {
    const start = Date.now();
    const authContext = req.auth;
    res.on("finish", () => {
      const duration = Date.now() - start;
      const logData = {
        method: req.method,
        path: req.path,
        status: res.statusCode,
        duration: `${duration}ms`,
        userId: authContext?.user?.id,
        ip: extractClientIP(req.headers),
        userAgent: extractUserAgent(req.headers)
      };
      console.log(`\uD83D\uDCDD Request: ${JSON.stringify(logData)}`);
    });
    next();
  };
}
function expressAuthErrorHandler() {
  return (error, req, res, next) => {
    console.error("Express auth error:", error);
    const authContext = req.auth;
    logAuthEvent("auth.error", authContext?.user?.id, {
      error: error.message,
      stack: error.stack,
      path: req.path,
      method: req.method
    });
    let statusCode = 500;
    let message = "Internal server error";
    if (error.name === "ValidationError") {
      statusCode = 400;
      message = "Validation error";
    } else if (error.name === "UnauthorizedError") {
      statusCode = 401;
      message = "Unauthorized";
    } else if (error.name === "ForbiddenError") {
      statusCode = 403;
      message = "Forbidden";
    }
    res.status(statusCode).json({
      error: message,
      timestamp: new Date().toISOString(),
      ...{ details: error.message }
    });
  };
}
function expressJsonValidator() {
  return (req, res, next) => {
    if (req.headers["content-type"]?.includes("application/json")) {
      try {
        if (req.body && typeof req.body === "string") {
          req.body = JSON.parse(req.body);
        }
      } catch (error) {
        return res.status(400).json({
          error: "Invalid JSON format",
          timestamp: new Date().toISOString()
        });
      }
    }
    next();
  };
}
function expressSanitizer() {
  return (req, res, next) => {
    if (req.query) {
      for (const key in req.query) {
        if (typeof req.query[key] === "string") {
          req.query[key] = req.query[key].replace(/<script[^>]*>.*?<\/script>/gi, "").replace(/<[^>]*>/g, "").trim();
        }
      }
    }
    if (req.body && typeof req.body === "object") {
      sanitizeObject(req.body);
    }
    next();
  };
}
function sanitizeObject(obj) {
  for (const key in obj) {
    if (typeof obj[key] === "string") {
      obj[key] = obj[key].replace(/<script[^>]*>.*?<\/script>/gi, "").replace(/<[^>]*>/g, "").trim();
    } else if (typeof obj[key] === "object" && obj[key] !== null) {
      sanitizeObject(obj[key]);
    }
  }
}
// src/scripts/dev.ts
var DEV_CONFIG2 = {
  jwtSecret: "dev-secret-key-change-in-production",
  jwtExpiration: "1h",
  refreshTokenExpiration: "7d"
};
var COMMANDS = {
  "db:init": "Inicializar base de datos",
  "db:migrate": "Ejecutar migraciones",
  "db:rollback": "Revertir migraciones",
  "db:status": "Estado de migraciones",
  "db:seed": "Poblar con datos iniciales",
  "db:clean": "Limpiar datos",
  "db:reset": "Resetear completamente",
  "db:check": "Verificar estado",
  "user:create": "Crear usuario",
  "user:list": "Listar usuarios",
  "user:roles": "Asignar roles a usuario",
  "user:delete": "Eliminar usuario",
  "role:create": "Crear rol",
  "role:list": "Listar roles",
  "role:get": "Obtener rol por nombre",
  "permission:create": "Crear permiso",
  "permission:list": "Listar permisos",
  "jwt:generate": "Generar token JWT",
  "jwt:verify": "Verificar token JWT",
  help: "Mostrar ayuda",
  "test:auth": "Probar autenticaci\xF3n",
  "test:permissions": "Probar permisos"
};
async function runDevCommand(command, ...args) {
  try {
    console.log(`\uD83D\uDE80 Ejecutando comando: ${command}`);
    switch (command) {
      case "db:init":
        initDatabase();
        console.log("\u2705 Base de datos inicializada");
        break;
      case "db:migrate":
        await runMigrations();
        console.log("\u2705 Migraciones ejecutadas");
        break;
      case "db:rollback":
        const version = args[0] ? parseInt(args[0]) : 0;
        await rollbackMigrations(version);
        console.log("\u2705 Migraciones revertidas");
        break;
      case "db:status":
        const data = await getMigrationStatus();
        console.log("\uD83D\uDCCA Estado de migraciones:");
        data.executedMigrations.forEach((migration) => {
          const status = migration ? "\u2705" : "\u23F3";
          console.log(`  ${status} ${migration.version}: ${migration.name}`);
        });
        break;
      case "db:seed":
        await seedDatabase();
        break;
      case "db:clean":
        await cleanDatabase();
        break;
      case "db:reset":
        await resetDatabase2();
        break;
      case "db:check":
        await checkDatabaseStatus();
        break;
      case "user:create":
        await createUser(args);
        break;
      case "user:list":
        await listUsers();
        break;
      case "user:roles":
        await assignUserRoles(args);
        break;
      case "user:delete":
        await deleteUser(args[0]);
        break;
      case "role:create":
        await createRole(args);
        break;
      case "role:list":
        await listRoles();
        break;
      case "role:get":
        await getRoleByName(args);
        break;
      case "permission:create":
        await createPermission(args);
        break;
      case "permission:list":
        await listPermissions();
        break;
      case "jwt:generate":
        await generateJWT(args);
        break;
      case "jwt:verify":
        await verifyJWT(args[0]);
        break;
      case "test:auth":
        await testAuthentication();
        break;
      case "test:permissions":
        await testPermissions();
        break;
      case "help":
      default:
        showHelp();
        break;
    }
  } catch (error) {
    console.error(`\u274C Error ejecutando comando ${command}:`, error);
  }
}
async function createUser(args) {
  if (args.length < 4) {
    console.log("Uso: user:create <email> <password> <firstName> <lastName> [roles...]");
    return;
  }
  const [email, password, firstName, lastName, ...roles] = args;
  const authService = new AuthService;
  const permissionService = new PermissionService;
  const result = await authService.register({
    email,
    password,
    firstName,
    lastName
  });
  if (!result || !result.user) {
    console.error("\u274C Error creando usuario:", result);
    return;
  }
  console.log(`\u2705 Usuario creado: ${email} (ID: ${result.user.id})`);
  if (roles.length > 0) {
    for (const roleName of roles) {
      try {
        const role = await permissionService.findRoleByName(roleName);
        if (role) {
          await permissionService.assignRoleToUser({ userId: result.user.id, roleId: role.id });
          console.log(`  \uD83C\uDFAD Rol asignado: ${roleName}`);
        }
      } catch (error) {
        console.log(`  \u26A0\uFE0F  No se pudo asignar rol: ${roleName}`);
      }
    }
  }
}
async function listUsers() {
  const db2 = getDatabase();
  const users = db2.query(`
    SELECT 
      u.id,
      u.email,
      u.first_name,
      u.last_name,
      u.is_active,
      u.created_at,
      GROUP_CONCAT(r.name) as roles
    FROM users u
    LEFT JOIN user_roles ur ON u.id = ur.user_id
    LEFT JOIN roles r ON ur.role_id = r.id
    GROUP BY u.id
    ORDER BY u.created_at DESC
  `).all();
  if (users.length === 0) {
    console.log("\uD83D\uDCED No hay usuarios registrados");
    return;
  }
  console.log("\uD83D\uDC65 Usuarios registrados:");
  users.forEach((user) => {
    const status = user.is_active ? "\uD83D\uDFE2" : "\uD83D\uDD34";
    console.log(`  ${status} ${user.email} (${user.first_name} ${user.last_name})`);
    console.log(`    ID: ${user.id}`);
    console.log(`    Roles: ${user.roles || "Sin roles"}`);
    console.log(`    Creado: ${new Date(user.created_at).toLocaleString()}`);
    console.log("");
  });
}
async function assignUserRoles(args) {
  if (args.length < 2) {
    console.log("Uso: user:roles <email> <role1> [role2] [role3]...");
    return;
  }
  const [email, ...roles] = args;
  const authService = new AuthService;
  const permissionService = new PermissionService;
  const user = await authService.findUserByEmail(email);
  if (!user) {
    console.error(`\u274C Usuario no encontrado: ${email}`);
    return;
  }
  console.log(`\uD83D\uDC64 Asignando roles al usuario: ${email}`);
  for (const roleName of roles) {
    try {
      const role = await permissionService.findRoleByName(roleName);
      if (role) {
        await permissionService.assignRoleToUser({ userId: user.id, roleId: role.id });
        console.log(`  \u2705 Rol asignado: ${roleName}`);
      } else {
        console.log(`  \u274C Rol no encontrado: ${roleName}`);
      }
    } catch (error) {
      console.log(`  \u26A0\uFE0F  Error asignando rol ${roleName}:`, error);
    }
  }
}
async function deleteUser(email) {
  if (!email) {
    console.log("Uso: user:delete <email>");
    return;
  }
  const authService = new AuthService;
  const user = await authService.findUserByEmail(email);
  if (!user) {
    console.error(`\u274C Usuario no encontrado: ${email}`);
    return;
  }
  const db2 = getDatabase();
  db2.run("DELETE FROM user_roles WHERE user_id = ?", [user.id]);
  db2.run("DELETE FROM sessions WHERE user_id = ?", [user.id]);
  db2.run("DELETE FROM users WHERE id = ?", [user.id]);
  console.log(`\u2705 Usuario eliminado: ${email}`);
}
async function createRole(args) {
  if (args.length < 2) {
    console.log("Uso: role:create <name> <description> [permission1] [permission2]...");
    return;
  }
  const [name, description, ...permissions] = args;
  const permissionService = new PermissionService;
  const result = await permissionService.createRole({ name, description });
  if (!result.success || !result) {
    console.error("\u274C Error creando rol:", result.error);
    return;
  }
  if (permissions.length > 0) {
    for (const permissionName of permissions) {
      try {
        const permission = await permissionService.findPermissionByName(permissionName);
        if (permission) {
          await permissionService.assignPermissionToRole(result.role.id, permission.id);
          console.log(`  \uD83D\uDCCB Permiso asignado: ${permissionName}`);
        }
      } catch (error) {
        console.log(`  \u26A0\uFE0F  No se pudo asignar permiso: ${permissionName}`);
      }
    }
  }
}
async function getRoleByName(args) {
  if (args.length < 1) {
    console.log("Uso: role:get <name>");
    return;
  }
  const [name] = args;
  const permissionService = new PermissionService;
  try {
    const role = await permissionService.findRoleByName(name, true);
    if (!role) {
      console.error(`\u274C Rol no encontrado: ${name}`);
      return;
    }
    console.log("\uD83C\uDFAD Informaci\xF3n del rol:");
    console.log(`  \uD83D\uDCCB Nombre: ${role.name}`);
    console.log(`  \uD83C\uDD94 ID: ${role.id}`);
    console.log(`  \uD83D\uDCC5 Creado: ${new Date(role.created_at).toLocaleString()}`);
    if (role.permissions && role.permissions.length > 0) {
      console.log("  \uD83D\uDD10 Permisos:");
      role.permissions.forEach((permission) => {
        console.log(`    - ${permission.name} (${permission.resource}:${permission.action})`);
      });
    } else {
      console.log("  \uD83D\uDD10 Permisos: Sin permisos asignados");
    }
  } catch (error) {
    console.error(`\u274C Error obteniendo rol: ${error}`);
  }
}
async function listRoles() {
  const db2 = getDatabase();
  const roles = db2.query(`
    SELECT 
      r.id,
      r.name,
      r.description,
      r.created_at,
      GROUP_CONCAT(p.name) as permissions
    FROM roles r
    LEFT JOIN role_permissions rp ON r.id = rp.role_id
    LEFT JOIN permissions p ON rp.permission_id = p.id
    GROUP BY r.id
    ORDER BY r.name
  `).all();
  if (roles.length === 0) {
    console.log("\uD83D\uDCED No hay roles registrados");
    return;
  }
  console.log("\uD83C\uDFAD Roles registrados:");
  roles.forEach((role) => {
    console.log(`  \uD83D\uDCCB ${role.name}`);
    console.log(`    Descripci\xF3n: ${role.description}`);
    console.log(`    Permisos: ${role.permissions || "Sin permisos"}`);
    console.log(`    Creado: ${new Date(role.created_at).toLocaleString()}`);
    console.log("");
  });
}
async function createPermission(args) {
  if (args.length < 2) {
    console.log("Uso: permission:create <name> <description>");
    return;
  }
  const [name, description] = args;
  const permissionService = new PermissionService;
  const result = await permissionService.createPermission({ name, description });
  if (!result.success || !result) {
    console.error("\u274C Error creando permiso:", result.error);
    return;
  }
}
async function listPermissions() {
  const db2 = getDatabase();
  const permissions = db2.query(`
    SELECT id, name, description, created_at
    FROM permissions
    ORDER BY name
  `).all();
  if (permissions.length === 0) {
    console.log("\uD83D\uDCED No hay permisos registrados");
    return;
  }
  console.log("\uD83D\uDD10 Permisos registrados:");
  permissions.forEach((permission) => {
    console.log(`  \uD83D\uDCDD ${permission.name}`);
    console.log(`    Descripci\xF3n: ${permission.description}`);
    console.log(`    Creado: ${new Date(permission.created_at).toLocaleString()}`);
    console.log("");
  });
}
async function generateJWT(args) {
  if (args.length < 1) {
    console.log("Uso: jwt:generate <email>");
    return;
  }
  const email = args[0];
  const authService = new AuthService;
  const user = await authService.findUserByEmail(email, { includeRoles: true });
  if (!user) {
    console.error(`\u274C Usuario no encontrado: ${email}`);
    return;
  }
  const jwtService = new JWTService(DEV_CONFIG2.jwtSecret);
  const token = await jwtService.generateToken(user);
  const refreshToken = await jwtService.generateRefreshToken(Number(user.id));
  const payload = {
    userId: user.id,
    email: user.email,
    roles: user.roles?.map((r) => r.name) || []
  };
  console.log("\uD83C\uDFAB Tokens generados:");
  console.log(`Access Token: ${token}`);
  console.log(`Refresh Token: ${refreshToken}`);
  console.log(`
Payload: ${JSON.stringify(payload, null, 2)}`);
}
async function verifyJWT(token) {
  if (!token) {
    console.log("Uso: jwt:verify <token>");
    return;
  }
  const jwtService = new JWTService(DEV_CONFIG2.jwtSecret);
  try {
    const payload = jwtService.verifyToken(token);
    console.log("\u2705 Token v\xE1lido");
    console.log(`Payload: ${JSON.stringify(payload, null, 2)}`);
  } catch (error) {
    console.error("\u274C Token inv\xE1lido:", error);
  }
}
async function testAuthentication() {
  console.log("\uD83E\uDDEA Probando sistema de autenticaci\xF3n...");
  const authService = new AuthService;
  console.log(`
1. Probando registro...`);
  const registerResult = await authService.register({
    email: "test@example.com",
    password: "Test123!",
    firstName: "Test",
    lastName: "User"
  });
  if (registerResult.success) {
    console.log("\u2705 Registro exitoso");
  } else {
    console.log("\u26A0\uFE0F  Usuario ya existe o error en registro");
  }
  console.log(`
2. Probando login...`);
  const loginResult = await authService.login({
    email: "test@example.com",
    password: "Test123!"
  });
  if (loginResult.success && loginResult.token) {
    console.log("\u2705 Login exitoso");
    console.log(`Token: ${loginResult.token.substring(0, 50)}...`);
  } else {
    console.log("\u274C Error en login:", loginResult.error);
  }
  console.log(`
3. Probando login con credenciales incorrectas...`);
  const badLoginResult = await authService.login({
    email: "test@example.com",
    password: "WrongPassword"
  });
  if (!badLoginResult.success) {
    console.log("\u2705 Login rechazado correctamente");
  } else {
    console.log("\u274C Error: login deber\xEDa haber fallado");
  }
}
async function testPermissions() {
  console.log("\uD83E\uDDEA Probando sistema de permisos...");
  const permissionService = new PermissionService;
  console.log(`
1. Creando permiso de prueba...`);
  const permResult = await permissionService.createPermission({
    name: "test.permission",
    description: "Permiso de prueba"
  });
  if (permResult.success) {
    console.log("\u2705 Permiso creado");
  } else {
    console.log("\u26A0\uFE0F  Permiso ya existe");
  }
  console.log(`
2. Creando rol de prueba...`);
  const roleResult = await permissionService.createRole({
    name: "test.role",
    description: "Rol de prueba"
  });
  if (roleResult.success) {
    console.log("\u2705 Rol creado");
  } else {
    console.log("\u26A0\uFE0F  Rol ya existe");
  }
  console.log(`
\u2705 Pruebas de permisos completadas`);
}
function showHelp() {
  console.log("\uD83D\uDEE0\uFE0F  CLI de Desarrollo - Auth Library");
  console.log(`
Comandos disponibles:`);
  Object.entries(COMMANDS).forEach(([command, description]) => {
    console.log(`  ${command.padEnd(20)} - ${description}`);
  });
  console.log(`
Ejemplos:`);
  console.log("  bun run src/scripts/dev.ts db:reset");
  console.log("  bun run src/scripts/dev.ts user:create admin@test.com Admin123! Admin User admin");
  console.log("  bun run src/scripts/dev.ts jwt:generate admin@test.com");
}
if (false) {}

// src/index.ts
class AuthLibrary {
  authService;
  jwtService;
  permissionService;
  config;
  constructor(config) {
    this.config = getAuthConfig();
    if (config) {
      this.config = { ...this.config, ...config };
    }
    const validation = validateAuthConfig(this.config);
    if (!validation.valid) {
      throw new Error(`Configuraci\xF3n inv\xE1lida: ${validation.errors.join(", ")}`);
    }
    this.jwtService = new JWTService(this.config.jwtSecret);
    this.authService = new AuthService;
    this.permissionService = new PermissionService;
  }
  async initialize() {
    try {
      initDatabase();
      await runMigrations();
      console.log("\u2705 Auth Library inicializada correctamente");
    } catch (error) {
      console.error("\u274C Error inicializando Auth Library:", error);
      throw error;
    }
  }
  getAuthService() {
    return this.authService;
  }
  getJWTService() {
    return this.jwtService;
  }
  getPermissionService() {
    return this.permissionService;
  }
  getConfig() {
    return { ...this.config };
  }
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    const validation = validateAuthConfig(this.config);
    if (!validation.valid) {
      throw new Error(`Configuraci\xF3n inv\xE1lida: ${validation.errors.join(", ")}`);
    }
    if (newConfig.jwtSecret) {
      this.jwtService = new JWTService(this.config.jwtSecret);
    }
  }
  async seed() {
    await seedDatabase();
  }
  async clean() {
    await cleanDatabase();
  }
  async reset() {
    await resetDatabase2();
  }
  async checkStatus() {
    await checkDatabaseStatus();
  }
  async close() {
    closeDatabase();
    console.log("\u2705 Auth Library cerrada correctamente");
  }
}
var defaultInstance = null;
function getAuthLibrary(config) {
  if (!defaultInstance) {
    defaultInstance = new AuthLibrary(config);
  }
  return defaultInstance;
}
async function initializeAuth(config) {
  const library = getAuthLibrary(config);
  await library.initialize();
  return library;
}
function createHonoAuth(config) {
  const library = getAuthLibrary(config);
  return {
    middleware: honoAuthMiddleware,
    optional: honoOptionalAuth,
    required: honoRequireAuth,
    permissions: honoRequirePermissions,
    roles: honoRequireRoles,
    admin: honoRequireAdmin,
    moderator: honoRequireModerator,
    ownership: honoRequireOwnership,
    rateLimit: honoRateLimit,
    cors: honoCorsAuth,
    logger: honoAuthLogger,
    library
  };
}
function createExpressAuth(config) {
  const library = getAuthLibrary(config);
  return {
    middleware: expressAuthMiddleware,
    optional: expressOptionalAuth,
    required: expressRequireAuth,
    permissions: expressRequirePermissions,
    roles: expressRequireRoles,
    admin: expressRequireAdmin,
    moderator: expressRequireModerator,
    ownership: expressRequireOwnership,
    rateLimit: expressRateLimit,
    cors: expressCorsAuth,
    logger: expressAuthLogger,
    errorHandler: expressAuthErrorHandler,
    jsonValidator: expressJsonValidator,
    sanitizer: expressSanitizer,
    library
  };
}
function createWebSocketAuth(config) {
  const library = getAuthLibrary(config);
  return {
    authenticate: authenticateWebSocket,
    checkPermissions: checkWebSocketPermissions,
    checkRoles: checkWebSocketRoles,
    getCurrentUser: getWebSocketCurrentUser,
    isAuthenticated: isWebSocketAuthenticated,
    getAuthContext: getWebSocketAuthContext,
    sendToUser,
    sendToUsersWithPermissions,
    sendToUsersWithRoles,
    broadcast: broadcastToAuthenticated,
    getStats: getConnectionStats,
    disconnect: disconnectUser,
    cleanup: cleanupInactiveConnections,
    handleMessage: handleAuthenticatedMessage,
    createResponse: createWebSocketResponse,
    initCleanup: initializeConnectionCleanup,
    library
  };
}
var src_default = AuthLibrary;
var AUTH_LIBRARY_INFO = {
  name: "Framework-Agnostic Auth Library",
  version: "1.0.0",
  description: "Librer\xEDa de autenticaci\xF3n y permisos agn\xF3stica de framework con TypeScript, Bun y SQLite",
  author: "Auth Library Team",
  frameworks: ["Hono", "Express", "WebSockets", "Socket.IO", "Fastify"],
  features: [
    "Framework-agnostic",
    "TypeScript nativo",
    "SQLite con Bun",
    "JWT + Bun.password",
    "RBAC (Role-Based Access Control)",
    "Middlewares reutilizables",
    "Migraciones autom\xE1ticas",
    "Scripts de utilidad",
    "Configuraci\xF3n flexible",
    "Logging integrado",
    "Rate limiting",
    "CORS configurado",
    "Validaci\xF3n de entrada",
    "Sanitizaci\xF3n de datos"
  ]
};
console.log(`\uD83D\uDCDA ${AUTH_LIBRARY_INFO.name} v${AUTH_LIBRARY_INFO.version} cargada`);
export {
  validateAuthConfig,
  testConnection,
  sendToUsersWithRoles,
  sendToUsersWithPermissions,
  sendToUser,
  seedDatabase,
  runMigrations,
  runDevCommand,
  rollbackMigrations,
  resetDatabase as resetDatabaseMigrations,
  resetDatabase2 as resetDatabase,
  printConfig,
  logAuthEvent,
  isWebSocketAuthenticated,
  isHonoAuthenticated,
  isExpressAuthenticated,
  initializeConnectionCleanup,
  initializeAuth,
  initPermissionService,
  initJWTService,
  initDatabase,
  initAuthService,
  honoSuccessResponse,
  honoRequireRoles,
  honoRequirePermissions,
  honoRequireOwnership,
  honoRequireModerator,
  honoRequireAuth,
  honoRequireAdmin,
  honoRateLimit,
  honoOptionalAuth,
  honoErrorResponse,
  honoCorsAuth,
  honoAuthMiddleware,
  honoAuthLogger,
  handleAuthenticatedMessage,
  getWebSocketCurrentUser,
  getWebSocketAuthContext,
  getRequiredEnvVars,
  getMigrationStatus,
  getHonoCurrentUser,
  getHonoAuthContext,
  getExpressCurrentUser,
  getExpressAuthContext,
  getDatabaseInfo,
  getDatabase,
  getCurrentUser,
  getConnectionStats,
  getAuthService,
  getAuthLibrary,
  getAuthConfig,
  generateEnvExample,
  extractUserAgent,
  extractClientIP,
  expressSuccessResponse,
  expressSanitizer,
  expressRequireRoles,
  expressRequirePermissions,
  expressRequireOwnership,
  expressRequireModerator,
  expressRequireAuth,
  expressRequireAdmin,
  expressRateLimit,
  expressOptionalAuth,
  expressJsonValidator,
  expressErrorResponse,
  expressCorsAuth,
  expressAuthMiddleware,
  expressAuthLogger,
  expressAuthErrorHandler,
  disconnectUser,
  src_default as default,
  createWebSocketResponse,
  createWebSocketAuth,
  createHonoAuth,
  createExpressAuth,
  createEmptyAuthContext,
  closeDatabase,
  cleanupInactiveConnections,
  cleanDatabase,
  checkWebSocketRoles,
  checkWebSocketPermissions,
  checkDatabaseStatus,
  broadcastToAuthenticated,
  authorizeRequest,
  authenticateWebSocket,
  authenticateRequest,
  SECURITY_CONFIG,
  PermissionService,
  PROD_CONFIG,
  JWTService,
  DEV_CONFIG,
  DEFAULT_AUTH_CONFIG,
  AuthService,
  AuthLibrary,
  AUTH_LIBRARY_INFO
};

//# debugId=3BCE83FB3D30827E64756E2164756E21
//# sourceMappingURL=index.js.map
