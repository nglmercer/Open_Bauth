// @bun
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
    const parts = authHeader.trim().split(" ");
    if (parts.length !== 2 || parts[0].toLowerCase() !== "bearer") {
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
function getDatabase(dbPath) {
  if (!db) {
    console.log("\u26A0\uFE0F Database not initialized, auto-initializing with auth.db");
    initDatabase(dbPath);
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
      initDatabase(dbPath);
    } else {
      throw error;
    }
  }
  if (!db) {
    throw new Error("Failed to initialize database");
  }
  return db;
}
function forceReinitDatabase(dbPath) {
  console.log("\uD83D\uDD04 Force reinitializing database...");
  db = null;
  initDatabase(dbPath);
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

// src/errors/auth.ts
class AuthError extends Error {
  timestamp;
  context;
  constructor(message, context) {
    super(message);
    this.name = this.constructor.name;
    this.timestamp = new Date;
    this.context = context;
    Object.setPrototypeOf(this, new.target.prototype);
  }
  toResponse() {
    return {
      success: false,
      error: {
        type: this.type,
        message: this.message,
        timestamp: this.timestamp.toISOString(),
        ...this.context && { context: this.context }
      }
    };
  }
}

class ValidationError extends AuthError {
  type = "VALIDATION_ERROR" /* VALIDATION_ERROR */;
  constructor(message, field) {
    super(message, field ? { field } : undefined);
  }
}

class AuthenticationError extends AuthError {
  type = "AUTHENTICATION_ERROR" /* AUTHENTICATION_ERROR */;
  constructor(message = "Authentication failed", context) {
    super(message, context);
  }
}

class AuthorizationError extends AuthError {
  type = "AUTHORIZATION_ERROR" /* AUTHORIZATION_ERROR */;
  constructor(message = "Access denied", context) {
    super(message, context);
  }
}

class UserNotFoundError extends AuthError {
  type = "USER_NOT_FOUND" /* USER_NOT_FOUND */;
  constructor(identifier) {
    const message = identifier ? `User not found: ${identifier}` : "User not found";
    super(message, identifier ? { identifier } : undefined);
  }
}

class NotFoundError extends AuthError {
  type = "NOT_FOUND_ERROR" /* NOT_FOUND_ERROR */;
  constructor(resource, identifier) {
    const message = identifier ? `${resource} not found: ${identifier}` : `${resource} not found`;
    super(message, { resource, identifier });
  }
}

class DatabaseError extends AuthError {
  type = "DATABASE_ERROR" /* DATABASE_ERROR */;
  constructor(message = "Database operation failed", operation) {
    super(message, operation ? { operation } : undefined);
  }
}

class ServerError extends AuthError {
  type = "SERVER_ERROR" /* SERVER_ERROR */;
  constructor(message = "Internal server error", context) {
    super(message, context);
  }
}

class RateLimitError extends AuthError {
  type = "RATE_LIMIT_ERROR" /* RATE_LIMIT_ERROR */;
  retryAfter;
  constructor(message = "Rate limit exceeded", retryAfter) {
    super(message, retryAfter ? { retryAfter } : undefined);
    this.retryAfter = retryAfter;
  }
}

class TokenError extends AuthError {
  type = "TOKEN_ERROR" /* TOKEN_ERROR */;
  constructor(message = "Token error", context) {
    super(message, context);
  }
}

class AccountError extends AuthError {
  type = "ACCOUNT_ERROR" /* ACCOUNT_ERROR */;
  constructor(message, status) {
    super(message, status ? { status } : undefined);
  }
}

class AuthErrorFactory {
  static fromUnknown(error, defaultMessage = "Unknown error") {
    if (error instanceof AuthError) {
      return error;
    }
    if (error instanceof Error) {
      const message = error.message.toLowerCase();
      if (message.includes("user not found") || message.includes("user does not exist")) {
        return new UserNotFoundError;
      }
      if (message.includes("invalid credentials") || message.includes("authentication")) {
        return new AuthenticationError(error.message);
      }
      if (message.includes("validation") || message.includes("invalid") || message.includes("required") || message.includes("must be") || message.includes("cannot be") || message.includes("contains") || message.includes("format") || message.includes("characters long") || message.includes("email") && (message.includes("format") || message.includes("invalid"))) {
        return new ValidationError(error.message);
      }
      if (message.includes("database") || message.includes("sql")) {
        return new DatabaseError(error.message);
      }
      return new ServerError(error.message);
    }
    return new ServerError(defaultMessage, { originalError: String(error) });
  }
  static validation(message, field) {
    return new ValidationError(message, field);
  }
  static authentication(message) {
    return new AuthenticationError(message);
  }
  static userNotFound(identifier) {
    return new UserNotFoundError(identifier);
  }
  static database(message, operation) {
    return new DatabaseError(message, operation);
  }
  static rateLimit(message, retryAfter) {
    return new RateLimitError(message, retryAfter);
  }
  static server(message, context) {
    return new ServerError(message, context);
  }
}

class ErrorHandler {
  static handle(error, operation = "operation") {
    const authError = AuthErrorFactory.fromUnknown(error, `${operation} failed`);
    console.error(`[${operation}] ${authError.type}: ${authError.message}`, {
      stack: authError.stack,
      context: authError.context,
      timestamp: authError.timestamp
    });
    return authError.toResponse();
  }
  static isType(error, ErrorClass) {
    return error instanceof ErrorClass;
  }
  static getMessage(error) {
    if (error instanceof Error) {
      return error.message;
    }
    return String(error);
  }
}

// src/repositories/user.ts
class UserRepository {
  async findById(id, options = {}, transaction) {
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
      const user = this.mapDatabaseUserToSafeUser(userData);
      if (options.includeRoles) {
        user.roles = await this.getUserRoles(id, options.includePermissions, transaction);
      }
      return user;
    } catch (error) {
      throw new DatabaseError(`Failed to find user by ID: ${error instanceof Error ? error.message : String(error)}`, "findById");
    }
  }
  async findByEmail(email, options = {}, transaction) {
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
      const user = this.mapDatabaseUserToSafeUser(userData);
      if (options.includeRoles) {
        user.roles = await this.getUserRoles(userData.id, options.includePermissions, transaction);
      }
      return user;
    } catch (error) {
      throw new DatabaseError(`Failed to find user by email: ${error instanceof Error ? error.message : String(error)}`, "findByEmail");
    }
  }
  async create(userData, transaction) {
    try {
      const db2 = getDatabase();
      const insertQuery = db2.query(`
        INSERT INTO users (id, email, password_hash, first_name, last_name, created_at, updated_at, is_active)
        VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'), ?)
      `);
      insertQuery.run(userData.id, userData.email.toLowerCase(), userData.passwordHash, userData.firstName || null, userData.lastName || null, userData.isActive !== false ? 1 : 0);
      const createdUser = await this.findById(userData.id, { includeRoles: true });
      if (!createdUser) {
        throw new DatabaseError("Failed to retrieve created user", "create");
      }
      return createdUser;
    } catch (error) {
      throw new DatabaseError(`Failed to create user: ${error instanceof Error ? error.message : String(error)}`, "create");
    }
  }
  async update(userId, updateData, transaction) {
    try {
      const db2 = getDatabase();
      const updateFields = [];
      const updateValues = [];
      if (updateData.email !== undefined) {
        updateFields.push("email = ?");
        updateValues.push(updateData.email.toLowerCase());
      }
      if (updateData.passwordHash !== undefined) {
        updateFields.push("password_hash = ?");
        updateValues.push(updateData.passwordHash);
      }
      if (updateData.firstName !== undefined) {
        updateFields.push("first_name = ?");
        updateValues.push(updateData.firstName);
      }
      if (updateData.lastName !== undefined) {
        updateFields.push("last_name = ?");
        updateValues.push(updateData.lastName);
      }
      if (updateData.isActive !== undefined) {
        updateFields.push("is_active = ?");
        updateValues.push(updateData.isActive ? 1 : 0);
      }
      if (updateData.lastLoginAt !== undefined) {
        updateFields.push("last_login_at = ?");
        const lastLoginDate = updateData.lastLoginAt instanceof Date ? updateData.lastLoginAt : new Date(updateData.lastLoginAt);
        updateValues.push(lastLoginDate.toISOString());
      }
      updateFields.push("updated_at = datetime('now')");
      updateValues.push(userId);
      if (updateFields.length === 1) {
        return;
      }
      const updateQuery = db2.query(`UPDATE users SET ${updateFields.join(", ")} WHERE id = ?`);
      updateQuery.run(...updateValues);
    } catch (error) {
      throw new DatabaseError(`Failed to update user: ${error instanceof Error ? error.message : String(error)}`, "update");
    }
  }
  async delete(userId, transaction) {
    try {
      const db2 = getDatabase();
      const deleteRolesQuery = db2.query("DELETE FROM user_roles WHERE user_id = ?");
      deleteRolesQuery.run(userId);
      const deleteUserQuery = db2.query("DELETE FROM users WHERE id = ?");
      deleteUserQuery.run(userId);
    } catch (error) {
      throw new DatabaseError(`Failed to delete user: ${error instanceof Error ? error.message : String(error)}`, "delete");
    }
  }
  async getUsers(options = {}) {
    try {
      const db2 = getDatabase();
      const page = Math.max(1, options.page || 1);
      const limit = Math.min(100, Math.max(1, options.limit || 10));
      const offset = (page - 1) * limit;
      const whereConditions = [];
      const whereParams = [];
      if (options.activeOnly !== undefined) {
        whereConditions.push(`is_active = ${options.activeOnly ? 1 : 0}`);
      }
      if (options.search) {
        whereConditions.push("(email LIKE ? OR first_name LIKE ? OR last_name LIKE ?)");
        const searchPattern = `%${options.search}%`;
        whereParams.push(searchPattern, searchPattern, searchPattern);
      }
      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
      const sortBy = options.sortBy || "created_at";
      const sortOrder = options.sortOrder || "desc";
      const orderClause = `ORDER BY ${sortBy} ${sortOrder.toUpperCase()}`;
      const countQuery = db2.query(`SELECT COUNT(*) as count FROM users ${whereClause}`);
      const countResult = countQuery.get(...whereParams);
      const total = countResult.count;
      const usersQuery = db2.query(`
        SELECT id, email, password_hash, first_name, last_name, created_at, updated_at, is_active, last_login_at
        FROM users
        ${whereClause}
        ${orderClause}
        LIMIT ? OFFSET ?
      `);
      const usersResult = usersQuery.all(...whereParams, limit, offset);
      const users = [];
      for (const userData of usersResult) {
        const user = this.mapDatabaseUserToSafeUser(userData);
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
      throw new DatabaseError(`Failed to get users: ${error instanceof Error ? error.message : String(error)}`, "getUsers");
    }
  }
  async getUserRoles(userId, includePermissions = false, transaction) {
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
          createdAt: new Date(roleData.created_at),
          updatedAt: new Date(roleData.created_at),
          created_at: new Date(roleData.created_at),
          isActive: Boolean(roleData.is_active),
          isDefault: false,
          description: undefined,
          permissions: [],
          metadata: undefined
        };
        if (includePermissions) {
          role.permissions = await this.getRolePermissions(role.id, transaction);
        }
        roles.push(role);
      }
      return roles;
    } catch (error) {
      throw new DatabaseError(`Failed to get user roles: ${error instanceof Error ? error.message : String(error)}`, "getUserRoles");
    }
  }
  async getRolePermissions(roleId, transaction) {
    try {
      const db2 = getDatabase();
      const permissionsQuery = db2.query(`
        SELECT p.id, p.name, p.resource, p.action, p.created_at
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = ?
        ORDER BY p.resource, p.action
      `);
      const permissionsResult = permissionsQuery.all(roleId);
      return permissionsResult.map((permData) => ({
        id: permData.id,
        name: permData.name,
        resource: permData.resource,
        action: permData.action,
        createdAt: new Date(permData.created_at),
        updatedAt: new Date
      }));
    } catch (error) {
      throw new DatabaseError(`Failed to get role permissions: ${error instanceof Error ? error.message : String(error)}`, "getRolePermissions");
    }
  }
  mapDatabaseUserToUser(userData) {
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
  mapDatabaseUserToSafeUser(userData) {
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
  async findByEmailForAuth(email, options = {}, transaction) {
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
        user.roles = await this.getUserRoles(userData.id, options.includePermissions, transaction);
      }
      return user;
    } catch (error) {
      throw new DatabaseError(`Failed to find user by email for auth: ${error instanceof Error ? error.message : String(error)}`, "findByEmailForAuth");
    }
  }
}

// src/repositories/role.ts
class RoleRepository {
  async findById(roleId, transaction) {
    try {
      const db2 = transaction ? transaction.getDatabase() : getDatabase();
      const query = db2.query("SELECT id, name, created_at, is_active FROM roles WHERE id = ?");
      const result = query.get(roleId);
      if (!result) {
        return null;
      }
      return this.mapDatabaseRoleToRole(result);
    } catch (error) {
      throw new DatabaseError(`Failed to find role by ID: ${error instanceof Error ? error.message : String(error)}`, "findById");
    }
  }
  async findByName(name, transaction) {
    try {
      const db2 = transaction ? transaction.getDatabase() : getDatabase();
      const query = db2.query("SELECT id, name, created_at, is_active FROM roles WHERE name = ?");
      const result = query.get(name.toLowerCase());
      if (!result) {
        return null;
      }
      return this.mapDatabaseRoleToRole(result);
    } catch (error) {
      throw new DatabaseError(`Failed to find role by name: ${error instanceof Error ? error.message : String(error)}`, "findByName");
    }
  }
  async create(roleData, transaction) {
    try {
      const db2 = transaction ? transaction.getDatabase() : getDatabase();
      const insertQuery = db2.query(`
        INSERT INTO roles (id, name, created_at, is_active)
        VALUES (?, ?, datetime('now'), ?)
      `);
      insertQuery.run(roleData.id, roleData.name.toLowerCase(), roleData.isActive !== false ? 1 : 0);
      return roleData.id;
    } catch (error) {
      throw new DatabaseError(`Failed to create role: ${error instanceof Error ? error.message : String(error)}`, "create");
    }
  }
  async userHasRole(userId, roleId, transaction) {
    try {
      const db2 = transaction ? transaction.getDatabase() : getDatabase();
      const query = db2.query("SELECT id FROM user_roles WHERE user_id = ? AND role_id = ?");
      const result = query.get(userId, roleId);
      return result !== null;
    } catch (error) {
      throw new DatabaseError(`Failed to check user role: ${error instanceof Error ? error.message : String(error)}`, "userHasRole");
    }
  }
  async assignToUser(userId, roleId, transaction) {
    try {
      const db2 = transaction ? transaction.getDatabase() : getDatabase();
      const exists = await this.userHasRole(userId, roleId, transaction);
      if (exists) {
        throw new Error("User already has this role");
      }
      const insertQuery = db2.query(`
        INSERT INTO user_roles (id, user_id, role_id, created_at)
        VALUES (?, ?, ?, datetime('now'))
      `);
      insertQuery.run(crypto.randomUUID(), userId, roleId);
    } catch (error) {
      throw new DatabaseError(`Failed to assign role to user: ${error instanceof Error ? error.message : String(error)}`, "assignToUser");
    }
  }
  async removeFromUser(userId, roleId, transaction) {
    try {
      const db2 = transaction ? transaction.getDatabase() : getDatabase();
      const deleteQuery = db2.query("DELETE FROM user_roles WHERE user_id = ? AND role_id = ?");
      deleteQuery.run(userId, roleId);
    } catch (error) {
      throw new DatabaseError(`Failed to remove role from user: ${error instanceof Error ? error.message : String(error)}`, "removeFromUser");
    }
  }
  async getOrCreateDefaultRole(transaction) {
    try {
      let role = await this.findByName("user", transaction);
      if (!role) {
        const roleId = crypto.randomUUID();
        await this.create({
          id: roleId,
          name: "user",
          isActive: true
        }, transaction);
        role = await this.findById(roleId, transaction);
        if (!role) {
          throw new Error("Failed to create default role");
        }
      }
      return role;
    } catch (error) {
      throw new DatabaseError(`Failed to get or create default role: ${error instanceof Error ? error.message : String(error)}`, "getOrCreateDefaultRole");
    }
  }
  async getAll(activeOnly = false) {
    try {
      const db2 = getDatabase();
      let query = "SELECT id, name, created_at, is_active FROM roles";
      const params = [];
      if (activeOnly) {
        query += " WHERE is_active = 1";
      }
      query += " ORDER BY name";
      const rolesQuery = db2.query(query);
      const results = rolesQuery.all(...params);
      return results.map((result) => this.mapDatabaseRoleToRole(result));
    } catch (error) {
      throw new DatabaseError(`Failed to get all roles: ${error instanceof Error ? error.message : String(error)}`, "getAll");
    }
  }
  mapDatabaseRoleToRole(roleData) {
    return {
      id: roleData.id,
      name: roleData.name,
      createdAt: new Date(roleData.created_at),
      updatedAt: new Date(roleData.created_at),
      isDefault: Boolean(roleData.is_active),
      permissions: [],
      isActive: roleData.is_active === 1
    };
  }
}

// src/validators/auth.ts
class EmailValidator {
  static EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  static validate(email) {
    if (!email || typeof email !== "string") {
      throw new ValidationError("Email is required");
    }
    if (!this.EMAIL_REGEX.test(email.trim())) {
      throw new ValidationError("Invalid email format");
    }
  }
  static normalize(email) {
    return email.toLowerCase().trim();
  }
}

class PasswordValidator {
  static MIN_LENGTH = 8;
  static STRENGTH_REGEX = /(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/;
  static validate(password) {
    if (!password || typeof password !== "string") {
      throw new ValidationError("Password is required");
    }
    if (password.length < this.MIN_LENGTH) {
      throw new ValidationError(`Password must be at least ${this.MIN_LENGTH} characters long`);
    }
    if (!this.STRENGTH_REGEX.test(password)) {
      throw new ValidationError("Password must contain at least one uppercase letter, one lowercase letter, and one number");
    }
  }
}

class NameValidator {
  static MAX_LENGTH = 50;
  static NAME_REGEX = /^[a-zA-Z0-9\s'-]+$/;
  static validate(name, fieldName) {
    if (name === undefined || name === null) {
      return;
    }
    if (typeof name !== "string") {
      throw new ValidationError(`${fieldName} must be a string`);
    }
    const trimmedName = name.trim();
    if (trimmedName.length === 0) {
      return;
    }
    if (trimmedName.length > this.MAX_LENGTH) {
      throw new ValidationError(`${fieldName} must not exceed ${this.MAX_LENGTH} characters`);
    }
    if (!this.NAME_REGEX.test(trimmedName)) {
      throw new ValidationError(`${fieldName} contains invalid characters`);
    }
  }
  static normalize(name) {
    if (!name || typeof name !== "string") {
      return "";
    }
    const trimmed = name.trim();
    return trimmed.length > 0 ? trimmed : "";
  }
}

class RegisterDataValidator {
  static validate(data) {
    if (!data || typeof data !== "object") {
      throw new ValidationError("Invalid registration data");
    }
    EmailValidator.validate(data.email);
    PasswordValidator.validate(data.password);
    NameValidator.validate(data.firstName, "First name");
    NameValidator.validate(data.lastName, "Last name");
    if (data.isActive !== undefined && typeof data.isActive !== "boolean") {
      throw new ValidationError("isActive must be a boolean");
    }
  }
  static normalize(data) {
    return {
      email: EmailValidator.normalize(data.email),
      password: data.password,
      firstName: NameValidator.normalize(data.firstName),
      lastName: NameValidator.normalize(data.lastName),
      isActive: data.isActive
    };
  }
}

class LoginDataValidator {
  static validate(data) {
    if (!data || typeof data !== "object") {
      throw new ValidationError("Invalid login data");
    }
    EmailValidator.validate(data.email);
    if (!data.password || typeof data.password !== "string") {
      throw new ValidationError("Password is required");
    }
  }
  static normalize(data) {
    return {
      email: EmailValidator.normalize(data.email),
      password: data.password
    };
  }
}

class UpdateUserDataValidator {
  static validate(data) {
    if (!data || typeof data !== "object") {
      throw new ValidationError("Invalid update data");
    }
    if (data.email !== undefined) {
      EmailValidator.validate(data.email);
    }
    NameValidator.validate(data.firstName, "First name");
    NameValidator.validate(data.lastName, "Last name");
    if (data.isActive !== undefined && typeof data.isActive !== "boolean") {
      throw new ValidationError("isActive must be a boolean");
    }
    return data;
  }
  static normalize(data) {
    const normalized = {};
    if (data.email !== undefined) {
      normalized.email = EmailValidator.normalize(data.email);
    }
    if (data.firstName !== undefined) {
      normalized.firstName = NameValidator.normalize(data.firstName);
    }
    if (data.lastName !== undefined) {
      normalized.lastName = NameValidator.normalize(data.lastName);
    }
    if (data.isActive !== undefined) {
      normalized.isActive = data.isActive;
    }
    return normalized;
  }
}

class UserIdValidator {
  static UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  static NUMERIC_ID_REGEX = /^[0-9]+$/;
  static validate(userId) {
    if (!userId || typeof userId !== "string") {
      throw new ValidationError("User ID is required");
    }
    if (!this.UUID_REGEX.test(userId) && !this.NUMERIC_ID_REGEX.test(userId)) {
      throw new ValidationError("Invalid user ID format");
    }
  }
}

class RoleNameValidator {
  static MAX_LENGTH = 50;
  static ROLE_REGEX = /^[a-zA-Z0-9_-]+$/;
  static validate(roleName) {
    if (!roleName || typeof roleName !== "string") {
      throw new ValidationError("Role name is required");
    }
    const trimmed = roleName.trim();
    if (trimmed.length === 0) {
      throw new ValidationError("Role name cannot be empty");
    }
    if (trimmed.length > this.MAX_LENGTH) {
      throw new ValidationError(`Role name must not exceed ${this.MAX_LENGTH} characters`);
    }
    if (!this.ROLE_REGEX.test(trimmed)) {
      throw new ValidationError("Role name contains invalid characters");
    }
  }
  static normalize(roleName) {
    return roleName.toLowerCase().trim();
  }
}

// src/config/constants.ts
var AUTH_CONFIG = {
  PASSWORD: {
    MIN_LENGTH: 8,
    MAX_LENGTH: 128,
    BCRYPT_ROUNDS: 12,
    STRENGTH_REGEX: /(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
    REQUIRE_SPECIAL_CHARS: false,
    SPECIAL_CHARS_REGEX: /[!@#$%^&*(),.?":{}|<>]/
  },
  EMAIL: {
    MAX_LENGTH: 254,
    VALIDATION_REGEX: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    NORMALIZE_CASE: true
  },
  NAME: {
    MAX_LENGTH: 50,
    MIN_LENGTH: 1,
    VALIDATION_REGEX: /^[a-zA-Z\s'-]+$/,
    ALLOW_EMPTY: true
  },
  USER_ID: {
    FORMAT: "UUID",
    UUID_REGEX: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
  },
  ROLE: {
    MAX_LENGTH: 50,
    MIN_LENGTH: 1,
    VALIDATION_REGEX: /^[a-zA-Z0-9_-]+$/,
    DEFAULT_ROLE: "user",
    NORMALIZE_CASE: true
  },
  SESSION: {
    MAX_CONCURRENT_SESSIONS: 5,
    CLEANUP_INTERVAL_MS: 60 * 60 * 1000,
    EXTEND_ON_ACTIVITY: true
  },
  RATE_LIMIT: {
    LOGIN: {
      MAX_ATTEMPTS: 5,
      WINDOW_MS: 15 * 60 * 1000,
      BLOCK_DURATION_MS: 30 * 60 * 1000
    },
    REGISTER: {
      MAX_ATTEMPTS: 3,
      WINDOW_MS: 60 * 60 * 1000,
      BLOCK_DURATION_MS: 60 * 60 * 1000
    },
    PASSWORD_RESET: {
      MAX_ATTEMPTS: 3,
      WINDOW_MS: 60 * 60 * 1000,
      BLOCK_DURATION_MS: 60 * 60 * 1000
    },
    GENERAL: {
      MAX_ATTEMPTS: 1000,
      WINDOW_MS: 15 * 60 * 1000,
      BLOCK_DURATION_MS: 15 * 60 * 1000
    },
    USER_MODIFICATION: {
      MAX_ATTEMPTS: 10,
      WINDOW_MS: 60 * 60 * 1000,
      BLOCK_DURATION_MS: 60 * 60 * 1000
    }
  },
  SECURITY: {
    HASH_ALGORITHM: "bcrypt",
    SALT_ROUNDS: 12,
    SECURE_HEADERS: true,
    AUDIT_LOGGING: true,
    INPUT_SANITIZATION: true,
    XSS_PROTECTION: true
  },
  DATABASE: {
    CONNECTION_TIMEOUT_MS: 30000,
    QUERY_TIMEOUT_MS: 1e4,
    MAX_RETRIES: 3,
    RETRY_DELAY_MS: 1000
  },
  PAGINATION: {
    DEFAULT_PAGE: 1,
    DEFAULT_LIMIT: 10,
    MAX_LIMIT: 100,
    MIN_LIMIT: 1
  },
  VALIDATION_MESSAGES: {
    EMAIL_REQUIRED: "Email is required",
    EMAIL_INVALID: "Invalid email format",
    PASSWORD_REQUIRED: "Password is required",
    PASSWORD_TOO_SHORT: "Password must be at least {min} characters long",
    PASSWORD_TOO_LONG: "Password must not exceed {max} characters",
    PASSWORD_WEAK: "Password must contain at least one uppercase letter, one lowercase letter, and one number",
    NAME_TOO_LONG: "{field} must not exceed {max} characters",
    NAME_INVALID_CHARS: "{field} contains invalid characters",
    USER_ID_REQUIRED: "User ID is required",
    USER_ID_INVALID: "Invalid user ID format",
    ROLE_NAME_REQUIRED: "Role name is required",
    ROLE_NAME_INVALID: "Role name contains invalid characters",
    ROLE_NAME_TOO_LONG: "Role name must not exceed {max} characters"
  },
  ERROR_MESSAGES: {
    USER_NOT_FOUND: "User not found",
    USER_EXISTS: "User already exists with this email",
    INVALID_CREDENTIALS: "Invalid credentials",
    ACCOUNT_INACTIVE: "Account is inactive",
    ROLE_NOT_FOUND: "Role not found",
    ROLE_ALREADY_ASSIGNED: "User already has this role",
    PERMISSION_DENIED: "Permission denied",
    RATE_LIMIT_EXCEEDED: "Rate limit exceeded. Please try again later",
    SERVER_ERROR: "Internal server error",
    DATABASE_ERROR: "Database operation failed",
    VALIDATION_ERROR: "Validation failed"
  },
  SUCCESS_MESSAGES: {
    USER_REGISTERED: "User registered successfully",
    USER_LOGGED_IN: "User logged in successfully",
    USER_UPDATED: "User updated successfully",
    USER_DELETED: "User deleted successfully",
    PASSWORD_UPDATED: "Password updated successfully",
    ROLE_ASSIGNED: "Role assigned successfully",
    ROLE_REMOVED: "Role removed successfully"
  }
};

// src/logger/Logger.ts
import { EventEmitter } from "events";

// src/logger/types.ts
var LogLevel2;
((LogLevel3) => {
  LogLevel3[LogLevel3["DEBUG"] = 0] = "DEBUG";
  LogLevel3[LogLevel3["INFO"] = 1] = "INFO";
  LogLevel3[LogLevel3["WARN"] = 2] = "WARN";
  LogLevel3[LogLevel3["ERROR"] = 3] = "ERROR";
  LogLevel3[LogLevel3["FATAL"] = 4] = "FATAL";
  LogLevel3[LogLevel3["SILENT"] = 5] = "SILENT";
})(LogLevel2 ||= {});

// src/logger/formatter.ts
var COLORS = {
  DEBUG: "\x1B[36m",
  INFO: "\x1B[32m",
  WARN: "\x1B[33m",
  ERROR: "\x1B[31m",
  FATAL: "\x1B[35m",
  RESET: "\x1B[0m"
};

class LogFormatter {
  config;
  constructor(config) {
    this.config = config;
  }
  formatForConsole(entry) {
    const color = this.config.enableColors ? COLORS[entry.level] : "";
    const reset = this.config.enableColors ? COLORS.RESET : "";
    const timestamp = new Date(entry.timestamp).toLocaleString();
    let formatted = `${color}[${timestamp}] ${entry.level} [${entry.event}] ${entry.message}${reset}`;
    if (entry.data) {
      formatted += `
${color}Data: ${this.stringifyData(entry.data)}${reset}`;
    }
    if (entry.stack) {
      formatted += `
${color}Stack: ${entry.stack}${reset}`;
    }
    if (entry.context && Object.keys(entry.context).length > 0) {
      formatted += `
${color}Context: ${JSON.stringify(entry.context, null, 2)}${reset}`;
    }
    return formatted;
  }
  formatForFile(entry) {
    if (this.config.format === "json") {
      return JSON.stringify(entry) + `
`;
    }
    const timestamp = new Date(entry.timestamp).toLocaleString();
    let formatted = `[${timestamp}] ${entry.level} [${entry.event}] ${entry.message}`;
    if (entry.data) {
      formatted += ` | Data: ${this.stringifyData(entry.data)}`;
    }
    if (entry.stack) {
      formatted += ` | Stack: ${entry.stack.replace(/\n/g, " ")}`;
    }
    if (entry.context && Object.keys(entry.context).length > 0) {
      formatted += ` | Context: ${JSON.stringify(entry.context)}`;
    }
    return formatted + `
`;
  }
  stringifyData(data) {
    try {
      return JSON.stringify(data, null, 2);
    } catch {
      return String(data);
    }
  }
}

// src/logger/fileManager.ts
import fs from "fs";
import path from "path";

class LogFileManager {
  config;
  currentLogFile = null;
  currentFileSize = 0;
  constructor(config) {
    this.config = config;
    if (this.config.enableFile) {
      this.ensureLogDirectory();
    }
  }
  writeToFile(content) {
    if (!this.config.enableFile)
      return;
    try {
      const fileName = this.getCurrentLogFileName();
      if (this.currentLogFile !== fileName) {
        this.currentLogFile = fileName;
        this.currentFileSize = fs.existsSync(fileName) ? fs.statSync(fileName).size : 0;
      }
      if (this.shouldRotateFile()) {
        this.rotateLogFile();
      }
      fs.appendFileSync(this.currentLogFile, content);
      this.currentFileSize += Buffer.byteLength(content, "utf8");
    } catch (error) {
      console.error("Error writing to log file:", error);
    }
  }
  ensureLogDirectory() {
    if (!fs.existsSync(this.config.logDirectory)) {
      fs.mkdirSync(this.config.logDirectory, { recursive: true });
    }
  }
  getCurrentLogFileName() {
    const date = new Date;
    const dateStr = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
    return path.join(this.config.logDirectory, `webrtc-signaling-${dateStr}.log`);
  }
  shouldRotateFile() {
    if (!this.currentLogFile)
      return false;
    try {
      const stats = fs.statSync(this.currentLogFile);
      return stats.size >= this.config.maxFileSize;
    } catch {
      return false;
    }
  }
  rotateLogFile() {
    if (!this.currentLogFile)
      return;
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const rotatedName = this.currentLogFile.replace(".log", `-${timestamp}.log`);
    try {
      fs.renameSync(this.currentLogFile, rotatedName);
      this.cleanOldLogFiles();
      this.currentFileSize = 0;
    } catch (error) {
      console.error("Error rotating log file:", error);
    }
  }
  cleanOldLogFiles() {
    try {
      const files = fs.readdirSync(this.config.logDirectory).filter((file) => file.startsWith("webrtc-signaling-") && file.endsWith(".log")).map((file) => ({
        name: file,
        path: path.join(this.config.logDirectory, file),
        stats: fs.statSync(path.join(this.config.logDirectory, file))
      })).sort((a, b) => b.stats.mtime.getTime() - a.stats.mtime.getTime());
      if (files.length > this.config.maxFiles) {
        const filesToDelete = files.slice(this.config.maxFiles);
        filesToDelete.forEach((file) => {
          try {
            fs.unlinkSync(file.path);
          } catch (error) {
            console.error(`Error deleting old log file ${file.name}:`, error);
          }
        });
      }
    } catch (error) {
      console.error("Error cleaning old log files:", error);
    }
  }
}

// src/logger/config.ts
import path2 from "path";
var BASE_CONFIG = {
  level: 1 /* INFO */,
  enableConsole: true,
  enableFile: false,
  logDirectory: path2.join(process.cwd(), "logs"),
  maxFileSize: 10 * 1024 * 1024,
  maxFiles: 5,
  datePattern: "YYYY-MM-DD",
  format: "text",
  includeStackTrace: true,
  enableColors: true
};
var ENVIRONMENT_CONFIGS = {
  development: {
    level: 0 /* DEBUG */,
    enableFile: true,
    maxFileSize: 5 * 1024 * 1024,
    maxFiles: 3
  },
  production: {
    level: 1 /* INFO */,
    enableConsole: false,
    enableFile: true,
    maxFileSize: 50 * 1024 * 1024,
    maxFiles: 10,
    format: "json",
    includeStackTrace: false,
    enableColors: false
  },
  test: {
    level: 2 /* WARN */,
    enableConsole: false,
    enableFile: false
  },
  silent: {
    level: 5 /* SILENT */,
    enableConsole: false,
    enableFile: false
  }
};
function createConfig(env, overrides = {}) {
  const environment = env || "development";
  const envConfig = ENVIRONMENT_CONFIGS[environment.toLowerCase()] || {};
  return {
    ...BASE_CONFIG,
    ...envConfig,
    ...overrides
  };
}

// src/logger/Logger.ts
class Logger extends EventEmitter {
  formatter;
  fileManager;
  config;
  constructor(config = {}) {
    super();
    this.config = createConfig("development", config);
    this.formatter = new LogFormatter(this.config);
    this.fileManager = new LogFileManager(this.config);
  }
  log(level, event, logData = {}, ...args) {
    if (this.config.level === 5 /* SILENT */ || level < this.config.level) {
      return;
    }
    const entry = this.createLogEntry(level, event, logData);
    this.emit("log", entry, ...args);
    if (this.config.enableConsole) {
      this.writeToConsole(entry);
    }
    if (this.config.enableFile) {
      const formatted = this.formatter.formatForFile(entry);
      this.fileManager.writeToFile(formatted);
    }
  }
  createLogEntry(level, event, logData = {}) {
    const { message = "", data, context } = logData;
    const entry = {
      timestamp: new Date().toISOString(),
      level: LogLevel2[level],
      event,
      message,
      context
    };
    if (data !== undefined) {
      if (data instanceof Error) {
        entry.message = entry.message || data.message;
        if (this.config.includeStackTrace) {
          entry.stack = data.stack;
        }
      } else {
        entry.data = data;
      }
    }
    return entry;
  }
  writeToConsole(entry) {
    const formatted = this.formatter.formatForConsole(entry);
    const level = LogLevel2[entry.level];
    if (level >= 3 /* ERROR */) {
      console.error(formatted);
    } else {
      console.log(formatted);
    }
  }
  debug(event, logData, ...args) {
    this.log(0 /* DEBUG */, event, logData, ...args);
  }
  info(event, logData, ...args) {
    this.log(1 /* INFO */, event, logData, ...args);
  }
  warn(event, logData, ...args) {
    this.log(2 /* WARN */, event, logData, ...args);
  }
  error(event, logData, ...args) {
    this.log(3 /* ERROR */, event, logData, ...args);
  }
  fatal(event, logData, ...args) {
    this.log(4 /* FATAL */, event, logData, ...args);
  }
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    this.formatter = new LogFormatter(this.config);
    this.fileManager = new LogFileManager(this.config);
  }
  getConfig() {
    return { ...this.config };
  }
  silence() {
    this.updateConfig({ level: 5 /* SILENT */, enableConsole: false });
  }
  unsilence(level = 1 /* INFO */) {
    this.updateConfig({ level, enableConsole: true });
  }
  enableConsoleOnly() {
    this.updateConfig({ enableConsole: true, enableFile: false });
  }
  enableFileOnly() {
    this.updateConfig({ enableConsole: false, enableFile: true });
  }
}
var globalLogger = null;
function getLogger(config) {
  if (!globalLogger) {
    globalLogger = new Logger(config);
  } else if (config) {
    globalLogger.updateConfig(config);
  }
  return globalLogger;
}
// src/logger/index.ts
var defaultLogger = getLogger();

// src/services/auth.ts
defaultLogger.silence();

class AuthService {
  userRepository;
  roleRepository;
  constructor() {
    this.userRepository = new UserRepository;
    this.roleRepository = new RoleRepository;
  }
  async register(data) {
    try {
      const jwtService = getJWTService();
      RegisterDataValidator.validate(data);
      const normalizedData = RegisterDataValidator.normalize(data);
      const existingUser = await this.userRepository.findByEmail(normalizedData.email);
      if (existingUser) {
        throw AuthErrorFactory.validation(AUTH_CONFIG.ERROR_MESSAGES.USER_EXISTS);
      }
      const passwordHash = await Bun.password.hash(normalizedData.password, {
        algorithm: AUTH_CONFIG.SECURITY.HASH_ALGORITHM,
        cost: AUTH_CONFIG.SECURITY.SALT_ROUNDS
      });
      const userId = crypto.randomUUID();
      await this.userRepository.create({
        id: userId,
        email: normalizedData.email,
        passwordHash,
        firstName: normalizedData.firstName,
        lastName: normalizedData.lastName,
        isActive: normalizedData.isActive !== false
      });
      await this.assignDefaultRole(userId);
      const user = await this.userRepository.findById(userId, {
        includeRoles: true,
        includePermissions: true
      });
      if (!user) {
        throw AuthErrorFactory.database("Failed to create user", "register");
      }
      await this.userRepository.update(userId, { lastLoginAt: new Date });
      const token = await jwtService.generateToken(user);
      const refreshToken = await jwtService.generateRefreshToken(Number(user.id));
      const updatedUser = await this.userRepository.findById(user.id, {
        includeRoles: true,
        includePermissions: true
      });
      defaultLogger.info(`\u2705 ${AUTH_CONFIG.SUCCESS_MESSAGES.USER_REGISTERED}: ${updatedUser?.email}`);
      return {
        success: true,
        user: updatedUser || user,
        token,
        refreshToken
      };
    } catch (error) {
      return ErrorHandler.handle(error, "register");
    }
  }
  async login(data) {
    try {
      const jwtService = getJWTService();
      LoginDataValidator.validate(data);
      const normalizedData = LoginDataValidator.normalize(data);
      const user = await this.userRepository.findByEmailForAuth(normalizedData.email, {
        includeRoles: true,
        includePermissions: true
      });
      if (!user) {
        throw AuthErrorFactory.authentication(AUTH_CONFIG.ERROR_MESSAGES.INVALID_CREDENTIALS);
      }
      if (!user.isActive) {
        throw AuthErrorFactory.authentication(AUTH_CONFIG.ERROR_MESSAGES.ACCOUNT_INACTIVE);
      }
      const isValidPassword = await Bun.password.verify(normalizedData.password, user.passwordHash);
      if (!isValidPassword) {
        throw AuthErrorFactory.authentication(AUTH_CONFIG.ERROR_MESSAGES.INVALID_CREDENTIALS);
      }
      await this.userRepository.update(user.id, { lastLoginAt: new Date });
      const updatedUser = await this.userRepository.findById(user.id, {
        includeRoles: true,
        includePermissions: true
      });
      if (!updatedUser) {
        throw AuthErrorFactory.database("User not found after update", "login");
      }
      const token = await jwtService.generateToken(updatedUser);
      const refreshToken = await jwtService.generateRefreshToken(Number(updatedUser.id));
      defaultLogger.info(`\u2705 ${AUTH_CONFIG.SUCCESS_MESSAGES.USER_LOGGED_IN}: ${updatedUser.email}`);
      return {
        success: true,
        user: updatedUser,
        token,
        refreshToken
      };
    } catch (error) {
      return ErrorHandler.handle(error, "login");
    }
  }
  async findUserById(id, options = {}) {
    try {
      UserIdValidator.validate(id);
      return await this.userRepository.findById(id, options);
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw AuthErrorFactory.database(`Failed to find user: ${ErrorHandler.getMessage(error)}`, "findUserById");
    }
  }
  async findUserByEmail(email, options = {}) {
    try {
      return await this.userRepository.findByEmail(email, options);
    } catch (error) {
      throw AuthErrorFactory.database(`Failed to find user: ${ErrorHandler.getMessage(error)}`, "findUserByEmail");
    }
  }
  async getUserRoles(userId, includePermissions = false) {
    try {
      UserIdValidator.validate(userId);
      return await this.userRepository.getUserRoles(userId, includePermissions);
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw AuthErrorFactory.database(`Failed to get user roles: ${ErrorHandler.getMessage(error)}`, "getUserRoles");
    }
  }
  async assignRole(userId, roleName) {
    try {
      UserIdValidator.validate(userId);
      RoleNameValidator.validate(roleName);
      const userExists = await this.userRepository.findById(userId);
      if (!userExists) {
        throw AuthErrorFactory.userNotFound(AUTH_CONFIG.ERROR_MESSAGES.USER_NOT_FOUND);
      }
      const role = await this.roleRepository.findByName(roleName);
      if (!role) {
        return false;
      }
      const hasRole = await this.roleRepository.userHasRole(userId, role.id);
      if (hasRole) {
        return false;
      }
      await this.roleRepository.assignToUser(userId, role.id);
      defaultLogger.info(`\u2705 Rol ${roleName} asignado al usuario: ${userId}`);
      return true;
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      throw AuthErrorFactory.database(`Failed to assign role: ${ErrorHandler.getMessage(error)}`, "assignRole");
    }
  }
  async assignDefaultRole(userId) {
    try {
      UserIdValidator.validate(userId);
      const defaultRole = await this.roleRepository.getOrCreateDefaultRole();
      const hasRole = await this.roleRepository.userHasRole(userId, defaultRole.id);
      if (hasRole) {
        return;
      }
      await this.roleRepository.assignToUser(userId, defaultRole.id);
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw AuthErrorFactory.database(`Failed to assign default role: ${ErrorHandler.getMessage(error)}`, "assignDefaultRole");
    }
  }
  async updatePassword(userId, newPassword) {
    try {
      UserIdValidator.validate(userId);
      PasswordValidator.validate(newPassword);
      const user = await this.userRepository.findById(userId);
      if (!user) {
        throw AuthErrorFactory.userNotFound(AUTH_CONFIG.ERROR_MESSAGES.USER_NOT_FOUND);
      }
      const hashedPassword = await Bun.password.hash(newPassword);
      await this.userRepository.update(userId, { passwordHash: hashedPassword });
      return true;
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      throw AuthErrorFactory.database(`Failed to update password: ${ErrorHandler.getMessage(error)}`, "updatePassword");
    }
  }
  async updateUser(userId, updateData) {
    try {
      const validatedData = UpdateUserDataValidator.validate(updateData);
      const normalizedData = UpdateUserDataValidator.normalize(validatedData);
      UserIdValidator.validate(userId);
      const existingUser = await this.userRepository.findById(userId);
      if (!existingUser) {
        throw AuthErrorFactory.userNotFound(AUTH_CONFIG.ERROR_MESSAGES.USER_NOT_FOUND);
      }
      if (normalizedData.email && normalizedData.email !== existingUser.email) {
        const emailExists = await this.userRepository.findByEmail(normalizedData.email);
        if (emailExists) {
          return { ...existingUser, isActive: false };
        }
      }
      const updateFields = {};
      if (normalizedData.email) {
        updateFields.email = normalizedData.email;
      }
      if (normalizedData.firstName !== undefined) {
        updateFields.firstName = normalizedData.firstName;
      }
      if (normalizedData.lastName !== undefined) {
        updateFields.lastName = normalizedData.lastName;
      }
      if (normalizedData.isActive !== undefined) {
        updateFields.isActive = normalizedData.isActive;
      }
      await this.userRepository.update(userId, updateFields);
      const updatedUser = await this.userRepository.findById(userId);
      if (!updatedUser) {
        throw AuthErrorFactory.database("Failed to retrieve updated user", "updateUser");
      }
      return updatedUser;
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      throw AuthErrorFactory.database(`Failed to update user: ${ErrorHandler.getMessage(error)}`, "updateUser");
    }
  }
  async deactivateUser(userId) {
    try {
      UserIdValidator.validate(userId);
      const user = await this.userRepository.findById(userId);
      if (!user) {
        throw AuthErrorFactory.userNotFound(AUTH_CONFIG.ERROR_MESSAGES.USER_NOT_FOUND);
      }
      await this.userRepository.update(userId, { isActive: false });
      defaultLogger.info(`\u2705 Usuario desactivado: ${userId}`);
      return user;
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      throw AuthErrorFactory.database(`Failed to deactivate user: ${ErrorHandler.getMessage(error)}`, "deactivateUser");
    }
  }
  async activateUser(userId) {
    try {
      UserIdValidator.validate(userId);
      const user = await this.userRepository.findById(userId);
      if (!user) {
        throw AuthErrorFactory.userNotFound(AUTH_CONFIG.ERROR_MESSAGES.USER_NOT_FOUND);
      }
      await this.userRepository.update(userId, { isActive: true });
      const updatedUser = await this.userRepository.findById(userId);
      if (!updatedUser) {
        throw AuthErrorFactory.database("Failed to retrieve updated user", "activateUser");
      }
      defaultLogger.info(`\u2705 Usuario activado: ${userId}`);
      return updatedUser;
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      throw AuthErrorFactory.database(`Failed to activate user: ${ErrorHandler.getMessage(error)}`, "activateUser");
    }
  }
  async deleteUser(userId) {
    try {
      UserIdValidator.validate(userId);
      const user = await this.userRepository.findById(userId);
      if (!user) {
        throw AuthErrorFactory.userNotFound(AUTH_CONFIG.ERROR_MESSAGES.USER_NOT_FOUND);
      }
      await this.userRepository.delete(userId);
      defaultLogger.info(`\u2705 Usuario eliminado: ${userId}`);
      return true;
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      throw AuthErrorFactory.database(`Failed to delete user: ${ErrorHandler.getMessage(error)}`, "deleteUser");
    }
  }
  async removeRole(userId, roleName) {
    try {
      UserIdValidator.validate(userId);
      RoleNameValidator.validate(roleName);
      const user = await this.userRepository.findById(userId);
      if (!user) {
        throw AuthErrorFactory.userNotFound(AUTH_CONFIG.ERROR_MESSAGES.USER_NOT_FOUND);
      }
      const role = await this.roleRepository.findByName(roleName);
      if (!role) {
        throw AuthErrorFactory.validation(AUTH_CONFIG.ERROR_MESSAGES.ROLE_NOT_FOUND);
      }
      await this.roleRepository.removeFromUser(userId, role.id);
      defaultLogger.info(`\u2705 Rol ${roleName} removido del usuario: ${userId}`);
      return true;
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      throw AuthErrorFactory.database(`Failed to remove role: ${ErrorHandler.getMessage(error)}`, "removeRole");
    }
  }
  async getUsers(page = 1, limit = 10, options = {}) {
    try {
      const repositoryOptions = {
        activeOnly: options.activeOnly,
        search: options.search,
        sortBy: options.sortBy,
        sortOrder: options.sortOrder,
        includeRoles: options.includeRoles,
        includePermissions: options.includePermissions
      };
      return await this.userRepository.getUsers({ page, limit, ...repositoryOptions });
    } catch (error) {
      throw AuthErrorFactory.database(`Failed to get users: ${ErrorHandler.getMessage(error)}`, "getUsers");
    }
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
      if (data.permissions && data.permissions.length > 0) {
        const assignResult = await this.assignPermissionsToRole(roleId, data.permissions);
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
      console.log(`\u2705 Role assigned to user: ${data.userId} -> ${data.roleId}`);
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
      console.log(`\u2705 Role removed from user: ${userId} -> ${roleId}`);
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
      console.log(`\u2705 Permissions removed from role: ${roleId}`);
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
      console.log(`\u2705 Permission updated: ${updatedPermission?.name}`);
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
      console.log(`\u2705 Permission deleted: ${existingPermission.name}`);
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
      console.log(`\u2705 Role updated: ${updatedRole?.name}`);
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
      console.log(`\u2705 Role deleted: ${existingRole.name}`);
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
        createdAt: new Date(row.created_at),
        updatedAt: new Date(row.created_at)
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
        createdAt: new Date(result.created_at),
        updatedAt: new Date(result.created_at)
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
        createdAt: new Date(result.created_at),
        updatedAt: new Date(result.created_at)
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
        createdAt: new Date(row.created_at),
        updatedAt: new Date(row.created_at)
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
        createdAt: new Date(row.created_at),
        updatedAt: new Date(row.created_at)
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
    token = extractTokenFromRequest(request, tokenHeader, config);
  }
  if (!token) {
    if (!required) {
      return { success: true, context: { permissions: [], isAuthenticated: false } };
    }
    return {
      success: false,
      error: extractToken ? "Token not found" : "Authentication token required. Provide token via Authorization header (Bearer <token>) or query parameter.",
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
function extractTokenFromRequest(request, tokenHeader, config) {
  const jwtService = config.jwtService || getJWTService();
  const authHeader = request.headers[tokenHeader] || request.headers[tokenHeader.toLowerCase()] || request.headers[tokenHeader.toUpperCase()];
  if (authHeader) {
    if (tokenHeader.toLowerCase() === "authorization") {
      const token = jwtService.extractTokenFromHeader(authHeader);
      if (token)
        return token;
    } else {
      return authHeader;
    }
  }
  if (request.query) {
    const queryToken = request.query.token || request.query.access_token || request.query.auth_token;
    if (queryToken) {
      return Array.isArray(queryToken) ? queryToken[0] : queryToken;
    }
  }
  if (request.url) {
    try {
      const url = new URL(request.url, "http://localhost");
      const urlToken = url.searchParams.get("token") || url.searchParams.get("access_token") || url.searchParams.get("auth_token");
      if (urlToken)
        return urlToken;
    } catch (error) {}
  }
  return null;
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
      const errorDetails = getWebSocketAuthErrorDetails("No token provided", 401);
      ws.close(errorDetails.closeCode, errorDetails.reason);
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
      const errorDetails = getWebSocketAuthErrorDetails(result.error, result.statusCode);
      ws.close(errorDetails.closeCode, errorDetails.reason);
      return false;
    }
    ws.auth = result.context;
    ws.userId = result.context?.user?.id;
    ws.sessionId = generateSessionId();
    ws.lastActivity = new Date;
    if (ws.userId && config.maxConnections) {
      const userConnections = activeConnections.get(ws.userId) || new Set;
      if (userConnections.size >= config.maxConnections) {
        const errorDetails = getWebSocketAuthErrorDetails("Maximum connections exceeded", 429);
        ws.close(errorDetails.closeCode, errorDetails.reason);
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
    const errorDetails = getWebSocketAuthErrorDetails("Internal authentication error", 500);
    ws.close(errorDetails.closeCode, errorDetails.reason);
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
    ws.send(JSON.stringify(createWebSocketAuthErrorResponse("Authentication required", 401)));
    return false;
  }
  if (permissions && !checkWebSocketPermissions(ws, permissions)) {
    ws.send(JSON.stringify(createWebSocketAuthErrorResponse("Insufficient permissions", 403, {
      requiredPermissions: permissions
    })));
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
function createWebSocketAuthErrorResponse(error = "Authentication failed", statusCode = 401, additionalData) {
  const errorResponse = {
    type: "auth_error",
    success: false,
    error: getDetailedWebSocketAuthError(error, statusCode),
    code: getWebSocketAuthErrorCode(error, statusCode),
    statusCode,
    timestamp: new Date().toISOString()
  };
  if (additionalData) {
    Object.assign(errorResponse, additionalData);
  }
  return errorResponse;
}
function getWebSocketAuthErrorDetails(error = "Authentication failed", statusCode) {
  const detailedError = getDetailedWebSocketAuthError(error, statusCode || 401);
  let closeCode;
  switch (statusCode) {
    case 400:
      closeCode = 1002;
      break;
    case 401:
      closeCode = 1008;
      break;
    case 403:
      closeCode = 1008;
      break;
    case 429:
      closeCode = 1008;
      break;
    case 500:
      closeCode = 1011;
      break;
    default:
      closeCode = 1008;
  }
  return {
    closeCode,
    reason: detailedError.length > 123 ? detailedError.substring(0, 120) + "..." : detailedError
  };
}
function getDetailedWebSocketAuthError(error, statusCode) {
  const errorMappings = {
    "Invalid token": "The provided authentication token is invalid or malformed. Please reconnect with a valid token.",
    "Token expired": "Your authentication token has expired. Please reconnect with a new token.",
    "No token provided": "Authentication token is required. Please provide a valid token in the connection URL or headers.",
    "Insufficient permissions": "You do not have the required permissions for this WebSocket operation.",
    "User not found": "The user associated with this token could not be found or has been deactivated.",
    "Token revoked": "This authentication token has been revoked. Please obtain a new token and reconnect.",
    "Invalid signature": "The token signature is invalid. This may indicate a compromised or tampered token.",
    "Malformed token": "The authentication token format is incorrect. Please ensure you are using a valid JWT token.",
    "Authentication required": "This WebSocket connection requires authentication. Please provide a valid token.",
    "Session expired": "Your session has expired. Please reconnect with a new authentication token.",
    "Account locked": "Your account has been temporarily locked. Please contact support.",
    "Invalid credentials": "The provided credentials are incorrect.",
    "Maximum connections exceeded": "You have reached the maximum number of allowed concurrent connections.",
    "Internal authentication error": "An internal error occurred during authentication. Please try reconnecting."
  };
  if (errorMappings[error]) {
    return errorMappings[error];
  }
  for (const [key, value] of Object.entries(errorMappings)) {
    if (error.toLowerCase().includes(key.toLowerCase())) {
      return value;
    }
  }
  switch (statusCode) {
    case 401:
      return error.includes("token") ? "WebSocket authentication failed: Invalid or missing token. Please provide a valid token and reconnect." : "WebSocket authentication required. Please provide valid credentials and reconnect.";
    case 403:
      return "WebSocket access forbidden: You do not have sufficient permissions for this connection.";
    case 429:
      return "WebSocket rate limit exceeded: Too many connection attempts. Please wait before reconnecting.";
    case 500:
      return "WebSocket internal error: An unexpected error occurred. Please try reconnecting.";
    default:
      return error || "WebSocket authentication error occurred.";
  }
}
function getWebSocketAuthErrorCode(error, statusCode) {
  const errorCodes = {
    "Invalid token": "WS_AUTH_INVALID_TOKEN",
    "Token expired": "WS_AUTH_TOKEN_EXPIRED",
    "No token provided": "WS_AUTH_TOKEN_MISSING",
    "Insufficient permissions": "WS_AUTH_INSUFFICIENT_PERMISSIONS",
    "User not found": "WS_AUTH_USER_NOT_FOUND",
    "Token revoked": "WS_AUTH_TOKEN_REVOKED",
    "Invalid signature": "WS_AUTH_INVALID_SIGNATURE",
    "Malformed token": "WS_AUTH_MALFORMED_TOKEN",
    "Authentication required": "WS_AUTH_REQUIRED",
    "Session expired": "WS_AUTH_SESSION_EXPIRED",
    "Account locked": "WS_AUTH_ACCOUNT_LOCKED",
    "Invalid credentials": "WS_AUTH_INVALID_CREDENTIALS",
    "Maximum connections exceeded": "WS_AUTH_MAX_CONNECTIONS",
    "Internal authentication error": "WS_AUTH_INTERNAL_ERROR"
  };
  if (errorCodes[error]) {
    return errorCodes[error];
  }
  for (const [key, value] of Object.entries(errorCodes)) {
    if (error.toLowerCase().includes(key.toLowerCase())) {
      return value;
    }
  }
  switch (statusCode) {
    case 401:
      return "WS_AUTH_UNAUTHORIZED";
    case 403:
      return "WS_AUTH_FORBIDDEN";
    case 429:
      return "WS_AUTH_RATE_LIMITED";
    case 500:
      return "WS_AUTH_INTERNAL_ERROR";
    default:
      return "WS_AUTH_ERROR";
  }
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
      defaultLogger.info("\u2705 Tabla users creada");
    },
    down: async (db2) => {
      db2.exec("DROP TABLE IF EXISTS users");
      defaultLogger.info("\u2705 Tabla users eliminada");
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
      defaultLogger.info("\u2705 Tabla roles creada");
    },
    down: async (db2) => {
      db2.exec("DROP TABLE IF EXISTS roles");
      defaultLogger.info("\u2705 Tabla roles eliminada");
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
      defaultLogger.info("\u2705 Tabla permissions creada");
    },
    down: async (db2) => {
      db2.exec("DROP TABLE IF EXISTS permissions");
      defaultLogger.info("\u2705 Tabla permissions eliminada");
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
      defaultLogger.info("\u2705 Tabla user_roles creada");
    },
    down: async (db2) => {
      db2.exec("DROP TABLE IF EXISTS user_roles");
      defaultLogger.info("\u2705 Tabla user_roles eliminada");
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
      defaultLogger.info("\u2705 Tabla role_permissions creada");
    },
    down: async (db2) => {
      db2.exec("DROP TABLE IF EXISTS role_permissions");
      defaultLogger.info("\u2705 Tabla role_permissions eliminada");
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
      defaultLogger.info("\u2705 Tabla sessions creada");
    },
    down: async (db2) => {
      db2.exec("DROP TABLE IF EXISTS sessions");
      defaultLogger.info("\u2705 Tabla sessions eliminada");
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
      defaultLogger.info("\u2705 Tabla migration_history creada");
    },
    down: async (db2) => {
      db2.exec("DROP TABLE IF EXISTS migration_history");
      defaultLogger.info("\u2705 Tabla migration_history eliminada");
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
      defaultLogger.info("\u2705 Campos description agregados a roles y permissions");
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
      defaultLogger.info("\u2705 Campos description removidos de roles y permissions");
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
      defaultLogger.info("\u2705 Campos first_name y last_name agregados a users");
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
      defaultLogger.info("\u2705 Campos first_name y last_name removidos de users");
    }
  },
  {
    version: 10,
    name: "add_last_login_at_field",
    up: async (db2) => {
      db2.exec(`
        ALTER TABLE users ADD COLUMN last_login_at DATETIME
      `);
      defaultLogger.info("\u2705 Campo last_login_at agregado a users");
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
      defaultLogger.info("\u2705 Campo last_login_at removido de users");
    }
  },
  {
    version: 11,
    name: "add_roles_is_active_field",
    up: async (db2) => {
      db2.exec(`
        ALTER TABLE roles ADD COLUMN is_active BOOLEAN DEFAULT 1
      `);
      defaultLogger.info("\u2705 Campo is_active agregado a roles");
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
      defaultLogger.info("\u2705 Campo is_active removido de roles");
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
  defaultLogger.info("\uD83D\uDD04 Iniciando migraciones...");
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
  defaultLogger.info(`\uD83D\uDCCA Versi\xF3n actual de la base de datos: ${currentVersion}`);
  const pendingMigrations = migrations.filter((m) => m.version > currentVersion);
  if (pendingMigrations.length === 0) {
    defaultLogger.info("\u2705 No hay migraciones pendientes");
    return;
  }
  defaultLogger.info(`\uD83D\uDCCB ${pendingMigrations.length} migraciones pendientes`);
  try {
    db2.exec("BEGIN TRANSACTION");
    for (const migration of pendingMigrations) {
      defaultLogger.info(`\u26A1 Ejecutando migraci\xF3n ${migration.version}: ${migration.name}`);
      await migration.up(db2);
      if (migration.name !== "create_migration_history_table") {
        await recordMigration(migration.version, migration.name);
      }
      defaultLogger.info(`\u2705 Migraci\xF3n ${migration.version} completada`);
    }
    db2.exec("COMMIT");
    defaultLogger.info("\uD83C\uDF89 Todas las migraciones completadas exitosamente");
  } catch (error) {
    db2.exec("ROLLBACK");
    console.error("\u274C Error durante las migraciones:", error);
    throw error;
  }
}
async function rollbackMigrations(targetVersion) {
  defaultLogger.info(`\uD83D\uDD04 Revirtiendo migraciones hasta la versi\xF3n ${targetVersion}...`);
  const db2 = getDatabase();
  const currentVersion = await getCurrentVersion();
  if (targetVersion >= currentVersion) {
    defaultLogger.info("\u2705 No hay migraciones para revertir");
    return;
  }
  const migrationsToRollback = migrations.filter((m) => m.version > targetVersion && m.version <= currentVersion).sort((a, b) => b.version - a.version);
  defaultLogger.info(`\uD83D\uDCCB ${migrationsToRollback.length} migraciones a revertir`);
  try {
    db2.exec("BEGIN TRANSACTION");
    for (const migration of migrationsToRollback) {
      defaultLogger.info(`\u26A1 Revirtiendo migraci\xF3n ${migration.version}: ${migration.name}`);
      await migration.down(db2);
      db2.query("DELETE FROM migration_history WHERE version = ?").run(migration.version);
      defaultLogger.info(`\u2705 Migraci\xF3n ${migration.version} revertida`);
    }
    db2.exec("COMMIT");
    defaultLogger.info("\uD83C\uDF89 Rollback completado exitosamente");
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
  defaultLogger.info("\uD83D\uDD04 Reseteando base de datos...");
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
    defaultLogger.info("\u2705 Base de datos reseteada");
    await runMigrations();
  } catch (error) {
    db2.exec("ROLLBACK");
    console.error("\u274C Error al resetear la base de datos:", error);
    throw error;
  }
}

// src/scripts/seed.ts
defaultLogger.silence();
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
var seedConfig = {
  createTestUsers: true,
  createDemoContent: true,
  userCount: process.env.SEED_USER_COUNT ? parseInt(process.env.SEED_USER_COUNT) : 15,
  skipExistingUsers: true,
  defaultPassword: process.env.DEFAULT_SEED_PASSWORD || "DevPassword123!"
};
function generateInitialUsers(options = {}) {
  const {
    includeAdmin = true,
    includeModerator = true,
    includeEditor = true,
    includeAuthor = true,
    includeUser = true,
    includeGuest = true,
    customUsers = []
  } = options;
  const users = [];
  if (includeAdmin) {
    users.push({
      email: "admin@blogapi.com",
      password: "Admin123!@#",
      firstName: "Admin",
      lastName: "User",
      roles: ["admin"]
    });
  }
  if (includeModerator) {
    users.push({
      email: "moderator@blogapi.com",
      password: "Moderator123!",
      firstName: "Moderator",
      lastName: "User",
      roles: ["moderator"]
    });
  }
  if (includeEditor) {
    users.push({
      email: "editor@blogapi.com",
      password: "Editor123!",
      firstName: "Editor",
      lastName: "User",
      roles: ["editor"]
    });
  }
  if (includeAuthor) {
    users.push({
      email: "author@blogapi.com",
      password: "Author123!",
      firstName: "Author",
      lastName: "User",
      roles: ["author"]
    });
  }
  if (includeUser) {
    users.push({
      email: "user@blogapi.com",
      password: "User123!",
      firstName: "Regular",
      lastName: "User",
      roles: ["user"]
    });
  }
  if (includeGuest) {
    users.push({
      email: "guest@blogapi.com",
      password: "Guest123!",
      firstName: "Guest",
      lastName: "User",
      roles: ["guest"]
    });
  }
  users.push(...customUsers);
  return users;
}
var initialUsers = generateInitialUsers();
function generateTestUsers(count) {
  const testUsers = [];
  const firstNames = ["Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace", "Henry", "Ivy", "Jack"];
  const lastNames = ["Adams", "Baker", "Clark", "Davis", "Evans", "Fisher", "Green", "Harris", "Jones", "King"];
  const roles = ["user", "author", "editor"];
  for (let i = 0;i < count; i++) {
    const firstName = firstNames[i % firstNames.length];
    const lastName = lastNames[Math.floor(i / firstNames.length) % lastNames.length];
    const role = roles[i % roles.length];
    testUsers.push({
      email: `test.user${i + 1}@blogapi.com`,
      password: seedConfig.defaultPassword,
      firstName,
      lastName,
      roles: [role]
    });
  }
  return testUsers;
}
function getAllUsers() {
  let allUsers = [...initialUsers];
  if (seedConfig.createTestUsers && true) {
    const testUsers = generateTestUsers(seedConfig.userCount - initialUsers.length);
    allUsers = [...allUsers, ...testUsers];
  }
  return allUsers;
}
async function seedDatabase(dbPath, allUsers = getAllUsers()) {
  try {
    defaultLogger.info("\uD83C\uDF31 Starting database seeding...");
    initDatabase(dbPath);
    await runMigrations();
    const permissionService = new PermissionService;
    const authService = new AuthService;
    const createdPermissions = new Map;
    for (const permission of initialPermissions) {
      try {
        const result = await permissionService.createPermission(permission);
        if (result && result.role) {
          createdPermissions.set(permission.name, result.role.id);
        }
      } catch (error) {}
    }
    const createdRoles = new Map;
    for (const role of initialRoles) {
      try {
        const result = await permissionService.createRole({
          name: role.name,
          description: role.description
        });
        if (result && result.role) {
          createdRoles.set(role.name, result.role?.id);
          for (const permissionName of role.permissions || []) {
            const permissionId = createdPermissions.get(permissionName);
            if (permissionId) {
              await permissionService.assignPermissionsToRole(result.role?.id, [permissionId]);
            }
          }
        }
      } catch (error) {}
    }
    let createdCount = 0;
    let skippedCount = 0;
    for (const user of allUsers) {
      try {
        const result = await authService.register({
          email: user.email,
          password: user.password
        });
        if (result) {
          createdCount++;
          for (const roleName of user.roles) {
            if (result.user) {
              await authService.assignRole(result.user.id, roleName);
            }
          }
        }
      } catch (error) {
        if (seedConfig.skipExistingUsers) {
          skippedCount++;
        }
      }
    }
    defaultLogger.info("\u2728 Seeding completed successfully!");
    defaultLogger.info(`\uD83D\uDCCA Summary: ${createdCount} users created, ${skippedCount} skipped`);
  } catch (error) {
    console.error("\u274C Error during seeding:", error);
    if (true) {
      throw error;
    }
  }
}
async function cleanDatabase(dbPath) {
  defaultLogger.info("\uD83E\uDDF9 Cleaning database...");
  try {
    if (!isDatabaseInitialized()) {
      initDatabase(dbPath);
    }
    let db2 = getDatabase();
    try {
      db2.exec("PRAGMA foreign_keys = OFF");
    } catch (error) {
      if (error instanceof Error && (error.message.includes("Database has closed") || error.message.includes("Cannot use a closed database"))) {
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
      } catch (error) {}
    }
    db2.exec("PRAGMA foreign_keys = ON");
    defaultLogger.info("\u2705 Database cleaned successfully");
  } catch (error) {
    console.error("\u274C Error during cleanup:", error);
    if (true) {
      throw error;
    }
  }
}
async function resetDatabase2() {
  try {
    defaultLogger.info("\uD83D\uDD04 Resetting database...");
    await cleanDatabase();
    await seedDatabase();
    defaultLogger.info("\u2728 Database reset successfully!");
  } catch (error) {
    console.error("\u274C Error during reset:", error);
    throw error;
  }
}
async function checkDatabaseStatus() {
  try {
    defaultLogger.info("\uD83D\uDD0D Verificando estado de la base de datos...");
    const db2 = getDatabase();
    const tables = ["users", "roles", "permissions", "user_roles", "role_permissions", "sessions"];
    defaultLogger.info(`
\uD83D\uDCCA Estado actual:`);
    for (const table of tables) {
      try {
        const result = db2.query(`SELECT COUNT(*) as count FROM ${table}`).get();
        defaultLogger.info(`  ${table}: ${result.count} registros`);
      } catch (error) {
        defaultLogger.info(`  ${table}: Tabla no existe`);
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
        defaultLogger.info(`
\uD83D\uDC65 Usuarios y sus roles:`);
        usersWithRoles.forEach((user) => {
          defaultLogger.info(`  ${user.email}: ${user.roles || "Sin roles"}`);
        });
      }
    } catch (error) {
      defaultLogger.info("  \u26A0\uFE0F  No se pudieron obtener usuarios con roles");
    }
  } catch (error) {
    console.error("\u274C Error verificando estado:", error);
    throw error;
  }
}
async function seedTestUsersOnly(count) {
  try {
    defaultLogger.info("\uD83E\uDDEA Creando solo usuarios de prueba...");
    const userCount = count || 10;
    const testUsers = generateTestUsers(userCount);
    initDatabase();
    await runMigrations();
    const authService = new AuthService;
    let createdCount = 0;
    for (const user of testUsers) {
      try {
        const result = await authService.register({
          email: user.email,
          password: user.password
        });
        if (result && result.user) {
          createdCount++;
          defaultLogger.info(`  \u2705 Usuario de prueba creado: ${user.email}`);
          for (const roleName of user.roles) {
            await authService.assignRole(result.user.id, roleName);
          }
        }
      } catch (error) {
        defaultLogger.info(`  \u26A0\uFE0F  Usuario ya existe: ${user.email}`);
      }
    }
    defaultLogger.info(`
\u2728 ${createdCount} usuarios de prueba creados exitosamente!`);
  } catch (error) {
    console.error("\u274C Error creando usuarios de prueba:", error);
    throw error;
  }
}
async function mainSeed() {
  const command = process.argv[2];
  const param = process.argv[3];
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
    case "test-users":
      const count = param ? parseInt(param) : undefined;
      await seedTestUsersOnly(count);
      break;
    default:
      defaultLogger.info("Uso: bun run src/scripts/seed.ts [comando] [par\xE1metros]");
      defaultLogger.info(`
Comandos disponibles:`);
      defaultLogger.info("  seed        - Poblar base de datos con datos iniciales");
      defaultLogger.info("  clean       - Limpiar todos los datos");
      defaultLogger.info("  reset       - Limpiar y volver a poblar");
      defaultLogger.info("  status      - Verificar estado actual");
      defaultLogger.info("  config      - Mostrar configuraci\xF3n actual");
      defaultLogger.info("  test-users  - Crear solo usuarios de prueba [cantidad]");
      defaultLogger.info(`
Ejemplos:`);
      defaultLogger.info("  bun run src/scripts/seed.ts seed");
      defaultLogger.info("  bun run src/scripts/seed.ts test-users 20");
      defaultLogger.info("  NODE_ENV=development SEED_USER_COUNT=25 bun run src/scripts/seed.ts seed");
      defaultLogger.info('  DEFAULT_SEED_PASSWORD="MyCustomPass123!" bun run src/scripts/seed.ts test-users 5');
  }
}
if (process.argv[1] && process.argv[1].endsWith("seed.ts") && true) {
  mainSeed().catch(console.error);
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
      const query = {};
      const url = new URL(c.req.url);
      url.searchParams.forEach((value, key) => {
        if (query[key]) {
          if (Array.isArray(query[key])) {
            query[key].push(value);
          } else {
            query[key] = [query[key], value];
          }
        } else {
          query[key] = value;
        }
      });
      const authRequest = {
        headers,
        query,
        url: c.req.url
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
        return createHonoAuthErrorResponse(c, result.error, result.statusCode);
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
      return createHonoAuthErrorResponse(c, "Internal authentication error", 500, {
        details: error.message
      });
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
function createHonoAuthErrorResponse(c, error = "Authentication failed", statusCode = 401, additionalData) {
  const errorResponse = {
    success: false,
    error: getDetailedAuthError(error, statusCode),
    code: getAuthErrorCode(error, statusCode),
    timestamp: new Date().toISOString(),
    path: c.req.path,
    method: c.req.method
  };
  if (additionalData) {
    Object.assign(errorResponse, additionalData);
  }
  if (statusCode === 401) {
    c.header("WWW-Authenticate", 'Bearer realm="API"');
  }
  return c.json(errorResponse, statusCode);
}
function getDetailedAuthError(error, statusCode) {
  const errorMappings = {
    "Invalid token": "The provided authentication token is invalid or malformed. Please check your token and try again.",
    "Token expired": "Your authentication token has expired. Please obtain a new token and try again.",
    "No token provided": "Authentication token is required. Please provide a valid Bearer token in the Authorization header.",
    "Insufficient permissions": "You do not have the required permissions to access this resource.",
    "User not found": "The user associated with this token could not be found or has been deactivated.",
    "Token revoked": "This authentication token has been revoked. Please obtain a new token.",
    "Invalid signature": "The token signature is invalid. This may indicate a compromised or tampered token.",
    "Malformed token": "The authentication token format is incorrect. Please ensure you are using a valid JWT token.",
    "Authentication required": "This endpoint requires authentication. Please provide a valid Bearer token.",
    "Session expired": "Your session has expired. Please log in again to continue.",
    "Account locked": "Your account has been temporarily locked due to security reasons. Please contact support.",
    "Invalid credentials": "The provided credentials are incorrect. Please check your username and password."
  };
  if (errorMappings[error]) {
    return errorMappings[error];
  }
  for (const [key, value] of Object.entries(errorMappings)) {
    if (error.toLowerCase().includes(key.toLowerCase())) {
      return value;
    }
  }
  switch (statusCode) {
    case 401:
      return error.includes("token") ? "Authentication failed: Invalid or missing token. Please provide a valid Bearer token in the Authorization header." : "Authentication required. Please provide valid credentials to access this resource.";
    case 403:
      return "Access forbidden: You do not have sufficient permissions to perform this action.";
    case 429:
      return "Rate limit exceeded: Too many requests. Please wait before trying again.";
    default:
      return error || "Authentication error occurred.";
  }
}
function getAuthErrorCode(error, statusCode) {
  const errorCodes = {
    "Invalid token": "AUTH_INVALID_TOKEN",
    "Token expired": "AUTH_TOKEN_EXPIRED",
    "No token provided": "AUTH_TOKEN_MISSING",
    "Insufficient permissions": "AUTH_INSUFFICIENT_PERMISSIONS",
    "User not found": "AUTH_USER_NOT_FOUND",
    "Token revoked": "AUTH_TOKEN_REVOKED",
    "Invalid signature": "AUTH_INVALID_SIGNATURE",
    "Malformed token": "AUTH_MALFORMED_TOKEN",
    "Authentication required": "AUTH_REQUIRED",
    "Session expired": "AUTH_SESSION_EXPIRED",
    "Account locked": "AUTH_ACCOUNT_LOCKED",
    "Invalid credentials": "AUTH_INVALID_CREDENTIALS"
  };
  if (errorCodes[error]) {
    return errorCodes[error];
  }
  for (const [key, value] of Object.entries(errorCodes)) {
    if (error.toLowerCase().includes(key.toLowerCase())) {
      return value;
    }
  }
  switch (statusCode) {
    case 401:
      return "AUTH_UNAUTHORIZED";
    case 403:
      return "AUTH_FORBIDDEN";
    case 429:
      return "AUTH_RATE_LIMITED";
    default:
      return "AUTH_ERROR";
  }
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
        headers: req.headers,
        url: req.path,
        method: req.method,
        query: req.query || {},
        params: req.params || {}
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
        return createExpressAuthErrorResponse(res, req, result.error, result.statusCode);
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
      return createExpressAuthErrorResponse(res, req, "Internal authentication error", 500, {
        details: error.message
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
function createExpressAuthErrorResponse(res, req, error = "Authentication failed", statusCode = 401, additionalData) {
  const errorResponse = {
    success: false,
    error: getDetailedAuthError2(error, statusCode),
    code: getAuthErrorCode2(error, statusCode),
    timestamp: new Date().toISOString(),
    path: req.path,
    method: req.method
  };
  if (additionalData) {
    Object.assign(errorResponse, additionalData);
  }
  if (statusCode === 401) {
    res.setHeader("WWW-Authenticate", 'Bearer realm="API"');
  }
  return res.status(statusCode).json(errorResponse);
}
function getDetailedAuthError2(error, statusCode) {
  const errorMappings = {
    "Invalid token": "The provided authentication token is invalid or malformed. Please check your token and try again.",
    "Token expired": "Your authentication token has expired. Please obtain a new token and try again.",
    "No token provided": "Authentication token is required. Please provide a valid Bearer token in the Authorization header.",
    "Insufficient permissions": "You do not have the required permissions to access this resource.",
    "User not found": "The user associated with this token could not be found or has been deactivated.",
    "Token revoked": "This authentication token has been revoked. Please obtain a new token.",
    "Invalid signature": "The token signature is invalid. This may indicate a compromised or tampered token.",
    "Malformed token": "The authentication token format is incorrect. Please ensure you are using a valid JWT token.",
    "Authentication required": "This endpoint requires authentication. Please provide a valid Bearer token.",
    "Session expired": "Your session has expired. Please log in again to continue.",
    "Account locked": "Your account has been temporarily locked due to security reasons. Please contact support.",
    "Invalid credentials": "The provided credentials are incorrect. Please check your username and password."
  };
  if (errorMappings[error]) {
    return errorMappings[error];
  }
  for (const [key, value] of Object.entries(errorMappings)) {
    if (error.toLowerCase().includes(key.toLowerCase())) {
      return value;
    }
  }
  switch (statusCode) {
    case 401:
      return error.includes("token") ? "Authentication failed: Invalid or missing token. Please provide a valid Bearer token in the Authorization header." : "Authentication required. Please provide valid credentials to access this resource.";
    case 403:
      return "Access forbidden: You do not have sufficient permissions to perform this action.";
    case 429:
      return "Rate limit exceeded: Too many requests. Please wait before trying again.";
    default:
      return error || "Authentication error occurred.";
  }
}
function getAuthErrorCode2(error, statusCode) {
  const errorCodes = {
    "Invalid token": "AUTH_INVALID_TOKEN",
    "Token expired": "AUTH_TOKEN_EXPIRED",
    "No token provided": "AUTH_TOKEN_MISSING",
    "Insufficient permissions": "AUTH_INSUFFICIENT_PERMISSIONS",
    "User not found": "AUTH_USER_NOT_FOUND",
    "Token revoked": "AUTH_TOKEN_REVOKED",
    "Invalid signature": "AUTH_INVALID_SIGNATURE",
    "Malformed token": "AUTH_MALFORMED_TOKEN",
    "Authentication required": "AUTH_REQUIRED",
    "Session expired": "AUTH_SESSION_EXPIRED",
    "Account locked": "AUTH_ACCOUNT_LOCKED",
    "Invalid credentials": "AUTH_INVALID_CREDENTIALS"
  };
  if (errorCodes[error]) {
    return errorCodes[error];
  }
  for (const [key, value] of Object.entries(errorCodes)) {
    if (error.toLowerCase().includes(key.toLowerCase())) {
      return value;
    }
  }
  switch (statusCode) {
    case 401:
      return "AUTH_UNAUTHORIZED";
    case 403:
      return "AUTH_FORBIDDEN";
    case 429:
      return "AUTH_RATE_LIMITED";
    default:
      return "AUTH_ERROR";
  }
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
    console.log(`  \uD83D\uDCC5 Creado: ${new Date(role.createdAt).toLocaleString()}`);
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
  name: "Framework-Agnostic Authentication Library",
  version: "1.0.8",
  description: "A comprehensive framework-agnostic authentication and authorization library built with TypeScript, Bun, and SQLite",
  author: "Auth Library Development Team",
  license: "MIT",
  repository: "https://github.com/auth-library/framework-agnostic-auth",
  frameworks: ["Hono", "Express", "WebSockets", "Socket.IO", "Fastify"],
  runtime: "Bun",
  database: "SQLite",
  features: [
    "Framework-agnostic design",
    "Full TypeScript support",
    "SQLite with Bun runtime",
    "Secure JWT with Web Crypto API",
    "Complete RBAC (Role-Based Access Control)",
    "Reusable middleware components",
    "Automatic database migrations",
    "Comprehensive utility scripts",
    "Flexible configuration system",
    "Advanced logging and monitoring",
    "Built-in rate limiting",
    "CORS support",
    "Input validation and sanitization",
    "WebSocket authentication",
    "Session management",
    "Password hashing with Bun.password",
    "Refresh token support",
    "Multi-tenant support",
    "Audit logging",
    "Error handling and recovery"
  ],
  security: [
    "Bcrypt password hashing",
    "JWT token validation",
    "CSRF protection",
    "Rate limiting",
    "Input sanitization",
    "SQL injection prevention",
    "XSS protection"
  ],
  performance: [
    "Optimized for Bun runtime",
    "Connection pooling",
    "Efficient SQLite queries",
    "Minimal memory footprint",
    "Fast startup time"
  ]
};
console.log(`\uD83D\uDCDA ${AUTH_LIBRARY_INFO.name} v${AUTH_LIBRARY_INFO.version} loaded successfully`);
export {
  validateAuthConfig,
  testConnection,
  sendToUsersWithRoles,
  sendToUsersWithPermissions,
  sendToUser,
  seedTestUsersOnly,
  seedDatabase,
  runMigrations,
  runDevCommand,
  rollbackMigrations,
  resetDatabase as resetDatabaseMigrations,
  resetDatabase2 as resetDatabase,
  printConfig,
  mainSeed,
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
  ValidationError,
  UserNotFoundError,
  TokenError,
  ServerError,
  SECURITY_CONFIG,
  RateLimitError,
  PermissionService,
  PROD_CONFIG,
  NotFoundError,
  JWTService,
  ErrorHandler,
  DatabaseError,
  DEV_CONFIG,
  DEFAULT_AUTH_CONFIG,
  AuthorizationError,
  AuthenticationError,
  AuthService,
  AuthLibrary,
  AuthErrorFactory,
  AuthError,
  AccountError,
  AUTH_LIBRARY_INFO
};

//# debugId=2D0A790244F6391164756E2164756E21
//# sourceMappingURL=index.js.map
