/**
 * Safe Database Initializer with TypeScript support
 * Provides type-safe database initialization, migrations, and integrity checks
 */

import type { Database } from 'bun:sqlite';
import { BaseController, type TableSchema, type ControllerResponse } from './base-controller';
import type { User, Role,Permission } from '../types/auth';
// Type definitions for better type safety
export interface DatabaseConfig {
  database: Database;
  logger?: Logger;
  enableWAL?: boolean;
  enableForeignKeys?: boolean;
  // Permite pasar esquemas externos desde fuera de la librería
  externalSchemas?: TableSchema[];
}

interface Logger {
  info(message: string, ...args: any[]): void;
  warn(message: string, ...args: any[]): void;
  error(message: string, ...args: any[]): void;
}

export interface MigrationResult {
  success: boolean;
  tablesCreated: string[];
  indexesCreated: string[];
  errors: string[];
  duration: number;
}

export interface IntegrityCheckResult {
  isValid: boolean;
  missingTables: string[];
  missingIndexes: string[];
  issues: string[];
}

// Default logger implementation
const defaultLogger: Logger = {
  info: (msg: string, ...args: any[]) => console.log(`[INFO] ${msg}`, ...args),
  warn: (msg: string, ...args: any[]) => console.warn(`[WARN] ${msg}`, ...args),
  error: (msg: string, ...args: any[]) => console.error(`[ERROR] ${msg}`, ...args)
};
const silenceLogger: Logger = {
  info: (msg: string, ...args: any[]) => {},
  warn: (msg: string, ...args: any[]) => {},
  error: (msg: string, ...args: any[]) => {}
};
// Database table schemas using your existing structure
export const DATABASE_SCHEMAS: TableSchema[] = [
  {
    tableName: "users",
    columns: [
      { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
      { name: "email", type: "TEXT", unique: true, notNull: true },
      { name: "password_hash", type: "TEXT", notNull: true },
      { name: "first_name", type: "TEXT" },
      { name: "last_name", type: "TEXT" },
      { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" },
      { name: "updated_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" },
      { name: "last_login_at", type: "DATETIME" },
      { name: "is_active", type: "BOOLEAN", defaultValue: true }
    ],
    indexes: [
      { name: "idx_users_email", columns: ["email"], unique: true },
      { name: "idx_users_active", columns: ["is_active"] }
    ]
  },
  {
    tableName: "roles",
    columns: [
      { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
      { name: "name", type: "TEXT", unique: true, notNull: true },
      { name: "description", type: "TEXT" },
      { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" },
      { name: "updated_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" },
      { name: "is_active", type: "BOOLEAN", defaultValue: true }
    ],
    indexes: [
      { name: "idx_roles_name", columns: ["name"], unique: true }
    ]
  },
  {
    tableName: "permissions",
    columns: [
      { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
      { name: "name", type: "TEXT", unique: true, notNull: true },
      { name: "resource", type: "TEXT", notNull: true },
      { name: "action", type: "TEXT", notNull: true },
      { name: "description", type: "TEXT" },
      { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" }
    ],
    indexes: [
      { name: "idx_permissions_name", columns: ["name"], unique: true },
      { name: "idx_permissions_resource", columns: ["resource"] },
      { name: "idx_permissions_action", columns: ["action"] }
    ]
  },
  {
    tableName: "user_roles",
    columns: [
      { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
      { name: "user_id", type: "TEXT", notNull: true, references: { table: "users", column: "id" } },
      { name: "role_id", type: "TEXT", notNull: true, references: { table: "roles", column: "id" } },
      { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" },
      { name: "updated_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" }
    ],
    indexes: [
      { name: "idx_user_roles_user_id", columns: ["user_id"] },
      { name: "idx_user_roles_role_id", columns: ["role_id"] },
      { name: "idx_user_roles_unique", columns: ["user_id", "role_id"], unique: true }
    ]
  },
  {
    tableName: "role_permissions",
    columns: [
      { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
      { name: "role_id", type: "TEXT", notNull: true, references: { table: "roles", column: "id" } },
      { name: "permission_id", type: "TEXT", notNull: true, references: { table: "permissions", column: "id" } },
      { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" },
      { name: "updated_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" }
    ],
    indexes: [
      { name: "idx_role_permissions_role_id", columns: ["role_id"] },
      { name: "idx_role_permissions_permission_id", columns: ["permission_id"] },
      { name: "idx_role_permissions_unique", columns: ["role_id", "permission_id"], unique: true }
    ]
  },
  {
    tableName: "sessions",
    columns: [
      { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
      { name: "user_id", type: "TEXT", notNull: true, references: { table: "users", column: "id" } },
      { name: "token", type: "TEXT", unique: true, notNull: true },
      { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" },
      { name: "expires_at", type: "DATETIME", notNull: true },
      { name: "last_activity", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" },
      { name: "ip_address", type: "TEXT" },
      { name: "user_agent", type: "TEXT" },
      { name: "is_active", type: "BOOLEAN", defaultValue: true }
    ],
    indexes: [
      { name: "idx_sessions_user_id", columns: ["user_id"] },
      { name: "idx_sessions_token", columns: ["token"], unique: true },
      { name: "idx_sessions_expires_at", columns: ["expires_at"] },
      { name: "idx_sessions_active", columns: ["is_active"] }
    ]
  }
];

// Alias público para el conjunto por defecto (retrocompatibilidad y claridad)
export const DEFAULT_SCHEMAS = DATABASE_SCHEMAS;

// API ligera para registrar y combinar esquemas desde fuera de la librería
export class SchemaRegistry {
  private schemas: Map<string, TableSchema> = new Map();

  constructor(initial: TableSchema[] = []) {
    this.registerMany(initial);
  }

  register(schema: TableSchema) {
    this.schemas.set(schema.tableName, schema);
  }

  registerMany(schemas: TableSchema[]) {
    for (const s of schemas) this.register(s);
  }

  remove(tableName: string) {
    this.schemas.delete(tableName);
  }

  has(tableName: string) {
    return this.schemas.has(tableName);
  }

  get(tableName: string) {
    return this.schemas.get(tableName);
  }

  getAll(): TableSchema[] {
    return Array.from(this.schemas.values());
  }

  static merge(...registries: SchemaRegistry[]) {
    const merged = new SchemaRegistry();
    for (const r of registries) merged.registerMany(r.getAll());
    return merged;
  }
}

export class DatabaseInitializer {
  private database: Database;
  private logger: Logger;
  private enableWAL: boolean;
  private enableForeignKeys: boolean;
  // Fuente efectiva de esquemas (base + externos)
  private schemas: TableSchema[];

  constructor(config: DatabaseConfig) {
    this.database = config.database;
    this.logger = config.logger || silenceLogger;
    this.enableWAL = config.enableWAL ?? true;
    this.enableForeignKeys = config.enableForeignKeys ?? true;
    // Combina los esquemas por defecto con los externos provistos por el consumidor
    this.schemas = [...DATABASE_SCHEMAS, ...(config.externalSchemas ?? [])];
  }

  /**
   * Get the database instance
   */
  get db(): Database {
    return this.database;
  }

  // Permite gestionar esquemas de manera dinámica
  getSchemas(): TableSchema[] {
    return [...this.schemas];
  }

  setSchemas(schemas: TableSchema[]) {
    this.schemas = [...schemas];
  }

  registerSchemas(schemas: TableSchema[] | TableSchema) {
    const list = Array.isArray(schemas) ? schemas : [schemas];
    // Dedupe por tableName
    const map = new Map(this.schemas.map(s => [s.tableName, s] as const));
    for (const s of list) map.set(s.tableName, s);
    this.schemas = Array.from(map.values());
  }

  /**
   * Initialize database with all required tables and indexes
   */
  async seedDefaults() {
    const roleController = this.createController<Role>('roles');
    const permissionController = this.createController<Permission>('permissions');
    const rolePermissionController = this.createController<RolePermission>('role_permissions');

    // Seed default roles
    const roles = [
      { name: 'admin', description: 'Administrator role' },
      { name: 'moderator', description: 'Moderator role' },
      { name: 'user', description: 'Standard user role' }
    ];

    for (const role of roles) {
      const existing = await roleController.findFirst({ name: role.name });
      if (!existing.data) {
        await roleController.create(role);
      }
    }

    // Seed default permissions
    const permissions = [
      { name: 'manage:users', resource: 'users', action: 'manage', description: 'Manage users' },
      { name: 'edit:content', resource: 'content', action: 'edit', description: 'Edit content' }
    ];

    for (const perm of permissions) {
      const existing = await permissionController.findFirst({ name: perm.name });
      if (!existing.data) {
        await permissionController.create(perm);
      }
    }

    // Assign permissions to roles
    const adminRole = await roleController.findFirst({ name: 'admin' });
    const moderatorRole = await roleController.findFirst({ name: 'moderator' });

    if (adminRole.data) {
      const manageUsers = await permissionController.findFirst({ name: 'manage:users' });
      if (manageUsers.data) {
        await rolePermissionController.create({ role_id: adminRole.data.id, permission_id: manageUsers.data.id });
      }
    }

    if (moderatorRole.data) {
      const editContent = await permissionController.findFirst({ name: 'edit:content' });
      if (editContent.data) {
        await rolePermissionController.create({ role_id: moderatorRole.data.id, permission_id: editContent.data.id });
      }
    }
  }

  async initialize(schemas?: TableSchema[]): Promise<MigrationResult> {
    const startTime = Date.now();
    const result: MigrationResult = {
      success: false,
      tablesCreated: [],
      indexesCreated: [],
      errors: [],
      duration: 0
    };

    const effectiveSchemas = schemas ?? this.schemas ?? DATABASE_SCHEMAS;

    this.logger.info('Starting database initialization...');

    try {
      // Configure database settings
      await this.configureDatabaseSettings();

      // Use BaseController's initialization method
      const initResult = await BaseController.initializeDatabase(
        this.database,
        effectiveSchemas,
        true // isSQLite
      );

      if (!initResult.success) {
        result.errors.push(initResult.error || 'Unknown initialization error');
        return result;
      }

      // Track what was created
      result.tablesCreated = effectiveSchemas.map(schema => schema.tableName);
      result.indexesCreated = effectiveSchemas.flatMap(schema => 
        schema.indexes?.map(idx => idx.name) || []
      );

      result.success = true;
      result.duration = Date.now() - startTime;

      this.logger.info(`Database initialized successfully in ${result.duration}ms`);
      this.logger.info(`Created ${result.tablesCreated.length} tables and ${result.indexesCreated.length} indexes`);

    } catch (error: any) {
      result.errors.push(error.message || 'Unknown error during initialization');
      this.logger.error('Database initialization failed:', error);
    }

    result.duration = Date.now() - startTime;
    return result;
  }

  /**
   * Check database integrity
   */
  async checkIntegrity(schemas?: TableSchema[]): Promise<IntegrityCheckResult> {
    const effectiveSchemas = schemas ?? this.schemas ?? DATABASE_SCHEMAS;
    const result: IntegrityCheckResult = {
      isValid: true,
      missingTables: [],
      missingIndexes: [],
      issues: []
    };

    try {
      // Check tables
      for (const schema of effectiveSchemas) {
        const tableExists = await this.checkTableExists(schema.tableName);
        if (!tableExists) {
          result.missingTables.push(schema.tableName);
          result.isValid = false;
        }

        // Check indexes for existing tables
        if (tableExists && schema.indexes) {
          for (const index of schema.indexes) {
            const indexExists = await this.checkIndexExists(index.name);
            if (!indexExists) {
              result.missingIndexes.push(index.name);
              result.isValid = false;
            }
          }
        }
      }

      // Log results
      if (result.isValid) {
        this.logger.info('Database integrity check passed');
      } else {
        this.logger.warn(`Database integrity issues found:\n          - Missing tables: ${result.missingTables.join(', ')}\n          - Missing indexes: ${result.missingIndexes.join(', ')}`);
      }

    } catch (error: any) {
      result.issues.push(error.message);
      result.isValid = false;
      this.logger.error('Error during integrity check:', error);
    }

    return result;
  }

  /**
   * Run migrations safely
   */
  async migrate(): Promise<MigrationResult> {
    this.logger.info('Starting database migration...');

    // First check current state
    const integrity = await this.checkIntegrity();

    // If database is intact, no migration needed
    if (integrity.isValid) {
      this.logger.info('Database is up to date, no migration needed');
      return {
        success: true,
        tablesCreated: [],
        indexesCreated: [],
        errors: [],
        duration: 0
      };
    }

    // Run initialization to fix issues
    return await this.initialize();
  }

  /**
   * Repair database by creating missing components
   */
  async repair(): Promise<MigrationResult> {
    this.logger.info('Starting database repair...');

    const integrity = await this.checkIntegrity();
    
    if (integrity.isValid) {
      this.logger.info('Database does not need repair');
      return {
        success: true,
        tablesCreated: [],
        indexesCreated: [],
        errors: [],
        duration: 0
      };
    }

    // Reinitialize to fix issues
    return await this.initialize();
  }

  /**
   * Reset database completely
   */
  async reset(schemas?: TableSchema[]): Promise<MigrationResult> {
    const effectiveSchemas = schemas ?? this.schemas ?? DATABASE_SCHEMAS;
    try {
      for (const schema of effectiveSchemas) {
        this.database.exec(`DROP TABLE IF EXISTS ${schema.tableName}`);
      }
      return await this.initialize(effectiveSchemas);
    } catch (error: any) {
      this.logger.error('Error during reset:', error);
      return {
        success: false,
        tablesCreated: [],
        indexesCreated: [],
        errors: [error.message],
        duration: 0
      };
    }
  }

  /**
   * Get database statistics
   */
  async getStatistics(): Promise<Record<string, any>> {
    const stats: Record<string, any> = {};

    try {
      for (const schema of this.schemas) {
        const controller = new BaseController(schema.tableName, {
          database: this.database,
          isSQLite: true
        });

        const count = await controller.count();
        stats[schema.tableName] = count.data || 0;
      }

      // Additional database info
      const dbInfo = this.database.query("PRAGMA database_list").all();
      stats._database_info = dbInfo;

    } catch (error: any) {
      this.logger.error('Error getting database statistics:', error);
      stats._error = error.message;
    }

    return stats;
  }

  /**
   * Configure database settings
   */
  private async configureDatabaseSettings(): Promise<void> {
    try {
      // Enable WAL mode for better performance
      if (this.enableWAL) {
        this.database.exec("PRAGMA journal_mode = WAL");
      }

      // Enable foreign key constraints
      if (this.enableForeignKeys) {
        this.database.exec("PRAGMA foreign_keys = ON");
      }

      // Other performance settings
      this.database.exec("PRAGMA synchronous = NORMAL");
      this.database.exec("PRAGMA cache_size = 1000");
      this.database.exec("PRAGMA temp_store = memory");

    } catch (error: any) {
      this.logger.warn('Error configuring database settings:', error);
    }
  }

  /**
   * Check if table exists
   */
  private async checkTableExists(tableName: string): Promise<boolean> {
    try {
      const result = this.database.query(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
      ).get(tableName);
      
      return !!result;
    } catch (error: any) {
      this.logger.error(`Error checking table ${tableName}:`, error);
      return false;
    }
  }

  /**
   * Check if index exists
   */
  private async checkIndexExists(indexName: string): Promise<boolean> {
    try {
      const result = this.database.query(
        "SELECT name FROM sqlite_master WHERE type='index' AND name=?"
      ).get(indexName);
      
      return !!result;
    } catch (error: any) {
      this.logger.error(`Error checking index ${indexName}:`, error);
      return false;
    }
  }

  /**
   * Create a controller instance for a specific table
   */
  createController<T = Record<string, any>>(tableName: string): BaseController<T> {
    return new BaseController<T>(tableName, {
      database: this.database,
      isSQLite: true
    });
  }
}

export interface UserRole {
  id: string;
  user_id: string;
  role_id: string;
  created_at: string;
  updated_at: string;
}

export interface RolePermission {
  id: string;
  role_id: string;
  permission_id: string;
  created_at: string;
  updated_at: string;
}

export interface Session {
  id: string;
  user_id: string;
  token: string;
  created_at: string;
  expires_at: string;
  last_activity: string;
  ip_address?: string;
  user_agent?: string;
  is_active: boolean;
}