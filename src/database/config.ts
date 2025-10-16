import type { TableSchema, ColumnDefinition } from './base-controller';

/**
 * Configuration interface for custom table names and schema extensions
 */
export interface DatabaseTableConfig {
  /** Custom table name (default: 'users') */
  users?: string;
  /** Custom table name (default: 'roles') */
  roles?: string;
  /** Custom table name (default: 'permissions') */
  permissions?: string;
  /** Custom table name (default: 'user_roles') */
  userRoles?: string;
  /** Custom table name (default: 'role_permissions') */
  rolePermissions?: string;
  /** Custom table name (default: 'sessions') */
  sessions?: string;
}

/**
 * Interface for extending table schemas with additional columns
 */
export interface SchemaExtension {
  /** Additional columns to add to the table */
  additionalColumns?: ColumnDefinition[];
  /** Columns to modify (will override existing columns) */
  modifiedColumns?: ColumnDefinition[];
  /** Columns to remove from the table */
  removedColumns?: string[];
}

/**
 * Configuration for extending table schemas
 */
export interface DatabaseSchemaExtensions {
  /** Extensions for users table */
  users?: SchemaExtension;
  /** Extensions for roles table */
  roles?: SchemaExtension;
  /** Extensions for permissions table */
  permissions?: SchemaExtension;
  /** Extensions for user_roles table */
  userRoles?: SchemaExtension;
  /** Extensions for role_permissions table */
  rolePermissions?: SchemaExtension;
  /** Extensions for sessions table */
  sessions?: SchemaExtension;
}

/**
 * Main database configuration interface
 */
export interface DatabaseConfig {
  /** Custom table names */
  tableNames?: DatabaseTableConfig;
  /** Schema extensions */
  schemaExtensions?: DatabaseSchemaExtensions;
  /** Whether to enable automatic migrations */
  enableMigrations?: boolean;
  /** Whether to enable foreign key constraints */
  enableForeignKeys?: boolean;
}

/**
 * Default table names
 */
export const DEFAULT_TABLE_NAMES: Required<DatabaseTableConfig> = {
  users: 'users',
  roles: 'roles',
  permissions: 'permissions',
  userRoles: 'user_roles',
  rolePermissions: 'role_permissions',
  sessions: 'sessions'
};

/**
 * Default configuration
 */
export const DEFAULT_DATABASE_CONFIG: DatabaseConfig = {
  tableNames: DEFAULT_TABLE_NAMES,
  schemaExtensions: {},
  enableMigrations: true,
  enableForeignKeys: true
};

/**
 * Global database configuration instance
 * This can be modified at runtime to customize table names and schemas
 */
let globalDatabaseConfig: DatabaseConfig = { ...DEFAULT_DATABASE_CONFIG };

/**
 * Set the global database configuration
 * Call this before initializing the database
 */
export function setDatabaseConfig(config: DatabaseConfig): void {
  globalDatabaseConfig = {
    ...DEFAULT_DATABASE_CONFIG,
    ...config,
    tableNames: {
      ...DEFAULT_TABLE_NAMES,
      ...config.tableNames
    },
    schemaExtensions: {
      ...config.schemaExtensions
    }
  };
}

/**
 * Get the current global database configuration
 */
export function getDatabaseConfig(): DatabaseConfig {
  return globalDatabaseConfig;
}

/**
 * Get a specific table name with fallback to default
 */
export function getTableName(tableKey: keyof DatabaseTableConfig): string {
  const config = getDatabaseConfig();
  const tableNames = config.tableNames || DEFAULT_TABLE_NAMES;
  return tableNames[tableKey] || DEFAULT_TABLE_NAMES[tableKey];
}

/**
 * Get all configured table names
 */
export function getAllTableNames(): Required<DatabaseTableConfig> {
  const config = getDatabaseConfig();
  return {
    ...DEFAULT_TABLE_NAMES,
    ...config.tableNames
  };
}

/**
 * Utility function to create a schema extension
 */
export function createSchemaExtension(
  additionalColumns?: ColumnDefinition[],
  modifiedColumns?: ColumnDefinition[],
  removedColumns?: string[]
): SchemaExtension {
  return {
    additionalColumns,
    modifiedColumns,
    removedColumns
  };
}

/**
 * Predefined common column definitions that can be used in extensions
 */
export const COMMON_COLUMNS = {
  // Timestamp columns
  createdAt: { name: 'created_at', type: 'DATETIME', defaultValue: 'CURRENT_TIMESTAMP' },
  updatedAt: { name: 'updated_at', type: 'DATETIME', defaultValue: 'CURRENT_TIMESTAMP' },
  deletedAt: { name: 'deleted_at', type: 'DATETIME' },

  // Soft delete columns
  isDeleted: { name: 'is_deleted', type: 'BOOLEAN', defaultValue: false },

  // Common user fields
  phoneNumber: { name: 'phone_number', type: 'TEXT' },
  avatarUrl: { name: 'avatar_url', type: 'TEXT' },
  timezone: { name: 'timezone', type: 'TEXT', defaultValue: 'UTC' },
  language: { name: 'language', type: 'TEXT', defaultValue: 'en' },

  // Status fields
  status: { name: 'status', type: 'TEXT', defaultValue: 'active' },
  isActive: { name: 'is_active', type: 'BOOLEAN', defaultValue: true },

  // Audit fields
  createdBy: { name: 'created_by', type: 'TEXT' },
  updatedBy: { name: 'updated_by', type: 'TEXT' },

  // Metadata
  metadata: { name: 'metadata', type: 'TEXT' } // JSON string
} as const;
