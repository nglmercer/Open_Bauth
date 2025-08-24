import type { Database } from 'bun:sqlite';
import type { BaseEntity, SoftDeleteEntity, AuditFields, QueryOptions, DatabaseTransaction } from './common';

// ============================================================================
// DATABASE CONNECTION TYPES
// ============================================================================

/**
 * Database configuration
 */
export interface DatabaseConfig {
  filename: string;
  readonly?: boolean;
  create?: boolean;
  readwrite?: boolean;
  memory?: boolean;
  strict?: boolean;
  safeIntegers?: boolean;
  timeout?: number;
  busyTimeout?: number;
  prepareCache?: number;
}

/**
 * Database connection pool configuration
 */
export interface ConnectionPoolConfig {
  min: number;
  max: number;
  acquireTimeoutMillis: number;
  createTimeoutMillis: number;
  destroyTimeoutMillis: number;
  idleTimeoutMillis: number;
  reapIntervalMillis: number;
  createRetryIntervalMillis: number;
  propagateCreateError: boolean;
}

/**
 * Database connection interface
 */
export interface DatabaseConnection {
  db: Database;
  id: string;
  createdAt: Date;
  lastUsed: Date;
  inUse: boolean;
  transactionCount: number;
}

// ============================================================================
// QUERY TYPES
// ============================================================================

/**
 * SQL query parameters
 */
export type QueryParams = Record<string, any> | any[];

/**
 * Query result metadata
 */
export interface QueryMetadata {
  changes: number;
  lastInsertRowid: number;
  duration: number;
  sql: string;
  params?: QueryParams;
}

/**
 * Query execution options
 */
export interface QueryExecutionOptions {
  timeout?: number;
  prepare?: boolean;
  transaction?: DatabaseTransaction;
  returnMetadata?: boolean;
  logQuery?: boolean;
}

/**
 * Prepared statement interface
 */
export interface PreparedStatement {
  sql: string;
  params: string[];
  execute(params?: QueryParams): any;
  get(params?: QueryParams): any;
  all(params?: QueryParams): any[];
  run(params?: QueryParams): QueryMetadata;
  finalize(): void;
}

// ============================================================================
// SCHEMA TYPES
// ============================================================================

/**
 * Column data types
 */
export type ColumnType = 
  | 'INTEGER'
  | 'REAL'
  | 'TEXT'
  | 'BLOB'
  | 'NUMERIC'
  | 'BOOLEAN'
  | 'DATE'
  | 'DATETIME'
  | 'TIMESTAMP'
  | 'JSON';

/**
 * Column definition
 */
export interface ColumnDefinition {
  name: string;
  type: ColumnType;
  primaryKey?: boolean;
  autoIncrement?: boolean;
  notNull?: boolean;
  unique?: boolean;
  defaultValue?: any;
  check?: string;
  references?: {
    table: string;
    column: string;
    onDelete?: 'CASCADE' | 'SET NULL' | 'RESTRICT' | 'NO ACTION';
    onUpdate?: 'CASCADE' | 'SET NULL' | 'RESTRICT' | 'NO ACTION';
  };
}

/**
 * Index definition
 */
export interface IndexDefinition {
  name: string;
  table: string;
  columns: string[];
  unique?: boolean;
  where?: string;
}

/**
 * Table definition
 */
export interface TableDefinition {
  name: string;
  columns: ColumnDefinition[];
  indexes?: IndexDefinition[];
  constraints?: string[];
  withoutRowid?: boolean;
  strict?: boolean;
}

/**
 * Database schema
 */
export interface DatabaseSchema {
  version: number;
  tables: TableDefinition[];
  views?: ViewDefinition[];
  triggers?: TriggerDefinition[];
  functions?: FunctionDefinition[];
}

/**
 * View definition
 */
export interface ViewDefinition {
  name: string;
  sql: string;
  temporary?: boolean;
}

/**
 * Trigger definition
 */
export interface TriggerDefinition {
  name: string;
  table: string;
  when: 'BEFORE' | 'AFTER' | 'INSTEAD OF';
  event: 'INSERT' | 'UPDATE' | 'DELETE';
  condition?: string;
  action: string;
  temporary?: boolean;
}

/**
 * Function definition
 */
export interface FunctionDefinition {
  name: string;
  deterministic?: boolean;
  function: (...args: any[]) => any;
}

// ============================================================================
// MIGRATION TYPES
// ============================================================================

/**
 * Migration interface
 */
export interface Migration {
  id: string;
  name: string;
  version: number;
  up: (db: Database) => Promise<void> | void;
  down: (db: Database) => Promise<void> | void;
  createdAt: Date;
}

/**
 * Migration status
 */
export interface MigrationStatus {
  id: string;
  name: string;
  version: number;
  appliedAt: Date;
  checksum: string;
}

/**
 * Migration runner options
 */
export interface MigrationOptions {
  migrationsPath: string;
  tableName?: string;
  schemaVersionTable?: string;
  validateChecksums?: boolean;
  allowOutOfOrder?: boolean;
  dryRun?: boolean;
}

// ============================================================================
// REPOSITORY TYPES
// ============================================================================

/**
 * Base repository interface
 */
export interface BaseRepository<T extends BaseEntity, CreateData = Omit<T, keyof BaseEntity>, UpdateData = Partial<CreateData>> {
  findById(id: string, options?: QueryOptions, transaction?: DatabaseTransaction): Promise<T | null>;
  findMany(options?: QueryOptions, transaction?: DatabaseTransaction): Promise<T[]>;
  create(data: CreateData, transaction?: DatabaseTransaction): Promise<T>;
  update(id: string, data: UpdateData, transaction?: DatabaseTransaction): Promise<T>;
  delete(id: string, transaction?: DatabaseTransaction): Promise<void>;
  count(options?: QueryOptions, transaction?: DatabaseTransaction): Promise<number>;
  exists(id: string, transaction?: DatabaseTransaction): Promise<boolean>;
}

/**
 * Soft delete repository interface
 */
export interface SoftDeleteRepository<T extends SoftDeleteEntity> extends BaseRepository<T> {
  softDelete(id: string, transaction?: DatabaseTransaction): Promise<void>;
  restore(id: string, transaction?: DatabaseTransaction): Promise<T>;
  findWithDeleted(options?: QueryOptions, transaction?: DatabaseTransaction): Promise<T[]>;
  findOnlyDeleted(options?: QueryOptions, transaction?: DatabaseTransaction): Promise<T[]>;
  forceDelete(id: string, transaction?: DatabaseTransaction): Promise<void>;
}

/**
 * Repository with audit fields
 */
export interface AuditRepository<T extends BaseEntity & AuditFields> extends BaseRepository<T> {
  findByCreatedBy(createdBy: string, options?: QueryOptions, transaction?: DatabaseTransaction): Promise<T[]>;
  findByUpdatedBy(updatedBy: string, options?: QueryOptions, transaction?: DatabaseTransaction): Promise<T[]>;
  findCreatedBetween(start: Date, end: Date, options?: QueryOptions, transaction?: DatabaseTransaction): Promise<T[]>;
  findUpdatedBetween(start: Date, end: Date, options?: QueryOptions, transaction?: DatabaseTransaction): Promise<T[]>;
}

// ============================================================================
// QUERY BUILDER TYPES
// ============================================================================

/**
 * Query builder interface
 */
export interface QueryBuilder<T = any> {
  select(columns?: string | string[]): QueryBuilder<T>;
  from(table: string): QueryBuilder<T>;
  join(table: string, condition: string, type?: 'INNER' | 'LEFT' | 'RIGHT' | 'FULL'): QueryBuilder<T>;
  where(condition: string | Record<string, any>, params?: QueryParams): QueryBuilder<T>;
  whereIn(column: string, values: any[]): QueryBuilder<T>;
  whereNotIn(column: string, values: any[]): QueryBuilder<T>;
  whereBetween(column: string, min: any, max: any): QueryBuilder<T>;
  whereNull(column: string): QueryBuilder<T>;
  whereNotNull(column: string): QueryBuilder<T>;
  orderBy(column: string, direction?: 'ASC' | 'DESC'): QueryBuilder<T>;
  groupBy(columns: string | string[]): QueryBuilder<T>;
  having(condition: string, params?: QueryParams): QueryBuilder<T>;
  limit(count: number): QueryBuilder<T>;
  offset(count: number): QueryBuilder<T>;
  insert(data: Record<string, any> | Record<string, any>[]): QueryBuilder<T>;
  update(data: Record<string, any>): QueryBuilder<T>;
  delete(): QueryBuilder<T>;
  toSQL(): { sql: string; params: QueryParams };
  execute(transaction?: DatabaseTransaction): Promise<T[]>;
  first(transaction?: DatabaseTransaction): Promise<T | null>;
  count(transaction?: DatabaseTransaction): Promise<number>;
  exists(transaction?: DatabaseTransaction): Promise<boolean>;
}

/**
 * Raw query builder
 */
export interface RawQueryBuilder {
  raw(sql: string, params?: QueryParams): QueryBuilder;
}

// ============================================================================
// SEEDER TYPES
// ============================================================================

/**
 * Seeder interface
 */
export interface Seeder {
  name: string;
  priority: number;
  run(db: Database): Promise<void> | void;
  rollback?(db: Database): Promise<void> | void;
}

/**
 * Seeder options
 */
export interface SeederOptions {
  seedersPath: string;
  tableName?: string;
  environment?: string;
  force?: boolean;
}

/**
 * Seeder status
 */
export interface SeederStatus {
  name: string;
  ranAt: Date;
  environment: string;
}

// ============================================================================
// BACKUP AND RESTORE TYPES
// ============================================================================

/**
 * Backup options
 */
export interface BackupOptions {
  filename: string;
  compress?: boolean;
  includeSchema?: boolean;
  includeData?: boolean;
  tables?: string[];
  excludeTables?: string[];
  batchSize?: number;
}

/**
 * Restore options
 */
export interface RestoreOptions {
  filename: string;
  dropExisting?: boolean;
  skipErrors?: boolean;
  dryRun?: boolean;
  tables?: string[];
  excludeTables?: string[];
}

/**
 * Backup metadata
 */
export interface BackupMetadata {
  filename: string;
  createdAt: Date;
  size: number;
  compressed: boolean;
  schemaVersion: number;
  tableCount: number;
  recordCount: number;
  checksum: string;
}

// ============================================================================
// PERFORMANCE AND MONITORING TYPES
// ============================================================================

/**
 * Query performance metrics
 */
export interface QueryMetrics {
  sql: string;
  executionTime: number;
  rowsAffected: number;
  memoryUsage: number;
  timestamp: Date;
  success: boolean;
  error?: string;
}

/**
 * Database statistics
 */
export interface DatabaseStats {
  totalQueries: number;
  averageQueryTime: number;
  slowQueries: number;
  failedQueries: number;
  connectionCount: number;
  activeConnections: number;
  memoryUsage: number;
  diskUsage: number;
  uptime: number;
}

/**
 * Performance monitoring options
 */
export interface MonitoringOptions {
  enabled: boolean;
  slowQueryThreshold: number;
  logSlowQueries: boolean;
  logFailedQueries: boolean;
  collectMetrics: boolean;
  metricsRetentionDays: number;
  alertThresholds?: {
    slowQueryCount?: number;
    failureRate?: number;
    memoryUsage?: number;
    connectionCount?: number;
  };
}

// ============================================================================
// CACHE TYPES
// ============================================================================

/**
 * Query cache interface
 */
export interface QueryCache {
  get(key: string): Promise<any | null>;
  set(key: string, value: any, ttl?: number): Promise<void>;
  delete(key: string): Promise<void>;
  clear(): Promise<void>;
  has(key: string): Promise<boolean>;
  size(): Promise<number>;
}

/**
 * Cache options
 */
export interface CacheOptions {
  enabled: boolean;
  ttl: number;
  maxSize: number;
  keyPrefix: string;
  invalidateOnWrite: boolean;
  cacheableQueries?: string[];
  excludeQueries?: string[];
}

// ============================================================================
// UTILITY TYPES
// ============================================================================

/**
 * Database event types
 */
export type DatabaseEvent = 
  | 'connection:created'
  | 'connection:destroyed'
  | 'query:start'
  | 'query:end'
  | 'query:error'
  | 'transaction:start'
  | 'transaction:commit'
  | 'transaction:rollback'
  | 'migration:start'
  | 'migration:end'
  | 'migration:error'
  | 'backup:start'
  | 'backup:end'
  | 'backup:error';

/**
 * Database event listener
 */
export type DatabaseEventListener = (event: DatabaseEvent, data?: any) => void | Promise<void>;

/**
 * Database health check result
 */
export interface HealthCheckResult {
  healthy: boolean;
  timestamp: Date;
  responseTime: number;
  connections: {
    total: number;
    active: number;
    idle: number;
  };
  memory: {
    used: number;
    available: number;
  };
  disk: {
    used: number;
    available: number;
  };
  errors?: string[];
}

/**
 * Database configuration validation result
 */
export interface ConfigValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Table information
 */
export interface TableInfo {
  name: string;
  type: 'table' | 'view';
  columns: {
    name: string;
    type: string;
    notNull: boolean;
    defaultValue: any;
    primaryKey: boolean;
  }[];
  indexes: {
    name: string;
    unique: boolean;
    columns: string[];
  }[];
  foreignKeys: {
    column: string;
    referencedTable: string;
    referencedColumn: string;
  }[];
  rowCount: number;
  sizeBytes: number;
}