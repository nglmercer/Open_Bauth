/**
 * Generic Base Controller for CRUD Operations
 * Database-agnostic controller that works with Bun's SQL interface
 * Enhanced with BIT type support for SQL Server compatibility
 */

import { SQL } from "bun";
import type { Database } from "bun:sqlite";

export type TruthyFilter = { isTruthy: true };
export type FalsyFilter = { isFalsy: true };
export type SetFilter = { isSet: boolean };
export type OperatorFilter<V> = {
  operator: string;
  value: V; 
};

export type AdvancedFilter<V> =
  | TruthyFilter
  | FalsyFilter
  | SetFilter
  | OperatorFilter<V>;

export type WhereConditions<T> = {
  [P in keyof T]?: T[P] | T[P][] | null | AdvancedFilter<T[P]>;
};

export interface QueryOptions<T = any> {
  limit?: number;
  offset?: number;
  orderBy?: string;
  orderDirection?: "ASC" | "DESC";
  where?: WhereConditions<T>;
}

export interface JoinOptions {
  table: string;
  on: string;
  type?: "INNER" | "LEFT" | "RIGHT" | "FULL";
  select?: string[];
}

export interface RelationOptions<T = any> extends QueryOptions<T> {
  joins?: JoinOptions[];
  select?: string[];
}

export interface SimpleSearchOptions {
  limit?: number;
  offset?: number;
  orderBy?: string;
  orderDirection?: "ASC" | "DESC";
}

export interface ControllerResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
  total?: number;
}

export interface ValidationSchema {
  parse(data: any): any;
}

export interface SchemaCollection {
  [tableName: string]: {
    create?: ValidationSchema;
    update?: ValidationSchema;
    read?: ValidationSchema;
  };
}

export interface ColumnDefinition {
  name: string;
  type:
    | "INTEGER"
    | "TEXT"
    | "REAL"
    | "BLOB"
    | "BOOLEAN"
    | "BIT"
    | "DATE"
    | "DATETIME"
    | "VARCHAR"
    | "SERIAL";
  primaryKey?: boolean;
  notNull?: boolean;
  unique?: boolean;
  defaultValue?: any;
  autoIncrement?: boolean;
  references?: {
    table: string;
    column: string;
  };
}

export interface TableSchema {
  tableName: string;
  columns: ColumnDefinition[];
  indexes?: {
    name: string;
    columns: string[];
    unique?: boolean;
  }[];
}

export interface DatabaseConnection {
  query(sql: string): {
    all(...params: any[]): Promise<any[]>;
    get(...params: any[]): Promise<any>;
    run(
      ...params: any[]
    ): Promise<{ changes: number; lastInsertRowid?: number }>;
  };
  prepare?(sql: string): any;
}

export interface BaseControllerOptions {
  database: SQL | Database;
  schemas?: SchemaCollection;
  isSQLite?: boolean;
  isSQLServer?: boolean;
}

export class DatabaseAdapter implements DatabaseConnection {
  private db: SQL | Database;
  private isSQLite: boolean;

  constructor(database: SQL | Database, isSQLite: boolean = false) {
    this.db = database;
    this.isSQLite = isSQLite;
  }

  query(sql: string) {
    return {
      all: async (...params: any[]): Promise<any[]> => {
        if (this.isSQLite) {
          const stmt = (this.db as Database).prepare(sql);
          return stmt.all(...params);
        } else {
          try {
            const result = await (this.db as SQL).unsafe(sql, params);
            return Array.isArray(result) ? result : [result];
          } catch (error: any) {
            console.error("DatabaseAdapter.query.all error:", error.message);
            throw error;
          }
        }
      },
      get: async (...params: any[]): Promise<any> => {
        if (this.isSQLite) {
          const stmt = (this.db as Database).prepare(sql);
          return stmt.get(...params);
        } else {
          try {
            const result = await (this.db as SQL).unsafe(sql, params);
            return Array.isArray(result) ? result[0] : result;
          } catch (error: any) {
            console.error("DatabaseAdapter.query.get error:", error.message);
            throw error;
          }
        }
      },
      run: async (
        ...params: any[]
      ): Promise<{ changes: number; lastInsertRowid?: number }> => {
        if (this.isSQLite) {
          const stmt = (this.db as Database).prepare(sql);
          const result = stmt.run(...params);
          return {
            changes: result.changes,
            lastInsertRowid:
              result.lastInsertRowid != null
                ? Number(result.lastInsertRowid)
                : undefined,
          };
        } else {
          try {
            await (this.db as SQL).unsafe(sql, params);
            // NOTE: This is a simplification. Getting actual changes/rowid from generic SQL is complex.
            return { changes: 1, lastInsertRowid: undefined };
          } catch (error: any) {
            console.error("DatabaseAdapter.query.run error:", error.message);
            throw error;
          }
        }
      },
    };
  }

  prepare(sql: string) {
    if (this.isSQLite) {
      return (this.db as Database).prepare(sql);
    }
    return null;
  }
}

export class BaseController<T = Record<string, any>> {
  protected adapter: DatabaseAdapter;
  protected tableName: string;
  protected schemas?: SchemaCollection;
  protected isSQLite: boolean;
  protected isSQLServer: boolean;

  constructor(tableName: string, options: BaseControllerOptions) {
    this.tableName = tableName;
    this.schemas = options.schemas;
    this.isSQLite = options.isSQLite ?? false;
    this.isSQLServer = options.isSQLServer ?? false;
    this.adapter = new DatabaseAdapter(options.database, this.isSQLite);
  }

  static async initializeDatabase(
    database: SQL | Database,
    schemas: TableSchema[],
    isSQLite: boolean = false,
    isSQLServer: boolean = false
  ): Promise<ControllerResponse> {
    const adapter = new DatabaseAdapter(database, isSQLite);

    // For SQLite, wrap initialization in a transaction for performance and safety
    if (isSQLite) (database as Database).exec("BEGIN TRANSACTION;");

    try {
      for (const schema of schemas) {
        const createTableSQL = BaseController.generateCreateTableSQL(
          schema,
          isSQLite,
          isSQLServer
        );
        await adapter.query(createTableSQL).run();

        if (schema.indexes) {
          for (const index of schema.indexes) {
            const createIndexSQL = BaseController.generateCreateIndexSQL(
              schema.tableName,
              index,
              isSQLite
            );
            await adapter.query(createIndexSQL).run();
          }
        }
      }

      if (isSQLite) (database as Database).exec("COMMIT;");

      return {
        success: true,
        message: `Successfully created ${schemas.length} tables`,
      };
    } catch (error: any) {
      if (isSQLite) (database as Database).exec("ROLLBACK;");
      return {
        success: false,
        error: error.message,
      };
    }
  }

  private static generateCreateTableSQL(
    schema: TableSchema,
    isSQLite: boolean,
    isSQLServer: boolean = false
  ): string {
    const columns = schema.columns
      .map((col) => {
        let columnDef = `"${col.name}" ${BaseController.mapDataType(
          col.type,
          isSQLite,
          isSQLServer
        )}`;

        if (col.primaryKey) {
          columnDef += " PRIMARY KEY";
          if (col.autoIncrement && isSQLite) {
            columnDef += " AUTOINCREMENT";
          }
        }

        if (col.notNull && !col.primaryKey) {
          columnDef += " NOT NULL";
        }

        if (col.unique && !col.primaryKey) {
          columnDef += " UNIQUE";
        }

        if (col.defaultValue !== undefined) {
          columnDef += ` DEFAULT ${BaseController.formatDefaultValue(
            col.defaultValue
          )}`;
        }

        if (col.references) {
          columnDef += ` REFERENCES "${col.references.table}"("${col.references.column}")`;
        }

        return columnDef;
      })
      .join(", ");

    return `CREATE TABLE IF NOT EXISTS "${schema.tableName}" (${columns})`;
  }

  private static generateCreateIndexSQL(
    tableName: string,
    index: { name: string; columns: string[]; unique?: boolean },
    isSQLite: boolean
  ): string {
    const unique = index.unique ? "UNIQUE " : "";
    const columns = index.columns.map((c) => `"${c}"`).join(", ");
    return `CREATE ${unique}INDEX IF NOT EXISTS "${index.name}" ON "${tableName}" (${columns})`;
  }

  private static mapDataType(type: string, isSQLite: boolean, isSQLServer: boolean = false): string {
    const upperType = type.toUpperCase();
    
    if (isSQLite) {
      switch (upperType) {
        case "SERIAL":
          return "INTEGER";
        case "VARCHAR":
          return "TEXT";
        case "BOOLEAN":
        case "BIT":
          return "INTEGER"; // Store booleans and bits as 0 or 1
        case "DATE":
          return "TEXT";
        case "DATETIME":
          return "TEXT";
        default:
          return upperType;
      }
    } else if (isSQLServer) {
      switch (upperType) {
        case "BOOLEAN":
          return "BIT";
        case "DATE":
          return "DATE";
        case "DATETIME":
          return "DATETIME";
        case "SERIAL":
          return "INT IDENTITY(1,1)";
        default:
          return upperType;
      }
    } else {
      // PostgreSQL (assumed default)
      switch (upperType) {
        case "BIT":
          return "BOOLEAN"; // Map BIT to BOOLEAN in PostgreSQL
        case "BOOLEAN":
          return "BOOLEAN";
        case "DATE":
          return "DATE";
        case "DATETIME":
          return "TIMESTAMP";
        default:
          return upperType;
      }
    }
  }

  private static formatDefaultValue(value: any): string {
    if (value === null) {
      return "NULL";
    }

    if (typeof value === "boolean") {
      return value ? "1" : "0"; // Use 1/0 for boolean in SQLite and SQL Server BIT
    }

    if (typeof value === "string") {
      const upperValue = value.toUpperCase();
      const isFunctionOrKeyword =
        /^\(.*\)$/.test(value.trim()) || // Matches anything in parentheses like (lower(...))
        ["CURRENT_TIMESTAMP", "CURRENT_DATE", "CURRENT_TIME"].includes(
          upperValue
        );

      if (isFunctionOrKeyword) {
        return value;
      } else {
        return `'${value.replace(/'/g, "''")}'`;
      }
    }

    return String(value);
  }

  private validateData(
    data: any,
    operation: "create" | "update" | "read"
  ): any {
    if (!this.schemas || !this.schemas[this.tableName]) {
      return data;
    }

    try {
      const tableSchemas = this.schemas[this.tableName];
      let schema: ValidationSchema | undefined;

      switch (operation) {
        case "create":
          schema = tableSchemas.create;
          break;
        case "update":
          schema = tableSchemas.update;
          break;
        case "read":
        default:
          schema = tableSchemas.read;
          break;
      }

      if (!schema) {
        return data;
      }

      return schema.parse(data);
    } catch (error: any) {
      throw new Error(`Validation error: ${error.message}`);
    }
  }

// src/database/base-controller.ts

  private buildWhereClause(conditions: Record<string, any>): {
    sql: string;
    params: any[];
  } {
    if (!conditions || Object.keys(conditions).length === 0) {
      return { sql: "", params: [] };
    }

    const clauses: string[] = [];
    const params: any[] = [];

    for (const [key, value] of Object.entries(conditions)) {
      if (value === null) {
        clauses.push(`"${key}" IS NULL`);
        continue;
      }

      if (Array.isArray(value)) {
        if (value.length === 0) {
          clauses.push("1 = 0");
          continue;
        }
        clauses.push(`"${key}" IN (${value.map(() => "?").join(", ")})`);
        params.push(...value.map((v) => this.convertValueForDatabase(v)));
        continue;
      }

      if (typeof value === "object" && !ArrayBuffer.isView(value) && !(value instanceof Date)) {
        if ('isTruthy' in value && value.isTruthy === true) {
          clauses.push(`"${key}" = ?`);
          params.push(1);
          continue;
        } else if ('isFalsy' in value && value.isFalsy === true) {
          clauses.push(`("${key}" IS NULL OR "${key}" = ?)`);
          params.push(0);
          continue;
        } else if ('isSet' in value) {
          clauses.push(`"${key}" IS ${value.isSet ? 'NOT NULL' : 'NULL'}`);
          continue;
        } else if ('operator' in value) {
          clauses.push(`"${key}" ${value.operator} ?`);
          params.push(value.value);
          continue;
        }
      }
      
      clauses.push(`"${key}" = ?`);
      params.push(this.convertValueForDatabase(value));
    }

    return {
      sql: ` WHERE ${clauses.join(" AND ")}`,
      params,
    };
  }

  /**
   * Enhanced boolean detection including BIT type support
   */
  private isBooleanLike(value: any): boolean {
    if (typeof value === "boolean") {
      return true;
    }
    if (typeof value === "number" && (value === 0 || value === 1)) {
      return true;
    }
    if ((value instanceof Uint8Array || value instanceof Buffer) && value.length === 1) {
      return true;
    }
    if (ArrayBuffer.isView(value) && value.byteLength === 1) {
        return true;
    }
    return false;
  }

  /**
   * Enhanced boolean normalization with BIT type support
   */
  private normalizeBooleanValue(value: any): boolean {
    if (typeof value === "boolean") {
      return value;
    }
    if (typeof value === "number") {
      return value === 1;
    }
    if (value instanceof Uint8Array || value instanceof Buffer) {
      return value[0] === 1;
    }
     if (ArrayBuffer.isView(value)) {
      const uint8View = new Uint8Array(value.buffer, value.byteOffset, 1);
      return uint8View[0] === 1;
    }
    return Boolean(value);
  }

  /**
   * Enhanced database value conversion with BIT type support
   */
  private convertValueForDatabase(value: any): any {
    if (this.isBooleanLike(value)) {
      const boolValue = this.normalizeBooleanValue(value);
      if (this.isSQLite || this.isSQLServer) {
        return boolValue ? 1 : 0;
      }
      return boolValue;
    }

    return value;
  }
  private async getTableInfo(): Promise<Array<{ name: string; pk: number }>> {
    try {
      if (this.isSQLite) {
        const result = await this.adapter
          .query(`PRAGMA table_info("${this.tableName}")`)
          .all();
        return Array.isArray(result)
          ? result.map((col: any) => ({ name: col.name, pk: col.pk }))
          : [];
      } else {
        // Generic SQL for PostgreSQL
        const result = await this.adapter
          .query(
            `
          SELECT
            column_name as name,
            CASE WHEN column_name = ANY(
              SELECT a.attname
              FROM pg_index i
              JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
              WHERE i.indrelid = $1::regclass AND i.indisprimary
            ) THEN 1 ELSE 0 END as pk
          FROM information_schema.columns
          WHERE table_name = $1 AND table_schema = 'public'
          ORDER BY ordinal_position
        `
          )
          .all(this.tableName);
        return Array.isArray(result) ? result : [];
      }
    } catch (error) {
      // Fallback for other systems or errors
      return [{ name: "id", pk: 1 }];
    }
  }

  private async getPrimaryKey(): Promise<string> {
    const tableInfo = await this.getTableInfo();
    const primaryKey = tableInfo.find((col) => col.pk === 1)?.name;
    return primaryKey || "id";
  }

  async create(data: Record<string, any>): Promise<ControllerResponse<T>> {
    try {
      const validatedData = this.validateData(data, "create");
      const cleanData = Object.fromEntries(
        Object.entries(validatedData).filter(
          ([_, value]) => value !== undefined // Allow null to be explicitly set
        )
      );
      if (Object.keys(cleanData).length === 0) {
        return { success: false, error: "No valid data provided" };
      }

      const columns = Object.keys(cleanData).map((c) => `"${c}"`);
      const placeholders = Object.keys(cleanData)
        .map(() => "?")
        .join(", ");
      const values = Object.values(cleanData).map((value) =>
        this.convertValueForDatabase(value)
      );

      // RETURNING * might not be supported everywhere, but works for SQLite & Postgres
      const insertQuery = `INSERT INTO "${this.tableName}" (${columns.join(
        ", "
      )}) VALUES (${placeholders}) RETURNING *`;

      const result = await this.adapter.query(insertQuery).get(...values);

      if (!result) {
        return {
          success: false,
          error:
            "Failed to create record or retrieve the created data from database",
        };
      }

      return {
        success: true,
        data: result as T,
        message: "Record created successfully",
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  async findById(id: number | string): Promise<ControllerResponse<T>> {
    try {
      const primaryKey = await this.getPrimaryKey();
      const result = await this.adapter
        .query(`SELECT * FROM "${this.tableName}" WHERE "${primaryKey}" = ?`)
        .get(id);

      if (!result) {
        return {
          success: false,
          error: "Record not found",
        };
      }

      return {
        success: true,
        data: result as T,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  async findAll(options: QueryOptions = {}): Promise<ControllerResponse<T[]>> {
    try {
      const {
        limit = 100,
        offset = 0,
        orderBy,
        orderDirection = "ASC",
        where,
      } = options;
      const { sql: whereClause, params } = this.buildWhereClause(where || {});

      let query = `SELECT * FROM "${this.tableName}"${whereClause}`;
      let countQuery = `SELECT COUNT(*) as total FROM "${this.tableName}"${whereClause}`;

      if (orderBy) {
        query += ` ORDER BY "${orderBy}" ${orderDirection}`;
      }

      query += ` LIMIT ? OFFSET ?`;
      params.push(limit, offset);

      const records = await this.adapter.query(query).all(...params);

      const countParams = params.slice(0, -2);
      const totalResult = (await this.adapter
        .query(countQuery)
        .get(...countParams)) as { total: number };

      return {
        success: true,
        data: records as T[],
        total: totalResult.total,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  async update(
    id: number | string,
    data: Record<string, any>
  ): Promise<ControllerResponse<T>> {
    try {
      const validatedData = this.validateData(data, "update");
      const cleanData = Object.fromEntries(
        Object.entries(validatedData).filter(
          ([_, value]) => value !== undefined
        )
      );

      if (Object.keys(cleanData).length === 0) {
        return {
          success: false,
          error: "No valid data provided for update",
        };
      }

      const primaryKey = await this.getPrimaryKey();
      const columns = Object.keys(cleanData);
      const setClause = columns.map((col) => `"${col}" = ?`).join(", ");
      const values = [
        ...Object.values(cleanData).map((value) =>
          this.convertValueForDatabase(value)
        ),
        id,
      ];

      const updateQuery = `UPDATE "${this.tableName}" SET ${setClause} WHERE "${primaryKey}" = ?`;
      const result = await this.adapter.query(updateQuery).run(...values);

      if (result.changes === 0) {
        return {
          success: false,
          error: "Record not found or no changes made",
        };
      }

      const updatedRecord = await this.findById(id);

      return {
        success: true,
        data: updatedRecord.data,
        message: "Record updated successfully",
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  async delete(id: number | string): Promise<ControllerResponse> {
    try {
      const primaryKey = await this.getPrimaryKey();
      const deleteQuery = `DELETE FROM "${this.tableName}" WHERE "${primaryKey}" = ?`;
      const result = await this.adapter.query(deleteQuery).run(id);

      if (result.changes === 0) {
        return {
          success: false,
          error: "Record not found",
        };
      }

      return {
        success: true,
        message: "Record deleted successfully",
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  async query(sql: string, params: any[] = []): Promise<ControllerResponse> {
    try {
      const records = await this.adapter.query(sql).all(...params);
      return {
        success: true,
        data: records,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  async getSchema(): Promise<ControllerResponse> {
    try {
      const tableInfo = await this.getTableInfo();
      return {
        success: true,
        data: {
          tableName: this.tableName,
          columns: tableInfo,
        },
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  async search(
    filters: WhereConditions<T> = {},
    options: SimpleSearchOptions = {}
  ): Promise<ControllerResponse<T[]>> {
    return this.findAll({ where: filters as WhereConditions<T>, ...options });
  }

  async findFirst(
    filters: WhereConditions<T> = {}
  ): Promise<ControllerResponse<T | null>> {
    const result = await this.search(filters, { limit: 1 });

    if (
      result.success &&
      Array.isArray(result.data) &&
      result.data.length > 0
    ) {
      return {
        success: true,
        data: result.data[0] as T,
      };
    } else if (!result.success) {
      return result as ControllerResponse<T | null>;
    }

    return {
      success: true,
      data: null,
    };
  }

  async count(filters: WhereConditions<T> = {}): Promise<ControllerResponse<number>> {
    try {
      const { sql: whereClause, params } = this.buildWhereClause(
        (filters as Record<string, any>) || {}
      );
      const query = `SELECT COUNT(*) as total FROM "${this.tableName}"${whereClause}`;
      const result = (await this.adapter.query(query).get(...params)) as {
        total: number;
      };

      return {
        success: true,
        data: result.total,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

async random(
    filters: WhereConditions<T> = {},
    limit: number = 1
  ): Promise<ControllerResponse<T[]>> {
    try {
      const { sql: whereClause, params } = this.buildWhereClause(
        (filters as Record<string, any>) || {}
      );
      
      const randomOrderClause = this._getRandomOrderClause();

      const query = `SELECT * FROM "${this.tableName}"${whereClause} ${randomOrderClause} LIMIT ?`;
      params.push(limit);

      const records = await this.adapter.query(query).all(...params);

      return {
        success: true,
        data: records as T[],
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }
  private _getRandomOrderClause(): string {
    if (this.isSQLServer) {
      return "ORDER BY NEWID()";
    }
    
    if (this.isSQLite) {
      return "ORDER BY RANDOM()";
    }

    return "ORDER BY RANDOM()";
  }
  async findWithRelations(
    options: RelationOptions<T> = {}
  ): Promise<ControllerResponse<T[]>> {
    try {
      const {
        limit = 100,
        offset = 0,
        orderBy,
        orderDirection = "ASC",
        where,
        joins = [],
        select = [],
      } = options;
      const { sql: whereClause, params } = this.buildWhereClause(where || {});

      let selectClause = `"${this.tableName}".*`;

      for (const join of joins) {
        if (join.select && join.select.length > 0) {
          const joinColumns = join.select
            .map((col) => {
              if (/\s+as\s+/i.test(col)) { // Case-insensitive "AS"
                const [originalCol, alias] = col.split(/\s+as\s+/i);
                return `"${
                  join.table
                }"."${originalCol.trim()}" AS "${alias.trim()}"`;
              }
              return `"${join.table}"."${col}" AS "${join.table}_${col}"`;
            })
            .join(", ");
          selectClause += `, ${joinColumns}`;
        }
      }

      if (select.length > 0) {
        selectClause = select
          .map((col) => {
            if (col.includes(".")) {
              const [tbl, cl] = col.split('.');
              return `"${tbl}"."${cl}"`;
            }
            return `"${this.tableName}"."${col}"`;
          })
          .join(", ");
      }

      let joinClause = "";
      for (const join of joins) {
        const joinType = join.type || "LEFT";
        joinClause += ` ${joinType} JOIN "${join.table}" ON ${join.on}`;
      }

      let query = `SELECT ${selectClause} FROM "${this.tableName}"${joinClause}${whereClause}`;

      if (orderBy) {
        const qualifiedOrderBy = orderBy.includes(".")
          ? orderBy.replace(/(\w+)\.(\w+)/, `"$1"."$2"`)
          : `"${this.tableName}"."${orderBy}"`;
        query += ` ORDER BY ${qualifiedOrderBy} ${orderDirection}`;
      }

      query += ` LIMIT ? OFFSET ?`;
      params.push(limit, offset);

      const records = await this.adapter.query(query).all(...params);

      let countQuery = `SELECT COUNT(*) as total FROM "${this.tableName}"${joinClause}${whereClause}`;
      const countParams = params.slice(0, -2);
      const totalResult = (await this.adapter
        .query(countQuery)
        .get(...countParams)) as { total: number };

      return {
        success: true,
        data: records as T[],
        total: totalResult.total,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Find a single record by ID with related data
   */
  async findByIdWithRelations(
    id: number | string,
    joins: JoinOptions[] = [],
    select: string[] = []
  ): Promise<ControllerResponse<T>> {
    try {
      const primaryKey = await this.getPrimaryKey();

      let selectClause = `"${this.tableName}".*`;

      for (const join of joins) {
        if (join.select && join.select.length > 0) {
          const joinColumns = join.select
            .map((col) => {
              if (/\s+as\s+/i.test(col)) {
                const [originalCol, alias] = col.split(/\s+as\s+/i);
                return `"${
                  join.table
                }"."${originalCol.trim()}" AS "${alias.trim()}"`;
              }
              return `"${join.table}"."${col}" AS "${join.table}_${col}"`;
            })
            .join(", ");
          selectClause += `, ${joinColumns}`;
        }
      }

      if (select.length > 0) {
        selectClause = select
          .map((col) => {
            if (col.includes(".")) {
              const [tbl, cl] = col.split('.');
              return `"${tbl}"."${cl}"`;
            }
            return `"${this.tableName}"."${col}"`;
          })
          .join(", ");
      }

      let joinClause = "";
      for (const join of joins) {
        const joinType = join.type || "LEFT";
        joinClause += ` ${joinType} JOIN "${join.table}" ON ${join.on}`;
      }

      const query = `SELECT ${selectClause} FROM "${this.tableName}"${joinClause} WHERE "${this.tableName}"."${primaryKey}" = ?`;
      const record = await this.adapter.query(query).get(id);

      if (!record) {
        return {
          success: false,
          error: "Record not found",
        };
      }

      return {
        success: true,
        data: record as T,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Helper method to create a simple join configuration
   */
  createJoin(
    table: string,
    localKey: string,
    foreignKey: string,
    type: "INNER" | "LEFT" | "RIGHT" | "FULL" = "LEFT",
    select?: string[]
  ): JoinOptions {
    return {
      table,
      on: `"${this.tableName}"."${localKey}" = "${table}"."${foreignKey}"`,
      type,
      select,
    };
  }

  /**
   * Helper method to create a reverse join configuration (for belongsTo relationships)
   */
  createReverseJoin(
    targetTable: string,
    sourceForeignKey: string,
    targetPrimaryKey: string = "id",
    type: "INNER" | "LEFT" | "RIGHT" = "LEFT",
    selectColumns: string[] = ["*"]
  ): JoinOptions {
    let select: string[] | undefined = undefined;

    if (!selectColumns.includes("*")) {
      select = selectColumns;
    } else {
      if (targetTable === "categories") {
        select = [
          "name AS category_name",
          "description AS category_description",
        ];
      } else if (targetTable === "users") {
        select = ["name AS user_name", "email AS user_email"];
      }
    }

    return {
      table: targetTable,
      on: `"${this.tableName}"."${sourceForeignKey}" = "${targetTable}"."${targetPrimaryKey}"`,
      type,
      select,
    };
  }
}