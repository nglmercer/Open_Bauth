import { Context } from 'hono';
import { DatabaseInitializer, BaseController, QueryOptions, RelationOptions, JoinOptions, WhereConditions } from '../../dist/index';
import { randomUUID } from 'crypto';

// Generic interfaces for API responses
interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string | ErrorDetail;
  message?: string;
  count?: number;
  total?: number;
}

interface ErrorDetail {
  type: string;
  message: string;
}

export interface ValidationRule {
  field: string;
  required?: boolean;
  type?: 'string' | 'number' | 'boolean' | 'array' | 'object';
  min?: number;
  max?: number;
  pattern?: RegExp;
  validator?: (value: any) => boolean;
  message?: string;
}

export interface ControllerConfig {
  tableName: string;
  primaryKey?: string;
  validation?: {
    create?: ValidationRule[];
    update?: ValidationRule[];
  };
  relationships?: RelationshipConfig[];
  defaultFilters?: Record<string, any>;
  defaultOrder?: {
    field: string;
    direction: 'ASC' | 'DESC';
  };
}

interface RelationshipConfig {
  name: string;
  table: string;
  localKey: string;
  foreignKey: string;
  type?: 'INNER' | 'LEFT' | 'RIGHT' | 'FULL';
  select?: string[];
  reverse?: boolean; // true for belongsTo relationships
}

export class GenericController<T extends Record<string, any> = Record<string, any>> {
  private controller: BaseController<T>;
  private config: ControllerConfig;
  constructor(
    public dbInitializer: DatabaseInitializer,
    config: ControllerConfig
  ) {
    this.config = {
      primaryKey: 'id',
      ...config
    };
    this.controller = dbInitializer.createController<T>(this.config.tableName);
  }

  // Generic validation method
  private validateData(data: any, operation: 'create' | 'update'): { valid: boolean; errors: string[] } {
    const rules = this.config.validation?.[operation];
    if (!rules) return { valid: true, errors: [] };

    const errors: string[] = [];

    for (const rule of rules) {
      const value = data[rule.field];
      
      // Required field check
      if (rule.required && (value === undefined || value === null || value === '')) {
        errors.push(rule.message || `${rule.field} is required`);
        continue;
      }

      // Skip further validation if field is not present and not required
      if (value === undefined || value === null) continue;

      // Type validation
      if (rule.type) {
        const actualType = Array.isArray(value) ? 'array' : typeof value;
        if (actualType !== rule.type) {
          errors.push(rule.message || `${rule.field} must be of type ${rule.type}`);
          continue;
        }
      }

      // Min/Max validation for numbers and strings
      if (rule.min !== undefined) {
        if (typeof value === 'number' && value < rule.min) {
          errors.push(rule.message || `${rule.field} must be at least ${rule.min}`);
        } else if (typeof value === 'string' && value.length < rule.min) {
          errors.push(rule.message || `${rule.field} must be at least ${rule.min} characters`);
        }
      }

      if (rule.max !== undefined) {
        if (typeof value === 'number' && value > rule.max) {
          errors.push(rule.message || `${rule.field} must be at most ${rule.max}`);
        } else if (typeof value === 'string' && value.length > rule.max) {
          errors.push(rule.message || `${rule.field} must be at most ${rule.max} characters`);
        }
      }

      // Pattern validation
      if (rule.pattern && typeof value === 'string' && !rule.pattern.test(value)) {
        errors.push(rule.message || `${rule.field} has invalid format`);
      }

      // Custom validator
      if (rule.validator && !rule.validator(value)) {
        errors.push(rule.message || `${rule.field} is invalid`);
      }
    }

    return { valid: errors.length === 0, errors };
  }

  // Build relationships/joins
  private buildJoins(): JoinOptions[] {
    if (!this.config.relationships) return [];

    return this.config.relationships.map(rel => {
      if (rel.reverse) {
        // For belongsTo relationships (e.g., product belongs to category)
        return this.controller.createReverseJoin(
          rel.table,
          rel.localKey,   // foreign key in current table
          rel.foreignKey, // primary key in target table
          rel.type as "INNER" | "LEFT" | "RIGHT" | undefined,
          rel.select
        );
      } else {
        // For hasMany relationships
        return this.controller.createJoin(
          rel.table,
          rel.localKey,   // primary key in current table
          rel.foreignKey, // foreign key in target table
          rel.type,
          rel.select
        );
      }
    });
  }

  // Get all records
  async getAll(c: Context): Promise<Response> {
    try {
      // Parse query parameters
      const limit = parseInt(c.req.query('limit') || '50');
      const offset = parseInt(c.req.query('offset') || '0');
      const orderBy = c.req.query('order_by') || this.config.defaultOrder?.field;
      const orderDirection = (c.req.query('order_direction') || this.config.defaultOrder?.direction || 'ASC') as 'ASC' | 'DESC';
      
      // Build filters from query parameters
      const filters: Record<string, any> = { ...this.config.defaultFilters };
      
      // Add query parameter filters
      for (const [key, value] of Object.entries(c.req.query())) {
        if (!['limit', 'offset', 'order_by', 'order_direction', 'include_relations'].includes(key) && value) {
          // Handle array filters (e.g., ?status=active,inactive)
          if (value.includes(',')) {
            filters[key] = value.split(',');
          } else {
            filters[key] = value;
          }
        }
      }

      const includeRelations = c.req.query('include_relations') === 'true';
      
      let result;
      
      if (includeRelations && this.config.relationships) {
        // Use relations
        const joins = this.buildJoins();
        const options: RelationOptions<T> = {
          where: filters as WhereConditions<T>,
          joins,
          limit,
          offset,
          orderBy,
          orderDirection
        };
        
        result = await this.controller.findWithRelations(options);
      } else {
        // Simple query without relations
        const options: QueryOptions<T> = {
          where: filters as WhereConditions<T>,
          limit,
          offset,
          orderBy,
          orderDirection
        };
        
        result = await this.controller.findAll(options);
      }

      if (!result.success) {
        return c.json({
          success: false,
          error: result.error || 'Failed to retrieve records'
        }, 500);
      }

      // Postprocess all records
      const processedData = result.data?.map((record: any) => 
        this.postprocessDataFromDatabase(record)
      ) || [];

      return c.json({
        success: true,
        data: processedData,
        count: processedData.length,
        total: result.total
      });
    } catch (error) {
      console.error(`Error fetching ${this.config.tableName}:`, error);
      return c.json({
        success: false,
        error: 'Internal server error'
      }, 500);
    }
  }

  // Get single record by ID
  async getById(c: Context): Promise<Response> {
    try {
      const id = c.req.param('id');
      const includeRelations = c.req.query('include_relations') === 'true';
      
      let result;
      
      if (includeRelations && this.config.relationships) {
        const joins = this.buildJoins();
        result = await this.controller.findByIdWithRelations(id, joins);
      } else {
        result = await this.controller.findById(id);
      }

      if (!result.success || !result.data) {
        return c.json({
          success: false,
          error: {
            type: 'NOT_FOUND',
            message: 'Record not found'
          }
        }, 404);
      }

      // Postprocess data from database
      const processedData = this.postprocessDataFromDatabase(result.data);

      return c.json({
        success: true,
        data: processedData,
        message: 'Record retrieved successfully'
      });
    } catch (error) {
      console.error(`Error getting ${this.config.tableName}:`, error);
      return c.json({
        success: false,
        error: {
          type: 'DATABASE_ERROR',
          message: 'Failed to retrieve record'
        }
      }, 500);
    }
  }

  private preprocessDataForDatabase(data: any, operation: 'create' | 'update'): any {
    const processedData = { ...data };
    
    // Definir campos que deben ser convertidos a JSON
    const jsonFields = this.getJsonFields();
    
    for (const field of jsonFields) {
      if (processedData[field] !== undefined && processedData[field] !== null) {
        if (Array.isArray(processedData[field]) || typeof processedData[field] === 'object') {
          processedData[field] = JSON.stringify(processedData[field]);
        }
      }
    }
    
    return processedData;
  }

  private postprocessDataFromDatabase(data: any): any {
    if (!data) return data;
    
    const processedData = { ...data };
    const jsonFields = this.getJsonFields();
    
    for (const field of jsonFields) {
      if (processedData[field] && typeof processedData[field] === 'string') {
        try {
          processedData[field] = JSON.parse(processedData[field]);
        } catch (error) {
          // Si no es JSON válido, mantener el valor original
          console.warn(`Failed to parse JSON for field ${field}:`, error);
        }
      }
    }
    
    return processedData;
  }

  private getJsonFields(): string[] {
    const jsonFieldsMap: Record<string, string[]> = {
      'projects': ['team'],
      //Not other tables with JSON fields yet
    };
    
    return jsonFieldsMap[this.config.tableName] || [];
  }

  async create(c: Context): Promise<Response> {
    try {
      const body = await c.req.json();
      
      // Validate data
      const validation = this.validateData(body, 'create');
      if (!validation.valid) {
        return c.json({
          success: false,
          error: validation.errors.join(', ')
        }, 400);
      }

      // Add ID if not present
      if (!body[this.config.primaryKey!]) {
        body[this.config.primaryKey!] = randomUUID();
      }

      // Add timestamps
      const now = new Date().toISOString();
      if (!body.created_at) body.created_at = now;
      if (!body.updated_at) body.updated_at = now;

      // Preprocess data for database (convert arrays/objects to JSON)
      const processedData = this.preprocessDataForDatabase(body, 'create');

      const createResult = await this.controller.create(processedData);

      if (!createResult.success || !createResult.data) {
        return c.json({
          success: false,
          error: createResult.error || 'Failed to create record'
        }, 500);
      }

      // Postprocess data from database (parse JSON back to arrays/objects)
      let finalData = this.postprocessDataFromDatabase(createResult.data);
      
      // Optionally fetch with relations
      if (this.config.relationships) {
        const joins = this.buildJoins();
        const withRelations = await this.controller.findByIdWithRelations(
          createResult.data[this.config.primaryKey!], 
          joins
        );
        if (withRelations.success && withRelations.data) {
          finalData = this.postprocessDataFromDatabase(withRelations.data);
        }
      }

      return c.json({
        success: true,
        data: finalData,
        message: 'Record created successfully'
      }, 201);
    } catch (error) {
      console.error(`Error creating ${this.config.tableName}:`, error);
      return c.json({
        success: false,
        error: 'Failed to create record'
      }, 500);
    }
  }

  async update(c: Context): Promise<Response> {
    try {
      const id = c.req.param('id');
      const body = await c.req.json();

      // Check if record exists
      const existingRecord = await this.controller.findById(id);
      if (!existingRecord.success || !existingRecord.data) {
        return c.json({
          success: false,
          error: 'Record not found'
        }, 404);
      }

      // Validate data
      const validation = this.validateData(body, 'update');
      if (!validation.valid) {
        return c.json({
          success: false,
          error: validation.errors.join(', ')
        }, 400);
      }

      // Add updated timestamp
      body.updated_at = new Date().toISOString();

      // Preprocess data for database
      const processedData = this.preprocessDataForDatabase(body, 'update');

      const updateResult = await this.controller.update(id, processedData);

      if (!updateResult.success || !updateResult.data) {
        return c.json({
          success: false,
          error: updateResult.error || 'Failed to update record'
        }, 500);
      }

      // Postprocess data from database
      let finalData = this.postprocessDataFromDatabase(updateResult.data);
      
      // Optionally fetch with relations
      if (this.config.relationships) {
        const joins = this.buildJoins();
        const withRelations = await this.controller.findByIdWithRelations(id, joins);
        if (withRelations.success && withRelations.data) {
          finalData = this.postprocessDataFromDatabase(withRelations.data);
        }
      }

      return c.json({
        success: true,
        data: finalData,
        message: 'Record updated successfully'
      });
    } catch (error) {
      console.error(`Error updating ${this.config.tableName}:`, error);
      return c.json({
        success: false,
        error: 'Failed to update record'
      }, 500);
    }
  }

  // Delete record
  async delete(c: Context): Promise<Response> {
    try {
      const id = c.req.param('id');

      // Check if record exists
      const existingRecord = await this.controller.findById(id);
      if (!existingRecord.success || !existingRecord.data) {
        return c.json({
          success: false,
          error: 'Record not found'
        }, 404);
      }

      const result = await this.controller.delete(id);

      if (!result.success) {
        return c.json({
          success: false,
          error: result.error || 'Failed to delete record'
        }, 500);
      }

      return c.json({
        success: true,
        message: 'Record deleted successfully'
      });
    } catch (error) {
      console.error(`Error deleting ${this.config.tableName}:`, error);
      return c.json({
        success: false,
        error: 'Failed to delete record'
      }, 500);
    }
  }

  // Search records
  async search(c: Context): Promise<Response> {
    try {
      const body = await c.req.json();
      const { filters = {}, limit = 50, offset = 0, orderBy, orderDirection = 'ASC' } = body;

      // Merge with default filters
      const combinedFilters = { ...this.config.defaultFilters, ...filters };
      const includeRelations = body.include_relations === true;

      let result;

      if (includeRelations && this.config.relationships) {
        const joins = this.buildJoins();
        const options: RelationOptions<T> = {
          where: combinedFilters as WhereConditions<T>,
          joins,
          limit,
          offset,
          orderBy,
          orderDirection: orderDirection as 'ASC' | 'DESC'
        };
        
        result = await this.controller.findWithRelations(options);
      } else {
        result = await this.controller.search(
          combinedFilters as WhereConditions<T>,
          { limit, offset, orderBy, orderDirection: orderDirection as 'ASC' | 'DESC' }
        );
      }

      if (!result.success) {
        return c.json({
          success: false,
          error: result.error || 'Search failed'
        }, 500);
      }

      return c.json({
        success: true,
        data: result.data || [],
        count: result.data?.length || 0,
        total: result.total
      });
    } catch (error) {
      console.error(`Error searching ${this.config.tableName}:`, error);
      return c.json({
        success: false,
        error: 'Search failed'
      }, 500);
    }
  }

  // Count records
  async count(c: Context): Promise<Response> {
    try {
      // Build filters from query parameters
      const filters: Record<string, any> = { ...this.config.defaultFilters };
      
      for (const [key, value] of Object.entries(c.req.query())) {
        if (value) {
          if (value.includes(',')) {
            filters[key] = value.split(',');
          } else {
            filters[key] = value;
          }
        }
      }

      const result = await this.controller.count(filters as WhereConditions<T>);

      if (!result.success) {
        return c.json({
          success: false,
          error: result.error || 'Count failed'
        }, 500);
      }

      return c.json({
        success: true,
        data: { count: result.data }
      });
    } catch (error) {
      console.error(`Error counting ${this.config.tableName}:`, error);
      return c.json({
        success: false,
        error: 'Count failed'
      }, 500);
    }
  }

  // Get random records
  async random(c: Context): Promise<Response> {
    try {
      const limit = parseInt(c.req.query('limit') || '5');
      const filters: Record<string, any> = { ...this.config.defaultFilters };
      
      // Build filters from query parameters
      for (const [key, value] of Object.entries(c.req.query())) {
        if (!['limit'].includes(key) && value) {
          filters[key] = value;
        }
      }

      const result = await this.controller.random(filters as WhereConditions<T>, limit);

      if (!result.success) {
        return c.json({
          success: false,
          error: result.error || 'Failed to get random records'
        }, 500);
      }

      return c.json({
        success: true,
        data: result.data || [],
        count: result.data?.length || 0
      });
    } catch (error) {
      console.error(`Error getting random ${this.config.tableName}:`, error);
      return c.json({
        success: false,
        error: 'Failed to get random records'
      }, 500);
    }
  }

  // Get first record matching criteria
  async findFirst(c: Context): Promise<Response> {
    try {
      const body = await c.req.json();
      const { filters = {} } = body;
      
      const combinedFilters = { ...this.config.defaultFilters, ...filters };
      
      const result = await this.controller.findFirst(combinedFilters as WhereConditions<T>);

      if (!result.success) {
        return c.json({
          success: false,
          error: result.error || 'Search failed'
        }, 500);
      }

      if (!result.data) {
        return c.json({
          success: false,
          error: 'No record found matching criteria'
        }, 404);
      }

      return c.json({
        success: true,
        data: result.data
      });
    } catch (error) {
      console.error(`Error finding first ${this.config.tableName}:`, error);
      return c.json({
        success: false,
        error: 'Search failed'
      }, 500);
    }
  }

  // Execute custom query
  async customQuery(c: Context): Promise<Response> {
    try {
      const body = await c.req.json();
      const { sql, params = [] } = body;

      if (!sql) {
        return c.json({
          success: false,
          error: 'SQL query is required'
        }, 400);
      }

      const result = await this.controller.query(sql, params);

      return c.json({
        success: result.success,
        data: result.data,
        error: result.error
      });
    } catch (error) {
      console.error(`Error executing custom query on ${this.config.tableName}:`, error);
      return c.json({
        success: false,
        error: 'Query execution failed'
      }, 500);
    }
  }

  // Get table schema
  async getSchema(c: Context): Promise<Response> {
    try {
      const result = await this.controller.getSchema();
      
      return c.json({
        success: result.success,
        data: {
          ...result.data,
          config: this.config
        },
        error: result.error
      });
    } catch (error) {
      console.error(`Error getting schema for ${this.config.tableName}:`, error);
      return c.json({
        success: false,
        error: 'Failed to get schema'
      }, 500);
    }
  }
}
const userConfig: ControllerConfig = {
  tableName: 'users',
  primaryKey: 'id',
  validation: {
    create: [
      { 
        field: 'email', 
        required: true, 
        type: 'string',
        pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        message: 'Email must be valid'
      },
      { field: 'name', required: true, type: 'string', min: 1, max: 255 },
      { field: 'age', type: 'number', min: 13, max: 120 },
      {
        field: 'password',
        required: true,
        type: 'string',
        min: 8,
        validator: (value) => /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(value),
        message: 'Password must contain at least one lowercase, uppercase, and number'
      }
    ],
    update: [
      { 
        field: 'email', 
        type: 'string',
        pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        message: 'Email must be valid'
      },
      { field: 'name', type: 'string', min: 1, max: 255 },
      { field: 'age', type: 'number', min: 13, max: 120 },
      {
        field: 'password',
        type: 'string',
        min: 8,
        validator: (value) => /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(value),
        message: 'Password must contain at least one lowercase, uppercase, and number'
      }
    ]
  },
  defaultFilters: {
    is_active: true
  },
  defaultOrder: {
    field: 'created_at',
    direction: 'DESC'
  }
};
export class userController extends GenericController {
  constructor(dbInitializer: DatabaseInitializer) {
    super(dbInitializer, userConfig);
  }
  
}