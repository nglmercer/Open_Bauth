import type { Request, Response, NextFunction } from 'express';
import { AUTH_CONFIG } from '../config/constants';

/**
 * Audit log entry interface
 */
export interface AuditLogEntry {
  id: string;
  timestamp: Date;
  userId?: string;
  userEmail?: string;
  action: string;
  resource: string;
  method: string;
  path: string;
  ip: string;
  userAgent?: string;
  statusCode?: number;
  success: boolean;
  duration?: number;
  details?: Record<string, any>;
  error?: string;
}

/**
 * Audit log store interface
 */
export interface AuditLogStore {
  log(entry: AuditLogEntry): Promise<void>;
  getLogs(filters?: AuditLogFilters): Promise<AuditLogEntry[]>;
  getLogById(id: string): Promise<AuditLogEntry | null>;
}

/**
 * Audit log filters
 */
export interface AuditLogFilters {
  userId?: string;
  action?: string;
  resource?: string;
  startDate?: Date;
  endDate?: Date;
  success?: boolean;
  limit?: number;
  offset?: number;
}

/**
 * In-memory audit log store (for development/testing)
 */
class MemoryAuditLogStore implements AuditLogStore {
  private logs: AuditLogEntry[] = [];
  private maxLogs = 10000; // Prevent memory overflow

  async log(entry: AuditLogEntry): Promise<void> {
    this.logs.push(entry);
    
    // Keep only the most recent logs
    if (this.logs.length > this.maxLogs) {
      this.logs = this.logs.slice(-this.maxLogs);
    }
  }

  async getLogs(filters: AuditLogFilters = {}): Promise<AuditLogEntry[]> {
    let filteredLogs = [...this.logs];

    if (filters.userId) {
      filteredLogs = filteredLogs.filter(log => log.userId === filters.userId);
    }

    if (filters.action) {
      filteredLogs = filteredLogs.filter(log => log.action === filters.action);
    }

    if (filters.resource) {
      filteredLogs = filteredLogs.filter(log => log.resource === filters.resource);
    }

    if (filters.success !== undefined) {
      filteredLogs = filteredLogs.filter(log => log.success === filters.success);
    }

    if (filters.startDate) {
      filteredLogs = filteredLogs.filter(log => log.timestamp >= filters.startDate!);
    }

    if (filters.endDate) {
      filteredLogs = filteredLogs.filter(log => log.timestamp <= filters.endDate!);
    }

    // Sort by timestamp (newest first)
    filteredLogs.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    // Apply pagination
    const offset = filters.offset || 0;
    const limit = filters.limit || 100;
    
    return filteredLogs.slice(offset, offset + limit);
  }

  async getLogById(id: string): Promise<AuditLogEntry | null> {
    return this.logs.find(log => log.id === id) || null;
  }
}

/**
 * Database audit log store (for production)
 */
class DatabaseAuditLogStore implements AuditLogStore {
  async log(entry: AuditLogEntry): Promise<void> {
    // In a real implementation, this would write to a database
    // For now, we'll use console logging as a fallback
    console.log('[AUDIT]', JSON.stringify(entry, null, 2));
  }

  async getLogs(filters: AuditLogFilters = {}): Promise<AuditLogEntry[]> {
    // In a real implementation, this would query the database
    // For now, return empty array
    return [];
  }

  async getLogById(id: string): Promise<AuditLogEntry | null> {
    // In a real implementation, this would query the database
    return null;
  }
}

/**
 * Audit logger configuration
 */
export interface AuditLoggerConfig {
  store?: AuditLogStore;
  logSuccessfulRequests?: boolean;
  logFailedRequests?: boolean;
  logAuthenticationEvents?: boolean;
  logAuthorizationEvents?: boolean;
  logDataModification?: boolean;
  logSensitiveOperations?: boolean;
  excludePaths?: string[];
  includePaths?: string[];
  logRequestBody?: boolean;
  logResponseBody?: boolean;
  maxBodySize?: number;
  sensitiveFields?: string[];
}

/**
 * Default audit logger configuration
 */
const DEFAULT_AUDIT_CONFIG: Required<AuditLoggerConfig> = {
  store: new MemoryAuditLogStore(),
  logSuccessfulRequests: true,
  logFailedRequests: true,
  logAuthenticationEvents: true,
  logAuthorizationEvents: true,
  logDataModification: true,
  logSensitiveOperations: true,
  excludePaths: ['/health', '/metrics', '/favicon.ico'],
  includePaths: [],
  logRequestBody: false,
  logResponseBody: false,
  maxBodySize: 1024,
  sensitiveFields: ['password', 'passwordHash', 'token', 'refreshToken', 'secret', 'key']
};

/**
 * Audit logger class
 */
export class AuditLogger {
  private config: Required<AuditLoggerConfig>;
  private store: AuditLogStore;

  constructor(config: AuditLoggerConfig = {}) {
    this.config = { ...DEFAULT_AUDIT_CONFIG, ...config };
    this.store = this.config.store;
  }

  /**
   * Generate unique ID for audit log entry
   */
  private generateId(): string {
    return `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Extract user information from request
   */
  private extractUserInfo(req: Request): { userId?: string; userEmail?: string } {
    const user = (req as any).user;
    return {
      userId: user?.id,
      userEmail: user?.email
    };
  }

  /**
   * Determine action from request
   */
  private determineAction(req: Request): string {
    const method = req.method.toUpperCase();
    const path = req.path;

    // Authentication actions
    if (path.includes('/login')) return 'LOGIN';
    if (path.includes('/logout')) return 'LOGOUT';
    if (path.includes('/register')) return 'REGISTER';
    if (path.includes('/password')) return 'PASSWORD_CHANGE';
    if (path.includes('/reset')) return 'PASSWORD_RESET';

    // User management actions
    if (path.includes('/users')) {
      switch (method) {
        case 'GET': return 'USER_VIEW';
        case 'POST': return 'USER_CREATE';
        case 'PUT': case 'PATCH': return 'USER_UPDATE';
        case 'DELETE': return 'USER_DELETE';
      }
    }

    // Role management actions
    if (path.includes('/roles')) {
      switch (method) {
        case 'GET': return 'ROLE_VIEW';
        case 'POST': return 'ROLE_ASSIGN';
        case 'DELETE': return 'ROLE_REMOVE';
      }
    }

    // Generic actions
    switch (method) {
      case 'GET': return 'READ';
      case 'POST': return 'create';
      case 'PUT': case 'PATCH': return 'update';
      case 'DELETE': return 'delete';
      default: return method.toLowerCase();
    }
  }

  /**
   * Determine resource from request
   */
  private determineResource(req: Request): string {
    const path = req.path;
    
    if (path.includes('/auth')) return 'authentication';
    if (path.includes('/users')) return 'user';
    if (path.includes('/roles')) return 'role';
    if (path.includes('/permissions')) return 'permission';
    
    // Extract resource from path (e.g., /api/v1/posts/123 -> posts)
    const pathParts = path.split('/').filter(part => part && part !== 'api' && !part.startsWith('v'));
    return pathParts[0] || 'unknown';
  }

  /**
   * Sanitize sensitive data from object
   */
  private sanitizeSensitiveData(obj: any): any {
    if (!obj || typeof obj !== 'object') {
      return obj;
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitizeSensitiveData(item));
    }

    const sanitized: any = {};
    for (const [key, value] of Object.entries(obj)) {
      if (this.config.sensitiveFields.some(field => 
        key.toLowerCase().includes(field.toLowerCase())
      )) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof value === 'object') {
        sanitized[key] = this.sanitizeSensitiveData(value);
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  /**
   * Check if path should be logged
   */
  private shouldLogPath(path: string): boolean {
    // If includePaths is specified, only log those paths
    if (this.config.includePaths.length > 0) {
      return this.config.includePaths.some(includePath => path.includes(includePath));
    }

    // Otherwise, log all paths except excluded ones
    return !this.config.excludePaths.some(excludePath => path.includes(excludePath));
  }

  /**
   * Log an audit entry
   */
  async logEntry(entry: Partial<AuditLogEntry>): Promise<void> {
    const fullEntry: AuditLogEntry = {
      id: this.generateId(),
      timestamp: new Date(),
      action: 'unknown',
      resource: 'unknown',
      method: 'unknown',
      path: 'unknown',
      ip: 'unknown',
      success: false,
      ...entry
    };

    try {
      await this.store.log(fullEntry);
    } catch (error) {
      console.error('Failed to log audit entry:', error);
    }
  }

  /**
   * Create middleware function
   */
  middleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      const startTime = Date.now();
      const { userId, userEmail } = this.extractUserInfo(req);
      const action = this.determineAction(req);
      const resource = this.determineResource(req);
      const ip = req.ip || req.connection.remoteAddress || 'unknown';
      const userAgent = req.get('User-Agent');

      // Skip logging if path is excluded
      if (!this.shouldLogPath(req.path)) {
        return next();
      }

      // Capture original response methods
      const originalSend = res.send;
      const originalJson = res.json;
      let responseBody: any;

      // Override response methods to capture response
      res.send = function(body) {
        responseBody = body;
        return originalSend.call(this, body);
      };

      res.json = function(body) {
        responseBody = body;
        return originalJson.call(this, body);
      };

      // Log when response finishes
      res.on('finish', async () => {
        const duration = Date.now() - startTime;
        const success = res.statusCode >= 200 && res.statusCode < 400;

        // Check if we should log this request
        const shouldLog = (
          (success && this.config.logSuccessfulRequests) ||
          (!success && this.config.logFailedRequests)
        );

        if (!shouldLog) {
          return;
        }

        const details: Record<string, any> = {};

        // Add request body if configured
        if (this.config.logRequestBody && req.body) {
          const bodyStr = JSON.stringify(req.body);
          if (bodyStr.length <= this.config.maxBodySize) {
            details.requestBody = this.sanitizeSensitiveData(req.body);
          } else {
            details.requestBody = '[BODY_TOO_LARGE]';
          }
        }

        // Add response body if configured
        if (this.config.logResponseBody && responseBody) {
          const bodyStr = JSON.stringify(responseBody);
          if (bodyStr.length <= this.config.maxBodySize) {
            details.responseBody = this.sanitizeSensitiveData(responseBody);
          } else {
            details.responseBody = '[BODY_TOO_LARGE]';
          }
        }

        // Add query parameters
        if (Object.keys(req.query).length > 0) {
          details.queryParams = this.sanitizeSensitiveData(req.query);
        }

        // Add route parameters
        if (Object.keys(req.params).length > 0) {
          details.routeParams = this.sanitizeSensitiveData(req.params);
        }

        await this.logEntry({
          userId,
          userEmail,
          action,
          resource,
          method: req.method,
          path: req.path,
          ip,
          userAgent,
          statusCode: res.statusCode,
          success,
          duration,
          details: Object.keys(details).length > 0 ? details : undefined,
          error: !success ? `HTTP ${res.statusCode}` : undefined
        });
      });

      next();
    };
  }

  /**
   * Get audit logs
   */
  async getLogs(filters?: AuditLogFilters): Promise<AuditLogEntry[]> {
    return this.store.getLogs(filters);
  }

  /**
   * Get audit log by ID
   */
  async getLogById(id: string): Promise<AuditLogEntry | null> {
    return this.store.getLogById(id);
  }
}

/**
 * Pre-configured audit loggers
 */
export const auditLoggers = {
  // Full audit logging for production
  production: new AuditLogger({
    store: new DatabaseAuditLogStore(),
    logSuccessfulRequests: true,
    logFailedRequests: true,
    logAuthenticationEvents: true,
    logAuthorizationEvents: true,
    logDataModification: true,
    logSensitiveOperations: true,
    logRequestBody: false,
    logResponseBody: false
  }),

  // Development audit logging
  development: new AuditLogger({
    store: new MemoryAuditLogStore(),
    logSuccessfulRequests: false,
    logFailedRequests: true,
    logAuthenticationEvents: true,
    logAuthorizationEvents: true,
    logDataModification: true,
    logSensitiveOperations: true,
    logRequestBody: true,
    logResponseBody: false
  }),

  // Security-focused audit logging
  security: new AuditLogger({
    logSuccessfulRequests: false,
    logFailedRequests: true,
    logAuthenticationEvents: true,
    logAuthorizationEvents: true,
    logDataModification: true,
    logSensitiveOperations: true,
    includePaths: ['/auth', '/users', '/roles', '/admin'],
    logRequestBody: false,
    logResponseBody: false
  })
};

/**
 * Create a custom audit logger
 */
export function createAuditLogger(config: AuditLoggerConfig): AuditLogger {
  return new AuditLogger(config);
}