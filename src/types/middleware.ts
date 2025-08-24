import type { Request, Response, NextFunction } from 'express';
import type { User } from './auth';
import type { ValidationResult, DatabaseTransaction } from './common';

// ============================================================================
// BASE MIDDLEWARE TYPES
// ============================================================================

/**
 * Extended Express Request with additional properties
 */
export interface ExtendedRequest extends Request {
  user?: User;
  userId?: string;
  requestId?: string;
  startTime?: number;
  transaction?: DatabaseTransaction;
  rateLimit?: {
    limit: number;
    remaining: number;
    resetTime: number;
  };
  sanitized?: {
    body?: any;
    query?: any;
    params?: any;
  };
  audit?: {
    action: string;
    resource: string;
    metadata?: Record<string, any>;
  };
}

/**
 * Extended Express Response with additional properties
 */
export interface ExtendedResponse extends Response {
  locals: {
    user?: User;
    requestId?: string;
    startTime?: number;
    [key: string]: any;
  };
}

/**
 * Middleware function type
 */
export type MiddlewareFunction = (
  req: ExtendedRequest,
  res: ExtendedResponse,
  next: NextFunction
) => void | Promise<void>;

/**
 * Error handling middleware function type
 */
export type ErrorMiddlewareFunction = (
  error: Error,
  req: ExtendedRequest,
  res: ExtendedResponse,
  next: NextFunction
) => void | Promise<void>;

// ============================================================================
// AUTHENTICATION MIDDLEWARE TYPES
// ============================================================================

/**
 * JWT payload interface
 */
export interface JwtPayload {
  userId: string;
  email: string;
  roles: string[];
  permissions: string[];
  iat: number;
  exp: number;
  iss: string;
  aud: string;
}

/**
 * Authentication middleware options
 */
export interface AuthMiddlewareOptions {
  required?: boolean;
  allowExpired?: boolean;
  skipPaths?: string[];
  extractToken?: (req: ExtendedRequest) => string | null;
  onSuccess?: (req: ExtendedRequest, user: User) => void | Promise<void>;
  onFailure?: (req: ExtendedRequest, error: Error) => void | Promise<void>;
}

/**
 * Authorization middleware options
 */
export interface AuthorizationOptions {
  permissions?: string[];
  roles?: string[];
  requireAll?: boolean; // true = AND logic, false = OR logic
  allowSelf?: boolean; // Allow users to access their own resources
  customCheck?: (req: ExtendedRequest, user: User) => boolean | Promise<boolean>;
}

// ============================================================================
// RATE LIMITING MIDDLEWARE TYPES
// ============================================================================

/**
 * Rate limit store interface
 */
export interface RateLimitStore {
  get(key: string): Promise<{ count: number; resetTime: number } | null>;
  set(key: string, value: { count: number; resetTime: number }, ttl: number): Promise<void>;
  increment(key: string, ttl: number): Promise<{ count: number; resetTime: number }>;
  reset(key: string): Promise<void>;
  cleanup(): Promise<void>;
}

/**
 * Rate limiting options
 */
export interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
  message?: string;
  statusCode?: number;
  headers?: boolean;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  keyGenerator?: (req: ExtendedRequest) => string;
  skip?: (req: ExtendedRequest) => boolean | Promise<boolean>;
  onLimitReached?: (req: ExtendedRequest, res: ExtendedResponse) => void | Promise<void>;
  store?: RateLimitStore;
}

/**
 * Rate limit result
 */
export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetTime: number;
  retryAfter?: number;
}

// ============================================================================
// VALIDATION MIDDLEWARE TYPES
// ============================================================================

/**
 * Validation schema interface
 */
export interface ValidationSchema {
  body?: Record<string, any>;
  query?: Record<string, any>;
  params?: Record<string, any>;
  headers?: Record<string, any>;
}

/**
 * Validation options
 */
export interface ValidationOptions {
  abortEarly?: boolean;
  allowUnknown?: boolean;
  stripUnknown?: boolean;
  skipOnError?: boolean;
  customValidators?: Record<string, (value: any) => boolean | Promise<boolean>>;
  onValidationError?: (errors: ValidationResult['errors']) => void;
}

/**
 * Field validation rule
 */
export interface FieldValidationRule {
  required?: boolean;
  type?: 'string' | 'number' | 'boolean' | 'array' | 'object' | 'email' | 'url' | 'uuid';
  min?: number;
  max?: number;
  pattern?: RegExp;
  enum?: any[];
  custom?: (value: any) => boolean | string | Promise<boolean | string>;
  transform?: (value: any) => any;
  default?: any;
}

// ============================================================================
// SANITIZATION MIDDLEWARE TYPES
// ============================================================================

/**
 * Sanitization configuration
 */
export interface SanitizationConfig {
  html?: {
    enabled: boolean;
    allowedTags?: string[];
    allowedAttributes?: Record<string, string[]>;
    stripTags?: boolean;
  };
  sql?: {
    enabled: boolean;
    escapeQuotes?: boolean;
    removeComments?: boolean;
  };
  xss?: {
    enabled: boolean;
    whiteList?: Record<string, string[]>;
  };
  trim?: boolean;
  lowercase?: string[]; // Field names to convert to lowercase
  uppercase?: string[]; // Field names to convert to uppercase
  removeEmpty?: boolean;
  maxLength?: Record<string, number>; // Field name to max length mapping
  customSanitizers?: Record<string, (value: any) => any>;
}

/**
 * Sanitization options
 */
export interface SanitizationOptions {
  body?: SanitizationConfig;
  query?: SanitizationConfig;
  params?: SanitizationConfig;
  skipPaths?: string[];
  onSanitized?: (req: ExtendedRequest, sanitized: any) => void;
}

// ============================================================================
// AUDIT LOGGING MIDDLEWARE TYPES
// ============================================================================

/**
 * Audit log entry
 */
export interface AuditLogEntry {
  id: string;
  timestamp: Date;
  userId?: string;
  userEmail?: string;
  action: string;
  resource: string;
  resourceId?: string;
  method: string;
  path: string;
  statusCode?: number;
  ipAddress: string;
  userAgent: string;
  requestId: string;
  duration?: number;
  metadata?: Record<string, any>;
  changes?: {
    before?: any;
    after?: any;
  };
  success: boolean;
  errorMessage?: string;
}

/**
 * Audit logging options
 */
export interface AuditLogOptions {
  enabled: boolean;
  logSuccessfulRequests?: boolean;
  logFailedRequests?: boolean;
  logSensitiveData?: boolean;
  skipPaths?: string[];
  skipMethods?: string[];
  includeRequestBody?: boolean;
  includeResponseBody?: boolean;
  maxBodySize?: number;
  sensitiveFields?: string[];
  customActionExtractor?: (req: ExtendedRequest) => string;
  customResourceExtractor?: (req: ExtendedRequest) => string;
  onLog?: (entry: AuditLogEntry) => void | Promise<void>;
}

/**
 * Audit log store interface
 */
export interface AuditLogStore {
  save(entry: AuditLogEntry): Promise<void>;
  find(filters: AuditLogFilters): Promise<AuditLogEntry[]>;
  count(filters: AuditLogFilters): Promise<number>;
  cleanup(olderThan: Date): Promise<number>;
}

/**
 * Audit log filters
 */
export interface AuditLogFilters {
  userId?: string;
  action?: string;
  resource?: string;
  method?: string;
  statusCode?: number;
  success?: boolean;
  startDate?: Date;
  endDate?: Date;
  ipAddress?: string;
  limit?: number;
  offset?: number;
  sortBy?: keyof AuditLogEntry;
  sortOrder?: 'asc' | 'desc';
}

// ============================================================================
// CORS MIDDLEWARE TYPES
// ============================================================================

/**
 * CORS options
 */
export interface CorsOptions {
  origin?: string | string[] | boolean | ((origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => void);
  methods?: string | string[];
  allowedHeaders?: string | string[];
  exposedHeaders?: string | string[];
  credentials?: boolean;
  maxAge?: number;
  preflightContinue?: boolean;
  optionsSuccessStatus?: number;
}

// ============================================================================
// COMPRESSION MIDDLEWARE TYPES
// ============================================================================

/**
 * Compression options
 */
export interface CompressionOptions {
  level?: number;
  threshold?: number;
  filter?: (req: ExtendedRequest, res: ExtendedResponse) => boolean;
  chunkSize?: number;
  windowBits?: number;
  memLevel?: number;
  strategy?: number;
}

// ============================================================================
// SECURITY MIDDLEWARE TYPES
// ============================================================================

/**
 * Security headers options
 */
export interface SecurityHeadersOptions {
  contentSecurityPolicy?: {
    enabled: boolean;
    directives?: Record<string, string | string[]>;
  };
  hsts?: {
    enabled: boolean;
    maxAge?: number;
    includeSubDomains?: boolean;
    preload?: boolean;
  };
  noSniff?: boolean;
  frameguard?: {
    enabled: boolean;
    action?: 'deny' | 'sameorigin' | 'allow-from';
    domain?: string;
  };
  xssFilter?: boolean;
  referrerPolicy?: string;
  permittedCrossDomainPolicies?: boolean;
}

// ============================================================================
// REQUEST LOGGING MIDDLEWARE TYPES
// ============================================================================

/**
 * Request log entry
 */
export interface RequestLogEntry {
  requestId: string;
  timestamp: Date;
  method: string;
  path: string;
  query: Record<string, any>;
  headers: Record<string, string>;
  body?: any;
  userId?: string;
  ipAddress: string;
  userAgent: string;
  duration?: number;
  statusCode?: number;
  responseSize?: number;
  error?: string;
}

/**
 * Request logging options
 */
export interface RequestLogOptions {
  enabled: boolean;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  includeHeaders?: boolean;
  includeBody?: boolean;
  includeQuery?: boolean;
  maxBodySize?: number;
  skipPaths?: string[];
  skipMethods?: string[];
  sensitiveHeaders?: string[];
  sensitiveFields?: string[];
  format?: 'json' | 'combined' | 'common' | 'short' | 'tiny';
  customFormat?: (entry: RequestLogEntry) => string;
}

// ============================================================================
// MIDDLEWARE FACTORY TYPES
// ============================================================================

/**
 * Middleware factory function
 */
export type MiddlewareFactory<T = any> = (options?: T) => MiddlewareFunction;

/**
 * Conditional middleware options
 */
export interface ConditionalMiddlewareOptions {
  condition: (req: ExtendedRequest) => boolean | Promise<boolean>;
  middleware: MiddlewareFunction;
  fallback?: MiddlewareFunction;
}

/**
 * Middleware chain options
 */
export interface MiddlewareChainOptions {
  middlewares: MiddlewareFunction[];
  stopOnError?: boolean;
  timeout?: number;
  onTimeout?: (req: ExtendedRequest, res: ExtendedResponse) => void;
}

// ============================================================================
// UTILITY TYPES
// ============================================================================

/**
 * Middleware configuration
 */
export interface MiddlewareConfig {
  auth?: AuthMiddlewareOptions;
  rateLimit?: RateLimitOptions;
  validation?: ValidationOptions;
  sanitization?: SanitizationOptions;
  audit?: AuditLogOptions;
  cors?: CorsOptions;
  compression?: CompressionOptions;
  security?: SecurityHeadersOptions;
  logging?: RequestLogOptions;
}

/**
 * Route-specific middleware configuration
 */
export interface RouteMiddlewareConfig extends MiddlewareConfig {
  path: string | RegExp;
  methods?: string[];
  priority?: number;
  enabled?: boolean;
}

/**
 * Global middleware configuration
 */
export interface GlobalMiddlewareConfig {
  order: string[]; // Order of middleware execution
  routes: RouteMiddlewareConfig[];
  defaults: MiddlewareConfig;
  development?: Partial<MiddlewareConfig>;
  production?: Partial<MiddlewareConfig>;
  test?: Partial<MiddlewareConfig>;
}