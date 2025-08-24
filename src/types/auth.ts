// src/types/auth.ts

import type { 
  BaseEntity, 
  Optional, 
  Email, 
  HashedPassword, 
  JWT, 
  RefreshToken, 
  EntityId, 
  UserId, 
  RoleId, 
  PermissionId,
  QueryOptions,
  PaginatedResponse,
  ValidationResult
} from './common';

/**
 * User metadata interface
 */
export interface UserMetadata {
  preferences?: Record<string, any>;
  settings?: Record<string, any>;
  profile?: {
    avatar?: string;
    bio?: string;
    location?: string;
  };
}

/**
 * Role metadata interface
 */
export interface RoleMetadata {
  color?: string;
  icon?: string;
  priority?: number;
  category?: string;
}

/**
 * Permission metadata interface
 */
export interface PermissionMetadata {
  category?: string;
  level?: number;
  scope?: string;
}

/**
 * User interface with enhanced type safety
 */
export interface User extends BaseEntity {
  id: UserId;
  email: Email;
  passwordHash: HashedPassword;
  firstName?: string;
  lastName?: string;
  isActive: boolean;
  lastLoginAt?: Date;
  emailVerifiedAt?: Date;
  roles: Role[];
  permissions?: Permission[];
  metadata?: UserMetadata;
}

/**
 * User creation data interface
 */
export interface CreateUserData {
  email: string;
  password: string;
  firstName?: string;
  lastName?: string;
  isActive?: boolean;
  roles?: string[];
}

/**
 * User update data interface
 */
export interface UpdateUserData {
  email?: string;
  firstName?: string;
  lastName?: string;
  isActive?: boolean;
}

/**
 * User query options interface
 */
export interface UserQueryOptions extends QueryOptions {
  includeRoles?: boolean;
  includePermissions?: boolean;
  activeOnly?: boolean;
  emailVerified?: boolean;
}

/**
 * User repository interface
 */
export interface UserRepositoryInterface {
  findById(id: UserId, options?: UserQueryOptions): Promise<User | null>;
  findByEmail(email: string, options?: UserQueryOptions): Promise<User | null>;
  findMany(options?: UserQueryOptions): Promise<PaginatedResponse<User>>;
  create(data: CreateUserData): Promise<User>;
  update(id: UserId, data: UpdateUserData): Promise<User>;
  delete(id: UserId): Promise<boolean>;
  activate(id: UserId): Promise<boolean>;
  deactivate(id: UserId): Promise<boolean>;
  getUserRoles(id: UserId): Promise<Role[]>;
  assignRole(userId: UserId, roleId: RoleId): Promise<boolean>;
  removeRole(userId: UserId, roleId: RoleId): Promise<boolean>;
  verifyEmail(id: UserId): Promise<boolean>;
  updateLastLogin(id: UserId): Promise<boolean>;
}

/**
 * Legacy User interface for backward compatibility
 */
export interface LegacyUser {
  id: string;
  email: string;
  password_hash: string;
  firstName?: string;
  lastName?: string;
  roles: Role[];
  created_at: Date;
  updated_at: Date;
  createdAt?: Date;
  updatedAt?: Date;
  is_active: boolean;
  isActive?: boolean;
  lastLoginAt?: Date;
}

/**
 * Role interface with enhanced type safety
 */
export interface Role extends BaseEntity {
  id: RoleId;
  name: string;
  description?: string;
  isDefault: boolean;
  isActive: boolean;
  permissions: Permission[];
  metadata?: RoleMetadata;
}

/**
 * Role creation data interface
 */
export interface CreateRoleData {
  name: string;
  description?: string;
  isDefault?: boolean;
  permissions?: string[];
}

/**
 * Role update data interface
 */
export interface UpdateRoleData {
  name?: string;
  description?: string;
  isDefault?: boolean;
  isActive?: boolean;
}

/**
 * Role query options interface
 */
export interface RoleQueryOptions extends QueryOptions {
  includePermissions?: boolean;
  defaultOnly?: boolean;
}

/**
 * Role repository interface
 */
export interface RoleRepositoryInterface {
  findById(id: RoleId, options?: RoleQueryOptions): Promise<Role | null>;
  findByName(name: string, options?: RoleQueryOptions): Promise<Role | null>;
  findMany(options?: RoleQueryOptions): Promise<PaginatedResponse<Role>>;
  create(data: CreateRoleData): Promise<Role>;
  update(id: RoleId, data: UpdateRoleData): Promise<Role>;
  delete(id: RoleId): Promise<boolean>;
  getDefaultRole(): Promise<Role | null>;
  assignPermission(roleId: RoleId, permissionId: PermissionId): Promise<boolean>;
  removePermission(roleId: RoleId, permissionId: PermissionId): Promise<boolean>;
  userHasRole(userId: UserId, roleId: RoleId): Promise<boolean>;
}

/**
 * Legacy Role interface for backward compatibility
 */
export interface LegacyRole {
  id: string;
  name: string;
  permissions: Permission[];
  description?: string;
  created_at: Date;
  isActive?: boolean;
}

/**
 * Permission interface with enhanced type safety
 */
export interface Permission extends BaseEntity {
  id: PermissionId;
  name: string;
  resource: string;
  action: string;
  description?: string;
  metadata?: PermissionMetadata;
}

/**
 * Permission creation data interface
 */
export interface CreatePermissionData {
  name: string;
  resource?: string;
  action?: string;
  description?: string;
}

/**
 * Permission update data interface
 */
export interface UpdatePermissionData {
  name?: string;
  resource?: string;
  action?: string;
  description?: string;
}

/**
 * Permission query options interface
 */
export interface PermissionQueryOptions extends QueryOptions {
  resource?: string;
  action?: string;
}

/**
 * Permission repository interface
 */
export interface PermissionRepositoryInterface {
  findById(id: PermissionId, options?: PermissionQueryOptions): Promise<Permission | null>;
  findByName(name: string, options?: PermissionQueryOptions): Promise<Permission | null>;
  findMany(options?: PermissionQueryOptions): Promise<PaginatedResponse<Permission>>;
  create(data: CreatePermissionData): Promise<Permission>;
  update(id: PermissionId, data: UpdatePermissionData): Promise<Permission>;
  delete(id: PermissionId): Promise<boolean>;
  findByResource(resource: string): Promise<Permission[]>;
  findByAction(action: string): Promise<Permission[]>;
}

/**
 * Legacy Permission interface for backward compatibility
 */
export interface LegacyPermission {
  id: string;
  name: string;
  resource: string;
  action: string;
  created_at: Date;
  description?: string;
}

/**
 * Interface for authentication context
 * Se adjunta a las requests autenticadas
 */
export interface AuthContext {
  user?: User;
  token?: string;
  permissions: string[];
  roles?: Role[] | string[];
  isAuthenticated: boolean;
}

/**
 * Interface for authentication system configuration
 */
export interface AuthConfig {
  jwtSecret: string;
  jwtExpiration: string;
  refreshTokenExpiration: string;
  database: {
    path: string;
    enableWAL: boolean;
    enableForeignKeys: boolean;
    busyTimeout: number;
  };
  security: {
    bcryptRounds: number;
    maxLoginAttempts: number;
    lockoutDuration: number;
    sessionTimeout: number;
    requireEmailVerification: boolean;
    allowMultipleSessions: boolean;
    passwordMinLength: number;
    passwordRequireUppercase: boolean;
    passwordRequireLowercase: boolean;
    passwordRequireNumbers: boolean;
    passwordRequireSymbols: boolean;
  };
  cors: {
    origins: string[];
    credentials: boolean;
    methods: string[];
    headers: string[];
  };
  rateLimit: {
    windowMs: number;
    maxRequests: number;
    skipSuccessfulRequests: boolean;
    skipFailedRequests: boolean;
  };
  logging: {
    level: 'debug' | 'info' | 'warn' | 'error';
    enableConsole: boolean;
    enableFile: boolean;
    filePath: string;
    enableDatabase: boolean;
  };
}

/**
 * Interface for authentication requests (framework agnostic)
 */
export interface AuthRequest {
  headers: Record<string, string>;
  url?: string;
  method?: string;
  query?: any;
  auth?: AuthContext;
  user?: User;
  authContext?: AuthContext;
  params?: any;
}

/**
 * Tipo para funciones de middleware next
 */
export type NextFunction = () => void;

/**
 * Interface for authentication responses (framework agnostic)
 */
export interface AuthResponse {
  status: (code: number) => AuthResponse;
  json: (data: any) => void;
}

/**
 * Data types for user registration
 */
export interface RegisterData {
  email: string;
  password: string;
  firstName?: string;
  lastName?: string;
  isActive?: boolean;
}

/**
 * Data types for user login
 */
export interface LoginData {
  email: string;
  password: string;
}

/**
 * Authentication process response
 */
export interface AuthResult {
  success: boolean;
  user?: User;
  token?: string;
  refreshToken?: string;
  error?: {
    type: AuthErrorType;
    message: string;
  };
}

/**
 * Payload del JWT token
 */
export interface JWTPayload {
  userId: string;
  email: string;
  roles: string[];
  iat?: number;
  exp?: number;
}

/**
 * Options for permission verification
 */
export interface PermissionOptions {
  requireAll?: boolean; // Whether all permissions are required (AND) or just one (OR)
  strict?: boolean; // Whether to verify exactly or allow superior permissions
}

/**
 * Data for assigning role to user
 */
export interface AssignRoleData {
  userId: string;
  roleId: string;
}

/**
 * Generic response for permission operations
 */
export interface PermissionResult<T = any> {
  success: boolean;
  data?: T;
  permission?: Permission;
  role?: Role;
  error?: {
    type: AuthErrorType;
    message: string;
  };
}

/**
 * Response for role operations
 */
export interface RoleResult<T = any> {
  success: boolean;
  data?: T;
  role?: Role;
  error?: {
    type: AuthErrorType;
    message: string;
  };
}

/**
 * Configuration for framework adapters
 */
export interface AdapterConfig extends AuthConfig {
  corsEnabled?: boolean;
  rateLimitEnabled?: boolean;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
}

/**
 * Resultado de operaciones de base de datos
 */
export interface DatabaseResult {
  success: boolean;
  data?: any;
  error?: string;
}

// Note: UserQueryOptions is already defined above, removing duplicate

/**
 * Authentication system statistics
 */
export interface AuthStats {
  totalUsers: number;
  activeUsers: number;
  totalRoles: number;
  totalPermissions: number;
  recentLogins: number;
}

/**
 * Authentication system events
 */
export type AuthEvent = 
  | 'user.registered'
  | 'user.login'
  | 'user.logout'
  | 'user.updated'
  | 'user.deactivated'
  | 'role.created'
  | 'role.updated'
  | 'permission.created'
  | 'permission.updated';

/**
 * Authentication event data
 */
export interface AuthEventData {
  event: AuthEvent;
  userId?: string;
  timestamp: Date;
  metadata?: Record<string, any>;
}

/**
 * Security configuration
 */
export interface SecurityConfig {
  // Security headers configuration
  securityHeaders: {
    [key: string]: string;
  };
  
  // Cookie configuration
  cookies: {
    httpOnly: boolean;
    secure: boolean;
    sameSite: 'strict' | 'lax' | 'none';
    maxAge: number;
  };
  
  // Input validation configuration
  validation: {
    maxEmailLength: number;
    maxNameLength: number;
    maxPasswordLength: number;
    allowedEmailDomains?: string[];
    blockedEmailDomains: string[];
  };
  
  // IP and geolocation configuration
  ipSecurity: {
    enableGeoBlocking: boolean;
    blockedCountries: string[];
    enableIPWhitelist: boolean;
    ipWhitelist: string[];
    enableIPBlacklist: boolean;
    ipBlacklist: string[];
  };
}

/**
 * Session information
 */
export interface SessionInfo {
  id: string;
  userId: string;
  token: string;
  createdAt: Date;
  expiresAt: Date;
  lastActivity: Date;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * Authentication system error types
 */
export enum AuthErrorType {
  INVALID_CREDENTIALS = 'INVALID_CREDENTIALS',
  USER_NOT_FOUND = 'USER_NOT_FOUND',
  USER_ALREADY_EXISTS = 'USER_ALREADY_EXISTS',
  INVALID_TOKEN = 'INVALID_TOKEN',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  INSUFFICIENT_PERMISSIONS = 'INSUFFICIENT_PERMISSIONS',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  ACCOUNT_INACTIVE = 'ACCOUNT_INACTIVE',
  WEAK_PASSWORD = 'WEAK_PASSWORD',
  DATABASE_ERROR = 'DATABASE_ERROR',
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  AUTHENTICATION_ERROR = 'AUTHENTICATION_ERROR',
  AUTHORIZATION_ERROR = 'AUTHORIZATION_ERROR',
  NOT_FOUND_ERROR = 'NOT_FOUND_ERROR',
  RATE_LIMIT_ERROR = 'RATE_LIMIT_ERROR',
  TOKEN_ERROR = 'TOKEN_ERROR',
  ACCOUNT_ERROR = 'ACCOUNT_ERROR',
  SERVER_ERROR = 'SERVER_ERROR'
}

// Note: The main AuthError class is defined in src/errors/auth.ts
// This is kept for backward compatibility
export class LegacyAuthError extends Error {
  public readonly type: AuthErrorType;
  public readonly statusCode: number;
  public readonly metadata?: Record<string, any>;

  constructor(
    type: AuthErrorType,
    message: string,
    statusCode: number = 400,
    metadata?: Record<string, any>
  ) {
    super(message);
    this.name = 'LegacyAuthError';
    this.type = type;
    this.statusCode = statusCode;
    this.metadata = metadata;
  }
}