// src/types/auth.ts

/**
 * Interface para representar un usuario en el sistema
 */
export interface User {
  id: string;
  email: string;
  password_hash: string;
  firstName?: string;
  lastName?: string;
  roles: Role[];
  created_at: Date;
  updated_at: Date;
  is_active: boolean;
  isActive?: boolean;
  lastLoginAt?: Date;
}

/**
 * Interface para representar un rol en el sistema
 */
export interface Role {
  id: string;
  name: string;
  permissions: Permission[];
  description?: string;
  created_at: Date;
}

/**
 * Interface para representar un permiso en el sistema
 */
export interface Permission {
  id: string;
  name: string;
  resource: string;
  action: string;
  created_at: Date;
  description?: string;
}

/**
 * Interface para el contexto de autenticación
 * Se adjunta a las requests autenticadas
 */
export interface AuthContext {
  user?: User;
  token?: string;
  permissions: string[];
}

/**
 * Interface para la configuración del sistema de autenticación
 */
export interface AuthConfig {
  jwtSecret: string;
  jwtExpiresIn: string;
  dbPath: string;
}

/**
 * Interface para requests de autenticación (framework agnóstico)
 */
export interface AuthRequest {
  headers: Record<string, string>;
  url?: string;
  method?: string;
  auth?: AuthContext;
}

/**
 * Tipo para funciones de middleware next
 */
export type NextFunction = () => void;

/**
 * Interface para responses de autenticación (framework agnóstico)
 */
export interface AuthResponse {
  status: (code: number) => AuthResponse;
  json: (data: any) => void;
}

/**
 * Tipos de datos para registro de usuario
 */
export interface RegisterData {
  email: string;
  password: string;
  firstName?: string;
  lastName?: string;
}

/**
 * Tipos de datos para login de usuario
 */
export interface LoginData {
  email: string;
  password: string;
}

/**
 * Response del proceso de autenticación
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
 * Opciones para verificación de permisos
 */
export interface PermissionOptions {
  requireAll?: boolean; // Si se requieren todos los permisos (AND) o solo uno (OR)
  strict?: boolean; // Si se debe verificar exactamente o permitir permisos superiores
}

/**
 * Datos para crear un nuevo permiso
 */
export interface CreatePermissionData {
  name: string;
  description?: string;
  resource: string;
  action: string;
}

/**
 * Datos para crear un nuevo rol
 */
export interface CreateRoleData {
  name: string;
  description?: string;
  permissionIds?: string[];
  permissions?: string[];
}

/**
 * Datos para asignar rol a usuario
 */
export interface AssignRoleData {
  userId: string;
  roleId: string;
}

/**
 * Tipos de datos para actualizar un permiso
 */
export interface UpdatePermissionData {
  description?: string;
  resource?: string;
  action?: string;
  name?: string;
}

/**
 * Tipos de datos para actualizar un usuario
 */
export interface UpdateUserData {
  email?: string;
  is_active?: boolean;
  isActive?: boolean;
  password?: string;
  lastLoginAt?: Date;
}

/**
 * Response genérico para operaciones de permisos
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
 * Response para operaciones de roles
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
 * Configuración para adaptadores de framework
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

/**
 * Opciones para consultas de usuario
 */
export interface UserQueryOptions {
  includeRoles?: boolean;
  includePermissions?: boolean;
  activeOnly?: boolean;
  search?: string;
  sortBy?: 'email' | 'created_at' | 'name';
  sortOrder?: 'asc' | 'desc';
}

/**
 * Estadísticas del sistema de autenticación
 */
export interface AuthStats {
  totalUsers: number;
  activeUsers: number;
  totalRoles: number;
  totalPermissions: number;
  recentLogins: number;
}

/**
 * Eventos del sistema de autenticación
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
 * Datos del evento de autenticación
 */
export interface AuthEventData {
  event: AuthEvent;
  userId?: string;
  timestamp: Date;
  metadata?: Record<string, any>;
}

/**
 * Configuración de seguridad
 */
export interface SecurityConfig {
  passwordMinLength: number;
  passwordRequireUppercase: boolean;
  passwordRequireLowercase: boolean;
  passwordRequireNumbers: boolean;
  passwordRequireSymbols: boolean;
  maxLoginAttempts: number;
  lockoutDuration: number; // en minutos
  sessionTimeout: number; // en minutos
}

/**
 * Información de sesión
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
 * Tipos de error del sistema de autenticación
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
  NOT_FOUND_ERROR = 'NOT_FOUND_ERROR',
  SERVER_ERROR = 'SERVER_ERROR'
}

/**
 * Error personalizado del sistema de autenticación
 */
export class AuthError extends Error {
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
    this.name = 'AuthError';
    this.type = type;
    this.statusCode = statusCode;
    this.metadata = metadata;
  }
}