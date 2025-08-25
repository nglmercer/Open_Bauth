// src/index.ts
// Punto de entrada principal de la librería de autenticación

// Servicios principales
export { AuthService, initAuthService, getAuthService } from './services/auth';
export { JWTService,initJWTService } from './services/jwt';
export { PermissionService,initPermissionService } from './services/permissions';

// Importaciones para uso interno
import { AuthService } from './services/auth';
import { JWTService } from './services/jwt';
import { PermissionService } from './services/permissions';
import { 
  getAuthConfig, 
  validateAuthConfig
} from './config/auth';
import { type AuthConfig } from './types/auth';
import {
  authenticateWebSocket,
  checkWebSocketPermissions,
  checkWebSocketRoles,
  getWebSocketCurrentUser,
  isWebSocketAuthenticated,
  getWebSocketAuthContext,
  sendToUser,
  sendToUsersWithPermissions,
  sendToUsersWithRoles,
  broadcastToAuthenticated,
  getConnectionStats,
  disconnectUser,
  cleanupInactiveConnections,
  handleAuthenticatedMessage,
  createWebSocketResponse,
  initializeConnectionCleanup
} from './adapters/websocket';
import { 
  initDatabase, 
  closeDatabase 
} from './db/connection';
import { runMigrations } from './db/migrations';
import { 
  seedDatabase, 
  cleanDatabase, 
  resetDatabase, 
  checkDatabaseStatus 
} from './scripts/seed';
import {
  honoAuthMiddleware,
  honoOptionalAuth,
  honoRequireAuth,
  honoRequirePermissions,
  honoRequireRoles,
  honoRequireAdmin,
  honoRequireModerator,
  honoRequireOwnership,
  honoRateLimit,
  honoCorsAuth,
  honoErrorResponse,
  honoSuccessResponse,
  honoAuthLogger
} from './adapters/hono';
import {
  expressAuthMiddleware,
  expressOptionalAuth,
  expressRequireAuth,
  expressRequirePermissions,
  expressRequireRoles,
  expressRequireAdmin,
  expressRequireModerator,
  expressRequireOwnership,
  expressRateLimit,
  expressCorsAuth,
  expressErrorResponse,
  expressSuccessResponse,
  expressAuthLogger,
  expressAuthErrorHandler,
  expressJsonValidator,
  expressSanitizer
} from './adapters/express';

// Middleware agnóstico
export {
  authenticateRequest,
  authorizeRequest,
  getCurrentUser,
  createEmptyAuthContext,
  logAuthEvent,
  extractClientIP,
  extractUserAgent,
  type AuthMiddlewareConfig
} from './middleware/auth';

// Adaptadores para frameworks
export {
  honoAuthMiddleware,
  honoOptionalAuth,
  honoRequireAuth,
  honoRequirePermissions,
  honoRequireRoles,
  honoRequireAdmin,
  honoRequireModerator,
  getHonoCurrentUser,
  isHonoAuthenticated,
  getHonoAuthContext,
  honoRequireOwnership,
  honoRateLimit,
  honoCorsAuth,
  honoErrorResponse,
  honoSuccessResponse,
  honoAuthLogger
} from './adapters/hono';

export {
  expressAuthMiddleware,
  expressOptionalAuth,
  expressRequireAuth,
  expressRequirePermissions,
  expressRequireRoles,
  expressRequireAdmin,
  expressRequireModerator,
  getExpressCurrentUser,
  isExpressAuthenticated,
  getExpressAuthContext,
  expressRequireOwnership,
  expressRateLimit,
  expressCorsAuth,
  expressErrorResponse,
  expressSuccessResponse,
  expressAuthLogger,
  expressAuthErrorHandler,
  expressJsonValidator,
  expressSanitizer
} from './adapters/express';

export {
  authenticateWebSocket,
  checkWebSocketPermissions,
  checkWebSocketRoles,
  getWebSocketCurrentUser,
  isWebSocketAuthenticated,
  getWebSocketAuthContext,
  sendToUser,
  sendToUsersWithPermissions,
  sendToUsersWithRoles,
  broadcastToAuthenticated,
  getConnectionStats,
  disconnectUser,
  cleanupInactiveConnections,
  handleAuthenticatedMessage,
  createWebSocketResponse,
  initializeConnectionCleanup,
  type AuthenticatedWebSocket,
  type WebSocketAuthConfig
} from './adapters/websocket';

// Base de datos
export {
  getDatabase,
  initDatabase,
  closeDatabase,
  testConnection,
  getDatabaseInfo
} from './db/connection';

export {
  runMigrations,
  rollbackMigrations,
  getMigrationStatus,
  resetDatabase as resetDatabaseMigrations
} from './db/migrations';

// Configuración
export {
  DEFAULT_AUTH_CONFIG,
  SECURITY_CONFIG,
  DEV_CONFIG,
  PROD_CONFIG,
  getAuthConfig,
  validateAuthConfig,
  getRequiredEnvVars,
  generateEnvExample,
  printConfig
} from './config/auth';

// Scripts de utilidad
export * from './scripts/seed';

export {
  runDevCommand
} from './scripts/dev';

// Tipos TypeScript
export type {
  User,
  Role,
  Permission,
  AuthContext,
  AuthConfig,
  AuthRequest,
  AuthResponse,
  RegisterData,
  LoginData,
  AuthResult,
  JWTPayload,
  PermissionOptions,
  CreatePermissionData,
  CreateRoleData,
  AssignRoleData,
  AdapterConfig,
  DatabaseResult,
  UserQueryOptions,
  AuthStats,
  AuthEvent,
  AuthEventData,
  SecurityConfig,
  SessionInfo,
  AuthErrorType,
  // Additional auth types
  CreateUserData,
  UpdateUserData,
  UserMetadata,
  RoleMetadata,
  PermissionMetadata
} from './types/auth';

// Common types
export type {
  ApiResponse,
  PaginatedResponse,
  BaseEntity,
  SoftDeleteEntity,
  AuditFields,
  QueryOptions,
  DatabaseTransaction,
  Repository,
  ValidationResult,
  Optional,
  RequiredFields,
  Nullable,
  Maybe,
  DeepPartial,
  DeepRequired,
  AsyncFunction,
  Callback,
  EventHandler,
  DateString,
  Timestamp,
  EntityId,
  UserId,
  RoleId,
  PermissionId,
  Email,
  HashedPassword,
  JWT,
  RefreshToken,
  Result,
  Option,
  DomainEvent,
  Command,
  Query,
  HttpStatusCode,
  Environment
} from './types/common';

// Service types
export type {
  BaseService,
  ServiceHealthStatus,
  ServiceConfig,
  AuthServiceInterface,
  RegisterServiceData,
  AuthServiceResult,
  TokenServiceResult
} from './types/service';

// Middleware types
export type {
  ExtendedRequest,
  ExtendedResponse,
  MiddlewareFunction,
  ErrorMiddlewareFunction,
  JwtPayload,
  AuthMiddlewareOptions,
  AuthorizationOptions
} from './types/middleware';

// Database types
export type {
  DatabaseConfig,
  ConnectionPoolConfig,
  DatabaseConnection,
  QueryParams,
  QueryMetadata,
  QueryExecutionOptions,
  PreparedStatement,
  ColumnType,
  ColumnDefinition,
  IndexDefinition,
  TableDefinition,
  DatabaseSchema,
  ViewDefinition,
  TriggerDefinition,
  FunctionDefinition,
  Migration,
  MigrationStatus,
  MigrationOptions,
  BaseRepository,
  SoftDeleteRepository
} from './types/database';

// Logger types
export type {
  LogLevel,
  LoggerConfig,
  LogEntry,
  LogData
} from './logger/types';

// Optional dependency types
export type {
  ExpressRequest,
  ExpressResponse,
  ExpressNextFunction,
  WSWebSocket,
  ConditionalExpress,
  ConditionalWebSocket
} from './types/optional-deps';

// API types
export type {
  BaseRequest,
  RegisterRequest,
  LoginRequest,
  RefreshTokenRequest,
  ForgotPasswordRequest,
  ResetPasswordRequest,
  ChangePasswordRequest,
  UpdateUserProfileRequest,
  CreateUserRequest,
  UpdateUserRequest,
  CreateRoleRequest,
  UpdateRoleRequest,
  AssignRoleRequest,
  LoginResponse,
  RegisterResponse,
  RefreshTokenResponse,
  LogoutResponse,
  ForgotPasswordResponse,
  ResetPasswordResponse,
  ChangePasswordResponse,
  GetUserResponse,
  GetUsersResponse,
  CreateUserResponse,
  UpdateUserResponse,
  DeleteUserResponse,
  GetUserProfileResponse,
  UpdateUserProfileResponse,
  GetRoleResponse,
  GetRolesResponse,
  CreateRoleResponse,
  UpdateRoleResponse,
  DeleteRoleResponse,
  AssignRoleResponse,
  RemoveRoleResponse,
  GetPermissionsResponse,
  GetUserPermissionsResponse,
  ValidationErrorResponse,
  AuthErrorResponse,
  NotFoundErrorResponse,
  RateLimitErrorResponse,
  ServerErrorResponse,
  AnyApiResponse,
  SuccessResponse,
  ErrorResponse,
  isSuccessResponse,
  isErrorResponse
} from './types/api';

// Error classes
export {
  AuthError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  UserNotFoundError,
  NotFoundError,
  DatabaseError,
  ServerError,
  RateLimitError,
  TokenError,
  AccountError,
  AuthErrorFactory,
  ErrorHandler
} from './errors/auth';

// Clase principal de la librería
export class AuthLibrary {
  private authService: AuthService;
  private jwtService: JWTService;
  private permissionService: PermissionService;
  private config: AuthConfig;

  constructor(config?: Partial<AuthConfig>) {
    this.config = getAuthConfig();
    
    // Mergear configuración personalizada
    if (config) {
      this.config = { ...this.config, ...config };
    }

    // Validar configuración
    const validation = validateAuthConfig(this.config);
    if (!validation.valid) {
      throw new Error(`Configuración inválida: ${validation.errors.join(', ')}`);
    }

    // Inicializar servicios
    this.jwtService = new JWTService(this.config.jwtSecret);
    this.authService = new AuthService();
    this.permissionService = new PermissionService();
  }

  /**
   * Inicializar la librería
   */
  async initialize(): Promise<void> {
    try {
      initDatabase();
      await runMigrations();
      console.log('✅ Auth Library inicializada correctamente');
    } catch (error:any) {
      console.error('❌ Error inicializando Auth Library:', error);
      throw error;
    }
  }

  /**
   * Obtener el servicio de autenticación
   */
  getAuthService(): AuthService {
    return this.authService;
  }

  /**
   * Obtener el servicio JWT
   */
  getJWTService(): JWTService {
    return this.jwtService;
  }

  /**
   * Obtener el servicio de permisos
   */
  getPermissionService(): PermissionService {
    return this.permissionService;
  }

  /**
   * Obtener la configuración actual
   */
  getConfig(): AuthConfig {
    return { ...this.config };
  }

  /**
   * Actualizar configuración
   */
  updateConfig(newConfig: Partial<AuthConfig>): void {
    this.config = { ...this.config, ...newConfig };
    
    const validation = validateAuthConfig(this.config);
    if (!validation.valid) {
      throw new Error(`Configuración inválida: ${validation.errors.join(', ')}`);
    }

    // Reinicializar servicios si es necesario
    if (newConfig.jwtSecret) {
      this.jwtService = new JWTService(this.config.jwtSecret);
    }
  }

  /**
   * Poblar base de datos con datos iniciales
   */
  async seed(): Promise<void> {
    await seedDatabase();
  }

  /**
   * Limpiar base de datos
   */
  async clean(): Promise<void> {
    await cleanDatabase();
  }

  /**
   * Resetear base de datos
   */
  async reset(): Promise<void> {
    await resetDatabase();
  }

  /**
   * Verificar estado de la base de datos
   */
  async checkStatus(): Promise<void> {
    await checkDatabaseStatus();
  }

  /**
   * Cerrar conexiones y limpiar recursos
   */
  async close(): Promise<void> {
    closeDatabase();
    console.log('✅ Auth Library cerrada correctamente');
  }
}

// Instancia por defecto
let defaultInstance: AuthLibrary | null = null;

/**
 * Obtener instancia por defecto de la librería
 */
export function getAuthLibrary(config?: Partial<AuthConfig>): AuthLibrary {
  if (!defaultInstance) {
    defaultInstance = new AuthLibrary(config);
  }
  return defaultInstance;
}

/**
 * Inicializar la librería con configuración por defecto
 */
export async function initializeAuth(config?: Partial<AuthConfig>): Promise<AuthLibrary> {
  const library = getAuthLibrary(config);
  await library.initialize();
  return library;
}

/**
 * Convenience function to create Hono middleware
 */
export function createHonoAuth(config?: Partial<AuthConfig>): {
  middleware: typeof honoAuthMiddleware;
  optional: typeof honoOptionalAuth;
  required: typeof honoRequireAuth;
  permissions: typeof honoRequirePermissions;
  roles: typeof honoRequireRoles;
  admin: typeof honoRequireAdmin;
  moderator: typeof honoRequireModerator;
  ownership: typeof honoRequireOwnership;
  rateLimit: typeof honoRateLimit;
  cors: typeof honoCorsAuth;
  logger: typeof honoAuthLogger;
  library: AuthLibrary;
} {
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

/**
 * Función de conveniencia para crear middleware de Express
 */
export function createExpressAuth(config?: Partial<AuthConfig>): {
  middleware: typeof expressAuthMiddleware;
  optional: typeof expressOptionalAuth;
  required: typeof expressRequireAuth;
  permissions: typeof expressRequirePermissions;
  roles: typeof expressRequireRoles;
  admin: typeof expressRequireAdmin;
  moderator: typeof expressRequireModerator;
  ownership: typeof expressRequireOwnership;
  rateLimit: typeof expressRateLimit;
  cors: typeof expressCorsAuth;
  logger: typeof expressAuthLogger;
  errorHandler: typeof expressAuthErrorHandler;
  jsonValidator: typeof expressJsonValidator;
  sanitizer: typeof expressSanitizer;
  library: AuthLibrary;
} {
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

/**
 * Función de conveniencia para WebSocket
 */
export function createWebSocketAuth(config?: Partial<AuthConfig>): {
  authenticate: typeof authenticateWebSocket;
  checkPermissions: typeof checkWebSocketPermissions;
  checkRoles: typeof checkWebSocketRoles;
  getCurrentUser: typeof getWebSocketCurrentUser;
  isAuthenticated: typeof isWebSocketAuthenticated;
  getAuthContext: typeof getWebSocketAuthContext;
  sendToUser: typeof sendToUser;
  sendToUsersWithPermissions: typeof sendToUsersWithPermissions;
  sendToUsersWithRoles: typeof sendToUsersWithRoles;
  broadcast: typeof broadcastToAuthenticated;
  getStats: typeof getConnectionStats;
  disconnect: typeof disconnectUser;
  cleanup: typeof cleanupInactiveConnections;
  handleMessage: typeof handleAuthenticatedMessage;
  createResponse: typeof createWebSocketResponse;
  initCleanup: typeof initializeConnectionCleanup;
  library: AuthLibrary;
} {
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

// Exportar por defecto la clase principal
export default AuthLibrary;

/**
 * Library Information
 */
export const AUTH_LIBRARY_INFO = {
  name: 'Framework-Agnostic Authentication Library',
  version: '1.1.0',
  description: 'A comprehensive framework-agnostic authentication and authorization library built with TypeScript, Bun, and SQLite',
  author: 'Auth Library Development Team',
  license: 'MIT',
  repository: 'https://github.com/auth-library/framework-agnostic-auth',
  frameworks: ['Hono', 'Express', 'WebSockets', 'Socket.IO', 'Fastify'],
  runtime: 'Bun',
  database: 'SQLite',
  features: [
    'Framework-agnostic design',
    'Full TypeScript support',
    'SQLite with Bun runtime',
    'Secure JWT with Web Crypto API',
    'Complete RBAC (Role-Based Access Control)',
    'Reusable middleware components',
    'Automatic database migrations',
    'Comprehensive utility scripts',
    'Flexible configuration system',
    'Advanced logging and monitoring',
    'Built-in rate limiting',
    'CORS support',
    'Input validation and sanitization',
    'WebSocket authentication',
    'Session management',
    'Password hashing with Bun.password',
    'Refresh token support',
    'Multi-tenant support',
    'Audit logging',
    'Error handling and recovery'
  ],
  security: [
    'Bcrypt password hashing',
    'JWT token validation',
    'CSRF protection',
    'Rate limiting',
    'Input sanitization',
    'SQL injection prevention',
    'XSS protection'
  ],
  performance: [
    'Optimized for Bun runtime',
    'Connection pooling',
    'Efficient SQLite queries',
    'Minimal memory footprint',
    'Fast startup time'
  ]
};

console.log(`📚 ${AUTH_LIBRARY_INFO.name} v${AUTH_LIBRARY_INFO.version} loaded successfully`);
