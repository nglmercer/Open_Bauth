// src/index.ts
// Punto de entrada principal de la librería de autenticación

// Servicios principales
export { AuthService } from './services/auth';
export { JWTService } from './services/jwt';
export { PermissionService } from './services/permissions';

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
export {
  seedDatabase,
  cleanDatabase,
  resetDatabase,
  checkDatabaseStatus
} from './scripts/seed';

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
  AuthError
} from './types/auth';

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
 * Función de conveniencia para crear middleware de Hono
 */
export function createHonoAuth(config?: Partial<AuthConfig>) {
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
export function createExpressAuth(config?: Partial<AuthConfig>) {
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
export function createWebSocketAuth(config?: Partial<AuthConfig>) {
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
 * Información de la librería
 */
export const AUTH_LIBRARY_INFO = {
  name: 'Framework-Agnostic Auth Library',
  version: '1.0.0',
  description: 'Librería de autenticación y permisos agnóstica de framework con TypeScript, Bun y SQLite',
  author: 'Auth Library Team',
  frameworks: ['Hono', 'Express', 'WebSockets', 'Socket.IO', 'Fastify'],
  features: [
    'Framework-agnostic',
    'TypeScript nativo',
    'SQLite con Bun',
    'JWT + bcrypt',
    'RBAC (Role-Based Access Control)',
    'Middlewares reutilizables',
    'Migraciones automáticas',
    'Scripts de utilidad',
    'Configuración flexible',
    'Logging integrado',
    'Rate limiting',
    'CORS configurado',
    'Validación de entrada',
    'Sanitización de datos'
  ]
};

console.log(`📚 ${AUTH_LIBRARY_INFO.name} v${AUTH_LIBRARY_INFO.version} cargada`);
