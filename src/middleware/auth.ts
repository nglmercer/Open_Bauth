// src/middleware/auth.ts
import { getJWTService } from '../services/jwt';
import { getAuthService } from '../services/auth';
import { getPermissionService } from '../services/permissions';
import type { 
  AuthRequest, 
  AuthResponse, 
  AuthContext, 
  PermissionOptions,
  AuthError,
  AuthErrorType 
} from '../types/auth';

/**
 * Configuración del middleware de autenticación
 */
export interface AuthMiddlewareConfig {
  required?: boolean; // Si la autenticación es requerida
  permissions?: string[]; // Permisos requeridos
  permissionOptions?: PermissionOptions; // Opciones de verificación de permisos
  skipPaths?: string[]; // Rutas que se saltan la autenticación
  tokenHeader?: string; // Header del token (default: 'authorization')
}

/**
 * Función de middleware agnóstica para autenticación
 * Esta función puede ser adaptada a cualquier framework
 */
export async function authenticateRequest(
  request: AuthRequest,
  config: AuthMiddlewareConfig = {}
): Promise<{ success: boolean; context?: AuthContext; error?: string; statusCode?: number }> {
  try {
    const {
      required = true,
      permissions = [],
      permissionOptions = {},
      tokenHeader = 'authorization'
    } = config;

    // Extraer token del header
    const authHeader = request.headers[tokenHeader] || request.headers[tokenHeader.toLowerCase()];
    
    if (!authHeader) {
      if (!required) {
        return { success: true, context: { permissions: [] } };
      }
      return {
        success: false,
        error: 'Authorization header is required',
        statusCode: 401
      };
    }

    const jwtService = getJWTService();
    const token = jwtService.extractTokenFromHeader(authHeader);
    
    if (!token) {
      return {
        success: false,
        error: 'Invalid authorization header format. Use: Bearer <token>',
        statusCode: 401
      };
    }

    // Verificar token
    let payload;
    try {
      payload = await jwtService.verifyToken(token);
    } catch (error) {
      return {
        success: false,
        error: 'Invalid or expired token',
        statusCode: 401
      };
    }

    // Obtener usuario completo
    const authService = getAuthService();
    const user = await authService.findUserById(payload.userId, {
      includeRoles: true,
      includePermissions: true,
      activeOnly: true
    });

    if (!user) {
      return {
        success: false,
        error: 'User not found or inactive',
        statusCode: 401
      };
    }

    // Obtener permisos del usuario
    const permissionService = getPermissionService();
    const userPermissions = await permissionService.getUserPermissions(user.id);
    const permissionNames = userPermissions.map(p => p.name);

    // Crear contexto de autenticación
    const authContext: AuthContext = {
      user,
      token,
      permissions: permissionNames
    };

    // Verificar permisos si se requieren
    if (permissions.length > 0) {
      const hasPermissions = await permissionService.userHasPermissions(
        user.id,
        permissions,
        permissionOptions
      );

      if (!hasPermissions) {
        return {
          success: false,
          error: `Insufficient permissions. Required: ${permissions.join(', ')}`,
          statusCode: 403
        };
      }
    }

    return { success: true, context: authContext };
  } catch (error) {
    console.error('Authentication middleware error:', error);
    return {
      success: false,
      error: 'Internal authentication error',
      statusCode: 500
    };
  }
}

/**
 * Middleware para verificar solo permisos (asume que ya está autenticado)
 */
export async function authorizeRequest(
  authContext: AuthContext,
  requiredPermissions: string[],
  options: PermissionOptions = {}
): Promise<{ success: boolean; error?: string; statusCode?: number }> {
  try {
    if (!authContext.user) {
      return {
        success: false,
        error: 'User not authenticated',
        statusCode: 401
      };
    }

    if (requiredPermissions.length === 0) {
      return { success: true };
    }

    const permissionService = getPermissionService();
    const hasPermissions = await permissionService.userHasPermissions(
      authContext.user.id,
      requiredPermissions,
      options
    );

    if (!hasPermissions) {
      return {
        success: false,
        error: `Insufficient permissions. Required: ${requiredPermissions.join(', ')}`,
        statusCode: 403
      };
    }

    return { success: true };
  } catch (error) {
    console.error('Authorization error:', error);
    return {
      success: false,
      error: 'Internal authorization error',
      statusCode: 500
    };
  }
}

/**
 * Función helper para verificar si una ruta debe ser saltada
 */
export function shouldSkipAuth(path: string, skipPaths: string[] = []): boolean {
  return skipPaths.some(skipPath => {
    // Soporte para wildcards simples
    if (skipPath.endsWith('*')) {
      const basePath = skipPath.slice(0, -1);
      return path.startsWith(basePath);
    }
    return path === skipPath;
  });
}

/**
 * Función helper para extraer información del usuario del contexto
 */
export function getCurrentUser(authContext?: AuthContext) {
  return authContext?.user || null;
}

/**
 * Función helper para verificar si el usuario tiene un rol específico
 */
export function userHasRole(authContext: AuthContext, roleName: string): boolean {
  if (!authContext.user) {
    return false;
  }
  return authContext.user.roles.some(role => role.name === roleName);
}

/**
 * Función helper para verificar si el usuario tiene alguno de los roles especificados
 */
export function userHasAnyRole(authContext: AuthContext, roleNames: string[]): boolean {
  if (!authContext.user) {
    return false;
  }
  return authContext.user.roles.some(role => roleNames.includes(role.name));
}

/**
 * Función helper para verificar si el usuario tiene todos los roles especificados
 */
export function userHasAllRoles(authContext: AuthContext, roleNames: string[]): boolean {
  if (!authContext.user) {
    return false;
  }
  return roleNames.every(roleName => 
    authContext.user!.roles.some(role => role.name === roleName)
  );
}

/**
 * Función helper para verificar si el usuario tiene un permiso específico
 */
export function userHasPermission(authContext: AuthContext, permissionName: string): boolean {
  if (!authContext.permissions) {
    return false;
  }
  return authContext.permissions.includes(permissionName);
}

/**
 * Función helper para verificar si el usuario tiene alguno de los permisos especificados
 */
export function userHasAnyPermission(authContext: AuthContext, permissionNames: string[]): boolean {
  if (!authContext.permissions) {
    return false;
  }
  return permissionNames.some(permission => authContext.permissions!.includes(permission));
}

/**
 * Función helper para verificar si el usuario tiene todos los permisos especificados
 */
export function userHasAllPermissions(authContext: AuthContext, permissionNames: string[]): boolean {
  if (!authContext.permissions) {
    return false;
  }
  return permissionNames.every(permission => authContext.permissions!.includes(permission));
}

/**
 * Función helper para verificar si el usuario es el propietario de un recurso
 */
export function isResourceOwner(authContext: AuthContext, resourceUserId: string): boolean {
  if (!authContext.user) {
    return false;
  }
  return authContext.user.id === resourceUserId;
}

/**
 * Función helper para verificar si el usuario es admin
 */
export function isAdmin(authContext: AuthContext): boolean {
  return userHasRole(authContext, 'admin') || userHasRole(authContext, 'administrator');
}

/**
 * Función helper para verificar si el usuario es moderador
 */
export function isModerator(authContext: AuthContext): boolean {
  return userHasRole(authContext, 'moderator') || isAdmin(authContext);
}

/**
 * Función helper para crear un contexto de autenticación vacío
 */
export function createEmptyAuthContext(): AuthContext {
  return {
    permissions: []
  };
}

/**
 * Función helper para refrescar el token si está próximo a expirar
 */
export async function refreshTokenIfNeeded(authContext: AuthContext): Promise<string | null> {
  try {
    if (!authContext.user || !authContext.token) {
      return null;
    }

    const jwtService = getJWTService();
    const newToken = await jwtService.refreshTokenIfNeeded(
      authContext.token,
      authContext.user,
      3600 // 1 hora antes de expirar
    );

    return newToken !== authContext.token ? newToken : null;
  } catch (error) {
    console.error('Error refreshing token:', error);
    return null;
  }
}

/**
 * Función helper para validar permisos de recursos específicos
 */
export async function validateResourcePermission(
  authContext: AuthContext,
  resource: string,
  action: string,
  resourceUserId?: string
): Promise<{ success: boolean; error?: string }> {
  try {
    // Verificar si es el propietario del recurso
    if (resourceUserId && isResourceOwner(authContext, resourceUserId)) {
      return { success: true };
    }

    // Verificar si es admin (puede hacer todo)
    if (isAdmin(authContext)) {
      return { success: true };
    }

    // Verificar permiso específico
    const permissionName = `${resource}.${action}`;
    if (userHasPermission(authContext, permissionName)) {
      return { success: true };
    }

    // Verificar permiso genérico
    const genericPermission = `${resource}.*`;
    if (userHasPermission(authContext, genericPermission)) {
      return { success: true };
    }

    return {
      success: false,
      error: `Insufficient permissions for ${resource}.${action}`
    };
  } catch (error) {
    console.error('Error validating resource permission:', error);
    return {
      success: false,
      error: 'Internal error validating permissions'
    };
  }
}

/**
 * Función helper para crear respuestas de error estandarizadas
 */
export function createAuthErrorResponse(
  error: string,
  statusCode: number = 401,
  type: AuthErrorType = 'INVALID_CREDENTIALS' as AuthErrorType
) {
  return {
    success: false,
    error: {
      type,
      message: error,
      statusCode,
      timestamp: new Date().toISOString()
    }
  };
}

/**
 * Función helper para logging de eventos de autenticación
 */
export function logAuthEvent(
  event: string,
  userId?: string,
  metadata?: Record<string, any>
): void {
  const logData = {
    event,
    userId,
    timestamp: new Date().toISOString(),
    metadata
  };
  
  console.log(`🔐 Auth Event: ${JSON.stringify(logData)}`);
}

/**
 * Función helper para extraer IP del request (framework agnóstico)
 */
export function extractClientIP(headers: Record<string, string>): string {
  return (
    headers['x-forwarded-for'] ||
    headers['x-real-ip'] ||
    headers['x-client-ip'] ||
    headers['cf-connecting-ip'] ||
    'unknown'
  );
}

/**
 * Función helper para extraer User-Agent del request
 */
export function extractUserAgent(headers: Record<string, string>): string {
  return headers['user-agent'] || 'unknown';
}