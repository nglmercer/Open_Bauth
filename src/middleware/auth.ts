// src/middleware/auth.ts
import { getJWTService } from '../services/jwt';
import { getAuthService } from '../services/auth';
import { getPermissionService } from '../services/permissions';
import type { 
  AuthRequest, 
  AuthResponse, 
  AuthContext, 
  PermissionOptions,
  AuthErrorType 
} from '../types/auth';
import { AuthError } from '../errors/auth';

/**
 * Configuración del middleware de autenticación
 */
export interface AuthMiddlewareConfig {
  required?: boolean; // Si la autenticación es requerida
  permissions?: string[]; // Permisos requeridos
  permissionOptions?: PermissionOptions; // Opciones de verificación de permisos
  skipPaths?: string[]; // Rutas que se saltan la autenticación
  tokenHeader?: string; // Header del token (default: 'authorization')
  extractToken?: (req: any) => string | null; // Custom token extraction function
  userProperty?: string; // Property name to attach user to request (default: 'user')
  contextProperty?: string; // Property name to attach auth context to request (default: 'authContext')
  jwtSecret?: string; // JWT secret for testing
  authService?: any; // Auth service instance for testing
  jwtService?: any; // JWT service instance for testing
  permissionService?: any; // Permission service instance for testing
  onError?: (error: Error, req: any, res: any) => void; // Custom error handler
  onSuccess?: (user: any, context: AuthContext, req: any) => void; // Custom success handler
  config?: { // Nested config object for backward compatibility
    tokenHeader?: string;
    userProperty?: string;
    contextProperty?: string;
  };
}

/**
 * Función de middleware agnóstica para autenticación
 * Esta función puede ser adaptada a cualquier framework
 */
export async function authenticateRequest(
  request: AuthRequest,
  config: AuthMiddlewareConfig = {}
): Promise<{ success: boolean; context?: AuthContext; error?: string; statusCode?: number }> {
  const {
    required = true,
    permissions = [],
      permissionOptions = {},
      tokenHeader = 'authorization',
      extractToken
    } = config;

    let token: string | null = null;
    
    // Use custom token extraction if provided
    if (extractToken) {
      token = extractToken(request);
    } else {
      // Try multiple token extraction methods
      token = extractTokenFromRequest(request, tokenHeader, config);
    }
    
    if (!token) {
      if (!required) {
        return { success: true, context: { permissions: [], isAuthenticated: false } };
      }
      return {
        success: false,
        error: extractToken ? 'Token not found' : 'Authentication token required. Provide token via Authorization header (Bearer <token>) or query parameter.',
        statusCode: 401
      };
    }

    // Verificar token
    const jwtService = config.jwtService || getJWTService();
    const result = await jwtService.verifyToken(token)
      .then((payload:any) => ({ success: true, payload }))
      .catch((error: any) => ({ success: false, error: error.message }));
    
    if (!result.success) {
      if (!required) {
        return { success: true, context: { permissions: [], isAuthenticated: false } };
      }
      return {
        success: false,
        error: 'Invalid or expired token',
        statusCode: 401
      };
    }
    
    const payload = result.payload;

    // Obtener usuario completo
    const authService = config.authService || getAuthService();
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
    const permissionService = config.permissionService || getPermissionService();
    const userPermissions = await permissionService.getUserPermissions(user.id);
    const permissionNames = userPermissions.map((p:any) => p.name);

    // Crear contexto de autenticación
    const authContext: AuthContext = {
      user,
      token,
      permissions: permissionNames,
      isAuthenticated: true
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
  } catch (error:any) {
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
  // Check roles in authContext.roles (Role objects or string array)
  if (authContext.roles) {
    // Handle both Role objects and string arrays
    const hasRole = authContext.roles.some(role => 
      typeof role === 'string' ? role === roleName : role.name === roleName
    );
    if (hasRole) {
      return true;
    }
  }
  
  // Check roles in authContext.user.roles (Role objects)
  if (authContext.user && authContext.user.roles) {
    return authContext.user.roles.some(role => role.name === roleName);
  }
  
  return false;
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
    permissions: [],
    isAuthenticated: false
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
  } catch (error:any) {
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
  } catch (error:any) {
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
  return headers['user-agent'] || headers['User-Agent'] || 'Unknown';
}

/**
 * Función helper para extraer token de diferentes fuentes del request
 * @param request Request object
 * @param tokenHeader Header name for token
 * @param config Auth middleware config
 * @returns Token string or null
 */
function extractTokenFromRequest(
  request: AuthRequest,
  tokenHeader: string,
  config: AuthMiddlewareConfig
): string | null {
  const jwtService = config.jwtService || getJWTService();
  
  // 1. Try to extract from headers (case-insensitive)
  const authHeader = request.headers[tokenHeader] || 
                    request.headers[tokenHeader.toLowerCase()] ||
                    request.headers[tokenHeader.toUpperCase()];
  
  if (authHeader) {
    // For authorization header, extract from Bearer format
    if (tokenHeader.toLowerCase() === 'authorization') {
      const token = jwtService.extractTokenFromHeader(authHeader);
      if (token) return token;
    } else {
      // For custom headers, use token directly
      return authHeader;
    }
  }
  
  // 2. Try to extract from query parameters (useful for GET requests)
  if (request.query) {
    const queryToken = request.query.token || request.query.access_token || request.query.auth_token;
    if (queryToken) {
      return Array.isArray(queryToken) ? queryToken[0] : queryToken;
    }
  }
  
  // 3. Try to extract from URL parameters (for WebSocket or other protocols)
  if (request.url) {
    try {
      const url = new URL(request.url, 'http://localhost');
      const urlToken = url.searchParams.get('token') || 
                      url.searchParams.get('access_token') || 
                      url.searchParams.get('auth_token');
      if (urlToken) return urlToken;
    } catch (error) {
      // Ignore URL parsing errors
    }
  }
  
  return null;
}

/**
 * Crea un middleware de autenticación para frameworks específicos
 */
export function createAuthMiddleware(config: AuthMiddlewareConfig = {}) {
  return async (req: any, res: any, next: any) => {
    try {
      // Handle nested config for backward compatibility
      const finalConfig = {
        ...config,
        tokenHeader: config.config?.tokenHeader || config.tokenHeader || 'authorization',
        userProperty: config.config?.userProperty || config.userProperty || 'user',
        contextProperty: config.config?.contextProperty || config.contextProperty || 'authContext'
      };

      const authRequest: AuthRequest = {
        headers: req.headers || {},
        url: req.url || '',
        method: req.method || 'GET',
        query: req.query
      };

      const result = await authenticateRequest(authRequest, finalConfig);
      
      if (!result.success) {
        if (config.onError) {
          const error = new Error(result.error || 'Authentication failed');
          return config.onError(error, req, res);
        }
        return res.status(result.statusCode || 401).json({
          success: false,
          error: result.error
        });
      }

      // Agregar contexto de autenticación al request usando propiedades configurables
      req[finalConfig.contextProperty] = result.context;
      req[finalConfig.userProperty] = result.context?.user;
      
      // Call success callback if provided
      if (config.onSuccess && result.context) {
        config.onSuccess(result.context.user, result.context, req);
      }
      
      next();
    } catch (error: any) {
      // Only catch unexpected errors, not authentication errors
      console.error('Unexpected error in auth middleware:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  };
}

/**
 * Crea un middleware de autenticación opcional
 */
export function createOptionalAuthMiddleware(config: AuthMiddlewareConfig = {}) {
  return createAuthMiddleware({ ...config, required: false });
}

/**
 * Crea un middleware de verificación de permisos
 */
export function createPermissionMiddleware(config: { permissions: string[], permissionService?: any, options?: PermissionOptions }) {
  return async (req: any, res: any, next: any) => {
    try {
      const authContext = req.authContext;
      if (!authContext) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      const result = await authorizeRequest(authContext, config.permissions, config.options || {});
      
      if (!result.success) {
        return res.status(result.statusCode || 403).json({
          success: false,
          error: result.error
        });
      }

      next();
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  };
}

/**
 * Crea un middleware de verificación de roles
 */
export function createRoleMiddleware(config: { roles: string[], requireAll?: boolean, permissionService?: any }) {
  return async (req: any, res: any, next: any) => {
    try {
      const authContext = req.authContext;
      if (!authContext) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      const { roles, requireAll = false } = config;
      let hasRole: boolean;
      
      if (requireAll) {
        hasRole = roles.every(role => userHasRole(authContext, role));
      } else {
        hasRole = roles.some(role => userHasRole(authContext, role));
      }
      
      if (!hasRole) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions'
        });
      }

      next();
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  };
}

/**
 * Crea un middleware de verificación de propiedad de recursos
 */
export function createOwnershipMiddleware(config: {
  getResourceOwnerId: (req: any) => number | string | Promise<number | string>;
  allowAdmin?: boolean;
  adminRoles?: string[];
}) {
  return async (req: any, res: any, next: any) => {
    try {
      const authContext = req.authContext;
      if (!authContext) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // Get the resource owner ID using the provided function
      const resourceOwnerId = await config.getResourceOwnerId(req);
      
      // Check if user is the resource owner
      const isOwner = authContext.user && authContext.user.id.toString() === resourceOwnerId.toString();
      
      // Check if user is admin (if admin access is allowed)
      let isAdminUser = false;
      if (config.allowAdmin) {
        const adminRoles = config.adminRoles || ['admin'];
        isAdminUser = adminRoles.some(role => userHasRole(authContext, role));
      }
      
      if (!isOwner && !isAdminUser) {
        return res.status(403).json({
          success: false,
          error: 'Access denied'
        });
      }

      next();
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  };
}

/**
 * Crea un middleware de rate limiting (implementación básica)
 */
export function createRateLimitMiddleware(config: {
  windowMs: number;
  maxRequests: number;
  keyGenerator?: (req: any) => string;
}) {
  const { windowMs, maxRequests, keyGenerator } = config;
  const requests = new Map<string, { count: number; resetTime: number }>();

  return async (req: any, res: any, next: any) => {
    try {
      const key = keyGenerator ? keyGenerator(req) : extractClientIP(req.headers);
      const now = Date.now();
      
      const clientData = requests.get(key) || { count: 0, resetTime: now + windowMs };
      
      if (now > clientData.resetTime) {
        clientData.count = 0;
        clientData.resetTime = now + windowMs;
      }
      
      clientData.count++;
      requests.set(key, clientData);
      
      if (clientData.count > maxRequests) {
        return res.status(429).json({
          success: false,
          error: 'Too many requests'
        });
      }
      
      next();
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  };
}