// src/adapters/hono.ts
import { Context, Next, MiddlewareHandler } from 'hono';
import { 
  authenticateRequest, 
  AuthMiddlewareConfig, 
  getCurrentUser,
  createEmptyAuthContext,
  logAuthEvent,
  extractClientIP,
  extractUserAgent
} from '../middleware/auth';
import type { AuthContext, AuthRequest, User } from '../types/auth';

/**
 * Extiende el contexto de Hono para incluir autenticación
 */
declare module 'hono' {
  interface ContextVariableMap {
    auth: AuthContext;
  }
}

/**
 * Adaptador de middleware de autenticación para Hono
 * @param config Configuración del middleware
 * @returns Middleware de Hono
 */
export function honoAuthMiddleware(config: AuthMiddlewareConfig = {}): MiddlewareHandler {
  return async (c: Context, next: Next) => {
    try {
      // Verificar si la ruta debe ser saltada
      if (config.skipPaths && config.skipPaths.includes(c.req.path)) {
        c.set('auth', createEmptyAuthContext());
        await next();
        return;
      }

      // Convertir request de Hono a formato agnóstico
      const headers: Record<string, string> = {};
      c.req.raw.headers.forEach((value, key) => {
        headers[key] = value;
      });
      
      // Extraer query parameters para soporte de tokens en GET requests
      const query: Record<string, string | string[]> = {};
      const url = new URL(c.req.url);
      url.searchParams.forEach((value, key) => {
        if (query[key]) {
          // Handle multiple values for the same parameter
          if (Array.isArray(query[key])) {
            (query[key] as string[]).push(value);
          } else {
            query[key] = [query[key] as string, value];
          }
        } else {
          query[key] = value;
        }
      });
      
      const authRequest: AuthRequest = {
        headers,
        query,
        url: c.req.url
      };

      // Ejecutar autenticación
      const result = await authenticateRequest(authRequest, config);

      if (!result.success) {
        // Log del evento de fallo de autenticación
        logAuthEvent('auth.failed', undefined, {
          path: c.req.path,
          method: c.req.method,
          ip: extractClientIP(authRequest.headers),
          userAgent: extractUserAgent(authRequest.headers),
          error: result.error
        });

        return createHonoAuthErrorResponse(c, result.error, result.statusCode);
      }

      // Establecer contexto de autenticación en Hono
      c.set('auth', result.context!);

      // Log del evento de autenticación exitosa
      if (result.context?.user) {
        logAuthEvent('auth.success', result.context.user.id, {
          path: c.req.path,
          method: c.req.method,
          ip: extractClientIP(authRequest.headers),
          userAgent: extractUserAgent(authRequest.headers)
        });
      }

      await next();
    } catch (error:any) {
      console.error('Hono auth middleware error:', error);
      return createHonoAuthErrorResponse(c, 'Internal authentication error', 500, {
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  };
}

/**
 * Middleware de autenticación opcional para Hono
 * No falla si no hay token, pero lo procesa si está presente
 */
export function honoOptionalAuth(): MiddlewareHandler {
  return honoAuthMiddleware({ required: false });
}

/**
 * Middleware que requiere autenticación para Hono
 */
export function honoRequireAuth(): MiddlewareHandler {
  return honoAuthMiddleware({ required: true });
}

/**
 * Middleware que requiere permisos específicos para Hono
 * @param permissions Array de permisos requeridos
 * @param requireAll Si se requieren todos los permisos (default: false)
 */
export function honoRequirePermissions(
  permissions: string[],
  requireAll: boolean = false
): MiddlewareHandler {
  return honoAuthMiddleware({
    required: true,
    permissions,
    permissionOptions: { requireAll }
  });
}

/**
 * Middleware que requiere roles específicos para Hono
 * @param roles Array de roles requeridos
 */
export function honoRequireRoles(roles: string[]): MiddlewareHandler {
  return async (c: Context, next: Next) => {
    const authContext = c.get('auth');
    
    if (!authContext?.user) {
      return c.json(
        {
          error: 'Authentication required',
          timestamp: new Date().toISOString()
        },
        401
      );
    }

    const userRoles = authContext.user.roles.map(role => role.name);
    const hasRequiredRole = roles.some(role => userRoles.includes(role));

    if (!hasRequiredRole) {
      logAuthEvent('auth.insufficient_roles', authContext.user.id, {
        requiredRoles: roles,
        userRoles,
        path: c.req.path
      });

      return c.json(
        {
          error: `Insufficient roles. Required: ${roles.join(', ')}`,
          timestamp: new Date().toISOString()
        },
        403
      );
    }

    await next();
  };
}

/**
 * Middleware que requiere ser admin para Hono
 */
export function honoRequireAdmin(): MiddlewareHandler {
  return honoRequireRoles(['admin', 'administrator']);
}

/**
 * Middleware que requiere ser moderador o admin para Hono
 */
export function honoRequireModerator(): MiddlewareHandler {
  return honoRequireRoles(['moderator', 'admin', 'administrator']);
}

/**
 * Helper para obtener el usuario actual del contexto de Hono
 * @param c Contexto de Hono
 * @returns Usuario actual o null
 */
export function getHonoCurrentUser(c: Context): User | null {
  const authContext = c.get('auth');
  return getCurrentUser(authContext);
}

/**
 * Helper para verificar si el usuario está autenticado en Hono
 * @param c Contexto de Hono
 * @returns true si está autenticado
 */
export function isHonoAuthenticated(c: Context): boolean {
  const authContext = c.get('auth');
  return !!authContext?.user;
}

/**
 * Helper para obtener el contexto de autenticación completo en Hono
 * @param c Contexto de Hono
 * @returns Contexto de autenticación
 */
export function getHonoAuthContext(c: Context): AuthContext {
  return c.get('auth') || createEmptyAuthContext();
}

/**
 * Middleware para validar ownership de recursos en Hono
 * @param getUserIdFromParams Función para extraer el ID del usuario del recurso
 */
export function honoRequireOwnership(
  getUserIdFromParams: (c: Context) => string
): MiddlewareHandler {
  return async (c: Context, next: Next) => {
    const authContext = c.get('auth');
    
    if (!authContext?.user) {
      return c.json(
        {
          error: 'Authentication required',
          timestamp: new Date().toISOString()
        },
        401
      );
    }

    const resourceUserId = getUserIdFromParams(c);
    const isOwner = authContext.user.id === resourceUserId;
    const isAdmin = authContext.user.roles.some(role => 
      ['admin', 'administrator'].includes(role.name)
    );

    if (!isOwner && !isAdmin) {
      logAuthEvent('auth.insufficient_ownership', authContext.user.id, {
        resourceUserId,
        path: c.req.path
      });

      return c.json(
        {
          error: 'Insufficient permissions. You can only access your own resources.',
          timestamp: new Date().toISOString()
        },
        403
      );
    }

    await next();
  };
}

/**
 * Middleware para rate limiting básico en Hono
 * @param maxRequests Máximo número de requests
 * @param windowMs Ventana de tiempo en milisegundos
 */
export function honoRateLimit(
  maxRequests: number = 100,
  windowMs: number = 15 * 60 * 1000 // 15 minutos
): MiddlewareHandler {
  const requests = new Map<string, { count: number; resetTime: number }>();

  return async (c: Context, next: Next) => {
    const authContext = c.get('auth');
    const headers: Record<string, string> = {};
    c.req.raw.headers.forEach((value, key) => {
      headers[key] = value;
    });
    const clientId = authContext?.user?.id || extractClientIP(headers);
    const now = Date.now();
    
    const clientData = requests.get(clientId);
    
    if (!clientData || now > clientData.resetTime) {
      requests.set(clientId, {
        count: 1,
        resetTime: now + windowMs
      });
    } else {
      clientData.count++;
      
      if (clientData.count > maxRequests) {
        return c.json(
          {
            error: 'Rate limit exceeded',
            retryAfter: Math.ceil((clientData.resetTime - now) / 1000),
            timestamp: new Date().toISOString()
          },
          429
        );
      }
    }

    await next();
  };
}

/**
 * Middleware para CORS en Hono con autenticación
 * @param origins Orígenes permitidos
 */
export function honoCorsAuth(origins: string[] = ['*']): MiddlewareHandler {
  return async (c: Context, next: Next) => {
    const origin = c.req.header('origin');
    
    if (origins.includes('*') || (origin && origins.includes(origin))) {
      c.header('Access-Control-Allow-Origin', origin || '*');
      c.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      c.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      c.header('Access-Control-Allow-Credentials', 'true');
    }

    if (c.req.method === 'OPTIONS') {
      return c.text('', 204 as any);
    }

    await next();
  };
}

/**
 * Helper para crear respuestas de error estandarizadas en Hono
 * @param c Contexto de Hono
 * @param error Mensaje de error
 * @param statusCode Código de estado HTTP
 */
export function honoErrorResponse(
  c: Context,
  error: string,
  statusCode: number = 400
) {
  return c.json(
    {
      error,
      timestamp: new Date().toISOString(),
      path: c.req.path,
      method: c.req.method
    },
    statusCode as any
  );
}

/**
 * Helper para crear respuestas de error de autenticación específicas en Hono
 * @param c Contexto de Hono
 * @param error Mensaje de error
 * @param statusCode Código de estado HTTP
 * @param additionalData Datos adicionales para incluir en la respuesta
 */
export function createHonoAuthErrorResponse(
  c: Context,
  error: string = 'Authentication failed',
  statusCode: number = 401,
  additionalData?: any
) {
  const errorResponse: any = {
    success: false,
    error: getDetailedAuthError(error, statusCode),
    code: getAuthErrorCode(error, statusCode),
    timestamp: new Date().toISOString(),
    path: c.req.path,
    method: c.req.method
  };

  if (additionalData) {
    Object.assign(errorResponse, additionalData);
  }

  // Agregar headers de autenticación según el tipo de error
  if (statusCode === 401) {
    c.header('WWW-Authenticate', 'Bearer realm="API"');
  }

  return c.json(errorResponse, statusCode as any);
}

/**
 * Obtener mensaje de error detallado basado en el error y código de estado
 * @param error Mensaje de error original
 * @param statusCode Código de estado HTTP
 * @returns Mensaje de error detallado
 */
function getDetailedAuthError(error: string, statusCode: number): string {
  // Mapear errores comunes a mensajes más descriptivos
  const errorMappings: Record<string, string> = {
    'Invalid token': 'The provided authentication token is invalid or malformed. Please check your token and try again.',
    'Token expired': 'Your authentication token has expired. Please obtain a new token and try again.',
    'No token provided': 'Authentication token is required. Please provide a valid Bearer token in the Authorization header.',
    'Insufficient permissions': 'You do not have the required permissions to access this resource.',
    'User not found': 'The user associated with this token could not be found or has been deactivated.',
    'Token revoked': 'This authentication token has been revoked. Please obtain a new token.',
    'Invalid signature': 'The token signature is invalid. This may indicate a compromised or tampered token.',
    'Malformed token': 'The authentication token format is incorrect. Please ensure you are using a valid JWT token.',
    'Authentication required': 'This endpoint requires authentication. Please provide a valid Bearer token.',
    'Session expired': 'Your session has expired. Please log in again to continue.',
    'Account locked': 'Your account has been temporarily locked due to security reasons. Please contact support.',
    'Invalid credentials': 'The provided credentials are incorrect. Please check your username and password.'
  };

  // Buscar coincidencia exacta primero
  if (errorMappings[error]) {
    return errorMappings[error];
  }

  // Buscar coincidencias parciales
  for (const [key, value] of Object.entries(errorMappings)) {
    if (error.toLowerCase().includes(key.toLowerCase())) {
      return value;
    }
  }

  // Mensajes por código de estado si no hay coincidencia específica
  switch (statusCode) {
    case 401:
      return error.includes('token') 
        ? 'Authentication failed: Invalid or missing token. Please provide a valid Bearer token in the Authorization header.'
        : 'Authentication required. Please provide valid credentials to access this resource.';
    case 403:
      return 'Access forbidden: You do not have sufficient permissions to perform this action.';
    case 429:
      return 'Rate limit exceeded: Too many requests. Please wait before trying again.';
    default:
      return error || 'Authentication error occurred.';
  }
}

/**
 * Obtener código de error específico para APIs
 * @param error Mensaje de error
 * @param statusCode Código de estado HTTP
 * @returns Código de error para APIs
 */
function getAuthErrorCode(error: string, statusCode: number): string {
  const errorCodes: Record<string, string> = {
    'Invalid token': 'AUTH_INVALID_TOKEN',
    'Token expired': 'AUTH_TOKEN_EXPIRED',
    'No token provided': 'AUTH_TOKEN_MISSING',
    'Insufficient permissions': 'AUTH_INSUFFICIENT_PERMISSIONS',
    'User not found': 'AUTH_USER_NOT_FOUND',
    'Token revoked': 'AUTH_TOKEN_REVOKED',
    'Invalid signature': 'AUTH_INVALID_SIGNATURE',
    'Malformed token': 'AUTH_MALFORMED_TOKEN',
    'Authentication required': 'AUTH_REQUIRED',
    'Session expired': 'AUTH_SESSION_EXPIRED',
    'Account locked': 'AUTH_ACCOUNT_LOCKED',
    'Invalid credentials': 'AUTH_INVALID_CREDENTIALS'
  };

  // Buscar coincidencia exacta
  if (errorCodes[error]) {
    return errorCodes[error];
  }

  // Buscar coincidencias parciales
  for (const [key, value] of Object.entries(errorCodes)) {
    if (error.toLowerCase().includes(key.toLowerCase())) {
      return value;
    }
  }

  // Códigos por estado HTTP
  switch (statusCode) {
    case 401:
      return 'AUTH_UNAUTHORIZED';
    case 403:
      return 'AUTH_FORBIDDEN';
    case 429:
      return 'AUTH_RATE_LIMITED';
    default:
      return 'AUTH_ERROR';
  }
}

/**
 * Helper para crear respuestas de éxito estandarizadas en Hono
 * @param c Contexto de Hono
 * @param data Datos de respuesta
 * @param message Mensaje opcional
 * @param statusCode Código de estado HTTP
 */
export function honoSuccessResponse(
  c: Context,
  data: any,
  message?: string,
  statusCode: number = 200
) {
  const response: any = {
    success: true,
    data,
    timestamp: new Date().toISOString()
  };

  if (message) {
    response.message = message;
  }

  return c.json(response, statusCode as any);
}

/**
 * Middleware para logging de requests autenticados en Hono
 */
export function honoAuthLogger(): MiddlewareHandler {
  return async (c: Context, next: Next) => {
    const start = Date.now();
    const authContext = c.get('auth');
    
    await next();
    
    const duration = Date.now() - start;
    const headers: Record<string, string> = {};
    c.req.raw.headers.forEach((value, key) => {
      headers[key] = value;
    });
    const logData = {
      method: c.req.method,
      path: c.req.path,
      status: c.res.status,
      duration: `${duration}ms`,
      userId: authContext?.user?.id,
      ip: extractClientIP(headers),
      userAgent: extractUserAgent(headers)
    };
    
    console.log(`📝 Request: ${JSON.stringify(logData)}`);
  };
}