// src/adapters/hono.ts
import { Context, Next } from 'hono';
import { 
  authenticateRequest, 
  AuthMiddlewareConfig, 
  getCurrentUser,
  createEmptyAuthContext,
  logAuthEvent,
  extractClientIP,
  extractUserAgent
} from '../middleware/auth';
import type { AuthContext, AuthRequest } from '../types/auth';

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
export function honoAuthMiddleware(config: AuthMiddlewareConfig = {}) {
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
      const authRequest: AuthRequest = {
        headers
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

        return c.json(
          {
            error: result.error,
            timestamp: new Date().toISOString()
          },
          (result.statusCode || 401) as any
        );
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
      return c.json(
        {
          error: 'Internal authentication error',
          timestamp: new Date().toISOString()
        },
        500
      );
    }
  };
}

/**
 * Middleware de autenticación opcional para Hono
 * No falla si no hay token, pero lo procesa si está presente
 */
export function honoOptionalAuth() {
  return honoAuthMiddleware({ required: false });
}

/**
 * Middleware que requiere autenticación para Hono
 */
export function honoRequireAuth() {
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
) {
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
export function honoRequireRoles(roles: string[]) {
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
export function honoRequireAdmin() {
  return honoRequireRoles(['admin', 'administrator']);
}

/**
 * Middleware que requiere ser moderador o admin para Hono
 */
export function honoRequireModerator() {
  return honoRequireRoles(['moderator', 'admin', 'administrator']);
}

/**
 * Helper para obtener el usuario actual del contexto de Hono
 * @param c Contexto de Hono
 * @returns Usuario actual o null
 */
export function getHonoCurrentUser(c: Context) {
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
) {
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
) {
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
export function honoCorsAuth(origins: string[] = ['*']) {
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
export function honoAuthLogger() {
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