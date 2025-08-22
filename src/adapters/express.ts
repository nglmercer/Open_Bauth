// src/adapters/express.ts
import { Request, Response, NextFunction } from 'express';
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
 * Extiende el tipo Request de Express para incluir autenticación
 */
declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
    }
  }
}

/**
 * Adaptador de middleware de autenticación para Express
 * @param config Configuración del middleware
 * @returns Middleware de Express
 */
export function expressAuthMiddleware(config: AuthMiddlewareConfig = {}) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Verificar si la ruta debe ser saltada
      if (config.skipPaths && config.skipPaths.includes(req.path)) {
        req.auth = createEmptyAuthContext();
        return next();
      }

      // Convertir request de Express a formato agnóstico
      const authRequest: AuthRequest = {
        headers: req.headers as Record<string, string>
      };

      // Ejecutar autenticación
      const result = await authenticateRequest(authRequest, config);

      if (!result.success) {
        // Log del evento de fallo de autenticación
        logAuthEvent('auth.failed', undefined, {
          path: req.path,
          method: req.method,
          ip: extractClientIP(authRequest.headers),
          userAgent: extractUserAgent(authRequest.headers),
          error: result.error
        });

        return res.status(result.statusCode || 401).json({
          error: result.error,
          timestamp: new Date().toISOString()
        });
      }

      // Establecer contexto de autenticación en Express
      req.auth = result.context!;

      // Log del evento de autenticación exitosa
      if (result.context?.user) {
        logAuthEvent('auth.success', result.context.user.id, {
          path: req.path,
          method: req.method,
          ip: extractClientIP(authRequest.headers),
          userAgent: extractUserAgent(authRequest.headers)
        });
      }

      next();
    } catch (error:any) {
      console.error('Express auth middleware error:', error);
      return res.status(500).json({
        error: 'Internal authentication error',
        timestamp: new Date().toISOString()
      });
    }
  };
}

/**
 * Middleware de autenticación opcional para Express
 * No falla si no hay token, pero lo procesa si está presente
 */
export function expressOptionalAuth() {
  return expressAuthMiddleware({ required: false });
}

/**
 * Middleware que requiere autenticación para Express
 */
export function expressRequireAuth() {
  return expressAuthMiddleware({ required: true });
}

/**
 * Middleware que requiere permisos específicos para Express
 * @param permissions Array de permisos requeridos
 * @param requireAll Si se requieren todos los permisos (default: false)
 */
export function expressRequirePermissions(
  permissions: string[],
  requireAll: boolean = false
) {
  return expressAuthMiddleware({
    required: true,
    permissions,
    permissionOptions: { requireAll }
  });
}

/**
 * Middleware que requiere roles específicos para Express
 * @param roles Array de roles requeridos
 */
export function expressRequireRoles(roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authContext = req.auth;
    
    if (!authContext?.user) {
      return res.status(401).json({
        error: 'Authentication required',
        timestamp: new Date().toISOString()
      });
    }

    const userRoles = authContext.user.roles.map(role => role.name);
    const hasRequiredRole = roles.some(role => userRoles.includes(role));

    if (!hasRequiredRole) {
      logAuthEvent('auth.insufficient_roles', authContext.user.id, {
        requiredRoles: roles,
        userRoles,
        path: req.path
      });

      return res.status(403).json({
        error: `Insufficient roles. Required: ${roles.join(', ')}`,
        timestamp: new Date().toISOString()
      });
    }

    next();
  };
}

/**
 * Middleware que requiere ser admin para Express
 */
export function expressRequireAdmin() {
  return expressRequireRoles(['admin', 'administrator']);
}

/**
 * Middleware que requiere ser moderador o admin para Express
 */
export function expressRequireModerator() {
  return expressRequireRoles(['moderator', 'admin', 'administrator']);
}

/**
 * Helper para obtener el usuario actual del request de Express
 * @param req Request de Express
 * @returns Usuario actual o null
 */
export function getExpressCurrentUser(req: Request) {
  return getCurrentUser(req.auth);
}

/**
 * Helper para verificar si el usuario está autenticado en Express
 * @param req Request de Express
 * @returns true si está autenticado
 */
export function isExpressAuthenticated(req: Request): boolean {
  return !!req.auth?.user;
}

/**
 * Helper para obtener el contexto de autenticación completo en Express
 * @param req Request de Express
 * @returns Contexto de autenticación
 */
export function getExpressAuthContext(req: Request): AuthContext {
  return req.auth || createEmptyAuthContext();
}

/**
 * Middleware para validar ownership de recursos en Express
 * @param getUserIdFromParams Función para extraer el ID del usuario del recurso
 */
export function expressRequireOwnership(
  getUserIdFromParams: (req: Request) => string
) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authContext = req.auth;
    
    if (!authContext?.user) {
      return res.status(401).json({
        error: 'Authentication required',
        timestamp: new Date().toISOString()
      });
    }

    const resourceUserId = getUserIdFromParams(req);
    const isOwner = authContext.user.id === resourceUserId;
    const isAdmin = authContext.user.roles.some(role => 
      ['admin', 'administrator'].includes(role.name)
    );

    if (!isOwner && !isAdmin) {
      logAuthEvent('auth.insufficient_ownership', authContext.user.id, {
        resourceUserId,
        path: req.path
      });

      return res.status(403).json({
        error: 'Insufficient permissions. You can only access your own resources.',
        timestamp: new Date().toISOString()
      });
    }

    next();
  };
}

/**
 * Middleware para rate limiting básico en Express
 * @param maxRequests Máximo número de requests
 * @param windowMs Ventana de tiempo en milisegundos
 */
export function expressRateLimit(
  maxRequests: number = 100,
  windowMs: number = 15 * 60 * 1000 // 15 minutos
) {
  const requests = new Map<string, { count: number; resetTime: number }>();

  return (req: Request, res: Response, next: NextFunction) => {
    const authContext = req.auth;
    const clientId = authContext?.user?.id || extractClientIP(req.headers as Record<string, string>);
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
        return res.status(429).json({
          error: 'Rate limit exceeded',
          retryAfter: Math.ceil((clientData.resetTime - now) / 1000),
          timestamp: new Date().toISOString()
        });
      }
    }

    next();
  };
}

/**
 * Middleware para CORS en Express con autenticación
 * @param origins Orígenes permitidos
 */
export function expressCorsAuth(origins: string[] = ['*']) {
  return (req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin;
    
    if (origins.includes('*') || (origin && origins.includes(origin))) {
      res.header('Access-Control-Allow-Origin', origin || '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      res.header('Access-Control-Allow-Credentials', 'true');
    }

    if (req.method === 'OPTIONS') {
      return res.sendStatus(204);
    }

    next();
  };
}

/**
 * Helper para crear respuestas de error estandarizadas en Express
 * @param res Response de Express
 * @param error Mensaje de error
 * @param statusCode Código de estado HTTP
 */
export function expressErrorResponse(
  res: Response,
  error: string,
  statusCode: number = 400
) {
  return res.status(statusCode).json({
    error,
    timestamp: new Date().toISOString()
  });
}

/**
 * Helper para crear respuestas de éxito estandarizadas en Express
 * @param res Response de Express
 * @param data Datos de respuesta
 * @param message Mensaje opcional
 * @param statusCode Código de estado HTTP
 */
export function expressSuccessResponse(
  res: Response,
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

  return res.status(statusCode).json(response);
}

/**
 * Middleware para logging de requests autenticados en Express
 */
export function expressAuthLogger() {
  return (req: Request, res: Response, next: NextFunction) => {
    const start = Date.now();
    const authContext = req.auth;
    
    res.on('finish', () => {
      const duration = Date.now() - start;
      const logData = {
        method: req.method,
        path: req.path,
        status: res.statusCode,
        duration: `${duration}ms`,
        userId: authContext?.user?.id,
        ip: extractClientIP(req.headers as Record<string, string>),
        userAgent: extractUserAgent(req.headers as Record<string, string>)
      };
      
      console.log(`📝 Request: ${JSON.stringify(logData)}`);
    });
    
    next();
  };
}

/**
 * Middleware de manejo de errores para Express con autenticación
 */
export function expressAuthErrorHandler() {
  return (error: any, req: Request, res: Response, next: NextFunction) => {
    console.error('Express auth error:', error);
    
    // Log del error con contexto de autenticación
    const authContext = req.auth;
    logAuthEvent('auth.error', authContext?.user?.id, {
      error: error.message,
      stack: error.stack,
      path: req.path,
      method: req.method
    });

    // Determinar código de estado basado en el tipo de error
    let statusCode = 500;
    let message = 'Internal server error';

    if (error.name === 'ValidationError') {
      statusCode = 400;
      message = 'Validation error';
    } else if (error.name === 'UnauthorizedError') {
      statusCode = 401;
      message = 'Unauthorized';
    } else if (error.name === 'ForbiddenError') {
      statusCode = 403;
      message = 'Forbidden';
    }

    res.status(statusCode).json({
      error: message,
      timestamp: new Date().toISOString(),
      ...(process.env.NODE_ENV === 'development' && { details: error.message })
    });
  };
}

/**
 * Middleware para validación de JSON en Express
 */
export function expressJsonValidator() {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.headers['content-type']?.includes('application/json')) {
      try {
        if (req.body && typeof req.body === 'string') {
          req.body = JSON.parse(req.body);
        }
      } catch (error:any) {
        return res.status(400).json({
          error: 'Invalid JSON format',
          timestamp: new Date().toISOString()
        });
      }
    }
    next();
  };
}

/**
 * Middleware para sanitización de datos en Express
 */
export function expressSanitizer() {
  return (req: Request, res: Response, next: NextFunction) => {
    // Sanitizar query parameters
    if (req.query) {
      for (const key in req.query) {
        if (typeof req.query[key] === 'string') {
          req.query[key] = (req.query[key] as string)
            .replace(/<script[^>]*>.*?<\/script>/gi, '')
            .replace(/<[^>]*>/g, '')
            .trim();
        }
      }
    }

    // Sanitizar body
    if (req.body && typeof req.body === 'object') {
      sanitizeObject(req.body);
    }

    next();
  };
}

/**
 * Función helper para sanitizar objetos recursivamente
 */
function sanitizeObject(obj: any): void {
  for (const key in obj) {
    if (typeof obj[key] === 'string') {
      obj[key] = obj[key]
        .replace(/<script[^>]*>.*?<\/script>/gi, '')
        .replace(/<[^>]*>/g, '')
        .trim();
    } else if (typeof obj[key] === 'object' && obj[key] !== null) {
      sanitizeObject(obj[key]);
    }
  }
}