// src/adapters/websocket.ts
import { WebSocket } from 'ws';
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
 * Interfaz para WebSocket con autenticación
 */
export interface AuthenticatedWebSocket extends WebSocket {
  auth?: AuthContext;
  userId?: string;
  sessionId?: string;
  lastActivity?: Date;
}

/**
 * Configuración para el servidor WebSocket con autenticación
 */
export interface WebSocketAuthConfig extends AuthMiddlewareConfig {
  heartbeatInterval?: number; // Intervalo de heartbeat en ms
  sessionTimeout?: number; // Timeout de sesión en ms
  maxConnections?: number; // Máximo de conexiones por usuario
}

/**
 * Mapa de conexiones activas por usuario
 */
const activeConnections = new Map<string, Set<AuthenticatedWebSocket>>();
const connectionsBySession = new Map<string, AuthenticatedWebSocket>();

/**
 * Middleware de autenticación para WebSockets
 * @param ws WebSocket connection
 * @param request Request inicial
 * @param config Configuración de autenticación
 * @returns Promise<boolean> true si la autenticación es exitosa
 */
export async function authenticateWebSocket(
  ws: AuthenticatedWebSocket,
  request: any,
  config: WebSocketAuthConfig = {}
): Promise<boolean> {
  try {
    // Extraer token de la query string o headers
    const url = new URL(request.url, 'http://localhost');
    let token = url.searchParams.get('token');
    
    if (!token && request.headers.authorization) {
      const authHeader = request.headers.authorization;
      if (authHeader.startsWith('Bearer ')) {
        token = authHeader.replace('Bearer ', '');
      }
    }

    if (!token && config.required !== false) {
      ws.close(1008, 'Authentication required');
      return false;
    }

    // Convertir request a formato agnóstico
    const authRequest: AuthRequest = {
      headers: {
        ...request.headers,
        ...(token && { authorization: `Bearer ${token}` })
      }
    };

    // Ejecutar autenticación
    const result = await authenticateRequest(authRequest, config);

    if (!result.success) {
      logAuthEvent('websocket.auth.failed', undefined, {
        ip: extractClientIP(authRequest.headers),
        userAgent: extractUserAgent(authRequest.headers),
        error: result.error
      });

      ws.close(1008, result.error || 'Authentication failed');
      return false;
    }

    // Establecer contexto de autenticación
    ws.auth = result.context!;
    ws.userId = result.context?.user?.id;
    ws.sessionId = generateSessionId();
    ws.lastActivity = new Date();

    // Verificar límite de conexiones por usuario
    if (ws.userId && config.maxConnections) {
      const userConnections = activeConnections.get(ws.userId) || new Set();
      if (userConnections.size >= config.maxConnections) {
        ws.close(1008, 'Maximum connections exceeded');
        return false;
      }
    }

    // Registrar conexión
    if (ws.userId) {
      registerConnection(ws);
      
      logAuthEvent('websocket.connected', ws.userId, {
        sessionId: ws.sessionId,
        ip: extractClientIP(authRequest.headers),
        userAgent: extractUserAgent(authRequest.headers)
      });
    }

    // Configurar heartbeat si está habilitado
    if (config.heartbeatInterval) {
      setupHeartbeat(ws, config.heartbeatInterval);
    }

    // Configurar timeout de sesión
    if (config.sessionTimeout) {
      setupSessionTimeout(ws, config.sessionTimeout);
    }

    return true;
  } catch (error:any) {
    console.error('WebSocket authentication error:', error);
    ws.close(1011, 'Internal authentication error');
    return false;
  }
}

/**
 * Middleware para verificar permisos en mensajes WebSocket
 * @param ws WebSocket autenticado
 * @param permissions Permisos requeridos
 * @param requireAll Si se requieren todos los permisos
 * @returns boolean
 */
export function checkWebSocketPermissions(
  ws: AuthenticatedWebSocket,
  permissions: string[],
  requireAll: boolean = false
): boolean {
  if (!ws.auth?.user) {
    return false;
  }

  const userPermissions = ws.auth.user.roles.flatMap(role => role.permissions.map(p => p.name));
  
  if (requireAll) {
    return permissions.every(permission => userPermissions.includes(permission));
  } else {
    return permissions.some(permission => userPermissions.includes(permission));
  }
}

/**
 * Verificar si el usuario tiene roles específicos
 * @param ws WebSocket autenticado
 * @param roles Roles requeridos
 * @returns boolean
 */
export function checkWebSocketRoles(
  ws: AuthenticatedWebSocket,
  roles: string[]
): boolean {
  if (!ws.auth?.user) {
    return false;
  }

  const userRoles = ws.auth.user.roles.map(role => role.name);
  return roles.some(role => userRoles.includes(role));
}

/**
 * Obtener el usuario actual del WebSocket
 * @param ws WebSocket autenticado
 * @returns Usuario actual o null
 */
export function getWebSocketCurrentUser(ws: AuthenticatedWebSocket): User | null {
  return getCurrentUser(ws.auth);
}

/**
 * Verificar si el WebSocket está autenticado
 * @param ws WebSocket
 * @returns boolean
 */
export function isWebSocketAuthenticated(ws: AuthenticatedWebSocket): boolean {
  return !!ws.auth?.user;
}

/**
 * Obtener el contexto de autenticación del WebSocket
 * @param ws WebSocket
 * @returns Contexto de autenticación
 */
export function getWebSocketAuthContext(ws: AuthenticatedWebSocket): AuthContext {
  return ws.auth || createEmptyAuthContext();
}

/**
 * Enviar mensaje a un usuario específico
 * @param userId ID del usuario
 * @param message Mensaje a enviar
 * @param excludeSession Sesión a excluir (opcional)
 */
export function sendToUser(
  userId: string,
  message: any,
  excludeSession?: string
): void {
  const userConnections = activeConnections.get(userId);
  if (!userConnections) return;

  const messageStr = typeof message === 'string' ? message : JSON.stringify(message);
  
  userConnections.forEach(ws => {
    if (excludeSession && ws.sessionId === excludeSession) return;
    
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(messageStr);
    }
  });
}

/**
 * Enviar mensaje a usuarios con permisos específicos
 * @param permissions Permisos requeridos
 * @param message Mensaje a enviar
 * @param requireAll Si se requieren todos los permisos
 */
export function sendToUsersWithPermissions(
  permissions: string[],
  message: any,
  requireAll: boolean = false
): void {
  const messageStr = typeof message === 'string' ? message : JSON.stringify(message);
  
  activeConnections.forEach((connections, userId) => {
    connections.forEach(ws => {
      if (ws.readyState === WebSocket.OPEN && 
          checkWebSocketPermissions(ws, permissions, requireAll)) {
        ws.send(messageStr);
      }
    });
  });
}

/**
 * Enviar mensaje a usuarios con roles específicos
 * @param roles Roles requeridos
 * @param message Mensaje a enviar
 */
export function sendToUsersWithRoles(
  roles: string[],
  message: any
): void {
  const messageStr = typeof message === 'string' ? message : JSON.stringify(message);
  
  activeConnections.forEach((connections, userId) => {
    connections.forEach(ws => {
      if (ws.readyState === WebSocket.OPEN && 
          checkWebSocketRoles(ws, roles)) {
        ws.send(messageStr);
      }
    });
  });
}

/**
 * Broadcast a todas las conexiones autenticadas
 * @param message Mensaje a enviar
 * @param excludeUser Usuario a excluir (opcional)
 */
export function broadcastToAuthenticated(
  message: any,
  excludeUser?: string
): void {
  const messageStr = typeof message === 'string' ? message : JSON.stringify(message);
  
  activeConnections.forEach((connections, userId) => {
    if (excludeUser && userId === excludeUser) return;
    
    connections.forEach(ws => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(messageStr);
      }
    });
  });
}

/**
 * Obtener estadísticas de conexiones
 * @returns Estadísticas de conexiones
 */
export function getConnectionStats() {
  let totalConnections = 0;
  const userStats: Record<string, number> = {};
  
  activeConnections.forEach((connections, userId) => {
    const activeCount = Array.from(connections).filter(
      ws => ws.readyState === WebSocket.OPEN
    ).length;
    
    totalConnections += activeCount;
    userStats[userId] = activeCount;
  });
  
  return {
    totalConnections,
    uniqueUsers: activeConnections.size,
    userStats
  };
}

/**
 * Desconectar todas las sesiones de un usuario
 * @param userId ID del usuario
 * @param reason Razón de la desconexión
 */
export function disconnectUser(userId: string, reason: string = 'User disconnected'): void {
  const userConnections = activeConnections.get(userId);
  if (!userConnections) return;
  
  userConnections.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.close(1000, reason);
    }
  });
  
  logAuthEvent('websocket.user_disconnected', userId, { reason });
}

/**
 * Limpiar conexiones inactivas
 */
export function cleanupInactiveConnections(): void {
  const now = new Date();
  const inactiveThreshold = 30 * 60 * 1000; // 30 minutos
  
  activeConnections.forEach((connections, userId) => {
    connections.forEach(ws => {
      if (ws.readyState !== WebSocket.OPEN || 
          (ws.lastActivity && now.getTime() - ws.lastActivity.getTime() > inactiveThreshold)) {
        unregisterConnection(ws);
      }
    });
  });
}

/**
 * Registrar una nueva conexión
 * @param ws WebSocket autenticado
 */
function registerConnection(ws: AuthenticatedWebSocket): void {
  if (!ws.userId || !ws.sessionId) return;
  
  // Agregar a conexiones por usuario
  if (!activeConnections.has(ws.userId)) {
    activeConnections.set(ws.userId, new Set());
  }
  activeConnections.get(ws.userId)!.add(ws);
  
  // Agregar a conexiones por sesión
  connectionsBySession.set(ws.sessionId, ws);
  
  // Configurar cleanup al cerrar
  ws.on('close', () => unregisterConnection(ws));
  ws.on('error', () => unregisterConnection(ws));
}

/**
 * Desregistrar una conexión
 * @param ws WebSocket autenticado
 */
function unregisterConnection(ws: AuthenticatedWebSocket): void {
  if (ws.userId) {
    const userConnections = activeConnections.get(ws.userId);
    if (userConnections) {
      userConnections.delete(ws);
      if (userConnections.size === 0) {
        activeConnections.delete(ws.userId);
      }
    }
    
    logAuthEvent('websocket.disconnected', ws.userId, {
      sessionId: ws.sessionId
    });
  }
  
  if (ws.sessionId) {
    connectionsBySession.delete(ws.sessionId);
  }
}

/**
 * Configurar heartbeat para mantener la conexión viva
 * @param ws WebSocket
 * @param interval Intervalo en milisegundos
 */
function setupHeartbeat(ws: AuthenticatedWebSocket, interval: number): void {
  const heartbeatTimer = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.ping();
      ws.lastActivity = new Date();
    } else {
      clearInterval(heartbeatTimer);
    }
  }, interval);
  
  ws.on('pong', () => {
    ws.lastActivity = new Date();
  });
  
  ws.on('close', () => {
    clearInterval(heartbeatTimer);
  });
}

/**
 * Configurar timeout de sesión
 * @param ws WebSocket
 * @param timeout Timeout en milisegundos
 */
function setupSessionTimeout(ws: AuthenticatedWebSocket, timeout: number): void {
  const timeoutTimer = setTimeout(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.close(1000, 'Session timeout');
    }
  }, timeout);
  
  ws.on('message', () => {
    ws.lastActivity = new Date();
  });
  
  ws.on('close', () => {
    clearTimeout(timeoutTimer);
  });
}

/**
 * Generar ID de sesión único
 * @returns String único para la sesión
 */
function generateSessionId(): string {
  return `ws_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Middleware para manejar mensajes WebSocket con autenticación
 * @param ws WebSocket autenticado
 * @param message Mensaje recibido
 * @param permissions Permisos requeridos para procesar el mensaje
 * @returns boolean true si el mensaje puede ser procesado
 */
export function handleAuthenticatedMessage(
  ws: AuthenticatedWebSocket,
  message: any,
  permissions?: string[]
): boolean {
  // Actualizar última actividad
  ws.lastActivity = new Date();
  
  // Verificar autenticación
  if (!isWebSocketAuthenticated(ws)) {
    ws.send(JSON.stringify({
      type: 'error',
      message: 'Authentication required',
      timestamp: new Date().toISOString()
    }));
    return false;
  }
  
  // Verificar permisos si se especifican
  if (permissions && !checkWebSocketPermissions(ws, permissions)) {
    ws.send(JSON.stringify({
      type: 'error',
      message: 'Insufficient permissions',
      timestamp: new Date().toISOString()
    }));
    
    logAuthEvent('websocket.insufficient_permissions', ws.userId, {
      requiredPermissions: permissions,
      sessionId: ws.sessionId
    });
    
    return false;
  }
  
  return true;
}

/**
 * Crear respuesta estandarizada para WebSocket
 * @param type Tipo de respuesta
 * @param data Datos de respuesta
 * @param message Mensaje opcional
 * @returns Objeto de respuesta
 */
export function createWebSocketResponse(
  type: 'success' | 'error' | 'info',
  data?: any,
  message?: string
) {
  return {
    type,
    data,
    message,
    timestamp: new Date().toISOString()
  };
}

/**
 * Inicializar limpieza automática de conexiones
 * @param interval Intervalo de limpieza en milisegundos
 */
export function initializeConnectionCleanup(interval: number = 5 * 60 * 1000): void {
  setInterval(() => {
    cleanupInactiveConnections();
  }, interval);
}