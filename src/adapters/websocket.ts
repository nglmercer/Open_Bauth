// src/adapters/websocket.ts
// Type-safe conditional imports for WebSocket

// Define WebSocket-compatible interface
export interface WSWebSocket {
  send(data: string | Buffer): void;
  close(code?: number, reason?: string): void;
  on(event: string, listener: (...args: any[]) => void): void;
  off(event: string, listener: (...args: any[]) => void): void;
  ping(data?: Buffer): void;
  readyState: number;
  CONNECTING: number;
  OPEN: number;
  CLOSING: number;
  CLOSED: number;
}

// Use our interface as the WebSocket type
type WebSocket = WSWebSocket;
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
export interface AuthenticatedWebSocket extends WSWebSocket {
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
      const errorDetails = getWebSocketAuthErrorDetails('No token provided', 401);
      ws.close(errorDetails.closeCode, errorDetails.reason);
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

      const errorDetails = getWebSocketAuthErrorDetails(result.error, result.statusCode);
      ws.close(errorDetails.closeCode, errorDetails.reason);
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
        const errorDetails = getWebSocketAuthErrorDetails('Maximum connections exceeded', 429);
        ws.close(errorDetails.closeCode, errorDetails.reason);
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
    const errorDetails = getWebSocketAuthErrorDetails('Internal authentication error', 500);
    ws.close(errorDetails.closeCode, errorDetails.reason);
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

  const userPermissions = ws.auth.user.roles.flatMap(role => 
    role.permissions?.map(p => p.name) || []
  );
  
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
    ws.send(JSON.stringify(createWebSocketAuthErrorResponse('Authentication required', 401)));
    return false;
  }
  
  // Verificar permisos si se especifican
  if (permissions && !checkWebSocketPermissions(ws, permissions)) {
    ws.send(JSON.stringify(createWebSocketAuthErrorResponse('Insufficient permissions', 403, {
      requiredPermissions: permissions
    })));
    
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
 * Crear respuesta de error de autenticación específica para WebSocket
 * @param error Mensaje de error
 * @param statusCode Código de estado HTTP
 * @param additionalData Datos adicionales
 * @returns Objeto de respuesta de error
 */
export function createWebSocketAuthErrorResponse(
  error: string = 'Authentication failed',
  statusCode: number = 401,
  additionalData?: any
) {
  const errorResponse: any = {
    type: 'auth_error',
    success: false,
    error: getDetailedWebSocketAuthError(error, statusCode),
    code: getWebSocketAuthErrorCode(error, statusCode),
    statusCode,
    timestamp: new Date().toISOString()
  };

  if (additionalData) {
    Object.assign(errorResponse, additionalData);
  }

  return errorResponse;
}

/**
 * Obtener detalles de error para cierre de conexión WebSocket
 * @param error Mensaje de error
 * @param statusCode Código de estado HTTP
 * @returns Detalles del error con código de cierre y razón
 */
export function getWebSocketAuthErrorDetails(
  error: string = 'Authentication failed',
  statusCode?: number
): { closeCode: number; reason: string } {
  const detailedError = getDetailedWebSocketAuthError(error, statusCode || 401);
  
  // Mapear códigos de estado HTTP a códigos de cierre WebSocket
  let closeCode: number;
  switch (statusCode) {
    case 400:
      closeCode = 1002; // Protocol error
      break;
    case 401:
      closeCode = 1008; // Policy violation (unauthorized)
      break;
    case 403:
      closeCode = 1008; // Policy violation (forbidden)
      break;
    case 429:
      closeCode = 1008; // Policy violation (rate limited)
      break;
    case 500:
      closeCode = 1011; // Internal error
      break;
    default:
      closeCode = 1008; // Policy violation (general auth error)
  }

  return {
    closeCode,
    reason: detailedError.length > 123 ? detailedError.substring(0, 120) + '...' : detailedError
  };
}

/**
 * Obtener mensaje de error detallado para WebSocket
 * @param error Mensaje de error original
 * @param statusCode Código de estado HTTP
 * @returns Mensaje de error detallado
 */
function getDetailedWebSocketAuthError(error: string, statusCode: number): string {
  // Mapear errores comunes a mensajes más descriptivos
  const errorMappings: Record<string, string> = {
    'Invalid token': 'The provided authentication token is invalid or malformed. Please reconnect with a valid token.',
    'Token expired': 'Your authentication token has expired. Please reconnect with a new token.',
    'No token provided': 'Authentication token is required. Please provide a valid token in the connection URL or headers.',
    'Insufficient permissions': 'You do not have the required permissions for this WebSocket operation.',
    'User not found': 'The user associated with this token could not be found or has been deactivated.',
    'Token revoked': 'This authentication token has been revoked. Please obtain a new token and reconnect.',
    'Invalid signature': 'The token signature is invalid. This may indicate a compromised or tampered token.',
    'Malformed token': 'The authentication token format is incorrect. Please ensure you are using a valid JWT token.',
    'Authentication required': 'This WebSocket connection requires authentication. Please provide a valid token.',
    'Session expired': 'Your session has expired. Please reconnect with a new authentication token.',
    'Account locked': 'Your account has been temporarily locked. Please contact support.',
    'Invalid credentials': 'The provided credentials are incorrect.',
    'Maximum connections exceeded': 'You have reached the maximum number of allowed concurrent connections.',
    'Internal authentication error': 'An internal error occurred during authentication. Please try reconnecting.'
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
        ? 'WebSocket authentication failed: Invalid or missing token. Please provide a valid token and reconnect.'
        : 'WebSocket authentication required. Please provide valid credentials and reconnect.';
    case 403:
      return 'WebSocket access forbidden: You do not have sufficient permissions for this connection.';
    case 429:
      return 'WebSocket rate limit exceeded: Too many connection attempts. Please wait before reconnecting.';
    case 500:
      return 'WebSocket internal error: An unexpected error occurred. Please try reconnecting.';
    default:
      return error || 'WebSocket authentication error occurred.';
  }
}

/**
 * Obtener código de error específico para WebSocket
 * @param error Mensaje de error
 * @param statusCode Código de estado HTTP
 * @returns Código de error para APIs
 */
function getWebSocketAuthErrorCode(error: string, statusCode: number): string {
  const errorCodes: Record<string, string> = {
    'Invalid token': 'WS_AUTH_INVALID_TOKEN',
    'Token expired': 'WS_AUTH_TOKEN_EXPIRED',
    'No token provided': 'WS_AUTH_TOKEN_MISSING',
    'Insufficient permissions': 'WS_AUTH_INSUFFICIENT_PERMISSIONS',
    'User not found': 'WS_AUTH_USER_NOT_FOUND',
    'Token revoked': 'WS_AUTH_TOKEN_REVOKED',
    'Invalid signature': 'WS_AUTH_INVALID_SIGNATURE',
    'Malformed token': 'WS_AUTH_MALFORMED_TOKEN',
    'Authentication required': 'WS_AUTH_REQUIRED',
    'Session expired': 'WS_AUTH_SESSION_EXPIRED',
    'Account locked': 'WS_AUTH_ACCOUNT_LOCKED',
    'Invalid credentials': 'WS_AUTH_INVALID_CREDENTIALS',
    'Maximum connections exceeded': 'WS_AUTH_MAX_CONNECTIONS',
    'Internal authentication error': 'WS_AUTH_INTERNAL_ERROR'
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
      return 'WS_AUTH_UNAUTHORIZED';
    case 403:
      return 'WS_AUTH_FORBIDDEN';
    case 429:
      return 'WS_AUTH_RATE_LIMITED';
    case 500:
      return 'WS_AUTH_INTERNAL_ERROR';
    default:
      return 'WS_AUTH_ERROR';
  }
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