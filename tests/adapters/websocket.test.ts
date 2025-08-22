// tests/adapters/websocket.test.ts
// Tests para el adaptador de WebSocket

import { describe, test, expect, beforeEach, afterEach, mock } from 'bun:test';
import {
  wsAuthMiddleware,
  wsRequireAuth,
  wsRequirePermissions,
  wsRequireRoles,
  wsRequireAdmin,
  wsRequireModerator,
  getWsCurrentUser,
  isWsAuthenticated,
  getWsAuthContext,
  wsRequireOwnership,
  wsRateLimit,
  wsErrorResponse,
  wsSuccessResponse,
  wsAuthLogger,
  wsMessageValidator,
  wsBroadcastAuth,
  wsRoomAuth,
  wsConnectionManager
} from '../../src/adapters/websocket';
import { AuthService } from '../../src/services/auth';
import { JWTService } from '../../src/services/jwt';
import { PermissionService } from '../../src/services/permissions';
import { testUtils, TEST_JWT_SECRET } from '../setup';
import type { WebSocket } from 'ws';

// Mock de WebSocket
interface MockWebSocket extends Partial<WebSocket> {
  user?: any;
  authContext?: any;
  rooms?: Set<string>;
  id?: string;
  send: ReturnType<typeof mock>;
  close: ReturnType<typeof mock>;
  ping: ReturnType<typeof mock>;
  pong: ReturnType<typeof mock>;
  terminate: ReturnType<typeof mock>;
  readyState: number;
  url?: string;
  protocol?: string;
  extensions?: string;
  bufferedAmount: number;
  binaryType: 'nodebuffer' | 'arraybuffer' | 'fragments';
  CONNECTING: 0;
  OPEN: 1;
  CLOSING: 2;
  CLOSED: 3;
}

const createMockWebSocket = (overrides: Partial<MockWebSocket> = {}): MockWebSocket => {
  return {
    readyState: 1, // OPEN
    bufferedAmount: 0,
    binaryType: 'nodebuffer',
    CONNECTING: 0,
    OPEN: 1,
    CLOSING: 2,
    CLOSED: 3,
    user: undefined,
    authContext: undefined,
    rooms: new Set(),
    id: `ws-${Math.random().toString(36).substr(2, 9)}`,
    send: mock((data: string) => {}),
    close: mock((code?: number, reason?: string) => {}),
    ping: mock((data?: Buffer) => {}),
    pong: mock((data?: Buffer) => {}),
    terminate: mock(() => {}),
    url: 'ws://localhost:3000',
    protocol: '',
    extensions: '',
    ...overrides
  };
};

// Mock de mensaje WebSocket
interface MockMessage {
  type: string;
  data?: any;
  token?: string;
  room?: string;
  target?: string;
  timestamp?: number;
}

const createMockMessage = (overrides: Partial<MockMessage> = {}): MockMessage => {
  return {
    type: 'test',
    data: { message: 'Hello World' },
    timestamp: Date.now(),
    ...overrides
  };
};

describe('WebSocket Adapter', () => {
  let authService: AuthService;
  let jwtService: JWTService;
  let permissionService: PermissionService;
  let testUserId: number;
  let testToken: string;
  let mockWs: MockWebSocket;

  beforeEach(async () => {
    authService = new AuthService();
    jwtService = new JWTService(TEST_JWT_SECRET);
    permissionService = new PermissionService();
    await testUtils.cleanTestData();
    
    // Crear usuario de prueba
    const userData = testUtils.generateTestUser();
    const result = await authService.register(userData);
    testUserId = result.user!.id;
    
    // Generar token de prueba
    testToken = testUtils.generateTestJWT({ userId: testUserId });
    
    mockWs = createMockWebSocket();
  });

  afterEach(async () => {
    await testUtils.cleanTestData();
  });

  describe('wsAuthMiddleware', () => {
    test('should authenticate valid token from message', async () => {
      const message = createMockMessage({
        type: 'auth',
        token: testToken
      });
      
      const middleware = wsAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(true);
      expect(mockWs.user).toBeDefined();
      expect(mockWs.user?.id).toBe(testUserId);
      expect(mockWs.authContext).toBeDefined();
      expect(mockWs.authContext?.isAuthenticated).toBe(true);
      testUtils.validateUserStructure(mockWs.user!);
    });

    test('should authenticate valid token from query string', async () => {
      mockWs.url = `ws://localhost:3000?token=${testToken}`;
      
      const message = createMockMessage({ type: 'connect' });
      
      const middleware = wsAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        extractToken: (ws, message) => {
          const url = new URL(ws.url!, 'ws://localhost');
          return url.searchParams.get('token');
        }
      });
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(true);
      expect(mockWs.user).toBeDefined();
    });

    test('should reject invalid token', async () => {
      const message = createMockMessage({
        type: 'auth',
        token: 'invalid-token'
      });
      
      const middleware = wsAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid token');
      expect(mockWs.user).toBeUndefined();
      expect(mockWs.authContext?.isAuthenticated).toBe(false);
    });

    test('should reject missing token', async () => {
      const message = createMockMessage({ type: 'auth' });
      
      const middleware = wsAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('No token provided');
    });

    test('should handle expired token', async () => {
      const expiredToken = testUtils.generateTestJWT(
        { userId: testUserId },
        { expiresIn: '-1h' }
      );
      
      const message = createMockMessage({
        type: 'auth',
        token: expiredToken
      });
      
      const middleware = wsAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('Token expired');
    });

    test('should handle non-existent user', async () => {
      const invalidUserToken = testUtils.generateTestJWT({ userId: 99999 });
      
      const message = createMockMessage({
        type: 'auth',
        token: invalidUserToken
      });
      
      const middleware = wsAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('User not found');
    });
  });

  describe('wsRequireAuth', () => {
    test('should allow authenticated connections', async () => {
      mockWs.user = await authService.findUserById(testUserId);
      mockWs.authContext = { isAuthenticated: true };
      
      const message = createMockMessage();
      
      const middleware = wsRequireAuth();
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(true);
    });

    test('should reject unauthenticated connections', async () => {
      mockWs.authContext = { isAuthenticated: false };
      
      const message = createMockMessage();
      
      const middleware = wsRequireAuth();
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('Authentication required');
    });
  });

  describe('wsRequirePermissions', () => {
    let permissionName: string;

    beforeEach(async () => {
      // Configurar permisos
      const roleData = testUtils.generateTestRole();
      const roleResult = await permissionService.createRole(roleData);
      
      const permissionData = testUtils.generateTestPermission();
      const permissionResult = await permissionService.createPermission(permissionData);
      permissionName = permissionData.name;
      
      await permissionService.assignPermissionToRole(roleResult.role!.id, permissionResult.permission!.id);
      await authService.assignRole(testUserId, roleData.name);
    });

    test('should allow access with required permission', async () => {
      const user = await authService.findUserById(testUserId);
      mockWs.user = user;
      mockWs.authContext = {
        isAuthenticated: true,
        user,
        permissions: await permissionService.getUserPermissions(testUserId)
      };
      
      const message = createMockMessage();
      
      const middleware = wsRequirePermissions([permissionName], {
        permissionService
      });
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(true);
    });

    test('should deny access without required permission', async () => {
      const user = await authService.findUserById(testUserId);
      mockWs.user = user;
      mockWs.authContext = {
        isAuthenticated: true,
        user,
        permissions: []
      };
      
      const message = createMockMessage();
      
      const middleware = wsRequirePermissions(['non-existent-permission'], {
        permissionService
      });
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('Insufficient permissions');
    });

    test('should support multiple permissions with OR logic', async () => {
      const user = await authService.findUserById(testUserId);
      mockWs.user = user;
      mockWs.authContext = {
        isAuthenticated: true,
        user,
        permissions: await permissionService.getUserPermissions(testUserId)
      };
      
      const message = createMockMessage();
      
      const middleware = wsRequirePermissions(
        [permissionName, 'non-existent-permission'],
        {
          permissionService,
          requireAll: false
        }
      );
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(true);
    });
  });

  describe('wsRequireRoles', () => {
    let roleName: string;

    beforeEach(async () => {
      // Configurar roles
      const roleData = testUtils.generateTestRole();
      const roleResult = await permissionService.createRole(roleData);
      roleName = roleData.name;
      
      await authService.assignRole(testUserId, roleName);
    });

    test('should allow access with required role', async () => {
      const user = await authService.findUserById(testUserId);
      mockWs.user = user;
      mockWs.authContext = {
        isAuthenticated: true,
        user,
        roles: await authService.getUserRoles(testUserId)
      };
      
      const message = createMockMessage();
      
      const middleware = wsRequireRoles([roleName], {
        permissionService
      });
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(true);
    });

    test('should deny access without required role', async () => {
      const user = await authService.findUserById(testUserId);
      mockWs.user = user;
      mockWs.authContext = {
        isAuthenticated: true,
        user,
        roles: []
      };
      
      const message = createMockMessage();
      
      const middleware = wsRequireRoles(['non-existent-role'], {
        permissionService
      });
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('Insufficient roles');
    });
  });

  describe('wsRequireAdmin', () => {
    test('should allow admin users', async () => {
      // Crear rol admin
      const adminRole = testUtils.generateTestRole({ name: 'admin' });
      await permissionService.createRole(adminRole);
      await authService.assignRole(testUserId, 'admin');
      
      const user = await authService.findUserById(testUserId);
      mockWs.user = user;
      mockWs.authContext = {
        isAuthenticated: true,
        user,
        roles: await authService.getUserRoles(testUserId)
      };
      
      const message = createMockMessage();
      
      const middleware = wsRequireAdmin({ permissionService });
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(true);
    });

    test('should deny non-admin users', async () => {
      const user = await authService.findUserById(testUserId);
      mockWs.user = user;
      mockWs.authContext = {
        isAuthenticated: true,
        user,
        roles: []
      };
      
      const message = createMockMessage();
      
      const middleware = wsRequireAdmin({ permissionService });
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('Admin access required');
    });
  });

  describe('Helper Functions', () => {
    test('getWsCurrentUser should return current user', () => {
      const user = { id: testUserId, email: 'test@example.com' };
      mockWs.user = user;
      
      const currentUser = getWsCurrentUser(mockWs);
      
      expect(currentUser).toEqual(user);
    });

    test('isWsAuthenticated should check authentication status', () => {
      mockWs.authContext = { isAuthenticated: true };
      
      const isAuth = isWsAuthenticated(mockWs);
      
      expect(isAuth).toBe(true);
    });

    test('getWsAuthContext should return auth context', () => {
      const authContext = { isAuthenticated: true, user: null };
      mockWs.authContext = authContext;
      
      const context = getWsAuthContext(mockWs);
      
      expect(context).toEqual(authContext);
    });
  });

  describe('wsRequireOwnership', () => {
    test('should allow resource owner', async () => {
      const message = createMockMessage({
        data: { userId: testUserId }
      });
      
      const user = await authService.findUserById(testUserId);
      mockWs.user = user;
      mockWs.authContext = { isAuthenticated: true, user };
      
      const middleware = wsRequireOwnership({
        getResourceOwnerId: (ws, message) => message.data?.userId
      });
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(true);
    });

    test('should deny non-owner', async () => {
      const message = createMockMessage({
        data: { userId: 99999 }
      });
      
      const user = await authService.findUserById(testUserId);
      mockWs.user = user;
      mockWs.authContext = { isAuthenticated: true, user };
      
      const middleware = wsRequireOwnership({
        getResourceOwnerId: (ws, message) => message.data?.userId
      });
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('Access denied');
    });

    test('should allow admin access', async () => {
      // Crear rol admin
      const adminRole = testUtils.generateTestRole({ name: 'admin' });
      await permissionService.createRole(adminRole);
      await authService.assignRole(testUserId, 'admin');
      
      const message = createMockMessage({
        data: { userId: 99999 }
      });
      
      const user = await authService.findUserById(testUserId);
      mockWs.user = user;
      mockWs.authContext = {
        isAuthenticated: true,
        user,
        roles: await authService.getUserRoles(testUserId)
      };
      
      const middleware = wsRequireOwnership({
        getResourceOwnerId: (ws, message) => message.data?.userId,
        allowAdmin: true,
        permissionService
      });
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(true);
    });
  });

  describe('wsRateLimit', () => {
    test('should allow messages within limit', async () => {
      const user = await authService.findUserById(testUserId);
      mockWs.user = user;
      
      const message = createMockMessage();
      
      const middleware = wsRateLimit({
        windowMs: 60000,
        maxMessages: 5,
        keyGenerator: (ws) => ws.user?.id.toString() || 'anonymous'
      });
      
      // Enviar 3 mensajes
      for (let i = 0; i < 3; i++) {
        const result = await middleware(mockWs, message);
        expect(result.success).toBe(true);
      }
    });

    test('should block messages exceeding limit', async () => {
      const user = await authService.findUserById(testUserId);
      mockWs.user = user;
      
      const message = createMockMessage();
      
      const middleware = wsRateLimit({
        windowMs: 60000,
        maxMessages: 2,
        keyGenerator: (ws) => ws.user?.id.toString() || 'anonymous'
      });
      
      // Exceder el límite
      let results = [];
      for (let i = 0; i < 3; i++) {
        const result = await middleware(mockWs, message);
        results.push(result);
      }
      
      expect(results[0].success).toBe(true);
      expect(results[1].success).toBe(true);
      expect(results[2].success).toBe(false);
      expect(results[2].error).toContain('Rate limit exceeded');
    });

    test('should reset limit after window expires', async () => {
      const user = await authService.findUserById(testUserId);
      mockWs.user = user;
      
      const message = createMockMessage();
      
      const middleware = wsRateLimit({
        windowMs: 100, // 100ms window
        maxMessages: 1,
        keyGenerator: (ws) => ws.user?.id.toString() || 'anonymous'
      });
      
      // Primer mensaje
      const result1 = await middleware(mockWs, message);
      expect(result1.success).toBe(true);
      
      // Segundo mensaje (debería fallar)
      const result2 = await middleware(mockWs, message);
      expect(result2.success).toBe(false);
      
      // Esperar que expire la ventana
      await new Promise(resolve => setTimeout(resolve, 150));
      
      // Tercer mensaje (debería pasar)
      const result3 = await middleware(mockWs, message);
      expect(result3.success).toBe(true);
    });
  });

  describe('Response Helpers', () => {
    test('wsErrorResponse should format error responses', () => {
      const response = wsErrorResponse('Test error', 'VALIDATION_ERROR');
      
      expect(response).toEqual({
        success: false,
        error: 'Test error',
        code: 'VALIDATION_ERROR',
        timestamp: expect.any(String)
      });
    });

    test('wsSuccessResponse should format success responses', () => {
      const data = { id: 1, name: 'Test' };
      const response = wsSuccessResponse(data, 'Success message');
      
      expect(response).toEqual({
        success: true,
        data,
        message: 'Success message',
        timestamp: expect.any(String)
      });
    });
  });

  describe('wsAuthLogger', () => {
    test('should log WebSocket events', async () => {
      const user = await authService.findUserById(testUserId);
      mockWs.user = user;
      
      const message = createMockMessage();
      
      const logSpy = mock(() => {});
      const middleware = wsAuthLogger({
        logLevel: 'info',
        logFunction: logSpy
      });
      
      const result = await middleware(mockWs, message);
      
      expect(logSpy).toHaveBeenCalled();
      expect(result.success).toBe(true);
    });

    test('should log errors', async () => {
      const message = createMockMessage();
      
      const logSpy = mock(() => {});
      const middleware = wsAuthLogger({
        logLevel: 'error',
        logFunction: logSpy,
        onError: () => {
          throw new Error('Test error');
        }
      });
      
      try {
        await middleware(mockWs, message);
      } catch (error) {
        // Error esperado
      }
      
      expect(logSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          level: 'error',
          message: expect.stringContaining('Test error')
        })
      );
    });
  });

  describe('wsMessageValidator', () => {
    test('should validate message schema', async () => {
      const message = createMockMessage({
        type: 'chat',
        data: {
          text: 'Hello World',
          room: 'general'
        }
      });
      
      const schema = {
        type: 'object',
        properties: {
          type: { type: 'string', enum: ['chat', 'join', 'leave'] },
          data: {
            type: 'object',
            properties: {
              text: { type: 'string', minLength: 1 },
              room: { type: 'string' }
            },
            required: ['text', 'room']
          }
        },
        required: ['type', 'data']
      };
      
      const middleware = wsMessageValidator(schema);
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(true);
    });

    test('should reject invalid messages', async () => {
      const message = createMockMessage({
        type: 'invalid-type',
        data: {
          text: '',
          room: 'general'
        }
      });
      
      const schema = {
        type: 'object',
        properties: {
          type: { type: 'string', enum: ['chat', 'join', 'leave'] },
          data: {
            type: 'object',
            properties: {
              text: { type: 'string', minLength: 1 },
              room: { type: 'string' }
            },
            required: ['text', 'room']
          }
        },
        required: ['type', 'data']
      };
      
      const middleware = wsMessageValidator(schema);
      
      const result = await middleware(mockWs, message);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('Message validation failed');
    });
  });

  describe('wsBroadcastAuth', () => {
    test('should broadcast to authenticated connections', () => {
      const connections = new Set([
        createMockWebSocket({ 
          user: { id: 1 }, 
          authContext: { isAuthenticated: true } 
        }),
        createMockWebSocket({ 
          user: { id: 2 }, 
          authContext: { isAuthenticated: true } 
        }),
        createMockWebSocket({ 
          authContext: { isAuthenticated: false } 
        })
      ]);
      
      const message = { type: 'broadcast', data: 'Hello everyone' };
      
      wsBroadcastAuth(connections, message, {
        requireAuth: true
      });
      
      // Solo las 2 primeras conexiones autenticadas deberían recibir el mensaje
      const authenticatedConnections = Array.from(connections).filter(ws => 
        ws.authContext?.isAuthenticated
      );
      
      authenticatedConnections.forEach(ws => {
        expect(ws.send).toHaveBeenCalledWith(JSON.stringify(message));
      });
      
      // La conexión no autenticada no debería recibir el mensaje
      const unauthenticatedConnection = Array.from(connections).find(ws => 
        !ws.authContext?.isAuthenticated
      );
      expect(unauthenticatedConnection?.send).not.toHaveBeenCalled();
    });

    test('should broadcast to specific roles', async () => {
      // Crear roles
      const adminRole = testUtils.generateTestRole({ name: 'admin' });
      const userRole = testUtils.generateTestRole({ name: 'user' });
      await permissionService.createRole(adminRole);
      await permissionService.createRole(userRole);
      
      const connections = new Set([
        createMockWebSocket({ 
          user: { id: 1, roles: ['admin'] }, 
          authContext: { isAuthenticated: true, roles: ['admin'] } 
        }),
        createMockWebSocket({ 
          user: { id: 2, roles: ['user'] }, 
          authContext: { isAuthenticated: true, roles: ['user'] } 
        }),
        createMockWebSocket({ 
          user: { id: 3, roles: [] }, 
          authContext: { isAuthenticated: true, roles: [] } 
        })
      ]);
      
      const message = { type: 'admin-broadcast', data: 'Admin message' };
      
      wsBroadcastAuth(connections, message, {
        requireRoles: ['admin']
      });
      
      // Solo la conexión admin debería recibir el mensaje
      const adminConnection = Array.from(connections).find(ws => 
        ws.authContext?.roles?.includes('admin')
      );
      expect(adminConnection?.send).toHaveBeenCalledWith(JSON.stringify(message));
      
      // Las otras conexiones no deberían recibir el mensaje
      const nonAdminConnections = Array.from(connections).filter(ws => 
        !ws.authContext?.roles?.includes('admin')
      );
      nonAdminConnections.forEach(ws => {
        expect(ws.send).not.toHaveBeenCalled();
      });
    });
  });

  describe('wsRoomAuth', () => {
    test('should manage room membership', () => {
      const roomManager = wsRoomAuth();
      
      // Unirse a una sala
      roomManager.joinRoom(mockWs, 'general');
      
      expect(mockWs.rooms?.has('general')).toBe(true);
      expect(roomManager.getRoomMembers('general').has(mockWs)).toBe(true);
    });

    test('should leave room', () => {
      const roomManager = wsRoomAuth();
      
      // Unirse y luego salir
      roomManager.joinRoom(mockWs, 'general');
      roomManager.leaveRoom(mockWs, 'general');
      
      expect(mockWs.rooms?.has('general')).toBe(false);
      expect(roomManager.getRoomMembers('general').has(mockWs)).toBe(false);
    });

    test('should broadcast to room members', () => {
      const roomManager = wsRoomAuth();
      
      const ws1 = createMockWebSocket();
      const ws2 = createMockWebSocket();
      const ws3 = createMockWebSocket();
      
      // Unir ws1 y ws2 a 'general', ws3 a 'private'
      roomManager.joinRoom(ws1, 'general');
      roomManager.joinRoom(ws2, 'general');
      roomManager.joinRoom(ws3, 'private');
      
      const message = { type: 'room-message', data: 'Hello room' };
      
      roomManager.broadcastToRoom('general', message);
      
      expect(ws1.send).toHaveBeenCalledWith(JSON.stringify(message));
      expect(ws2.send).toHaveBeenCalledWith(JSON.stringify(message));
      expect(ws3.send).not.toHaveBeenCalled();
    });

    test('should require permissions for room access', async () => {
      // Configurar permisos
      const roleData = testUtils.generateTestRole();
      const roleResult = await permissionService.createRole(roleData);
      
      const permissionData = testUtils.generateTestPermission({
        name: 'rooms:private',
        resource: 'rooms',
        action: 'access'
      });
      const permissionResult = await permissionService.createPermission(permissionData);
      
      await permissionService.assignPermissionToRole(roleResult.role!.id, permissionResult.permission!.id);
      await authService.assignRole(testUserId, roleData.name);
      
      const user = await authService.findUserById(testUserId);
      mockWs.user = user;
      mockWs.authContext = {
        isAuthenticated: true,
        user,
        permissions: await permissionService.getUserPermissions(testUserId)
      };
      
      const roomManager = wsRoomAuth({
        permissionService,
        roomPermissions: {
          'private': ['rooms:private']
        }
      });
      
      const result = roomManager.joinRoom(mockWs, 'private');
      
      expect(result.success).toBe(true);
      expect(mockWs.rooms?.has('private')).toBe(true);
    });
  });

  describe('wsConnectionManager', () => {
    test('should manage WebSocket connections', () => {
      const manager = wsConnectionManager();
      
      // Agregar conexión
      manager.addConnection(mockWs);
      
      expect(manager.getConnection(mockWs.id!)).toBe(mockWs);
      expect(manager.getConnectionCount()).toBe(1);
    });

    test('should remove connections', () => {
      const manager = wsConnectionManager();
      
      manager.addConnection(mockWs);
      manager.removeConnection(mockWs.id!);
      
      expect(manager.getConnection(mockWs.id!)).toBeUndefined();
      expect(manager.getConnectionCount()).toBe(0);
    });

    test('should get connections by user', async () => {
      const manager = wsConnectionManager();
      
      const user = await authService.findUserById(testUserId);
      mockWs.user = user;
      
      const ws2 = createMockWebSocket({ user });
      const ws3 = createMockWebSocket({ user: { id: 999 } });
      
      manager.addConnection(mockWs);
      manager.addConnection(ws2);
      manager.addConnection(ws3);
      
      const userConnections = manager.getConnectionsByUser(testUserId);
      
      expect(userConnections).toHaveLength(2);
      expect(userConnections).toContain(mockWs);
      expect(userConnections).toContain(ws2);
      expect(userConnections).not.toContain(ws3);
    });

    test('should handle connection cleanup', () => {
      const manager = wsConnectionManager();
      
      // Simular conexión cerrada
      mockWs.readyState = 3; // CLOSED
      
      manager.addConnection(mockWs);
      manager.cleanupClosedConnections();
      
      expect(manager.getConnection(mockWs.id!)).toBeUndefined();
    });
  });

  describe('Integration Tests', () => {
    test('should work with complete WebSocket authentication flow', async () => {
      // Configurar permisos completos
      const roleData = testUtils.generateTestRole({ name: 'user' });
      const roleResult = await permissionService.createRole(roleData);
      
      const permissionData = testUtils.generateTestPermission({
        name: 'chat:send',
        resource: 'chat',
        action: 'send'
      });
      const permissionResult = await permissionService.createPermission(permissionData);
      
      await permissionService.assignPermissionToRole(roleResult.role!.id, permissionResult.permission!.id);
      await authService.assignRole(testUserId, 'user');
      
      // Autenticación
      const authMessage = createMockMessage({
        type: 'auth',
        token: testToken
      });
      
      const authMiddleware = wsAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      const authResult = await authMiddleware(mockWs, authMessage);
      
      expect(authResult.success).toBe(true);
      expect(mockWs.user).toBeDefined();
      expect(mockWs.authContext?.isAuthenticated).toBe(true);
      
      // Verificar permisos
      const chatMessage = createMockMessage({
        type: 'chat',
        data: { text: 'Hello World', room: 'general' }
      });
      
      const permissionMiddleware = wsRequirePermissions(['chat:send'], {
        permissionService
      });
      
      const permissionResult = await permissionMiddleware(mockWs, chatMessage);
      
      expect(permissionResult.success).toBe(true);
    });

    test('should handle authentication failure gracefully', async () => {
      const authMessage = createMockMessage({
        type: 'auth',
        token: 'invalid-token'
      });
      
      const authMiddleware = wsAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      const authResult = await authMiddleware(mockWs, authMessage);
      
      expect(authResult.success).toBe(false);
      expect(authResult.error).toContain('Invalid token');
      expect(mockWs.user).toBeUndefined();
    });

    test('should handle room-based permissions', async () => {
      // Configurar permisos para salas
      const roleData = testUtils.generateTestRole({ name: 'moderator' });
      const roleResult = await permissionService.createRole(roleData);
      
      const permissionData = testUtils.generateTestPermission({
        name: 'rooms:moderate',
        resource: 'rooms',
        action: 'moderate'
      });
      const permissionResult = await permissionService.createPermission(permissionData);
      
      await permissionService.assignPermissionToRole(roleResult.role!.id, permissionResult.permission!.id);
      await authService.assignRole(testUserId, 'moderator');
      
      // Autenticar
      const user = await authService.findUserById(testUserId);
      mockWs.user = user;
      mockWs.authContext = {
        isAuthenticated: true,
        user,
        permissions: await permissionService.getUserPermissions(testUserId)
      };
      
      // Crear manager de salas con permisos
      const roomManager = wsRoomAuth({
        permissionService,
        roomPermissions: {
          'moderator-room': ['rooms:moderate']
        }
      });
      
      const joinResult = roomManager.joinRoom(mockWs, 'moderator-room');
      
      expect(joinResult.success).toBe(true);
      expect(mockWs.rooms?.has('moderator-room')).toBe(true);
    });
  });
});