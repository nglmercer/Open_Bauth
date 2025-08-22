// tests/adapters/websocket.test.ts
// Tests para el adaptador de WebSocket

import { describe, test, expect, beforeEach, afterEach, mock } from 'bun:test';
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
  initializeConnectionCleanup,
  type AuthenticatedWebSocket,
  type WebSocketAuthConfig
} from '../../src/adapters/websocket';
import { AuthService } from '../../src/services/auth';
import { JWTService } from '../../src/services/jwt';
import { PermissionService, initPermissionService } from '../../src/services/permissions';
import { testUtils, TEST_JWT_SECRET } from '../setup';
import type { WebSocket } from 'ws';

// Mock de WebSocket
interface MockWebSocket extends Partial<AuthenticatedWebSocket> {
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

function createMockWebSocket(options: Partial<MockWebSocket> = {}): MockWebSocket {
  return {
    send: mock(() => {}),
    close: mock(() => {}),
    ping: mock(() => {}),
    pong: mock(() => {}),
    terminate: mock(() => {}),
    readyState: 1, // OPEN
    url: 'ws://localhost:3000',
    protocol: '',
    extensions: '',
    bufferedAmount: 0,
    binaryType: 'nodebuffer',
    CONNECTING: 0,
    OPEN: 1,
    CLOSING: 2,
    CLOSED: 3,
    ...options
  };
}

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
    permissionService = initPermissionService();
    await testUtils.cleanTestData();
    
    // Crear usuario de prueba
    const userData = testUtils.generateTestUser();
    const result = await authService.register(userData);
    testUserId = result.user!.id;
    
    // Generar token de prueba
    testToken = await testUtils.generateTestJWT({ id: testUserId });
    
    mockWs = createMockWebSocket();
  });

  afterEach(async () => {
    await testUtils.cleanTestData();
  });

  describe('authenticateWebSocket', () => {
    test('should authenticate valid token from request', async () => {
      const request = {
        url: `ws://localhost?token=${testToken}`,
        headers: {}
      };
      
      const result = await authenticateWebSocket(mockWs as any, request, {
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      expect(result).toBe(true);
      expect(mockWs.auth).toBeDefined();
      expect(mockWs.auth?.user?.id).toBe(testUserId);
      expect(mockWs.userId).toBe(testUserId);
      testUtils.validateUserStructure(mockWs.auth!.user!);
    });

    test('should authenticate valid token from headers', async () => {
      const request = {
        url: 'ws://localhost',
        headers: {
          authorization: `Bearer ${testToken}`
        }
      };
      
      const result = await authenticateWebSocket(mockWs as any, request, {
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      expect(result).toBe(true);
      expect(mockWs.auth?.user?.id).toBe(testUserId);
    });

    test('should reject invalid token', async () => {
      const request = {
        url: 'ws://localhost?token=invalid-token',
        headers: {}
      };
      
      const result = await authenticateWebSocket(mockWs as any, request, {
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      expect(result).toBe(false);
      expect(mockWs.close).toHaveBeenCalledWith(1008, expect.any(String));
    });

    test('should reject missing token when required', async () => {
      const request = {
        url: 'ws://localhost',
        headers: {}
      };
      
      const result = await authenticateWebSocket(mockWs as any, request, {
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        required: true
      });
      
      expect(result).toBe(false);
      expect(mockWs.close).toHaveBeenCalledWith(1008, 'Authentication required');
    });
  });

  describe('checkWebSocketPermissions', () => {
    test('should check user permissions', async () => {
      // Setup authenticated websocket
      mockWs.auth = {
        user: {
          id: testUserId,
          email: 'test@example.com',
          permissions: [{ name: 'chat:send', resource: 'chat', action: 'send' }],
          roles: []
        },
        isAuthenticated: true,
        permissions: ['chat:send'],
        roles: []
      };
      
      const hasPermission = checkWebSocketPermissions(mockWs as any, ['chat:send']);
      expect(hasPermission).toBe(true);
      
      const noPermission = checkWebSocketPermissions(mockWs as any, ['admin:delete']);
      expect(noPermission).toBe(false);
    });
  });

  describe('checkWebSocketRoles', () => {
    test('should check user roles', async () => {
      // Setup authenticated websocket
      mockWs.auth = {
        user: {
          id: testUserId,
          email: 'test@example.com',
          permissions: [],
          roles: [{ name: 'user', description: 'Regular user' }]
        },
        isAuthenticated: true,
        permissions: [],
        roles: ['user']
      };
      
      const hasRole = checkWebSocketRoles(mockWs as any, ['user']);
      expect(hasRole).toBe(true);
      
      const noRole = checkWebSocketRoles(mockWs as any, ['admin']);
      expect(noRole).toBe(false);
    });
  });

  describe('utility functions', () => {
    test('getWebSocketCurrentUser should return current user', () => {
      const user = { id: testUserId, email: 'test@example.com', permissions: [], roles: [] };
      mockWs.auth = { user, isAuthenticated: true, permissions: [], roles: [] };
      
      const currentUser = getWebSocketCurrentUser(mockWs as any);
      expect(currentUser).toEqual(user);
    });

    test('isWebSocketAuthenticated should check authentication status', () => {
      mockWs.auth = { user: { id: testUserId }, isAuthenticated: true, permissions: [], roles: [] };
      expect(isWebSocketAuthenticated(mockWs as any)).toBe(true);
      
      mockWs.auth = undefined;
      expect(isWebSocketAuthenticated(mockWs as any)).toBe(false);
    });

    test('getWebSocketAuthContext should return auth context', () => {
      const authContext = { user: { id: testUserId }, isAuthenticated: true, permissions: [], roles: [] };
      mockWs.auth = authContext;
      
      const context = getWebSocketAuthContext(mockWs as any);
      expect(context).toEqual(authContext);
    });

    test('createWebSocketResponse should create standardized response', () => {
      const response = createWebSocketResponse('success', { message: 'Hello' }, 'Operation successful');
      
      expect(response.type).toBe('success');
      expect(response.data).toEqual({ message: 'Hello' });
      expect(response.message).toBe('Operation successful');
      expect(response.timestamp).toBeDefined();
    });
  });

  describe('connection management', () => {
    test('getConnectionStats should return connection statistics', () => {
      const stats = getConnectionStats();
      
      expect(stats).toHaveProperty('totalConnections');
      expect(stats).toHaveProperty('uniqueUsers');
      expect(stats).toHaveProperty('userStats');
      expect(typeof stats.totalConnections).toBe('number');
      expect(typeof stats.uniqueUsers).toBe('number');
    });
  });
});