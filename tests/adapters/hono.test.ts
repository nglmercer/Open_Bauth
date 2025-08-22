// tests/adapters/hono.test.ts
// Tests para el adaptador de Hono

import { describe, test, expect, beforeEach, afterEach, mock } from 'bun:test';
import {
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
} from '../../src/adapters/hono';
import { AuthService } from '../../src/services/auth';
import { JWTService } from '../../src/services/jwt';
import { PermissionService } from '../../src/services/permissions';
import { testUtils, TEST_JWT_SECRET } from '../setup';
import type { Context, Next } from 'hono';

// Mock de Hono Context
const createMockHonoContext = (overrides: Partial<Context> = {}): Context => {
  const mockContext = {
    req: {
      header: mock((name: string) => {
        const headers: Record<string, string> = {
          authorization: `Bearer ${testToken}`,
          ...overrides.headers
        };
        return headers[name.toLowerCase()];
      }),
      query: mock((name: string) => overrides.query?.[name]),
      param: mock((name: string) => overrides.params?.[name]),
      json: mock(() => Promise.resolve(overrides.body || {})),
      parseBody: mock(() => Promise.resolve(overrides.body || {}))
    },
    res: {
      headers: new Headers()
    },
    set: mock((key: string, value: any) => {
      (mockContext as any)[key] = value;
    }),
    get: mock((key: string) => (mockContext as any)[key]),
    status: mock((code: number) => mockContext),
    json: mock((data: any) => {
      mockContext.responseData = data;
      return new Response(JSON.stringify(data), {
        status: mockContext.statusCode || 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }),
    text: mock((text: string) => {
      mockContext.responseData = text;
      return new Response(text, {
        status: mockContext.statusCode || 200,
        headers: { 'Content-Type': 'text/plain' }
      });
    }),
    header: mock((name: string, value: string) => {
      mockContext.res.headers.set(name, value);
    }),
    statusCode: 200,
    responseData: undefined,
    ...overrides
  } as unknown as Context;
  
  return mockContext;
};

describe('Hono Adapter', () => {
  let authService: AuthService;
  let jwtService: JWTService;
  let permissionService: PermissionService;
  let testUserId: number;
  let testToken: string;
  let mockNext: Next;

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
    
    mockNext = mock(() => Promise.resolve());
  });

  afterEach(async () => {
    await testUtils.cleanTestData();
  });

  describe('honoAuthMiddleware', () => {
    test('should authenticate valid token', async () => {
      const c = createMockHonoContext();
      
      const middleware = honoAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await middleware(c, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
      expect(c.get('user')).toBeDefined();
      expect(c.get('user').id).toBe(testUserId);
      expect(c.get('authContext')).toBeDefined();
      expect(c.get('authContext').isAuthenticated).toBe(true);
      testUtils.validateUserStructure(c.get('user'));
    });

    test('should reject invalid token', async () => {
      const c = createMockHonoContext({
        headers: { authorization: 'Bearer invalid-token' }
      });
      
      const middleware = honoAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      const response = await middleware(c, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(c.statusCode).toBe(401);
      expect(c.responseData).toEqual(
        expect.objectContaining({
          error: expect.stringContaining('Invalid token')
        })
      );
    });

    test('should reject missing token', async () => {
      const c = createMockHonoContext({
        headers: {}
      });
      
      const middleware = honoAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await middleware(c, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(c.statusCode).toBe(401);
      expect(c.responseData).toEqual(
        expect.objectContaining({
          error: expect.stringContaining('No token provided')
        })
      );
    });

    test('should handle expired token', async () => {
      const expiredToken = testUtils.generateTestJWT(
        { userId: testUserId },
        { expiresIn: '-1h' }
      );
      
      const c = createMockHonoContext({
        headers: { authorization: `Bearer ${expiredToken}` }
      });
      
      const middleware = honoAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await middleware(c, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(c.statusCode).toBe(401);
      expect(c.responseData).toEqual(
        expect.objectContaining({
          error: expect.stringContaining('Token expired')
        })
      );
    });

    test('should support custom token extraction', async () => {
      const c = createMockHonoContext({
        headers: {},
        query: { token: testToken }
      });
      
      const middleware = honoAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        extractToken: (c) => c.req.query('token')
      });
      
      await middleware(c, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
      expect(c.get('user')).toBeDefined();
    });
  });

  describe('honoOptionalAuth', () => {
    test('should authenticate when token is provided', async () => {
      const c = createMockHonoContext();
      
      const middleware = honoOptionalAuth({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await middleware(c, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
      expect(c.get('user')).toBeDefined();
      expect(c.get('authContext').isAuthenticated).toBe(true);
    });

    test('should continue without authentication when no token', async () => {
      const c = createMockHonoContext({
        headers: {}
      });
      
      const middleware = honoOptionalAuth({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await middleware(c, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
      expect(c.get('user')).toBeUndefined();
      expect(c.get('authContext').isAuthenticated).toBe(false);
    });

    test('should continue when token is invalid', async () => {
      const c = createMockHonoContext({
        headers: { authorization: 'Bearer invalid-token' }
      });
      
      const middleware = honoOptionalAuth({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await middleware(c, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
      expect(c.get('user')).toBeUndefined();
      expect(c.get('authContext').isAuthenticated).toBe(false);
    });
  });

  describe('honoRequireAuth', () => {
    test('should allow authenticated users', async () => {
      const c = createMockHonoContext();
      c.set('user', await authService.findUserById(testUserId));
      c.set('authContext', { isAuthenticated: true });
      
      const middleware = honoRequireAuth();
      
      await middleware(c, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should reject unauthenticated users', async () => {
      const c = createMockHonoContext();
      c.set('authContext', { isAuthenticated: false });
      
      const middleware = honoRequireAuth();
      
      await middleware(c, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(c.statusCode).toBe(401);
    });
  });

  describe('honoRequirePermissions', () => {
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
      const c = createMockHonoContext();
      const user = await authService.findUserById(testUserId);
      c.set('user', user);
      c.set('authContext', {
        isAuthenticated: true,
        user,
        permissions: await permissionService.getUserPermissions(testUserId)
      });
      
      const middleware = honoRequirePermissions([permissionName], {
        permissionService
      });
      
      await middleware(c, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should deny access without required permission', async () => {
      const c = createMockHonoContext();
      const user = await authService.findUserById(testUserId);
      c.set('user', user);
      c.set('authContext', {
        isAuthenticated: true,
        user,
        permissions: []
      });
      
      const middleware = honoRequirePermissions(['non-existent-permission'], {
        permissionService
      });
      
      await middleware(c, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(c.statusCode).toBe(403);
    });
  });

  describe('honoRequireRoles', () => {
    let roleName: string;

    beforeEach(async () => {
      // Configurar roles
      const roleData = testUtils.generateTestRole();
      const roleResult = await permissionService.createRole(roleData);
      roleName = roleData.name;
      
      await authService.assignRole(testUserId, roleName);
    });

    test('should allow access with required role', async () => {
      const c = createMockHonoContext();
      const user = await authService.findUserById(testUserId);
      c.set('user', user);
      c.set('authContext', {
        isAuthenticated: true,
        user,
        roles: await authService.getUserRoles(testUserId)
      });
      
      const middleware = honoRequireRoles([roleName], {
        permissionService
      });
      
      await middleware(c, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should deny access without required role', async () => {
      const c = createMockHonoContext();
      const user = await authService.findUserById(testUserId);
      c.set('user', user);
      c.set('authContext', {
        isAuthenticated: true,
        user,
        roles: []
      });
      
      const middleware = honoRequireRoles(['non-existent-role'], {
        permissionService
      });
      
      await middleware(c, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(c.statusCode).toBe(403);
    });
  });

  describe('honoRequireAdmin', () => {
    test('should allow admin users', async () => {
      // Crear rol admin
      const adminRole = testUtils.generateTestRole({ name: 'admin' });
      await permissionService.createRole(adminRole);
      await authService.assignRole(testUserId, 'admin');
      
      const c = createMockHonoContext();
      const user = await authService.findUserById(testUserId);
      c.set('user', user);
      c.set('authContext', {
        isAuthenticated: true,
        user,
        roles: await authService.getUserRoles(testUserId)
      });
      
      const middleware = honoRequireAdmin({ permissionService });
      
      await middleware(c, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should deny non-admin users', async () => {
      const c = createMockHonoContext();
      const user = await authService.findUserById(testUserId);
      c.set('user', user);
      c.set('authContext', {
        isAuthenticated: true,
        user,
        roles: []
      });
      
      const middleware = honoRequireAdmin({ permissionService });
      
      await middleware(c, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(c.statusCode).toBe(403);
    });
  });

  describe('honoRequireModerator', () => {
    test('should allow moderator users', async () => {
      // Crear rol moderator
      const modRole = testUtils.generateTestRole({ name: 'moderator' });
      await permissionService.createRole(modRole);
      await authService.assignRole(testUserId, 'moderator');
      
      const c = createMockHonoContext();
      const user = await authService.findUserById(testUserId);
      c.set('user', user);
      c.set('authContext', {
        isAuthenticated: true,
        user,
        roles: await authService.getUserRoles(testUserId)
      });
      
      const middleware = honoRequireModerator({ permissionService });
      
      await middleware(c, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Helper Functions', () => {
    test('getHonoCurrentUser should return current user', () => {
      const c = createMockHonoContext();
      const user = { id: testUserId, email: 'test@example.com' };
      c.set('user', user);
      
      const currentUser = getHonoCurrentUser(c);
      
      expect(currentUser).toEqual(user);
    });

    test('isHonoAuthenticated should check authentication status', () => {
      const c = createMockHonoContext();
      c.set('authContext', { isAuthenticated: true });
      
      const isAuth = isHonoAuthenticated(c);
      
      expect(isAuth).toBe(true);
    });

    test('getHonoAuthContext should return auth context', () => {
      const c = createMockHonoContext();
      const authContext = { isAuthenticated: true, user: null };
      c.set('authContext', authContext);
      
      const context = getHonoAuthContext(c);
      
      expect(context).toEqual(authContext);
    });
  });

  describe('honoRequireOwnership', () => {
    test('should allow resource owner', async () => {
      const c = createMockHonoContext({
        params: { userId: testUserId.toString() }
      });
      
      const user = await authService.findUserById(testUserId);
      c.set('user', user);
      c.set('authContext', { isAuthenticated: true, user });
      
      const middleware = honoRequireOwnership({
        getResourceOwnerId: (c) => parseInt(c.req.param('userId'))
      });
      
      await middleware(c, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should deny non-owner', async () => {
      const c = createMockHonoContext({
        params: { userId: '99999' }
      });
      
      const user = await authService.findUserById(testUserId);
      c.set('user', user);
      c.set('authContext', { isAuthenticated: true, user });
      
      const middleware = honoRequireOwnership({
        getResourceOwnerId: (c) => parseInt(c.req.param('userId'))
      });
      
      await middleware(c, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(c.statusCode).toBe(403);
    });
  });

  describe('honoRateLimit', () => {
    test('should allow requests within limit', async () => {
      const c = createMockHonoContext();
      const user = await authService.findUserById(testUserId);
      c.set('user', user);
      
      const middleware = honoRateLimit({
        windowMs: 60000,
        maxRequests: 5,
        keyGenerator: (c) => c.get('user')?.id.toString() || 'anonymous'
      });
      
      // Realizar 3 requests
      for (let i = 0; i < 3; i++) {
        await middleware(c, mockNext);
      }
      
      expect(mockNext).toHaveBeenCalledTimes(3);
    });

    test('should block requests exceeding limit', async () => {
      const c = createMockHonoContext();
      const user = await authService.findUserById(testUserId);
      c.set('user', user);
      
      const middleware = honoRateLimit({
        windowMs: 60000,
        maxRequests: 2,
        keyGenerator: (c) => c.get('user')?.id.toString() || 'anonymous'
      });
      
      // Exceder el límite
      await middleware(c, mockNext);
      await middleware(c, mockNext);
      await middleware(c, mockNext);
      
      expect(mockNext).toHaveBeenCalledTimes(2);
      expect(c.statusCode).toBe(429);
    });
  });

  describe('honoCorsAuth', () => {
    test('should set CORS headers', async () => {
      const c = createMockHonoContext();
      
      const middleware = honoCorsAuth({
        origin: 'https://example.com',
        credentials: true
      });
      
      await middleware(c, mockNext);
      
      expect(c.res.headers.get('Access-Control-Allow-Origin')).toBe('https://example.com');
      expect(c.res.headers.get('Access-Control-Allow-Credentials')).toBe('true');
      expect(mockNext).toHaveBeenCalled();
    });

    test('should handle preflight requests', async () => {
      const c = createMockHonoContext();
      c.req.method = 'OPTIONS';
      
      const middleware = honoCorsAuth({
        origin: '*',
        methods: ['GET', 'POST', 'PUT', 'DELETE']
      });
      
      const response = await middleware(c, mockNext);
      
      expect(c.res.headers.get('Access-Control-Allow-Methods')).toContain('GET');
      expect(c.statusCode).toBe(204);
    });
  });

  describe('Response Helpers', () => {
    test('honoErrorResponse should format error responses', () => {
      const c = createMockHonoContext();
      
      const response = honoErrorResponse(c, 'Test error', 400, 'VALIDATION_ERROR');
      
      expect(c.statusCode).toBe(400);
      expect(c.responseData).toEqual({
        success: false,
        error: 'Test error',
        code: 'VALIDATION_ERROR',
        timestamp: expect.any(String)
      });
    });

    test('honoSuccessResponse should format success responses', () => {
      const c = createMockHonoContext();
      const data = { id: 1, name: 'Test' };
      
      const response = honoSuccessResponse(c, data, 'Success message');
      
      expect(c.statusCode).toBe(200);
      expect(c.responseData).toEqual({
        success: true,
        data,
        message: 'Success message',
        timestamp: expect.any(String)
      });
    });
  });

  describe('honoAuthLogger', () => {
    test('should log authentication events', async () => {
      const c = createMockHonoContext();
      const user = await authService.findUserById(testUserId);
      c.set('user', user);
      
      const logSpy = mock(() => {});
      const middleware = honoAuthLogger({
        logLevel: 'info',
        logFunction: logSpy
      });
      
      await middleware(c, mockNext);
      
      expect(logSpy).toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    test('should log errors', async () => {
      const c = createMockHonoContext();
      const errorNext = mock(() => {
        throw new Error('Test error');
      });
      
      const logSpy = mock(() => {});
      const middleware = honoAuthLogger({
        logLevel: 'error',
        logFunction: logSpy
      });
      
      try {
        await middleware(c, errorNext);
      } catch (error:any) {
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

  describe('Integration Tests', () => {
    test('should work with complete authentication flow', async () => {
      // Configurar permisos completos
      const roleData = testUtils.generateTestRole({ name: 'user' });
      const roleResult = await permissionService.createRole(roleData);
      
      const permissionData = testUtils.generateTestPermission({
        name: 'posts:read',
        resource: 'posts',
        action: 'read'
      });
      const permissionResult = await permissionService.createPermission(permissionData);
      
      await permissionService.assignPermissionToRole(roleResult.role!.id, permissionResult.permission!.id);
      await authService.assignRole(testUserId, 'user');
      
      const c = createMockHonoContext();
      
      // Ejecutar middleware de autenticación
      const authMiddleware = honoAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await authMiddleware(c, mockNext);
      
      // Verificar autenticación
      expect(c.get('user')).toBeDefined();
      expect(c.get('authContext').isAuthenticated).toBe(true);
      
      // Ejecutar middleware de permisos
      const permissionMiddleware = honoRequirePermissions(['posts:read'], {
        permissionService
      });
      
      await permissionMiddleware(c, mockNext);
      
      expect(mockNext).toHaveBeenCalledTimes(2);
    });

    test('should handle authentication failure gracefully', async () => {
      const c = createMockHonoContext({
        headers: { authorization: 'Bearer invalid-token' }
      });
      
      const authMiddleware = honoAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await authMiddleware(c, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(c.statusCode).toBe(401);
      expect(c.responseData.success).toBe(false);
    });
  });
});