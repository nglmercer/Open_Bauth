// tests/middleware/auth.test.ts
// Tests para el middleware de autenticación agnóstico

import { describe, test, expect, beforeEach, afterEach, mock } from 'bun:test';
import { 
  createAuthMiddleware,
  createOptionalAuthMiddleware,
  createPermissionMiddleware,
  createRoleMiddleware,
  createOwnershipMiddleware,
  createRateLimitMiddleware
} from '../../src/middleware/auth';
import { AuthService } from '../../src/services/auth';
import { JWTService } from '../../src/services/jwt';
import { PermissionService, initPermissionService } from '../../src/services/permissions';
import { testUtils, TEST_JWT_SECRET } from '../setup';
import type { AuthContext, AuthRequest, AuthResponse, NextFunction } from '../../src/types/auth';

describe('Auth Middleware', () => {
  let authService: AuthService;
  let jwtService: JWTService;
  let permissionService: PermissionService;
  let testUserId: number |string;
  let testToken: string;
  let mockRequest: AuthRequest;
  let mockResponse: AuthResponse;
  let mockNext: NextFunction;

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
    testToken = await jwtService.generateToken(result.user!);
    
    // Configurar mocks
    mockRequest = {
      headers: {
        authorization: `Bearer ${testToken}`
      },
      body: {},
      params: {},
      query: {},
      user: undefined,
      authContext: undefined
    } as AuthRequest;
    
    mockResponse = {
      status: mock(() => mockResponse),
      json: mock(() => mockResponse),
      send: mock(() => mockResponse),
      setHeader: mock(() => mockResponse)
    } as AuthResponse;
    
    mockNext = mock(() => {});
  });

  afterEach(async () => {
    await testUtils.cleanTestData();
  });

  describe('createAuthMiddleware', () => {
    test('should authenticate valid token', async () => {
      const middleware = createAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
      expect(mockRequest.user).toBeDefined();
      expect(mockRequest.user?.id).toBe(testUserId);
      expect(mockRequest.authContext).toBeDefined();
      expect(mockRequest.authContext?.isAuthenticated).toBe(true);
      testUtils.validateUserStructure(mockRequest.user!);
    });

    test('should reject invalid token', async () => {
      mockRequest.headers.authorization = 'Bearer invalid-token';
      
      const middleware = createAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: expect.stringContaining('Invalid')
        })
      );
    });

    test('should reject missing token', async () => {
      delete mockRequest.headers.authorization;
      
      const middleware = createAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: expect.stringContaining('Authorization header is required')
        })
      );
    });

    test('should handle malformed authorization header', async () => {
      mockRequest.headers.authorization = 'InvalidFormat';
      
      const middleware = createAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(401);
    });

    test('should reject token for non-existent user', async () => {
      const invalidToken = testUtils.generateTestJWT({ userId: 99999 });
      mockRequest.headers.authorization = `Bearer ${invalidToken}`;
      
      const middleware = createAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(401);
    });

    test('should reject token for inactive user', async () => {
      // Desactivar usuario
      await authService.updateUser(String(testUserId), { isActive: false });
      
      const middleware = createAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: expect.stringContaining('User not found or inactive')
        })
      );
    });

    test('should reject expired token', async () => {
      const expiredToken = await testUtils.generateTestJWT(
        { userId: testUserId },
        { expiresIn: '-1h' }
      );
      mockRequest.headers.authorization = `Bearer ${expiredToken}`;
      
      const middleware = createAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: 'Invalid or expired token'
        })
      );
    });

    test('should support custom token extraction', async () => {
      delete mockRequest.headers.authorization;
      // Ensure query object exists and set the token
      if (!mockRequest.query) {
        mockRequest.query = {};
      }
      mockRequest.query.token = testToken;
      
      const middleware = createAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        permissionService,
        extractToken: (req) => req.query?.token || null
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
      expect(mockRequest.user).toBeDefined();
    });

    test('should support custom error handler', async () => {
      mockRequest.headers.authorization = 'Bearer invalid-token';
      const customErrorHandler = mock((error, req, res) => {
        res.status(403).json({ customError: error.message });
      });
      
      const middleware = createAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        permissionService,
        onError: customErrorHandler
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(customErrorHandler).toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(403);
    });
  });

  describe('createOptionalAuthMiddleware', () => {
    test('should authenticate when token is provided', async () => {
      const middleware = createOptionalAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
      expect(mockRequest.user).toBeDefined();
      expect(mockRequest.authContext?.isAuthenticated).toBe(true);
    });

    test('should continue without authentication when no token', async () => {
      delete mockRequest.headers.authorization;
      
      const middleware = createOptionalAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
      expect(mockRequest.user).toBeUndefined();
      expect(mockRequest.authContext?.isAuthenticated).toBe(false);
    });

    test('should continue when token is invalid', async () => {
      mockRequest.headers.authorization = 'Bearer invalid-token';
      
      const middleware = createOptionalAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
      expect(mockRequest.user).toBeUndefined();
      expect(mockRequest.authContext?.isAuthenticated).toBe(false);
    });
  });

  describe('createPermissionMiddleware', () => {
    let permissionName: string;

    beforeEach(async () => {
      // Configurar permisos de prueba
      const roleData = testUtils.generateTestRole();
      const roleResult = await permissionService.createRole(roleData);
      
      const permissionData = testUtils.generateTestPermission();
      const permissionResult = await permissionService.createPermission(permissionData);
      permissionName = permissionData.name;
      
      await permissionService.assignPermissionToRole(roleResult.role!.id, permissionResult.permission!.id);
      await authService.assignRole(testUserId, roleData.name);
      
      // Configurar usuario autenticado en request
      mockRequest.user = (await authService.findUserById(testUserId))!;
      mockRequest.authContext = {
        isAuthenticated: true,
        user: mockRequest.user,
        permissions: await permissionService.getUserPermissions(testUserId),
        roles: await authService.getUserRoles(testUserId)
      };
    });

    test('should allow access with required permission', async () => {
      const middleware = createPermissionMiddleware({
        permissions: [permissionName],
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should deny access without required permission', async () => {
      const middleware = createPermissionMiddleware({
        permissions: ['non-existent-permission'],
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: expect.stringContaining('Insufficient permissions')
        })
      );
    });

    test('should handle multiple permissions with AND logic', async () => {
      // Crear segundo permiso
      const permission2Data = testUtils.generateTestPermission({
        name: 'second_permission',
        resource: 'second_resource',
        action: 'second_action'
      });
      const permission2Result = await permissionService.createPermission(permission2Data);
      
      // Asignar al mismo rol
      const userRoles = await authService.getUserRoles(testUserId);
      const roleId = userRoles[0].id;
      await permissionService.assignPermissionToRole(roleId, permission2Result.permission!.id);
      
      const middleware = createPermissionMiddleware({
        permissions: [permissionName, permission2Data.name],
        requireAll: true,
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should handle multiple permissions with OR logic', async () => {
      const middleware = createPermissionMiddleware({
        permissions: [permissionName, 'non-existent-permission'],
        requireAll: false,
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should deny access for unauthenticated user', async () => {
      mockRequest.user = undefined;
      mockRequest.authContext = { isAuthenticated: false };
      
      const middleware = createPermissionMiddleware({
        permissions: [permissionName],
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(401);
    });
  });

  describe('createRoleMiddleware', () => {
    let roleName: string;

    beforeEach(async () => {
      // Configurar roles de prueba
      const roleData = testUtils.generateTestRole();
      const roleResult = await permissionService.createRole(roleData);
      roleName = roleData.name;
      
      await authService.assignRole(testUserId, roleName);
      
      // Configurar usuario autenticado en request
      mockRequest.user = (await authService.findUserById(testUserId))!;
      mockRequest.authContext = {
        isAuthenticated: true,
        user: mockRequest.user,
        permissions: await permissionService.getUserPermissions(testUserId),
        roles: await authService.getUserRoles(testUserId)
      };
    });

    test('should allow access with required role', async () => {
      const middleware = createRoleMiddleware({
        roles: [roleName],
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should deny access without required role', async () => {
      const middleware = createRoleMiddleware({
        roles: ['non-existent-role'],
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(403);
    });

    test('should handle multiple roles with AND logic', async () => {
      // Crear segundo rol
      const role2Data = testUtils.generateTestRole({ name: 'second_role' });
      await permissionService.createRole(role2Data);
      await authService.assignRole(testUserId, role2Data.name);
      
      // Actualizar el contexto de autenticación con los nuevos roles
      mockRequest.authContext.roles = await authService.getUserRoles(testUserId);
      
      const middleware = createRoleMiddleware({
        roles: [roleName, role2Data.name],
        requireAll: true,
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should handle multiple roles with OR logic', async () => {
      const middleware = createRoleMiddleware({
        roles: [roleName, 'non-existent-role'],
        requireAll: false,
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('createOwnershipMiddleware', () => {
    beforeEach(async () => {
      // Configurar usuario autenticado
      mockRequest.user = (await authService.findUserById(testUserId))!;
      mockRequest.authContext = {
        isAuthenticated: true,
        user: mockRequest.user,
        permissions: [],
        roles: []
      };
      
      // Configurar parámetros de request
      mockRequest.params = { userId: testUserId.toString() };
    });

    test('should allow access for resource owner', async () => {
      const middleware = createOwnershipMiddleware({
        getResourceOwnerId: (req) => req.params.userId,
        allowAdmin: false
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should deny access for non-owner', async () => {
      mockRequest.params.userId = '99999';
      
      const middleware = createOwnershipMiddleware({
        getResourceOwnerId: (req) => req.params.userId,
        allowAdmin: false
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(403);
    });

    test('should allow admin access when configured', async () => {
      mockRequest.params.userId = '99999';
      
      // Asignar rol admin
      const adminRole = testUtils.generateTestRole({ name: 'admin' });
      await permissionService.createRole(adminRole);
      await authService.assignRole(testUserId, 'admin');
      
      // Actualizar contexto
      mockRequest.authContext!.roles = await authService.getUserRoles(testUserId);
      
      const middleware = createOwnershipMiddleware({
        getResourceOwnerId: (req) => req.params.userId,
        allowAdmin: true,
        adminRoles: ['admin']
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should handle async resource owner resolution', async () => {
      const middleware = createOwnershipMiddleware({
        getResourceOwnerId: async (req) => {
          // Simular consulta async
          await new Promise(resolve => setTimeout(resolve, 10));
          return req.params.userId;
        },
        allowAdmin: false
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('createRateLimitMiddleware', () => {
    test('should allow requests within limit', async () => {
      const middleware = createRateLimitMiddleware({
        windowMs: 60000, // 1 minuto
        maxRequests: 5,
        keyGenerator: (req) => req.user?.id.toString() || 'anonymous'
      });
      
      mockRequest.user = (await authService.findUserById(testUserId))!;
      
      // Realizar 3 requests (dentro del límite)
      for (let i = 0; i < 3; i++) {
        await middleware(mockRequest, mockResponse, mockNext);
      }
      
      expect(mockNext).toHaveBeenCalledTimes(3);
    });

    test('should block requests exceeding limit', async () => {
      const middleware = createRateLimitMiddleware({
        windowMs: 60000,
        maxRequests: 2,
        keyGenerator: (req) => req.user?.id.toString() || 'anonymous'
      });
      
      mockRequest.user = (await authService.findUserById(testUserId))!;
      
      // Realizar requests hasta exceder el límite
      await middleware(mockRequest, mockResponse, mockNext);
      await middleware(mockRequest, mockResponse, mockNext);
      await middleware(mockRequest, mockResponse, mockNext); // Esta debería ser bloqueada
      
      expect(mockNext).toHaveBeenCalledTimes(2);
      expect(mockResponse.status).toHaveBeenCalledWith(429);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: expect.stringContaining('Too many requests')
        })
      );
    });

    test('should reset limit after window expires', async () => {
      const middleware = createRateLimitMiddleware({
        windowMs: 100, // 100ms
        maxRequests: 1,
        keyGenerator: (req) => req.user?.id.toString() || 'anonymous'
      });
      
      mockRequest.user = (await authService.findUserById(testUserId))!;
      
      // Primera request
      await middleware(mockRequest, mockResponse, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
      
      // Esperar que expire la ventana
      await new Promise(resolve => setTimeout(resolve, 150));
      
      // Segunda request (debería ser permitida)
      await middleware(mockRequest, mockResponse, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(2);
    });

    test('should handle different keys separately', async () => {
      const middleware = createRateLimitMiddleware({
        windowMs: 60000,
        maxRequests: 1,
        keyGenerator: (req) => req.user?.id.toString() || 'anonymous'
      });
      
      // Request con primer usuario
      mockRequest.user = (await authService.findUserById(testUserId))!;
      await middleware(mockRequest, mockResponse, mockNext);
      
      // Request con segundo usuario
      const user2Data = testUtils.generateTestUser({ email: 'user2@test.com' });
      const user2Result = await authService.register(user2Data);
      mockRequest.user = user2Result.user!;
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).toHaveBeenCalledTimes(2);
    });
  });

  describe('Middleware Composition', () => {
    test('should compose multiple middlewares correctly', async () => {
      // Configurar permisos
      const roleData = testUtils.generateTestRole();
      const roleResult = await permissionService.createRole(roleData);
      
      const permissionData = testUtils.generateTestPermission();
      const permissionResult = await permissionService.createPermission(permissionData);
      
      await permissionService.assignPermissionToRole(roleResult.role!.id, permissionResult.permission!.id);
      await authService.assignRole(testUserId, roleData.name);
      
      // Crear middlewares
      const authMiddleware = createAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        permissionService
      });
      
      const permissionMiddleware = createPermissionMiddleware({
        permissions: [permissionData.name],
        permissionService
      });
      
      // Ejecutar en secuencia
      await authMiddleware(mockRequest, mockResponse, mockNext);
      
      if (mockNext.mock.calls.length > 0) {
        await permissionMiddleware(mockRequest, mockResponse, mockNext);
      }
      
      expect(mockNext).toHaveBeenCalledTimes(2);
      expect(mockRequest.user).toBeDefined();
      expect(mockRequest.authContext?.isAuthenticated).toBe(true);
    });

    test('should stop execution on middleware failure', async () => {
      mockRequest.headers.authorization = 'Bearer invalid-token';
      
      const authMiddleware = createAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        permissionService
      });
      
      const permissionMiddleware = createPermissionMiddleware({
        permissions: ['any-permission'],
        permissionService
      });
      
      // Ejecutar auth middleware (debería fallar)
      await authMiddleware(mockRequest, mockResponse, mockNext);
      
      // Permission middleware no debería ejecutarse
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(401);
    });
  });

  describe('Error Handling', () => {
    test('should handle service errors gracefully', async () => {
      // Simular error en authService
      const errorAuthService = {
        ...authService,
        findUserById: mock(() => {
          throw new Error('Database connection failed');
        })
      };
      
      const middleware = createAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService: errorAuthService,
        jwtService,
        permissionService
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: expect.stringContaining('Internal server error')
        })
      );
    });

    test('should handle malformed requests', async () => {
      // Request sin headers
      const malformedRequest = {} as AuthRequest;
      
      const middleware = createAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        permissionService
      });
      
      await middleware(malformedRequest, mockResponse, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(401);
    });
  });

  describe('Configuration Options', () => {
    test('should respect custom configuration', async () => {
      const middleware = createAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        permissionService,
        config: {
          tokenHeader: 'x-auth-token',
          userProperty: 'currentUser',
          contextProperty: 'auth'
        }
      });
      
      mockRequest.headers['x-auth-token'] = testToken;
      delete mockRequest.headers.authorization;
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
      expect((mockRequest as any).currentUser).toBeDefined();
      expect((mockRequest as any).auth).toBeDefined();
    });

    test('should support custom success callbacks', async () => {
      const onSuccess = mock((user, context, req) => {
        req.customProperty = 'success';
      });
      
      const middleware = createAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        permissionService,
        onSuccess
      });
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(onSuccess).toHaveBeenCalled();
      expect((mockRequest as any).customProperty).toBe('success');
    });
  });
});