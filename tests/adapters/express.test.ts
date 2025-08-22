// tests/adapters/express.test.ts
// Tests para el adaptador de Express

import { describe, test, expect, beforeEach, afterEach, mock } from 'bun:test';
import {
  expressAuthMiddleware,
  expressOptionalAuth,
  expressRequireAuth,
  expressRequirePermissions,
  expressRequireRoles,
  expressRequireAdmin,
  expressRequireModerator,
  getExpressCurrentUser,
  isExpressAuthenticated,
  getExpressAuthContext,
  expressRequireOwnership,
  expressRateLimit,
  expressCorsAuth,
  expressErrorResponse,
  expressSuccessResponse,
  expressAuthLogger,
  expressAuthErrorHandler,
  expressJsonValidator,
  expressSanitizer
} from '../../src/adapters/express';
import { AuthService } from '../../src/services/auth';
import { JWTService } from '../../src/services/jwt';
import { PermissionService } from '../../src/services/permissions';
import { testUtils, TEST_JWT_SECRET } from '../setup';
import type { Request, Response, NextFunction } from 'express';

// Mock de Express Request/Response
const createMockExpressRequest = (overrides: Partial<Request> = {}): Request => {
  return {
    headers: {
      authorization: `Bearer ${testToken}`,
      ...overrides.headers
    },
    body: overrides.body || {},
    params: overrides.params || {},
    query: overrides.query || {},
    user: undefined,
    authContext: undefined,
    get: mock((name: string) => {
      const headers: Record<string, string> = {
        authorization: `Bearer ${testToken}`,
        ...overrides.headers
      };
      return headers[name.toLowerCase()];
    }),
    ip: '127.0.0.1',
    method: 'GET',
    url: '/test',
    ...overrides
  } as Request;
};

const createMockExpressResponse = (): Response => {
  const res = {
    statusCode: 200,
    responseData: undefined,
    headersSent: false,
    locals: {},
    status: mock((code: number) => {
      res.statusCode = code;
      return res;
    }),
    json: mock((data: any) => {
      res.responseData = data;
      return res;
    }),
    send: mock((data: any) => {
      res.responseData = data;
      return res;
    }),
    setHeader: mock((name: string, value: string) => {
      res.locals[name] = value;
      return res;
    }),
    header: mock((name: string, value: string) => {
      res.locals[name] = value;
      return res;
    }),
    end: mock(() => res)
  } as unknown as Response;
  
  return res;
};

describe('Express Adapter', () => {
  let authService: AuthService;
  let jwtService: JWTService;
  let permissionService: PermissionService;
  let testUserId: number;
  let testToken: string;
  let mockNext: NextFunction;

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
    
    mockNext = mock(() => {});
  });

  afterEach(async () => {
    await testUtils.cleanTestData();
  });

  describe('expressAuthMiddleware', () => {
    test('should authenticate valid token', async () => {
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      const middleware = expressAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
      expect(req.user).toBeDefined();
      expect(req.user?.id).toBe(testUserId);
      expect(req.authContext).toBeDefined();
      expect(req.authContext?.isAuthenticated).toBe(true);
      testUtils.validateUserStructure(req.user!);
    });

    test('should reject invalid token', async () => {
      const req = createMockExpressRequest({
        headers: { authorization: 'Bearer invalid-token' }
      });
      const res = createMockExpressResponse();
      
      const middleware = expressAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.stringContaining('Invalid token')
        })
      );
    });

    test('should reject missing token', async () => {
      const req = createMockExpressRequest({
        headers: {}
      });
      const res = createMockExpressResponse();
      
      const middleware = expressAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
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
      
      const req = createMockExpressRequest({
        headers: { authorization: `Bearer ${expiredToken}` }
      });
      const res = createMockExpressResponse();
      
      const middleware = expressAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.stringContaining('Token expired')
        })
      );
    });

    test('should support custom token extraction', async () => {
      const req = createMockExpressRequest({
        headers: {},
        query: { token: testToken }
      });
      const res = createMockExpressResponse();
      
      const middleware = expressAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService,
        extractToken: (req) => req.query.token as string
      });
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
      expect(req.user).toBeDefined();
    });
  });

  describe('expressOptionalAuth', () => {
    test('should authenticate when token is provided', async () => {
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      const middleware = expressOptionalAuth({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
      expect(req.user).toBeDefined();
      expect(req.authContext?.isAuthenticated).toBe(true);
    });

    test('should continue without authentication when no token', async () => {
      const req = createMockExpressRequest({
        headers: {}
      });
      const res = createMockExpressResponse();
      
      const middleware = expressOptionalAuth({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
      expect(req.user).toBeUndefined();
      expect(req.authContext?.isAuthenticated).toBe(false);
    });

    test('should continue when token is invalid', async () => {
      const req = createMockExpressRequest({
        headers: { authorization: 'Bearer invalid-token' }
      });
      const res = createMockExpressResponse();
      
      const middleware = expressOptionalAuth({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
      expect(req.user).toBeUndefined();
      expect(req.authContext?.isAuthenticated).toBe(false);
    });
  });

  describe('expressRequireAuth', () => {
    test('should allow authenticated users', async () => {
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      req.user = await authService.findUserById(testUserId);
      req.authContext = { isAuthenticated: true };
      
      const middleware = expressRequireAuth();
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should reject unauthenticated users', async () => {
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      req.authContext = { isAuthenticated: false };
      
      const middleware = expressRequireAuth();
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(401);
    });
  });

  describe('expressRequirePermissions', () => {
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
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      const user = await authService.findUserById(testUserId);
      req.user = user;
      req.authContext = {
        isAuthenticated: true,
        user,
        permissions: await permissionService.getUserPermissions(testUserId)
      };
      
      const middleware = expressRequirePermissions([permissionName], {
        permissionService
      });
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should deny access without required permission', async () => {
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      const user = await authService.findUserById(testUserId);
      req.user = user;
      req.authContext = {
        isAuthenticated: true,
        user,
        permissions: []
      };
      
      const middleware = expressRequirePermissions(['non-existent-permission'], {
        permissionService
      });
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });
  });

  describe('expressRequireRoles', () => {
    let roleName: string;

    beforeEach(async () => {
      // Configurar roles
      const roleData = testUtils.generateTestRole();
      const roleResult = await permissionService.createRole(roleData);
      roleName = roleData.name;
      
      await authService.assignRole(testUserId, roleName);
    });

    test('should allow access with required role', async () => {
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      const user = await authService.findUserById(testUserId);
      req.user = user;
      req.authContext = {
        isAuthenticated: true,
        user,
        roles: await authService.getUserRoles(testUserId)
      };
      
      const middleware = expressRequireRoles([roleName], {
        permissionService
      });
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should deny access without required role', async () => {
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      const user = await authService.findUserById(testUserId);
      req.user = user;
      req.authContext = {
        isAuthenticated: true,
        user,
        roles: []
      };
      
      const middleware = expressRequireRoles(['non-existent-role'], {
        permissionService
      });
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });
  });

  describe('expressRequireAdmin', () => {
    test('should allow admin users', async () => {
      // Crear rol admin
      const adminRole = testUtils.generateTestRole({ name: 'admin' });
      await permissionService.createRole(adminRole);
      await authService.assignRole(testUserId, 'admin');
      
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      const user = await authService.findUserById(testUserId);
      req.user = user;
      req.authContext = {
        isAuthenticated: true,
        user,
        roles: await authService.getUserRoles(testUserId)
      };
      
      const middleware = expressRequireAdmin({ permissionService });
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should deny non-admin users', async () => {
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      const user = await authService.findUserById(testUserId);
      req.user = user;
      req.authContext = {
        isAuthenticated: true,
        user,
        roles: []
      };
      
      const middleware = expressRequireAdmin({ permissionService });
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });
  });

  describe('Helper Functions', () => {
    test('getExpressCurrentUser should return current user', () => {
      const req = createMockExpressRequest();
      const user = { id: testUserId, email: 'test@example.com' };
      req.user = user;
      
      const currentUser = getExpressCurrentUser(req);
      
      expect(currentUser).toEqual(user);
    });

    test('isExpressAuthenticated should check authentication status', () => {
      const req = createMockExpressRequest();
      req.authContext = { isAuthenticated: true };
      
      const isAuth = isExpressAuthenticated(req);
      
      expect(isAuth).toBe(true);
    });

    test('getExpressAuthContext should return auth context', () => {
      const req = createMockExpressRequest();
      const authContext = { isAuthenticated: true, user: null };
      req.authContext = authContext;
      
      const context = getExpressAuthContext(req);
      
      expect(context).toEqual(authContext);
    });
  });

  describe('expressRequireOwnership', () => {
    test('should allow resource owner', async () => {
      const req = createMockExpressRequest({
        params: { userId: testUserId.toString() }
      });
      const res = createMockExpressResponse();
      
      const user = await authService.findUserById(testUserId);
      req.user = user;
      req.authContext = { isAuthenticated: true, user };
      
      const middleware = expressRequireOwnership({
        getResourceOwnerId: (req) => parseInt(req.params.userId)
      });
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should deny non-owner', async () => {
      const req = createMockExpressRequest({
        params: { userId: '99999' }
      });
      const res = createMockExpressResponse();
      
      const user = await authService.findUserById(testUserId);
      req.user = user;
      req.authContext = { isAuthenticated: true, user };
      
      const middleware = expressRequireOwnership({
        getResourceOwnerId: (req) => parseInt(req.params.userId)
      });
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });
  });

  describe('expressRateLimit', () => {
    test('should allow requests within limit', async () => {
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      const user = await authService.findUserById(testUserId);
      req.user = user;
      
      const middleware = expressRateLimit({
        windowMs: 60000,
        maxRequests: 5,
        keyGenerator: (req) => req.user?.id.toString() || 'anonymous'
      });
      
      // Realizar 3 requests
      for (let i = 0; i < 3; i++) {
        await middleware(req, res, mockNext);
      }
      
      expect(mockNext).toHaveBeenCalledTimes(3);
    });

    test('should block requests exceeding limit', async () => {
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      const user = await authService.findUserById(testUserId);
      req.user = user;
      
      const middleware = expressRateLimit({
        windowMs: 60000,
        maxRequests: 2,
        keyGenerator: (req) => req.user?.id.toString() || 'anonymous'
      });
      
      // Exceder el límite
      await middleware(req, res, mockNext);
      await middleware(req, res, mockNext);
      await middleware(req, res, mockNext);
      
      expect(mockNext).toHaveBeenCalledTimes(2);
      expect(res.status).toHaveBeenCalledWith(429);
    });
  });

  describe('expressCorsAuth', () => {
    test('should set CORS headers', async () => {
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      const middleware = expressCorsAuth({
        origin: 'https://example.com',
        credentials: true
      });
      
      await middleware(req, res, mockNext);
      
      expect(res.header).toHaveBeenCalledWith('Access-Control-Allow-Origin', 'https://example.com');
      expect(res.header).toHaveBeenCalledWith('Access-Control-Allow-Credentials', 'true');
      expect(mockNext).toHaveBeenCalled();
    });

    test('should handle preflight requests', async () => {
      const req = createMockExpressRequest({ method: 'OPTIONS' });
      const res = createMockExpressResponse();
      
      const middleware = expressCorsAuth({
        origin: '*',
        methods: ['GET', 'POST', 'PUT', 'DELETE']
      });
      
      await middleware(req, res, mockNext);
      
      expect(res.header).toHaveBeenCalledWith(
        'Access-Control-Allow-Methods',
        'GET,POST,PUT,DELETE'
      );
      expect(res.status).toHaveBeenCalledWith(204);
      expect(res.end).toHaveBeenCalled();
    });
  });

  describe('Response Helpers', () => {
    test('expressErrorResponse should format error responses', () => {
      const res = createMockExpressResponse();
      
      expressErrorResponse(res, 'Test error', 400, 'VALIDATION_ERROR');
      
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        error: 'Test error',
        code: 'VALIDATION_ERROR',
        timestamp: expect.any(String)
      });
    });

    test('expressSuccessResponse should format success responses', () => {
      const res = createMockExpressResponse();
      const data = { id: 1, name: 'Test' };
      
      expressSuccessResponse(res, data, 'Success message');
      
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        success: true,
        data,
        message: 'Success message',
        timestamp: expect.any(String)
      });
    });
  });

  describe('expressAuthLogger', () => {
    test('should log authentication events', async () => {
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      const user = await authService.findUserById(testUserId);
      req.user = user;
      
      const logSpy = mock(() => {});
      const middleware = expressAuthLogger({
        logLevel: 'info',
        logFunction: logSpy
      });
      
      await middleware(req, res, mockNext);
      
      expect(logSpy).toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    test('should log errors', async () => {
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      const errorNext = mock(() => {
        throw new Error('Test error');
      });
      
      const logSpy = mock(() => {});
      const middleware = expressAuthLogger({
        logLevel: 'error',
        logFunction: logSpy
      });
      
      try {
        await middleware(req, res, errorNext);
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

  describe('expressAuthErrorHandler', () => {
    test('should handle authentication errors', () => {
      const error = new Error('Authentication failed');
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      expressAuthErrorHandler(error, req, res, mockNext);
      
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Authentication failed'
        })
      );
    });

    test('should handle authorization errors', () => {
      const error = new Error('Insufficient permissions');
      (error as any).code = 'INSUFFICIENT_PERMISSIONS';
      
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      expressAuthErrorHandler(error, req, res, mockNext);
      
      expect(res.status).toHaveBeenCalledWith(403);
    });

    test('should handle validation errors', () => {
      const error = new Error('Invalid input');
      (error as any).code = 'VALIDATION_ERROR';
      
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      expressAuthErrorHandler(error, req, res, mockNext);
      
      expect(res.status).toHaveBeenCalledWith(400);
    });
  });

  describe('expressJsonValidator', () => {
    test('should validate JSON schema', async () => {
      const req = createMockExpressRequest({
        body: {
          email: 'test@example.com',
          password: 'password123'
        }
      });
      const res = createMockExpressResponse();
      
      const schema = {
        type: 'object',
        properties: {
          email: { type: 'string', format: 'email' },
          password: { type: 'string', minLength: 6 }
        },
        required: ['email', 'password']
      };
      
      const middleware = expressJsonValidator(schema);
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should reject invalid JSON', async () => {
      const req = createMockExpressRequest({
        body: {
          email: 'invalid-email',
          password: '123'
        }
      });
      const res = createMockExpressResponse();
      
      const schema = {
        type: 'object',
        properties: {
          email: { type: 'string', format: 'email' },
          password: { type: 'string', minLength: 6 }
        },
        required: ['email', 'password']
      };
      
      const middleware = expressJsonValidator(schema);
      
      await middleware(req, res, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.stringContaining('Validation failed')
        })
      );
    });
  });

  describe('expressSanitizer', () => {
    test('should sanitize input data', async () => {
      const req = createMockExpressRequest({
        body: {
          name: '  John Doe  ',
          email: 'JOHN@EXAMPLE.COM',
          description: '<script>alert("xss")</script>Safe content'
        }
      });
      const res = createMockExpressResponse();
      
      const middleware = expressSanitizer({
        fields: ['name', 'email', 'description'],
        options: {
          trim: true,
          lowercase: ['email'],
          stripHtml: ['description']
        }
      });
      
      await middleware(req, res, mockNext);
      
      expect(req.body.name).toBe('John Doe');
      expect(req.body.email).toBe('john@example.com');
      expect(req.body.description).toBe('Safe content');
      expect(mockNext).toHaveBeenCalled();
    });

    test('should handle nested objects', async () => {
      const req = createMockExpressRequest({
        body: {
          user: {
            name: '  Jane Doe  ',
            profile: {
              bio: '<p>Hello <script>alert("xss")</script>World</p>'
            }
          }
        }
      });
      const res = createMockExpressResponse();
      
      const middleware = expressSanitizer({
        fields: ['user.name', 'user.profile.bio'],
        options: {
          trim: true,
          stripHtml: ['user.profile.bio']
        }
      });
      
      await middleware(req, res, mockNext);
      
      expect(req.body.user.name).toBe('Jane Doe');
      expect(req.body.user.profile.bio).toBe('Hello World');
      expect(mockNext).toHaveBeenCalled();
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
      
      const req = createMockExpressRequest();
      const res = createMockExpressResponse();
      
      // Ejecutar middleware de autenticación
      const authMiddleware = expressAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await authMiddleware(req, res, mockNext);
      
      // Verificar autenticación
      expect(req.user).toBeDefined();
      expect(req.authContext?.isAuthenticated).toBe(true);
      
      // Ejecutar middleware de permisos
      const permissionMiddleware = expressRequirePermissions(['posts:read'], {
        permissionService
      });
      
      await permissionMiddleware(req, res, mockNext);
      
      expect(mockNext).toHaveBeenCalledTimes(2);
    });

    test('should handle authentication failure gracefully', async () => {
      const req = createMockExpressRequest({
        headers: { authorization: 'Bearer invalid-token' }
      });
      const res = createMockExpressResponse();
      
      const authMiddleware = expressAuthMiddleware({
        jwtSecret: TEST_JWT_SECRET,
        authService,
        jwtService
      });
      
      await authMiddleware(req, res, mockNext);
      
      expect(mockNext).not.toHaveBeenCalled();
      expect(res.statusCode).toBe(401);
      expect(res.responseData.success).toBe(false);
    });
  });
});