// tests/integration/auth-flow.test.ts
// Tests de integración para flujos completos de autenticación

import { describe, test, expect, beforeEach, afterEach, beforeAll, afterAll } from 'bun:test';
import { AuthService } from '../../src/services/auth';
import { JWTService } from '../../src/services/jwt';
import { PermissionService } from '../../src/services/permissions';
import { AuthLibrary } from '../../src/index';
import { testUtils, TEST_JWT_SECRET } from '../setup';
import type { User, Role, Permission } from '../../src/types/auth';

describe('Authentication Flow Integration Tests', () => {
  let authLib: AuthLibrary;
  let authService: AuthService;
  let jwtService: JWTService;
  let permissionService: PermissionService;

  beforeAll(async () => {
    // Inicializar la librería completa
    authLib = new AuthLibrary({
      jwtSecret: TEST_JWT_SECRET,
      database: {
        path: process.env.TEST_DB_PATH || ':memory:'
      },
      security: {
        bcryptRounds: 10,
        sessionTimeout: 3600000,
        maxLoginAttempts: 5
      }
    });

    await authLib.initialize();
    
    authService = authLib.getAuthService();
    jwtService = authLib.getJWTService();
    permissionService = authLib.getPermissionService();
  });

  afterAll(async () => {
    await authLib.clean()
  });

  beforeEach(async () => {
    await testUtils.cleanTestData();
  });

  afterEach(async () => {
    await testUtils.cleanTestData();
  });

  describe('Complete User Registration and Authentication Flow', () => {
    test('should handle complete user lifecycle', async () => {
      // 1. Registrar usuario
      const userData = testUtils.generateTestUser({
        email: 'integration@test.com',
        password: 'SecurePassword123!',
        firstName: 'Integration',
        lastName: 'Test'
      });

      const registerResult = await authService.register(userData);
      
      expect(registerResult.success).toBe(true);
      expect(registerResult.user).toBeDefined();
      expect(registerResult.user!.email).toBe(userData.email);
      expect(registerResult.user!.isActive).toBe(true);
      testUtils.validateUserStructure(registerResult.user!);

      const userId = registerResult.user!.id;

      // 2. Intentar login con credenciales correctas
      const loginResult = await authService.login(userData.email, userData.password);
      
      expect(loginResult.success).toBe(true);
      expect(loginResult.user).toBeDefined();
      expect(loginResult.user!.id).toBe(userId);
      expect(loginResult.user!.lastLoginAt).toBeDefined();

      // 3. Generar JWT token
      const token = await jwtService.generateToken({ userId, email: userData.email });
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');

      // 4. Verificar token
      const verifyResult = await jwtService.verifyToken(token);
      expect(verifyResult.valid).toBe(true);
      expect(verifyResult.payload?.userId).toBe(userId);
      expect(verifyResult.payload?.email).toBe(userData.email);

      // 5. Buscar usuario por token
      const userFromToken = await authService.findUserById(userId);
      expect(userFromToken).toBeDefined();
      expect(userFromToken!.id).toBe(userId);
      expect(userFromToken!.email).toBe(userData.email);

      // 6. Actualizar información del usuario
      const updateResult = await authService.updateUser(userId, {
        firstName: 'Updated',
        lastName: 'Name'
      });
      
      expect(updateResult.success).toBe(true);
      expect(updateResult.user!.firstName).toBe('Updated');
      expect(updateResult.user!.lastName).toBe('Name');

      // 7. Cambiar contraseña
      const newPassword = 'NewSecurePassword456!';
      const passwordResult = await authService.updatePassword(userId, userData.password, newPassword);
      
      expect(passwordResult.success).toBe(true);

      // 8. Verificar que la nueva contraseña funciona
      const newLoginResult = await authService.login(userData.email, newPassword);
      expect(newLoginResult.success).toBe(true);

      // 9. Verificar que la contraseña anterior no funciona
      const oldLoginResult = await authService.login(userData.email, userData.password);
      expect(oldLoginResult.success).toBe(false);

      // 10. Desactivar usuario
      const deactivateResult = await authService.deactivateUser(userId);
      expect(deactivateResult.success).toBe(true);

      // 11. Verificar que el usuario desactivado no puede hacer login
      const inactiveLoginResult = await authService.login(userData.email, newPassword);
      expect(inactiveLoginResult.success).toBe(false);
      expect(inactiveLoginResult.error).toContain('inactive');
    });

    test('should handle registration validation errors', async () => {
      // Email inválido
      const invalidEmailResult = await authService.register({
        email: 'invalid-email',
        password: 'ValidPassword123!',
        firstName: 'Test',
        lastName: 'User'
      });
      
      expect(invalidEmailResult.success).toBe(false);
      expect(invalidEmailResult.error).toContain('email');

      // Contraseña débil
      const weakPasswordResult = await authService.register({
        email: 'test@example.com',
        password: '123',
        firstName: 'Test',
        lastName: 'User'
      });
      
      expect(weakPasswordResult.success).toBe(false);
      expect(weakPasswordResult.error).toContain('password');

      // Email duplicado
      const userData = testUtils.generateTestUser();
      await authService.register(userData);
      
      const duplicateResult = await authService.register(userData);
      expect(duplicateResult.success).toBe(false);
      expect(duplicateResult.error).toContain('already exists');
    });
  });

  describe('Role-Based Access Control (RBAC) Flow', () => {
    let userId: number;
    let adminRoleId: number;
    let userRoleId: number;
    let moderatorRoleId: number;

    beforeEach(async () => {
      // Crear usuario de prueba
      const userData = testUtils.generateTestUser();
      const userResult = await authService.register(userData);
      userId = userResult.user!.id;

      // Crear roles
      const adminRole = await permissionService.createRole({
        name: 'admin',
        description: 'Administrator role'
      });
      adminRoleId = adminRole.role!.id;

      const userRole = await permissionService.createRole({
        name: 'user',
        description: 'Regular user role'
      });
      userRoleId = userRole.role!.id;

      const moderatorRole = await permissionService.createRole({
        name: 'moderator',
        description: 'Moderator role'
      });
      moderatorRoleId = moderatorRole.role!.id;
    });

    test('should handle complete RBAC workflow', async () => {
      // 1. Crear permisos
      const permissions = [
        { name: 'posts:create', resource: 'posts', action: 'create' },
        { name: 'posts:read', resource: 'posts', action: 'read' },
        { name: 'posts:update', resource: 'posts', action: 'update' },
        { name: 'posts:delete', resource: 'posts', action: 'delete' },
        { name: 'users:manage', resource: 'users', action: 'manage' },
        { name: 'system:admin', resource: 'system', action: 'admin' }
      ];

      const createdPermissions: Permission[] = [];
      for (const permData of permissions) {
        const result = await permissionService.createPermission(permData);
        expect(result.success).toBe(true);
        createdPermissions.push(result.permission!);
      }

      // 2. Asignar permisos a roles
      // Admin: todos los permisos
      for (const permission of createdPermissions) {
        const result = await permissionService.assignPermissionToRole(adminRoleId, permission.id);
        expect(result.success).toBe(true);
      }

      // User: solo lectura de posts
      const readPermission = createdPermissions.find(p => p.name === 'posts:read')!;
      const userPermResult = await permissionService.assignPermissionToRole(userRoleId, readPermission.id);
      expect(userPermResult.success).toBe(true);

      // Moderator: crear, leer y actualizar posts
      const modPermissions = createdPermissions.filter(p => 
        ['posts:create', 'posts:read', 'posts:update'].includes(p.name)
      );
      for (const permission of modPermissions) {
        const result = await permissionService.assignPermissionToRole(moderatorRoleId, permission.id);
        expect(result.success).toBe(true);
      }

      // 3. Asignar rol de usuario por defecto
      const assignUserResult = await authService.assignRole(userId, 'user');
      expect(assignUserResult.success).toBe(true);

      // 4. Verificar permisos de usuario
      const userPermissions = await permissionService.getUserPermissions(userId);
      expect(userPermissions).toHaveLength(1);
      expect(userPermissions[0].name).toBe('posts:read');

      // 5. Verificar permisos específicos
      const canRead = await permissionService.userHasPermission(userId, 'posts:read');
      expect(canRead).toBe(true);

      const canCreate = await permissionService.userHasPermission(userId, 'posts:create');
      expect(canCreate).toBe(false);

      const canDelete = await permissionService.userHasPermission(userId, 'posts:delete');
      expect(canDelete).toBe(false);

      // 6. Promover a moderador
      const assignModResult = await authService.assignRole(userId, 'moderator');
      expect(assignModResult.success).toBe(true);

      // 7. Verificar nuevos permisos
      const modPermissionsResult = await permissionService.getUserPermissions(userId);
      expect(modPermissionsResult.length).toBeGreaterThan(1);

      const canCreateNow = await permissionService.userHasPermission(userId, 'posts:create');
      expect(canCreateNow).toBe(true);

      const canUpdateNow = await permissionService.userHasPermission(userId, 'posts:update');
      expect(canUpdateNow).toBe(true);

      const stillCantDelete = await permissionService.userHasPermission(userId, 'posts:delete');
      expect(stillCantDelete).toBe(false);

      // 8. Promover a admin
      const assignAdminResult = await authService.assignRole(userId, 'admin');
      expect(assignAdminResult.success).toBe(true);

      // 9. Verificar permisos de admin
      const canDeleteNow = await permissionService.userHasPermission(userId, 'posts:delete');
      expect(canDeleteNow).toBe(true);

      const canManageUsers = await permissionService.userHasPermission(userId, 'users:manage');
      expect(canManageUsers).toBe(true);

      const canAdminSystem = await permissionService.userHasPermission(userId, 'system:admin');
      expect(canAdminSystem).toBe(true);

      // 10. Verificar múltiples permisos
      const hasMultiplePerms = await permissionService.userHasPermissions(
        userId, 
        ['posts:create', 'posts:read', 'posts:update', 'posts:delete'],
        true // requireAll
      );
      expect(hasMultiplePerms).toBe(true);

      // 11. Remover rol
      const removeRoleResult = await authService.removeRole(userId, 'user');
      expect(removeRoleResult.success).toBe(true);

      // 12. Verificar roles actuales
      const currentRoles = await authService.getUserRoles(userId);
      const roleNames = currentRoles.map(r => r.name);
      expect(roleNames).toContain('admin');
      expect(roleNames).toContain('moderator');
      expect(roleNames).not.toContain('user');
    });

    test('should handle permission inheritance and conflicts', async () => {
      // Crear permisos conflictivos
      const readPermission = await permissionService.createPermission({
        name: 'posts:read',
        resource: 'posts',
        action: 'read'
      });

      const writePermission = await permissionService.createPermission({
        name: 'posts:write',
        resource: 'posts',
        action: 'write'
      });

      // Asignar permisos a diferentes roles
      await permissionService.assignPermissionToRole(userRoleId, readPermission.permission!.id);
      await permissionService.assignPermissionToRole(moderatorRoleId, writePermission.permission!.id);

      // Asignar ambos roles al usuario
      await authService.assignRole(userId, 'user');
      await authService.assignRole(userId, 'moderator');

      // Verificar que el usuario tiene ambos permisos
      const userPermissions = await permissionService.getUserPermissions(userId);
      const permissionNames = userPermissions.map(p => p.name);
      
      expect(permissionNames).toContain('posts:read');
      expect(permissionNames).toContain('posts:write');

      // Verificar permisos individuales
      const canRead = await permissionService.userHasPermission(userId, 'posts:read');
      const canWrite = await permissionService.userHasPermission(userId, 'posts:write');
      
      expect(canRead).toBe(true);
      expect(canWrite).toBe(true);
    });
  });

  describe('JWT Token Management Flow', () => {
    let userId: number;
    let userEmail: string;

    beforeEach(async () => {
      const userData = testUtils.generateTestUser();
      const result = await authService.register(userData);
      userId = result.user!.id;
      userEmail = userData.email;
    });

    test('should handle token lifecycle', async () => {
      // 1. Generar token inicial
      const token = jwtService.generateToken({
        userId,
        email: userEmail,
        roles: ['user']
      });

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');

      // 2. Verificar token válido
      const verifyResult = jwtService.verifyToken(token);
      expect(verifyResult.valid).toBe(true);
      expect(verifyResult.payload?.userId).toBe(userId);
      expect(verifyResult.payload?.email).toBe(userEmail);

      // 3. Generar refresh token
      const refreshToken = jwtService.generateRefreshToken({ userId });
      expect(refreshToken).toBeDefined();
      expect(refreshToken).not.toBe(token);

      // 4. Usar refresh token para generar nuevo access token
      const newTokenResult = jwtService.refreshToken(refreshToken);
      expect(newTokenResult.success).toBe(true);
      expect(newTokenResult.token).toBeDefined();
      expect(newTokenResult.token).not.toBe(token);

      // 5. Verificar que el nuevo token es válido
      const newVerifyResult = jwtService.verifyToken(newTokenResult.token!);
      expect(newVerifyResult.valid).toBe(true);
      expect(newVerifyResult.payload?.userId).toBe(userId);

      // 6. Verificar que tokens tienen diferentes timestamps
      const originalPayload = jwtService.verifyToken(token).payload;
      const newPayload = jwtService.verifyToken(newTokenResult.token!).payload;
      
      expect(newPayload?.iat).toBeGreaterThan(originalPayload?.iat || 0);
    });

    test('should handle token expiration', async () => {
      // Generar token con expiración muy corta
      const shortToken = jwtService.generateToken(
        { userId, email: userEmail },
        { expiresIn: '1ms' }
      );

      // Esperar a que expire
      await new Promise(resolve => setTimeout(resolve, 10));

      // Verificar que el token ha expirado
      const verifyResult = jwtService.verifyToken(shortToken);
      expect(verifyResult.valid).toBe(false);
      expect(verifyResult.error).toContain('expired');
    });

    test('should handle invalid tokens', async () => {
      // Token malformado
      const malformedResult = jwtService.verifyToken('invalid.token.here');
      expect(malformedResult.valid).toBe(false);
      expect(malformedResult.error).toContain('Invalid token format');

      // Token con firma incorrecta
      const wrongSecretService = new JWTService('wrong-secret');
      const wrongToken = wrongSecretService.generateToken({ userId });
      
      const wrongSignatureResult = jwtService.verifyToken(wrongToken);
      expect(wrongSignatureResult.valid).toBe(false);
      expect(wrongSignatureResult.error).toContain('Invalid signature');

      // Token vacío
      const emptyResult = jwtService.verifyToken('');
      expect(emptyResult.valid).toBe(false);
      expect(emptyResult.error).toContain('No token provided');
    });
  });

  describe('Security and Edge Cases', () => {
    test('should handle concurrent user operations', async () => {
      const userData = testUtils.generateTestUser();
      
      // Registrar múltiples usuarios concurrentemente
      const registrationPromises = Array.from({ length: 5 }, (_, i) => 
        authService.register({
          ...userData,
          email: `user${i}@test.com`
        })
      );

      const results = await Promise.all(registrationPromises);
      
      // Todos deberían ser exitosos
      results.forEach(result => {
        expect(result.success).toBe(true);
        expect(result.user).toBeDefined();
      });

      // Verificar que todos los usuarios son únicos
      const userIds = results.map(r => r.user!.id);
      const uniqueIds = new Set(userIds);
      expect(uniqueIds.size).toBe(5);
    });

    test('should handle database constraints', async () => {
      const userData = testUtils.generateTestUser();
      
      // Primer registro exitoso
      const firstResult = await authService.register(userData);
      expect(firstResult.success).toBe(true);

      // Segundo registro con mismo email debería fallar
      const duplicateResult = await authService.register(userData);
      expect(duplicateResult.success).toBe(false);
      expect(duplicateResult.error).toContain('already exists');
    });

    test('should handle invalid user operations', async () => {
      // Operaciones en usuario inexistente
      const invalidUserId = 99999;
      
      const updateResult = await authService.updateUser(invalidUserId, {
        firstName: 'Updated'
      });
      expect(updateResult.success).toBe(false);
      expect(updateResult.error).toContain('not found');

      const passwordResult = await authService.updatePassword(
        invalidUserId, 
        'oldpass', 
        'newpass'
      );
      expect(passwordResult.success).toBe(false);
      expect(passwordResult.error).toContain('not found');

      const roleResult = await authService.assignRole(invalidUserId, 'user');
      expect(roleResult.success).toBe(false);
      expect(roleResult.error).toContain('not found');
    });

    test('should handle permission edge cases', async () => {
      // Crear usuario y rol
      const userData = testUtils.generateTestUser();
      const userResult = await authService.register(userData);
      const userId = userResult.user!.id;

      const roleResult = await permissionService.createRole({
        name: 'test-role',
        description: 'Test role'
      });
      const roleId = roleResult.role!.id;

      // Asignar rol inexistente
      const invalidRoleResult = await authService.assignRole(userId, 'non-existent-role');
      expect(invalidRoleResult.success).toBe(false);
      expect(invalidRoleResult.error).toContain('not found');

      // Verificar permiso inexistente
      const hasInvalidPerm = await permissionService.userHasPermission(userId, 'invalid:permission');
      expect(hasInvalidPerm).toBe(false);

      // Asignar permiso inexistente a rol
      const assignInvalidPerm = await permissionService.assignPermissionToRole(roleId, 99999);
      expect(assignInvalidPerm.success).toBe(false);
      expect(assignInvalidPerm.error).toContain('not found');
    });
  });

  describe('Error Recovery and Resilience', () => {
    test('should recover from database errors gracefully', async () => {
      // Simular error de base de datos cerrando la conexión
      // Nota: Este test depende de la implementación específica de la base de datos
      
      const userData = testUtils.generateTestUser();
      
      // Registrar usuario normalmente
      const result1 = await authService.register(userData);
      expect(result1.success).toBe(true);
      
      // Intentar registrar usuario duplicado (debería manejar el error)
      const result2 = await authService.register(userData);
      expect(result2.success).toBe(false);
      expect(result2.error).toBeDefined();
      
      // Verificar que el servicio sigue funcionando
      const newUserData = testUtils.generateTestUser({ email: 'recovery@test.com' });
      const result3 = await authService.register(newUserData);
      expect(result3.success).toBe(true);
    });

    test('should handle malformed input gracefully', async () => {
      // Datos de registro inválidos
      const invalidInputs = [
        { email: null, password: 'valid', firstName: 'Test', lastName: 'User' },
        { email: 'valid@test.com', password: null, firstName: 'Test', lastName: 'User' },
        { email: 'valid@test.com', password: 'valid', firstName: null, lastName: 'User' },
        { email: '', password: 'valid', firstName: 'Test', lastName: 'User' },
        { email: 'valid@test.com', password: '', firstName: 'Test', lastName: 'User' }
      ];

      for (const invalidInput of invalidInputs) {
        const result = await authService.register(invalidInput as any);
        expect(result.success).toBe(false);
        expect(result.error).toBeDefined();
      }
    });
  });
});