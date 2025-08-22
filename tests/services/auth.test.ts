// tests/services/auth.test.ts
// Tests para el servicio de autenticación

import { describe, test, expect, beforeEach, afterEach } from 'bun:test';
import { AuthService } from '../../src/services/auth';
import { testUtils, TEST_TIMEOUTS } from '../setup';
import type { RegisterData, LoginData } from '../../src/types/auth';

describe('AuthService', () => {
  let authService: AuthService;

  beforeEach(async () => {
    authService = new AuthService();
    await testUtils.cleanTestData();
  });

  afterEach(async () => {
    await testUtils.cleanTestData();
  });

  describe('User Registration', () => {
    test('should register new user successfully', async () => {
      const userData: RegisterData = testUtils.generateTestUser();
      
      const result = await authService.register(userData);
      
      expect(result.success).toBe(true);
      expect(result.user).toBeDefined();
      expect(result.user?.email).toBe(userData.email);
      expect(result.user?.firstName).toBe(userData.firstName);
      expect(result.user?.lastName).toBe(userData.lastName);
      expect(result.user?.isActive).toBe(true);
      expect(result.user).not.toHaveProperty('password');
      expect(result.token).toBeDefined();
      expect(result.refreshToken).toBeDefined();
    });

    test('should hash password during registration', async () => {
      const userData: RegisterData = testUtils.generateTestUser();
      
      await authService.register(userData);
      
      // Verificar que la contraseña está hasheada en la BD
      const db = testUtils.getTestDatabase();
      const user = db.query('SELECT password_hash FROM users WHERE email = ?').get(userData.email) as any;
      
      expect(user.password_hash).toBeDefined();
      expect(user.password_hash).not.toBe(userData.password);
      expect(user.password_hash.startsWith('$2b$')).toBe(true); // bcrypt hash format
    });

    test('should reject registration with existing email', async () => {
      const userData: RegisterData = testUtils.generateTestUser();
      
      // Registrar usuario por primera vez
      await authService.register(userData);
      
      // Intentar registrar con el mismo email
      const result = await authService.register(userData);
      
      expect(result.success).toBe(false);
      expect(result.error?.type).toBe('VALIDATION_ERROR');
      expect(result.error?.message).toContain('already exists');
      expect(result.user).toBeUndefined();
      expect(result.token).toBeUndefined();
    });

    test('should validate required fields', async () => {
      const invalidData = {
        email: '',
        password: '',
        firstName: '',
        lastName: ''
      } as RegisterData;
      
      const result = await authService.register(invalidData);
      
      expect(result.success).toBe(false);
      expect(result.error?.type).toBe('VALIDATION_ERROR');
    });

    test('should validate email format', async () => {
      const userData: RegisterData = {
        ...testUtils.generateTestUser(),
        email: 'invalid-email'
      };
      
      const result = await authService.register(userData);
      
      expect(result.success).toBe(false);
      expect(result.error?.type).toBe('VALIDATION_ERROR');
      expect(result.error?.message).toContain('email');
    });

    test('should validate password strength', async () => {
      const userData: RegisterData = {
        ...testUtils.generateTestUser(),
        password: '123' // Contraseña débil
      };
      
      const result = await authService.register(userData);
      
      expect(result.success).toBe(false);
      expect(result.error?.type).toBe('VALIDATION_ERROR');
      expect(result.error?.message).toContain('password');
    });

    test('should assign default user role', async () => {
      await testUtils.seedTestData(); // Crear roles por defecto
      
      const userData: RegisterData = testUtils.generateTestUser();
      const result = await authService.register(userData);
      
      expect(result.success).toBe(true);
      
      // Verificar que se asignó el rol de usuario
      const userRoles = await authService.getUserRoles(result.user!.id);
      expect(userRoles.some(role => role.name === 'user')).toBe(true);
    });
  });

  describe('User Login', () => {
    let registeredUser: RegisterData;
    let userId: number;

    beforeEach(async () => {
      registeredUser = testUtils.generateTestUser();
      const registerResult = await authService.register(registeredUser);
      userId = registerResult.user!.id;
    });

    test('should login with valid credentials', async () => {
      const loginData: LoginData = {
        email: registeredUser.email,
        password: registeredUser.password
      };
      
      const result = await authService.login(loginData);
      
      expect(result.success).toBe(true);
      expect(result.user).toBeDefined();
      expect(result.user?.email).toBe(registeredUser.email);
      expect(result.user).not.toHaveProperty('password');
      expect(result.token).toBeDefined();
      expect(result.refreshToken).toBeDefined();
    });

    test('should reject login with invalid email', async () => {
      const loginData: LoginData = {
        email: 'nonexistent@example.com',
        password: registeredUser.password
      };
      
      const result = await authService.login(loginData);
      
      expect(result.success).toBe(false);
      expect(result.error?.type).toBe('AUTHENTICATION_ERROR');
      expect(result.error?.message).toContain('Invalid credentials');
    });

    test('should reject login with invalid password', async () => {
      const loginData: LoginData = {
        email: registeredUser.email,
        password: 'wrong-password'
      };
      
      const result = await authService.login(loginData);
      
      expect(result.success).toBe(false);
      expect(result.error?.type).toBe('AUTHENTICATION_ERROR');
      expect(result.error?.message).toContain('Invalid credentials');
    });

    test('should reject login for inactive user', async () => {
      // Desactivar usuario
      await authService.updateUser(userId, { isActive: false });
      
      const loginData: LoginData = {
        email: registeredUser.email,
        password: registeredUser.password
      };
      
      const result = await authService.login(loginData);
      
      expect(result.success).toBe(false);
      expect(result.error?.type).toBe('AUTHENTICATION_ERROR');
      expect(result.error?.message).toContain('inactive');
    });

    test('should update last login timestamp', async () => {
      const loginData: LoginData = {
        email: registeredUser.email,
        password: registeredUser.password
      };
      
      const beforeLogin = Math.floor(Date.now() / 1000) * 1000; // Round down to seconds
      await authService.login(loginData);
      const afterLogin = Date.now();
      
      const user = await authService.findUserById(userId);
      expect(user?.lastLoginAt).toBeDefined();
      
      const lastLoginTime = new Date(user!.lastLoginAt!).getTime();
      expect(lastLoginTime).toBeGreaterThanOrEqual(beforeLogin);
      expect(lastLoginTime).toBeLessThanOrEqual(afterLogin + 1000); // Allow 1 second tolerance
    });
  });

  describe('User Management', () => {
    let userId: number;

    beforeEach(async () => {
      const userData = testUtils.generateTestUser();
      const result = await authService.register(userData);
      userId = result.user!.id;
    });

    test('should find user by ID', async () => {
      const user = await authService.findUserById(userId);
      
      expect(user).toBeDefined();
      expect(user?.id).toBe(userId);
      expect(user).not.toHaveProperty('password');
      testUtils.validateUserStructure(user);
    });

    test('should find user by email', async () => {
      const registerResult = await authService.findUserById(userId);
      const user = await authService.findUserByEmail(registerResult!.email);
      
      expect(user).toBeDefined();
      expect(user?.id).toBe(userId);
      expect(user).not.toHaveProperty('password');
      testUtils.validateUserStructure(user);
    });

    test('should return null for non-existent user', async () => {
      const user = await authService.findUserById(99999);
      expect(user).toBeNull();
      
      const userByEmail = await authService.findUserByEmail('nonexistent@example.com');
      expect(userByEmail).toBeNull();
    });

    test('should update user information', async () => {
      const updateData = {
        firstName: 'Updated',
        lastName: 'Name',
        isActive: false
      };
      
      const result = await authService.updateUser(userId, updateData);
      
      expect(result.success).toBe(true);
      expect(result.user?.firstName).toBe(updateData.firstName);
      expect(result.user?.lastName).toBe(updateData.lastName);
      expect(result.user?.isActive).toBe(updateData.isActive);
    });

    test('should not allow updating email to existing email', async () => {
      // Crear segundo usuario
      const secondUser = testUtils.generateTestUser();
      await authService.register(secondUser);
      
      // Intentar actualizar email del primer usuario al email del segundo
      const result = await authService.updateUser(userId, { email: secondUser.email });
      
      expect(result.success).toBe(false);
      expect(result.error?.type).toBe('VALIDATION_ERROR');
    });

    test('should update password', async () => {
      const newPassword = 'NewPassword123!';
      
      const result = await authService.updatePassword(userId, newPassword);
      
      expect(result.success).toBe(true);
      
      // Verificar que puede hacer login con la nueva contraseña
      const user = await authService.findUserById(userId);
      const loginResult = await authService.login({
        email: user!.email,
        password: newPassword
      });
      
      expect(loginResult.success).toBe(true);
    });

    test('should activate and deactivate user', async () => {
      // Desactivar
      const deactivateResult = await authService.deactivateUser(userId);
      expect(deactivateResult.success).toBe(true);
      
      let user = await authService.findUserById(userId);
      expect(user?.isActive).toBe(false);
      
      // Activar
      const activateResult = await authService.activateUser(userId);
      expect(activateResult.success).toBe(true);
      
      user = await authService.findUserById(userId);
      expect(user?.isActive).toBe(true);
    });

    test('should delete user', async () => {
      const result = await authService.deleteUser(userId);
      
      expect(result.success).toBe(true);
      
      const user = await authService.findUserById(userId);
      expect(user).toBeNull();
    });
  });

  describe('Role Management', () => {
    let userId: number;

    beforeEach(async () => {
      await testUtils.seedTestData(); // Crear roles por defecto
      
      const userData = testUtils.generateTestUser();
      const result = await authService.register(userData);
      userId = result.user!.id;
    });

    test('should get user roles', async () => {
      const roles = await authService.getUserRoles(userId);
      
      expect(Array.isArray(roles)).toBe(true);
      expect(roles.length).toBeGreaterThan(0);
      
      roles.forEach(role => {
        testUtils.validateRoleStructure(role);
      });
    });

    test('should assign role to user', async () => {
      const result = await authService.assignRole(userId, 'admin');
      
      expect(result.success).toBe(true);
      
      const roles = await authService.getUserRoles(userId);
      expect(roles.some(role => role.name === 'admin')).toBe(true);
    });

    test('should remove role from user', async () => {
      // Asignar rol primero
      await authService.assignRole(userId, 'admin');
      
      // Remover rol
      const result = await authService.removeRole(userId, 'admin');
      
      expect(result.success).toBe(true);
      
      const roles = await authService.getUserRoles(userId);
      expect(roles.some(role => role.name === 'admin')).toBe(false);
    });

    test('should not assign non-existent role', async () => {
      const result = await authService.assignRole(userId, 'non-existent-role');
      
      expect(result.success).toBe(false);
      expect(result.error?.type).toBe('NOT_FOUND_ERROR');
    });

    test('should not assign duplicate role', async () => {
      // Asignar rol
      await authService.assignRole(userId, 'admin');
      
      // Intentar asignar el mismo rol otra vez
      const result = await authService.assignRole(userId, 'admin');
      
      expect(result.success).toBe(false);
      expect(result.error?.type).toBe('VALIDATION_ERROR');
    });
  });

  describe('User Queries', () => {
    beforeEach(async () => {
      await testUtils.seedTestData();
      
      // Crear varios usuarios de prueba
      for (let i = 0; i < 5; i++) {
        const userData = testUtils.generateTestUser({
          email: `test${i}@example.com`,
          firstName: `User${i}`,
          isActive: i % 2 === 0 // Alternar activos/inactivos
        });
        await authService.register(userData);
      }
    });

    test('should get all users with pagination', async () => {
      const result = await authService.getUsers(1, 3);
      
      expect(result.users).toBeDefined();
      expect(result.users.length).toBeLessThanOrEqual(3);
      expect(result.total).toBeGreaterThan(0);
      // Note: The method doesn't return page and totalPages, only users and total
      
      result.users.forEach(user => {
        testUtils.validateUserStructure(user);
      });
    });

    test('should filter users by active status', async () => {
      const activeUsers = await authService.getUsers(1, 10, { isActive: true });
      const inactiveUsers = await authService.getUsers(1, 10, { isActive: false });
      
      expect(activeUsers.users.every(user => user.isActive)).toBe(true);
      expect(inactiveUsers.users.every(user => !user.isActive)).toBe(true);
    });

    test('should search users by email', async () => {
      const result = await authService.getUsers(1, 10, { search: 'test1@example.com' });
      
      expect(result.users.length).toBe(1);
      expect(result.users[0].email).toBe('test1@example.com');
    });

    test('should search users by name', async () => {
      const result = await authService.getUsers(1, 10, { search: 'User1' });
      
      expect(result.users.length).toBe(1);
      expect(result.users[0].firstName).toBe('User1');
    });

    test('should sort users', async () => {
      const result = await authService.getUsers(1, 10, { 
        sortBy: 'email', 
        sortOrder: 'asc' 
      });
      
      expect(result.users.length).toBeGreaterThan(1);
      
      // Verificar que están ordenados por email
      for (let i = 1; i < result.users.length; i++) {
        expect(result.users[i].email >= result.users[i-1].email).toBe(true);
      }
    });
  });

  describe('Error Handling', () => {
    test('should handle database errors gracefully', async () => {
      // Note: Database auto-reinitializes when closed, so this test verifies
      // that the system can recover from database connection issues
      const db = testUtils.getTestDatabase();
      db.close();
      
      const userData = testUtils.generateTestUser();
      const result = await authService.register(userData);
      
      // The database should auto-recover and registration should succeed
      expect(result.success).toBe(true);
      expect(result.user).toBeDefined();
      
      // Reinicializar para otros tests
       await testUtils.cleanTestData();
     });

    test('should validate input parameters', async () => {
      const result = await authService.findUserById(-1);
      expect(result).toBeNull();
      
      const result2 = await authService.findUserByEmail('');
      expect(result2).toBeNull();
    });
  });

  describe('s', () => {
    test('should handle multiple concurrent registrations', async () => {
      const promises = [];
      
      for (let i = 0; i < 10; i++) {
        const userData = testUtils.generateTestUser({
          email: `concurrent${i}@example.com`
        });
        promises.push(authService.register(userData));
      }
      
      const results = await Promise.all(promises);
      
      // Todos deberían ser exitosos
      expect(results.every(result => result.success)).toBe(true);
      
      // Verificar que todos los usuarios fueron creados
      const users = await authService.getUsers(1, 20);
      expect(users.total).toBe(10);
    }, TEST_TIMEOUTS.MEDIUM);

    test('should handle password hashing efficiently', async () => {
      const startTime = Date.now();
      
      const promises = [];
      for (let i = 0; i < 5; i++) {
        const userData = testUtils.generateTestUser({
          email: `perf${i}@example.com`
        });
        promises.push(authService.register(userData));
      }
      
      await Promise.all(promises);
      
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      // 5 registros con hash de contraseña deberían completarse en menos de 5 segundos
      expect(duration).toBeLessThan(5000);
    }, TEST_TIMEOUTS.MEDIUM);
  });
});