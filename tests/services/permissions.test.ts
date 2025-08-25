// tests/services/permissions.test.ts
// Tests para el servicio de permisos (versión simplificada y corregida)

import { describe, test, expect, beforeEach, afterEach } from 'bun:test';
import { PermissionService } from '../../src/services/permissions';
import { AuthService } from '../../src/services/auth';
import { testUtils } from '../setup';
import type { CreatePermissionData, CreateRoleData } from '../../src/types/auth';
import { AuthErrorType } from '../../src/types/auth';
import { defaultLogger as logger } from '../../src/logger';

logger.silence();

describe('PermissionService', () => {
  let permissionService: PermissionService;
  let authService: AuthService;
  let testUserId: string;

  beforeEach(async () => {
    // Limpia la base de datos y crea un usuario de prueba base para cada test
    await testUtils.cleanTestData();
    permissionService = new PermissionService();
    authService = new AuthService();
    
    const userData = testUtils.generateTestUser();
    const result = await authService.register(userData);
    testUserId = result.user!.id;
  });

  afterEach(async () => {
    await testUtils.cleanTestData();
  });

  // --- Pruebas de Gestión de Permisos ---
  describe('Permission Management', () => {
    test('should create a new permission', async () => {
      const permissionData: CreatePermissionData = { name: 'posts:create', resource: 'posts', action: 'create' };
      const result = await permissionService.createPermission(permissionData);

      expect(result.success).toBe(true);
      expect(result.permission).toBeDefined();
      expect(result.permission?.name).toBe('posts:create');
      testUtils.validatePermissionStructure(result.permission!);
    });

    test('should not create a duplicate permission', async () => {
      const permissionData: CreatePermissionData = { name: 'posts:create', resource: 'posts', action: 'create' };
      await permissionService.createPermission(permissionData); // Primer intento (exitoso)
      const result = await permissionService.createPermission(permissionData); // Segundo intento (debe fallar)

      expect(result.success).toBe(false);
      expect(result.error?.type).toBe(AuthErrorType.VALIDATION_ERROR);
      expect(result.error?.message).toContain('already exists');
    });
    
    test('should get all permissions', async () => {
      await permissionService.createPermission({ name: 'posts:read', resource: 'posts', action: 'read' });
      await permissionService.createPermission({ name: 'posts:write', resource: 'posts', action: 'write' });
      
      const permissions = await permissionService.getAllPermissions();
      
      expect(permissions.length).toBe(2);
      expect(permissions[0].name).toBe('posts:read');
    });

    test('should find a permission by name', async () => {
      const permissionData = { name: 'posts:delete', resource: 'posts', action: 'delete' };
      await permissionService.createPermission(permissionData);
      
      const found = await permissionService.findPermissionByName('posts:delete');
      
      expect(found).toBeDefined();
      expect(found?.name).toBe('posts:delete');
    });

    test('should return null for a non-existent permission', async () => {
      const found = await permissionService.findPermissionByName('non-existent');
      expect(found).toBeNull();
    });

    test('should update a permission', async () => {
      const createResult = await permissionService.createPermission({ name: 'posts:update', resource: 'posts', action: 'update' });
      const permissionId = createResult.permission!.id;
      
      const updateResult = await permissionService.updatePermission(permissionId, { description: 'Updated description' });
      
      expect(updateResult.success).toBe(true);
      expect(updateResult.permission?.description).toBe('Updated description');
    });

    test('should delete a permission', async () => {
      const createResult = await permissionService.createPermission({ name: 'posts:delete', resource: 'posts', action: 'delete' });
      const permissionId = createResult.permission!.id;

      const deleteResult = await permissionService.deletePermission(permissionId);
      expect(deleteResult.success).toBe(true);
      
      const found = await permissionService.findPermissionByName('posts:delete');
      expect(found).toBeNull();
    });
  });

  // --- Pruebas de Gestión de Roles ---
  describe('Role Management', () => {
    test('should create a new role', async () => {
      const roleData: CreateRoleData = { name: 'editor', description: 'Can edit content' };
      const result = await permissionService.createRole(roleData);

      expect(result.success).toBe(true);
      expect(result.role).toBeDefined();
      expect(result.role?.name).toBe('editor');
      testUtils.validateRoleStructure(result.role!);
    });

    test('should not create a duplicate role', async () => {
      const roleData: CreateRoleData = { name: 'editor' };
      await permissionService.createRole(roleData); // Primer intento
      const result = await permissionService.createRole(roleData); // Segundo intento

      expect(result.success).toBe(false);
      expect(result.error?.type).toBe(AuthErrorType.VALIDATION_ERROR);
    });
    
    test('should find a role by name', async () => {
      await permissionService.createRole({ name: 'moderator' });
      
      const found = await permissionService.findRoleByName('moderator');
      
      expect(found).toBeDefined();
      expect(found?.name).toBe('moderator');
    });

    test('should update a role', async () => {
      const createResult = await permissionService.createRole({ name: 'moderator' });
      const roleId = createResult.role!.id;
      
      const updateResult = await permissionService.updateRole(roleId, { description: 'Updated description', isActive: false });
      
      expect(updateResult.success).toBe(true);
      expect(updateResult.role?.description).toBe('Updated description');
      expect(updateResult.role?.isActive).toBe(false);
    });

    test('should delete a role', async () => {
      const createResult = await permissionService.createRole({ name: 'guest' });
      const roleId = createResult.role!.id;

      const deleteResult = await permissionService.deleteRole(roleId);
      expect(deleteResult.success).toBe(true);
      
      const found = await permissionService.findRoleByName('guest');
      expect(found).toBeNull();
    });
  });

  // --- Pruebas de Asignación de Permisos a Roles ---
  describe('Role-Permission Assignment', () => {
    let roleId: string;
    let permissionId: string;

    beforeEach(async () => {
      // Crear un rol y un permiso base para las pruebas de esta sección
      const roleResult = await permissionService.createRole({ name: 'author' });
      roleId = roleResult.role!.id;
      
      const permissionResult = await permissionService.createPermission({ name: 'posts:create', resource: 'posts', action: 'create' });
      permissionId = permissionResult.permission!.id;
    });

    test('should assign a permission to a role', async () => {
      const result = await permissionService.assignPermissionToRole(roleId, permissionId);
      expect(result.success).toBe(true);
      
      const rolePermissions = await permissionService.getRolePermissions(roleId);
      expect(rolePermissions).toHaveLength(1);
      expect(rolePermissions[0].id).toBe(permissionId);
    });

    test('should remove a permission from a role', async () => {
      await permissionService.assignPermissionToRole(roleId, permissionId); // Asignar primero
      const result = await permissionService.removePermissionFromRole(roleId, permissionId); // Luego remover
      
      expect(result.success).toBe(true);
      
      const rolePermissions = await permissionService.getRolePermissions(roleId);
      expect(rolePermissions).toBeEmpty();
    });

    test('should replace all role permissions', async () => {
      // Crear permisos nuevos (CORREGIDO: añadiendo resource y action)
      const perm1 = await permissionService.createPermission({ name: 'posts:read', resource: 'posts', action: 'read' });
      const perm2 = await permissionService.createPermission({ name: 'posts:update', resource: 'posts', action: 'update' });

      // Asegurarse de que los permisos se crearon correctamente antes de usarlos
      expect(perm1.success).toBe(true);
      expect(perm2.success).toBe(true);

      const newPermissionIds = [perm1.permission!.id, perm2.permission!.id];

      await permissionService.assignPermissionToRole(roleId, permissionId); // Asignar permiso inicial
      
      // Reemplazar con los nuevos
      const result = await permissionService.replaceRolePermissions(roleId, newPermissionIds);
      expect(result.success).toBe(true);
      
      const rolePermissions = await permissionService.getRolePermissions(roleId);
      expect(rolePermissions).toHaveLength(2);
      expect(rolePermissions.some(p => p.name === 'posts:read')).toBe(true);
      expect(rolePermissions.some(p => p.name === 'posts:create')).toBe(false); // El permiso inicial ya no debe estar
    });
  });

  // --- Pruebas de Verificación de Permisos de Usuario ---
  describe('User Permission Checking', () => {
    // Nombres descriptivos para roles y permisos para facilitar la lectura de las pruebas
    const ROLE_NAME = 'test-editor';
    const PERMISSION_NAME = 'posts:edit';
    let roleId: string;

    beforeEach(async () => {
      // Configuración común: crear un rol, un permiso, asignarlos y dárselos al usuario de prueba
      const roleResult = await permissionService.createRole({ name: ROLE_NAME });
      roleId = roleResult.role!.id;

      const permResult = await permissionService.createPermission({ name: PERMISSION_NAME, resource: 'posts', action: 'edit' });
      
      await permissionService.assignPermissionToRole(roleId, permResult.permission!.id);
      await authService.assignRole(testUserId, ROLE_NAME);
    });

    test('should return true if user has the required permission', async () => {
      const hasPermission = await permissionService.userHasPermission(testUserId, PERMISSION_NAME);
      expect(hasPermission).toBe(true);
    });

    test('should return false if user does not have the permission', async () => {
      const hasPermission = await permissionService.userHasPermission(testUserId, 'posts:delete');
      expect(hasPermission).toBe(false);
    });

    test('should return true if user has the required role', async () => {
      const hasRole = await permissionService.userHasRole(testUserId, ROLE_NAME);
      expect(hasRole).toBe(true);
    });
    
    test('should return false if user does not have the role', async () => {
      const hasRole = await permissionService.userHasRole(testUserId, 'admin');
      expect(hasRole).toBe(false);
    });

    test('should get all permissions for a user', async () => {
      const userPermissions = await permissionService.getUserPermissions(testUserId);
      
      expect(userPermissions).toHaveLength(1);
      expect(userPermissions[0].name).toBe(PERMISSION_NAME);
    });

    // PRUEBA CORREGIDA: Esta prueba ahora verifica correctamente el estado "inactivo" de un rol.
    test('should not grant permission if the user\'s role is inactive', async () => {
      // 1. Verificar que el permiso existe
      let hasPermission = await permissionService.userHasPermission(testUserId, PERMISSION_NAME);
      expect(hasPermission).toBe(true);

      // 2. Desactivar el rol
      await permissionService.updateRole(roleId, { isActive: false });

      // 3. Verificar que el permiso ahora es denegado
      hasPermission = await permissionService.userHasPermission(testUserId, PERMISSION_NAME);
      expect(hasPermission).toBe(false);
    });

    test('should not grant permission if the user is inactive', async () => {
      // 1. Desactivar al usuario
      await authService.updateUser(testUserId, { isActive: false });
      
      // 2. Verificar que el permiso es denegado
      const hasPermission = await permissionService.userHasPermission(testUserId, PERMISSION_NAME);
      expect(hasPermission).toBe(false);
    });

    test('should correctly check resource and action access', async () => {
      const canAccess = await permissionService.userCanAccessResource(testUserId, 'posts', 'edit');
      expect(canAccess).toBe(true);

      const cannotAccess = await permissionService.userCanAccessResource(testUserId, 'posts', 'delete');
      expect(cannotAccess).toBe(false);
    });
  });
});