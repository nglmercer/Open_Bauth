// tests/scripts/dev.test.ts
import { describe, test, expect, beforeEach, afterEach, spyOn } from 'bun:test';
import { runDevCommand } from '../../src/scripts/dev';
import { PermissionService } from '../../src/services/permissions';
import { AuthService } from '../../src/services/auth';
import { testUtils } from '../setup';

describe('Dev CLI Commands', () => {
  let permissionService: PermissionService;
  let authService: AuthService;
  let consoleSpy: any;
  let consoleErrorSpy: any;

  beforeEach(async () => {
    permissionService = new PermissionService();
    authService = new AuthService();
    await testUtils.cleanTestData();
    
    // Espiar console.log y console.error
    consoleSpy = spyOn(console, 'log').mockImplementation(() => {});
    consoleErrorSpy = spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(async () => {
    await testUtils.cleanTestData();
    
    // Restaurar console
    consoleSpy.mockRestore();
    consoleErrorSpy.mockRestore();
  });

  describe('role:get command', () => {
    test('should display role information when role exists', async () => {
      // Crear un rol de prueba
      const roleData = testUtils.generateTestRole({
        name: 'test_role',
        description: 'Test role description'
      });
      
      const createdRole = await permissionService.createRole(roleData);
      expect(createdRole.success).toBe(true);
      expect(createdRole.role).toBeDefined();
      expect(createdRole.role!.name).toBe('test_role');
      
      // Crear un permiso y asignarlo al rol
      const permissionData = testUtils.generateTestPermission({
        name: 'test_resource:read',
        resource: 'test_resource',
        action: 'read'
      });
      
      const createdPermission = await permissionService.createPermission(permissionData);
      expect(createdPermission.success).toBe(true);
      expect(createdPermission.permission).toBeDefined();
      expect(createdPermission.permission!.name).toBe('test_resource:read');
      
      await permissionService.assignPermissionsToRole(
        createdRole.role!.id,
        [createdPermission.permission!.id]
      );
      
      // Ejecutar comando role:get
      await runDevCommand('role:get', 'test_role');
      
      // Verificar que se mostraron los datos correctos
      expect(consoleSpy).toHaveBeenCalledWith('🎭 Información del rol:');
      expect(consoleSpy).toHaveBeenCalledWith('  📋 Nombre: test_role');
      expect(consoleSpy).toHaveBeenCalledWith(`  🆔 ID: ${createdRole.role!.id}`);
      expect(consoleSpy).toHaveBeenCalledWith('  🔐 Permisos:');
      expect(consoleSpy).toHaveBeenCalledWith('    - test_resource:read (test_resource:read)');
    });

    test('should display error when role does not exist', async () => {
      // Ejecutar comando con rol inexistente
      await runDevCommand('role:get', 'non_existent_role');
      
      // Verificar que se mostró el error
      expect(consoleErrorSpy).toHaveBeenCalledWith('❌ Rol no encontrado: non_existent_role');
    });

    test('should display usage when no role name provided', async () => {
      // Ejecutar comando sin argumentos
      await runDevCommand('role:get');
      
      // Verificar que se mostró el uso correcto
      expect(consoleSpy).toHaveBeenCalledWith('Uso: role:get <name>');
    });

    test('should display role without permissions', async () => {
      // Crear un rol sin permisos
      const roleData = testUtils.generateTestRole({
        name: 'empty_role',
        description: 'Role without permissions'
      });
      
      const createdRole = await permissionService.createRole(roleData);
      expect(createdRole.success).toBe(true);
      expect(createdRole.role).toBeDefined();
      expect(createdRole.role!.name).toBe('empty_role');
      
      // Ejecutar comando role:get
      await runDevCommand('role:get', 'empty_role');
      
      // Verificar que se mostraron los datos correctos
      expect(consoleSpy).toHaveBeenCalledWith('🎭 Información del rol:');
      expect(consoleSpy).toHaveBeenCalledWith('  📋 Nombre: empty_role');
      expect(consoleSpy).toHaveBeenCalledWith(`  🆔 ID: ${createdRole.role!.id}`);
      expect(consoleSpy).toHaveBeenCalledWith('  🔐 Permisos: Sin permisos asignados');
    });

    test('should handle multiple permissions correctly', async () => {
      // Crear un rol
      const roleData = testUtils.generateTestRole({
        name: 'multi_perm_role',
        description: 'Role with multiple permissions'
      });
      
      const createdRole = await permissionService.createRole(roleData);
      expect(createdRole.success).toBe(true);
      expect(createdRole.role).toBeDefined();
      expect(createdRole.role!.name).toBe('multi_perm_role');
      
      // Crear múltiples permisos
      const permissions = [
        { name: 'read_permission', resource: 'posts', action: 'read' },
        { name: 'write_permission', resource: 'posts', action: 'write' },
        { name: 'delete_permission', resource: 'posts', action: 'delete' }
      ];
      
      const createdPermissions = [];
      for (const perm of permissions) {
        const permissionData = testUtils.generateTestPermission(perm);
        const createdPermission = await permissionService.createPermission(permissionData);
        expect(createdPermission.success).toBe(true);
        expect(createdPermission.permission).toBeDefined();
        expect(createdPermission.permission!.name).toBe(perm.name);
        createdPermissions.push(createdPermission.permission!);
      }
      
      // Assign all permissions to the role at once
      await permissionService.assignPermissionsToRole(
        createdRole.role!.id,
        createdPermissions.map(p => p.id)
      );
      
      // Ejecutar comando role:get
      await runDevCommand('role:get', 'multi_perm_role');
      
      // Verificar que se mostraron todos los permisos
      expect(consoleSpy).toHaveBeenCalledWith('🎭 Información del rol:');
      expect(consoleSpy).toHaveBeenCalledWith('  📋 Nombre: multi_perm_role');
      expect(consoleSpy).toHaveBeenCalledWith('  🔐 Permisos:');
      expect(consoleSpy).toHaveBeenCalledWith('    - read_permission (posts:read)');
      expect(consoleSpy).toHaveBeenCalledWith('    - write_permission (posts:write)');
      expect(consoleSpy).toHaveBeenCalledWith('    - delete_permission (posts:delete)');
    });

    test('should handle service errors gracefully', async () => {
      // Espiar el método findRoleByName para que lance un error
      const findRoleByNameSpy = spyOn(PermissionService.prototype, 'findRoleByName')
        .mockRejectedValue(new Error('Database connection error'));
      
      // Ejecutar comando
      await runDevCommand('role:get', 'test_role');
      
      // Verificar que se manejó el error
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('❌ Error obteniendo rol:')
      );
      
      // Restaurar el spy
      findRoleByNameSpy.mockRestore();
    });
  });

  describe('help command', () => {
    test('should include role:get in help output', async () => {
      // Ejecutar comando help
      await runDevCommand('help');
      
      // Verificar que role:get aparece en la ayuda
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('role:get')
      );
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Obtener rol por nombre')
      );
    });
  });
});