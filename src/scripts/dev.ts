// src/scripts/dev.ts
import { seedDatabase, cleanDatabase, resetDatabase, checkDatabaseStatus } from './seed';
import { runMigrations, rollbackMigrations, getMigrationStatus,type Migration } from '../db/migrations';
import { getDatabase, initDatabase, closeDatabase } from '../db/connection';
import { AuthService } from '../services/auth';
import { PermissionService } from '../services/permissions';
import { JWTService } from '../services/jwt';

/**
 * Configuración de desarrollo
 */
const DEV_CONFIG = {
  jwtSecret: 'dev-secret-key-change-in-production',
  jwtExpiration: '1h',
  refreshTokenExpiration: '7d'
};

/**
 * Comandos disponibles para desarrollo
 */
const COMMANDS = {
  // Base de datos
  'db:init': 'Inicializar base de datos',
  'db:migrate': 'Ejecutar migraciones',
  'db:rollback': 'Revertir migraciones',
  'db:status': 'Estado de migraciones',
  'db:seed': 'Poblar con datos iniciales',
  'db:clean': 'Limpiar datos',
  'db:reset': 'Resetear completamente',
  'db:check': 'Verificar estado',
  
  // Usuarios
  'user:create': 'Crear usuario',
  'user:list': 'Listar usuarios',
  'user:roles': 'Asignar roles a usuario',
  'user:delete': 'Eliminar usuario',
  
  // Roles y permisos
  'role:create': 'Crear rol',
  'role:list': 'Listar roles',
  'role:get': 'Obtener rol por nombre',
  'permission:create': 'Crear permiso',
  'permission:list': 'Listar permisos',
  
  // JWT
  'jwt:generate': 'Generar token JWT',
  'jwt:verify': 'Verificar token JWT',
  
  // Utilidades
  'help': 'Mostrar ayuda',
  'test:auth': 'Probar autenticación',
  'test:permissions': 'Probar permisos'
};

/**
 * Función principal del CLI de desarrollo
 */
export async function runDevCommand(command: string, ...args: string[]): Promise<void> {
  try {
    console.log(`🚀 Ejecutando comando: ${command}`);
    
    switch (command) {
      // Comandos de base de datos
      case 'db:init':
        initDatabase();
        console.log('✅ Base de datos inicializada');
        break;
        
      case 'db:migrate':
        await runMigrations();
        console.log('✅ Migraciones ejecutadas');
        break;
        
      case 'db:rollback':
        const version = args[0] ? parseInt(args[0]) : 0;
        await rollbackMigrations(version);
        console.log('✅ Migraciones revertidas');
        break;
        
      case 'db:status':
        const data = await getMigrationStatus();
        console.log('📊 Estado de migraciones:');
        data.executedMigrations.forEach(migration => {
          const status = migration ? '✅' : '⏳';
          console.log(`  ${status} ${migration.version}: ${migration.name}`);
        });
        break;
        
      case 'db:seed':
        await seedDatabase();
        break;
        
      case 'db:clean':
        await cleanDatabase();
        break;
        
      case 'db:reset':
        await resetDatabase();
        break;
        
      case 'db:check':
        await checkDatabaseStatus();
        break;
        
      // Comandos de usuarios
      case 'user:create':
        await createUser(args);
        break;
        
      case 'user:list':
        await listUsers();
        break;
        
      case 'user:roles':
        await assignUserRoles(args);
        break;
        
      case 'user:delete':
        await deleteUser(args[0]);
        break;
        
      // Comandos de roles
      case 'role:create':
        await createRole(args);
        break;
        
      case 'role:list':
        await listRoles();
        break;
        
      case 'role:get':
        await getRoleByName(args);
        break;
        
      // Comandos de permisos
      case 'permission:create':
        await createPermission(args);
        break;
        
      case 'permission:list':
        await listPermissions();
        break;
        
      // Comandos JWT
      case 'jwt:generate':
        await generateJWT(args);
        break;
        
      case 'jwt:verify':
        await verifyJWT(args[0]);
        break;
        
      // Comandos de prueba
      case 'test:auth':
        await testAuthentication();
        break;
        
      case 'test:permissions':
        await testPermissions();
        break;
        
      case 'help':
      default:
        showHelp();
        break;
    }
    
  } catch (error:any) {
    console.error(`❌ Error ejecutando comando ${command}:`, error);
    process.exit(1);
  }
}

/**
 * Crear un nuevo usuario
 */
async function createUser(args: string[]): Promise<void> {
  if (args.length < 4) {
    console.log('Uso: user:create <email> <password> <firstName> <lastName> [roles...]');
    return;
  }
  
  const [email, password, firstName, lastName, ...roles] = args;
  
  const authService = new AuthService();
  const permissionService = new PermissionService();
  
  const result = await authService.register({
    email,
    password,
    firstName,
    lastName
  });
  
  if (!result  || !result.user) {
    console.error('❌ Error creando usuario:', result);
    return;
  }
  
  console.log(`✅ Usuario creado: ${email} (ID: ${result.user.id})`);
  
  // Asignar roles si se especificaron
  if (roles.length > 0) {
    for (const roleName of roles) {
      try {
        const roleResult = await permissionService.getRoleByName(roleName);
        if (roleResult.success && roleResult) {
          await permissionService.assignRoleToUser(result.user.id, roleResult.id);
          console.log(`  🎭 Rol asignado: ${roleName}`);
        }
      } catch (error:any) {
        console.log(`  ⚠️  No se pudo asignar rol: ${roleName}`);
      }
    }
  }
}

/**
 * Listar todos los usuarios
 */
async function listUsers(): Promise<void> {
  const db = getDatabase();
  
  const users = db.query(`
    SELECT 
      u.id,
      u.email,
      u.first_name,
      u.last_name,
      u.is_active,
      u.created_at,
      GROUP_CONCAT(r.name) as roles
    FROM users u
    LEFT JOIN user_roles ur ON u.id = ur.user_id
    LEFT JOIN roles r ON ur.role_id = r.id
    GROUP BY u.id
    ORDER BY u.created_at DESC
  `).all();
  
  if (users.length === 0) {
    console.log('📭 No hay usuarios registrados');
    return;
  }
  
  console.log('👥 Usuarios registrados:');
  users.forEach((user: any) => {
    const status = user.is_active ? '🟢' : '🔴';
    console.log(`  ${status} ${user.email} (${user.first_name} ${user.last_name})`);
    console.log(`    ID: ${user.id}`);
    console.log(`    Roles: ${user.roles || 'Sin roles'}`);
    console.log(`    Creado: ${new Date(user.created_at).toLocaleString()}`);
    console.log('');
  });
}

/**
 * Asignar roles a un usuario
 */
async function assignUserRoles(args: string[]): Promise<void> {
  if (args.length < 2) {
    console.log('Uso: user:roles <email> <role1> [role2] [role3]...');
    return;
  }
  
  const [email, ...roles] = args;
  
  const authService = new AuthService();
  const permissionService = new PermissionService();
  
  const user = await authService.findUserByEmail(email);
  if (!user) {
    console.error(`❌ Usuario no encontrado: ${email}`);
    return;
  }
  
  console.log(`👤 Asignando roles al usuario: ${email}`);
  
  for (const roleName of roles) {
    try {
      const roleResult = await permissionService.getRoleByName(roleName);
      if (roleResult.success && roleResult) {
        await permissionService.assignRoleToUser(user.id, roleResult.id);
        console.log(`  ✅ Rol asignado: ${roleName}`);
      } else {
        console.log(`  ❌ Rol no encontrado: ${roleName}`);
      }
    } catch (error:any) {
      console.log(`  ⚠️  Error asignando rol ${roleName}:`, error);
    }
  }
}

/**
 * Eliminar un usuario
 */
async function deleteUser(email: string): Promise<void> {
  if (!email) {
    console.log('Uso: user:delete <email>');
    return;
  }
  
  const authService = new AuthService();
  const user = await authService.findUserByEmail(email);
  
  if (!user) {
    console.error(`❌ Usuario no encontrado: ${email}`);
    return;
  }
  
  const db = getDatabase();
  
  // Eliminar relaciones primero
  db.run('DELETE FROM user_roles WHERE user_id = ?', [user.id]);
  db.run('DELETE FROM sessions WHERE user_id = ?', [user.id]);
  
  // Eliminar usuario
  db.run('DELETE FROM users WHERE id = ?', [user.id]);
  
  console.log(`✅ Usuario eliminado: ${email}`);
}

/**
 * Crear un nuevo rol
 */
async function createRole(args: string[]): Promise<void> {
  if (args.length < 2) {
    console.log('Uso: role:create <name> <description> [permission1] [permission2]...');
    return;
  }
  
  const [name, description, ...permissions] = args;
  
  const permissionService = new PermissionService();
  
  const result = await permissionService.createRole({ name, description });
  
  if (!result.success || !result) {
    console.error('❌ Error creando rol:', result.error);
    return;
  }  
  // Asignar permisos si se especificaron
  if (permissions.length > 0) {
    for (const permissionName of permissions) {
      try {
        const permResult = await permissionService.getPermissionByName(permissionName);
        if (permResult.success && permResult) {
          await permissionService.assignPermissionToRole(result.id, permResult.id);
          console.log(`  📋 Permiso asignado: ${permissionName}`);
        }
      } catch (error:any) {
        console.log(`  ⚠️  No se pudo asignar permiso: ${permissionName}`);
      }
    }
  }
}

/**
 * Obtener un rol por nombre
 */
async function getRoleByName(args: string[]): Promise<void> {
  if (args.length < 1) {
    console.log('Uso: role:get <name>');
    return;
  }
  
  const [name] = args;
  
  const permissionService = new PermissionService();
  
  try {
    const role = await permissionService.findRoleByName(name, true);
    
    if (!role) {
      console.error(`❌ Rol no encontrado: ${name}`);
      return;
    }
    
    console.log('🎭 Información del rol:');
    console.log(`  📋 Nombre: ${role.name}`);
    console.log(`  🆔 ID: ${role.id}`);
    console.log(`  📅 Creado: ${new Date(role.created_at).toLocaleString()}`);
    
    if (role.permissions && role.permissions.length > 0) {
      console.log('  🔐 Permisos:');
      role.permissions.forEach(permission => {
        console.log(`    - ${permission.name} (${permission.resource}:${permission.action})`);
      });
    } else {
      console.log('  🔐 Permisos: Sin permisos asignados');
    }
    
  } catch (error:any) {
    console.error(`❌ Error obteniendo rol: ${error}`);
  }
}

/**
 * Listar todos los roles
 */
async function listRoles(): Promise<void> {
  const db = getDatabase();
  
  const roles = db.query(`
    SELECT 
      r.id,
      r.name,
      r.description,
      r.created_at,
      GROUP_CONCAT(p.name) as permissions
    FROM roles r
    LEFT JOIN role_permissions rp ON r.id = rp.role_id
    LEFT JOIN permissions p ON rp.permission_id = p.id
    GROUP BY r.id
    ORDER BY r.name
  `).all();
  
  if (roles.length === 0) {
    console.log('📭 No hay roles registrados');
    return;
  }
  
  console.log('🎭 Roles registrados:');
  roles.forEach((role: any) => {
    console.log(`  📋 ${role.name}`);
    console.log(`    Descripción: ${role.description}`);
    console.log(`    Permisos: ${role.permissions || 'Sin permisos'}`);
    console.log(`    Creado: ${new Date(role.created_at).toLocaleString()}`);
    console.log('');
  });
}

/**
 * Crear un nuevo permiso
 */
async function createPermission(args: string[]): Promise<void> {
  if (args.length < 2) {
    console.log('Uso: permission:create <name> <description>');
    return;
  }
  
  const [name, description] = args;
  
  const permissionService = new PermissionService();
  
  const result = await permissionService.createPermission({ name, description });
  
  if (!result.success || !result) {
    console.error('❌ Error creando permiso:', result.error);
    return;
  }
  
}

/**
 * Listar todos los permisos
 */
async function listPermissions(): Promise<void> {
  const db = getDatabase();
  
  const permissions = db.query(`
    SELECT id, name, description, created_at
    FROM permissions
    ORDER BY name
  `).all();
  
  if (permissions.length === 0) {
    console.log('📭 No hay permisos registrados');
    return;
  }
  
  console.log('🔐 Permisos registrados:');
  permissions.forEach((permission: any) => {
    console.log(`  📝 ${permission.name}`);
    console.log(`    Descripción: ${permission.description}`);
    console.log(`    Creado: ${new Date(permission.created_at).toLocaleString()}`);
    console.log('');
  });
}

/**
 * Generar un token JWT
 */
async function generateJWT(args: string[]): Promise<void> {
  if (args.length < 1) {
    console.log('Uso: jwt:generate <email>');
    return;
  }
  
  const email = args[0];
  
  const authService = new AuthService();
  const user = await authService.findUserByEmail(email);
  
  if (!user) {
    console.error(`❌ Usuario no encontrado: ${email}`);
    return;
  }
  
  const jwtService = new JWTService(DEV_CONFIG.jwtSecret);
  
  const payload = {
    userId: user.id,
    email: user.email,
    roles: user.roles.map(r => r.name)
  };
  
  const token = jwtService.generateToken(payload, DEV_CONFIG.jwtExpiration);
  const refreshToken = jwtService.generateRefreshToken(user.id, DEV_CONFIG.refreshTokenExpiration);
  
  console.log('🎫 Tokens generados:');
  console.log(`Access Token: ${token}`);
  console.log(`Refresh Token: ${refreshToken}`);
  console.log(`\nPayload: ${JSON.stringify(payload, null, 2)}`);
}

/**
 * Verificar un token JWT
 */
async function verifyJWT(token: string): Promise<void> {
  if (!token) {
    console.log('Uso: jwt:verify <token>');
    return;
  }
  
  const jwtService = new JWTService(DEV_CONFIG.jwtSecret);
  
  try {
    const payload = jwtService.verifyToken(token);
    console.log('✅ Token válido');
    console.log(`Payload: ${JSON.stringify(payload, null, 2)}`);
  } catch (error:any) {
    console.error('❌ Token inválido:', error);
  }
}

/**
 * Probar el sistema de autenticación
 */
async function testAuthentication(): Promise<void> {
  console.log('🧪 Probando sistema de autenticación...');
  
  const authService = new AuthService();
  
  // Probar registro
  console.log('\n1. Probando registro...');
  const registerResult = await authService.register({
    email: 'test@example.com',
    password: 'Test123!',
    firstName: 'Test',
    lastName: 'User'
  });
  
  if (registerResult.success) {
    console.log('✅ Registro exitoso');
  } else {
    console.log('⚠️  Usuario ya existe o error en registro');
  }
  
  // Probar login
  console.log('\n2. Probando login...');
  const loginResult = await authService.login({
    email: 'test@example.com',
    password: 'Test123!'
  });
  
  if (loginResult.success && loginResult) {
    console.log('✅ Login exitoso');
    console.log(`Token: ${loginResult.accessToken.substring(0, 50)}...`);
  } else {
    console.log('❌ Error en login:', loginResult.error);
  }
  
  // Probar login con credenciales incorrectas
  console.log('\n3. Probando login con credenciales incorrectas...');
  const badLoginResult = await authService.login({
    email: 'test@example.com',
    password: 'WrongPassword'
  });
  
  if (!badLoginResult.success) {
    console.log('✅ Login rechazado correctamente');
  } else {
    console.log('❌ Error: login debería haber fallado');
  }
}

/**
 * Probar el sistema de permisos
 */
async function testPermissions(): Promise<void> {
  console.log('🧪 Probando sistema de permisos...');
  
  const permissionService = new PermissionService();
  
  // Crear permiso de prueba
  console.log('\n1. Creando permiso de prueba...');
  const permResult = await permissionService.createPermission({
    name: 'test.permission',
    description: 'Permiso de prueba'
  });
  
  if (permResult.success) {
    console.log('✅ Permiso creado');
  } else {
    console.log('⚠️  Permiso ya existe');
  }
  
  // Crear rol de prueba
  console.log('\n2. Creando rol de prueba...');
  const roleResult = await permissionService.createRole({
    name: 'test.role',
    description: 'Rol de prueba'
  });
  
  if (roleResult.success) {
    console.log('✅ Rol creado');
  } else {
    console.log('⚠️  Rol ya existe');
  }
  
  console.log('\n✅ Pruebas de permisos completadas');
}

/**
 * Mostrar ayuda
 */
function showHelp(): void {
  console.log('🛠️  CLI de Desarrollo - Auth Library');
  console.log('\nComandos disponibles:');
  
  Object.entries(COMMANDS).forEach(([command, description]) => {
    console.log(`  ${command.padEnd(20)} - ${description}`);
  });
  
  console.log('\nEjemplos:');
  console.log('  bun run src/scripts/dev.ts db:reset');
  console.log('  bun run src/scripts/dev.ts user:create admin@test.com Admin123! Admin User admin');
  console.log('  bun run src/scripts/dev.ts jwt:generate admin@test.com');
}

// Ejecutar comando si el script se ejecuta directamente
if (import.meta.main) {
  const command = process.argv[2] || 'help';
  const args = process.argv.slice(3);
  
  await runDevCommand(command, ...args);
  
  // Cerrar conexión a la base de datos
  closeDatabase();
  
  process.exit(0);
}