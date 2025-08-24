// src/scripts/seed.ts
// Example usage:
// const customUsers = generateInitialUsers({
//   includeAdmin: true,
//   includeUser: false,
//   customUsers: [
//     {
//       email: 'custom@example.com',
//       password: 'Custom123!',
//       firstName: 'Custom',
//       lastName: 'User',
//       roles: ['editor']
//     }
//   ]
// });

import { getDatabase, isDatabaseInitialized, initDatabase, forceReinitDatabase } from '../db/connection';
import { runMigrations } from '../db/migrations';
import { AuthService } from '../services/auth';
import { PermissionService } from '../services/permissions';
import type { CreatePermissionData, CreateRoleData } from '../types/auth';

/**
 * Datos iniciales para permisos
 */
const initialPermissions: CreatePermissionData[] = [
  // Permisos de usuarios
  { name: 'users.read', resource: 'users', action: 'read' },
  { name: 'users.create', resource: 'users', action: 'create' },
  { name: 'users.update', resource: 'users', action: 'update' },
  { name: 'users.delete', resource: 'users', action: 'delete' },
  { name: 'users.manage', resource: 'users', action: 'manage' },
  
  // Permisos de roles
  { name: 'roles.read', resource: 'roles', action: 'read' },
  { name: 'roles.create', resource: 'roles', action: 'create' },
  { name: 'roles.update', resource: 'roles', action: 'update' },
  { name: 'roles.delete', resource: 'roles', action: 'delete' },
  { name: 'roles.manage', resource: 'roles', action: 'manage' },
  
  // Permisos de permisos
  { name: 'permissions.read', resource: 'permissions', action: 'read' },
  { name: 'permissions.create', resource: 'permissions', action: 'create' },
  { name: 'permissions.update', resource: 'permissions', action: 'update' },
  { name: 'permissions.delete', resource: 'permissions', action: 'delete' },
  { name: 'permissions.manage', resource: 'permissions', action: 'manage' },
  
  // Permisos de contenido
  { name: 'content.read', resource: 'content', action: 'read' },
  { name: 'content.create', resource: 'content', action: 'create' },
  { name: 'content.update', resource: 'content', action: 'update' },
  { name: 'content.delete', resource: 'content', action: 'delete' },
  { name: 'content.publish', resource: 'content', action: 'publish' },
  { name: 'content.moderate', resource: 'content', action: 'moderate' },
  
  // Permisos de sistema
  { name: 'system.admin', resource: 'system', action: 'admin' },
  { name: 'system.settings', resource: 'system', action: 'settings' },
  { name: 'system.logs', resource: 'system', action: 'logs' },
  { name: 'system.backup', resource: 'system', action: 'backup' },
  { name: 'system.maintenance', resource: 'system', action: 'maintenance' },
  
  // Permisos de reportes
  { name: 'reports.view', resource: 'reports', action: 'view' },
  { name: 'reports.create', resource: 'reports', action: 'create' },
  { name: 'reports.export', resource: 'reports', action: 'export' },
  
  // Permisos de API
  { name: 'api.read', resource: 'api', action: 'read' },
  { name: 'api.write', resource: 'api', action: 'write' },
  { name: 'api.admin', resource: 'api', action: 'admin' }
];

/**
 * Datos iniciales para roles
 */
const initialRoles: CreateRoleData[] = [
  {
    name: 'admin',
    description: 'Administrador del sistema con acceso completo',
    permissions: [
      'users.manage', 'roles.manage', 'permissions.manage',
      'content.read', 'content.create', 'content.update', 'content.delete', 'content.publish', 'content.moderate',
      'system.admin', 'system.settings', 'system.logs', 'system.backup', 'system.maintenance',
      'reports.view', 'reports.create', 'reports.export',
      'api.admin'
    ]
  },
  {
    name: 'moderator',
    description: 'Moderador con permisos de gestión de contenido',
    permissions: [
      'users.read', 'users.update',
      'content.read', 'content.create', 'content.update', 'content.delete', 'content.moderate',
      'reports.view',
      'api.read', 'api.write'
    ]
  },
  {
    name: 'editor',
    description: 'Editor con permisos de creación y edición de contenido',
    permissions: [
      'content.read', 'content.create', 'content.update', 'content.publish',
      'api.read', 'api.write'
    ]
  },
  {
    name: 'author',
    description: 'Autor con permisos básicos de creación de contenido',
    permissions: [
      'content.read', 'content.create', 'content.update',
      'api.read'
    ]
  },
  {
    name: 'user',
    description: 'Usuario básico con permisos de lectura',
    permissions: [
      'content.read',
      'api.read'
    ]
  },
  {
    name: 'guest',
    description: 'Invitado con acceso muy limitado',
    permissions: [
      'content.read'
    ]
  }
];

/**
 * Configuración de seeding personalizable
 */
interface SeedConfig {
  createTestUsers: boolean;
  createDemoContent: boolean;
  userCount: number;
  skipExistingUsers: boolean;
  defaultPassword: string;
}

const seedConfig: SeedConfig = {
  createTestUsers: process.env.NODE_ENV === 'development',
  createDemoContent: true,
  userCount: process.env.SEED_USER_COUNT ? parseInt(process.env.SEED_USER_COUNT) : 15,
  skipExistingUsers: true,
  defaultPassword: process.env.DEFAULT_SEED_PASSWORD || 'DevPassword123!'
};

/**
 * Generate initial users with customizable options
 */
function generateInitialUsers(options: {
  includeAdmin?: boolean;
  includeModerator?: boolean;
  includeEditor?: boolean;
  includeAuthor?: boolean;
  includeUser?: boolean;
  includeGuest?: boolean;
  customUsers?: Array<{
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    roles: string[];
  }>;
} = {}) {
  const {
    includeAdmin = true,
    includeModerator = true,
    includeEditor = true,
    includeAuthor = true,
    includeUser = true,
    includeGuest = true,
    customUsers = []
  } = options;

  const users = [];

  if (includeAdmin) {
    users.push({
      email: 'admin@blogapi.com',
      password: 'Admin123!@#',
      firstName: 'Admin',
      lastName: 'User',
      roles: ['admin']
    });
  }

  if (includeModerator) {
    users.push({
      email: 'moderator@blogapi.com',
      password: 'Moderator123!',
      firstName: 'Moderator',
      lastName: 'User',
      roles: ['moderator']
    });
  }

  if (includeEditor) {
    users.push({
      email: 'editor@blogapi.com',
      password: 'Editor123!',
      firstName: 'Editor',
      lastName: 'User',
      roles: ['editor']
    });
  }

  if (includeAuthor) {
    users.push({
      email: 'author@blogapi.com',
      password: 'Author123!',
      firstName: 'Author',
      lastName: 'User',
      roles: ['author']
    });
  }

  if (includeUser) {
    users.push({
      email: 'user@blogapi.com',
      password: 'User123!',
      firstName: 'Regular',
      lastName: 'User',
      roles: ['user']
    });
  }

  if (includeGuest) {
    users.push({
      email: 'guest@blogapi.com',
      password: 'Guest123!',
      firstName: 'Guest',
      lastName: 'User',
      roles: ['guest']
    });
  }

  // Add custom users
  users.push(...customUsers);

  return users;
}

/**
 * Default initial users
 */
const initialUsers = generateInitialUsers();

/**
 * Genera usuarios adicionales para testing
 */
function generateTestUsers(count: number): typeof initialUsers {
  const testUsers = [];
  const firstNames = ['Alice', 'Bob', 'Charlie', 'Diana', 'Eve', 'Frank', 'Grace', 'Henry', 'Ivy', 'Jack'];
  const lastNames = ['Adams', 'Baker', 'Clark', 'Davis', 'Evans', 'Fisher', 'Green', 'Harris', 'Jones', 'King'];
  const roles = ['user', 'author', 'editor'];
  
  for (let i = 0; i < count; i++) {
    const firstName = firstNames[i % firstNames.length];
    const lastName = lastNames[Math.floor(i / firstNames.length) % lastNames.length];
    const role = roles[i % roles.length];
    
    testUsers.push({
      email: `test.user${i + 1}@blogapi.com`,
      password: seedConfig.defaultPassword,
      firstName,
      lastName,
      roles: [role]
    });
  }
  
  return testUsers;
}

/**
 * Obtiene la lista completa de usuarios según la configuración
 */
function getAllUsers(): typeof initialUsers {
  let allUsers = [...initialUsers];
  
  if (seedConfig.createTestUsers && process.env.NODE_ENV === 'development') {
    const testUsers = generateTestUsers(seedConfig.userCount - initialUsers.length);
    allUsers = [...allUsers, ...testUsers];
  }
  
  return allUsers;
}

/**
 * Función principal de seeding
 */
export async function seedDatabase(dbPath?: string,
  allUsers = getAllUsers()
): Promise<void> {
  try {
    console.log('🌱 Starting database seeding...');
    
    // Initialize database and run migrations
    initDatabase(dbPath);
    await runMigrations();
    
    const permissionService = new PermissionService();
    const authService = new AuthService();
    
    // Create permissions
    const createdPermissions = new Map<string, string>();
    for (const permission of initialPermissions) {
      try {
        const result = await permissionService.createPermission(permission);
        if (result && result.role) {
          createdPermissions.set(permission.name, result.role.id);
        }
      } catch (error:any) {
        // Permission already exists
      }
    }
    
    // Create roles
    const createdRoles = new Map<string, string>();
    for (const role of initialRoles) {
      try {
        const result = await permissionService.createRole({
          name: role.name,
          description: role.description
        });
        
        if (result && result.role) {
          createdRoles.set(role.name, result.role?.id);
          
          // Assign permissions to role
          for (const permissionName of role.permissions || []) {
            const permissionId = createdPermissions.get(permissionName);
            if (permissionId) {
              await permissionService.assignPermissionsToRole(result.role?.id, [permissionId]);
            }
          }
        }
      } catch (error:any) {
        // Role already exists
      }
    }
        
    // Create users
    let createdCount = 0;
    let skippedCount = 0;
    
    for (const user of allUsers) {
      try {
        const result = await authService.register({
          email: user.email,
          password: user.password,
        });
        
        if (result) {
          createdCount++;
          
          // Assign roles to user
          for (const roleName of user.roles) {
            if (result.user) {
              await authService.assignRole(result.user.id, roleName);
            }
          }
        }
      } catch (error:any) {
        if (seedConfig.skipExistingUsers) {
          skippedCount++;
        }
      }
    }
    
    console.log('✨ Seeding completed successfully!');
    console.log(`📊 Summary: ${createdCount} users created, ${skippedCount} skipped`);
    
  } catch (error:any) {
    console.error('❌ Error during seeding:', error);
    if (process.env.NODE_ENV !== 'test') {
      throw error;
    }
  }
}

/**
 * Función para limpiar la base de datos
 */
export async function cleanDatabase(dbPath?: string): Promise<void> {
  console.log('🧹 Cleaning database...');
  
  try {
    // Check if database is initialized
    if (!isDatabaseInitialized()) {
      initDatabase(dbPath);
    }
    
    let db = getDatabase();

    // Temporarily disable foreign keys
    try {
        db.exec('PRAGMA foreign_keys = OFF');
    } catch (error:any) {
        if (error instanceof Error && (error.message.includes('Database has closed') || error.message.includes('Cannot use a closed database'))) {
            db = forceReinitDatabase();
            db.exec('PRAGMA foreign_keys = OFF');
        } else {
            throw error;
        }
    }
    
    // Clean tables in correct order (respecting foreign keys)
    const tables = [
      'user_roles',
      'role_permissions', 
      'sessions',
      'users',
      'roles',
      'permissions'
    ];
    
    for (const table of tables) {
      try {
        db.exec(`DELETE FROM ${table}`);
      } catch (error:any) {
        // Table cleanup error
      }
    }
    
    // Re-enable foreign keys
    db.exec('PRAGMA foreign_keys = ON');
    
    console.log('✅ Database cleaned successfully');
    
  } catch (error:any) {
    console.error('❌ Error during cleanup:', error);
    if (process.env.NODE_ENV !== 'test') {
      throw error;
    }
  }
}

/**
 * Function to completely reset the database
 */
export async function resetDatabase(): Promise<void> {
  try {
    console.log('🔄 Resetting database...');
    
    await cleanDatabase();
    await seedDatabase();
    
    console.log('✨ Database reset successfully!');
    
  } catch (error:any) {
    console.error('❌ Error during reset:', error);
    throw error;
  }
}

/**
 * Función para verificar el estado de la base de datos
 */
export async function checkDatabaseStatus(): Promise<void> {
  try {
    console.log('🔍 Verificando estado de la base de datos...');
    
    const db = getDatabase();
    
    // Contar registros en cada tabla
    const tables = ['users', 'roles', 'permissions', 'user_roles', 'role_permissions', 'sessions'];
    
    console.log('\n📊 Estado actual:');
    for (const table of tables) {
      try {
        const result = db.query(`SELECT COUNT(*) as count FROM ${table}`).get() as { count: number };
        console.log(`  ${table}: ${result.count} registros`);
      } catch (error:any) {
        console.log(`  ${table}: Tabla no existe`);
      }
    }
    
    // Verificar usuarios con roles
    try {
      const usersWithRoles = db.query(`
        SELECT u.email, GROUP_CONCAT(r.name) as roles
        FROM users u
        LEFT JOIN user_roles ur ON u.id = ur.user_id
        LEFT JOIN roles r ON ur.role_id = r.id
        GROUP BY u.id, u.email
        ORDER BY u.email
      `).all();
      
      if (usersWithRoles.length > 0) {
        console.log('\n👥 Usuarios y sus roles:');
        usersWithRoles.forEach((user: any) => {
          console.log(`  ${user.email}: ${user.roles || 'Sin roles'}`);
        });
      }
    } catch (error:any) {
      console.log('  ⚠️  No se pudieron obtener usuarios con roles');
    }
    
  } catch (error:any) {
    console.error('❌ Error verificando estado:', error);
    throw error;
  }
}

/**
 * Función para crear solo usuarios de prueba
 */
export async function seedTestUsersOnly(count?: number): Promise<void> {
  try {
    console.log('🧪 Creando solo usuarios de prueba...');
    
    const userCount = count || 10;
    const testUsers = generateTestUsers(userCount);
    
    initDatabase();
    await runMigrations();
    
    const authService = new AuthService();
    
    let createdCount = 0;
    for (const user of testUsers) {
      try {
        const result = await authService.register({
          email: user.email,
          password: user.password,
        });
        
        if (result && result.user) {
          createdCount++;
          console.log(`  ✅ Usuario de prueba creado: ${user.email}`);
          
          // Asignar roles
          for (const roleName of user.roles) {
            await authService.assignRole(result.user.id, roleName);
          }
        }
      } catch (error: any) {
        console.log(`  ⚠️  Usuario ya existe: ${user.email}`);
      }
    }
    
    console.log(`\n✨ ${createdCount} usuarios de prueba creados exitosamente!`);
    
  } catch (error: any) {
    console.error('❌ Error creando usuarios de prueba:', error);
    throw error;
  }
}

// Ejecutar seeding si el script se ejecuta directamente
export async function mainSeed() {
  const command = process.argv[2];
  const param = process.argv[3];
  
  switch (command) {
    case 'seed':
      await seedDatabase();
      break;
    case 'clean':
      await cleanDatabase();
      break;
    case 'reset':
      await resetDatabase();
      break;
    case 'status':
      await checkDatabaseStatus();
      break;
    case 'test-users':
      const count = param ? parseInt(param) : undefined;
      await seedTestUsersOnly(count);
      break;
    default:
      console.log('Uso: bun run src/scripts/seed.ts [comando] [parámetros]');
      console.log('\nComandos disponibles:');
      console.log('  seed        - Poblar base de datos con datos iniciales');
      console.log('  clean       - Limpiar todos los datos');
      console.log('  reset       - Limpiar y volver a poblar');
      console.log('  status      - Verificar estado actual');
      console.log('  config      - Mostrar configuración actual');
      console.log('  test-users  - Crear solo usuarios de prueba [cantidad]');
      console.log('\nEjemplos:');
      console.log('  bun run src/scripts/seed.ts seed');
      console.log('  bun run src/scripts/seed.ts test-users 20');
      console.log('  NODE_ENV=development SEED_USER_COUNT=25 bun run src/scripts/seed.ts seed');
      console.log('  DEFAULT_SEED_PASSWORD="MyCustomPass123!" bun run src/scripts/seed.ts test-users 5');
  }
}

// Check if this script is being run directly
if (process.argv[1] && process.argv[1].endsWith('seed.ts') && process.env.NODE_ENV !== 'test') {
  mainSeed().catch(console.error);
}