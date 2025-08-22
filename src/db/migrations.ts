// src/db/migrations.ts
import { getDatabase } from './connection';
import type { Database } from 'bun:sqlite';

/**
 * Interface para definir una migración
 */
export interface Migration {
  version: number;
  name: string;
  up: (db: Database) => Promise<void>;
  down: (db: Database) => Promise<void>;
}

/**
 * Lista de todas las migraciones en orden
 */
const migrations: Migration[] = [
  {
    version: 1,
    name: 'create_users_table',
    up: async (db: Database) => {
      db.exec(`
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          is_active BOOLEAN DEFAULT 1
        )
      `);
      
      // Índices para optimizar consultas
      db.exec("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)");
      db.exec("CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active)");
      
      console.log('✅ Tabla users creada');
    },
    down: async (db: Database) => {
      db.exec("DROP TABLE IF EXISTS users");
      console.log('✅ Tabla users eliminada');
    }
  },
  
  {
    version: 2,
    name: 'create_roles_table',
    up: async (db: Database) => {
      db.exec(`
        CREATE TABLE IF NOT EXISTS roles (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          name TEXT UNIQUE NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);
      
      db.exec("CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name)");
      
      console.log('✅ Tabla roles creada');
    },
    down: async (db: Database) => {
      db.exec("DROP TABLE IF EXISTS roles");
      console.log('✅ Tabla roles eliminada');
    }
  },
  
  {
    version: 3,
    name: 'create_permissions_table',
    up: async (db: Database) => {
      db.exec(`
        CREATE TABLE IF NOT EXISTS permissions (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          name TEXT UNIQUE NOT NULL,
          resource TEXT NOT NULL,
          action TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);
      
      db.exec("CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name)");
      db.exec("CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource)");
      db.exec("CREATE INDEX IF NOT EXISTS idx_permissions_action ON permissions(action)");
      
      console.log('✅ Tabla permissions creada');
    },
    down: async (db: Database) => {
      db.exec("DROP TABLE IF EXISTS permissions");
      console.log('✅ Tabla permissions eliminada');
    }
  },
  
  {
    version: 4,
    name: 'create_user_roles_table',
    up: async (db: Database) => {
      db.exec(`
        CREATE TABLE IF NOT EXISTS user_roles (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          user_id TEXT NOT NULL,
          role_id TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
          UNIQUE(user_id, role_id)
        )
      `);
      
      db.exec("CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id)");
      db.exec("CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id)");
      
      console.log('✅ Tabla user_roles creada');
    },
    down: async (db: Database) => {
      db.exec("DROP TABLE IF EXISTS user_roles");
      console.log('✅ Tabla user_roles eliminada');
    }
  },
  
  {
    version: 5,
    name: 'create_role_permissions_table',
    up: async (db: Database) => {
      db.exec(`
        CREATE TABLE IF NOT EXISTS role_permissions (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          role_id TEXT NOT NULL,
          permission_id TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
          FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
          UNIQUE(role_id, permission_id)
        )
      `);
      
      db.exec("CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id)");
      db.exec("CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id)");
      
      console.log('✅ Tabla role_permissions creada');
    },
    down: async (db: Database) => {
      db.exec("DROP TABLE IF EXISTS role_permissions");
      console.log('✅ Tabla role_permissions eliminada');
    }
  },
  
  {
    version: 6,
    name: 'create_sessions_table',
    up: async (db: Database) => {
      db.exec(`
        CREATE TABLE IF NOT EXISTS sessions (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          user_id TEXT NOT NULL,
          token TEXT UNIQUE NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          expires_at DATETIME NOT NULL,
          last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
          ip_address TEXT,
          user_agent TEXT,
          is_active BOOLEAN DEFAULT 1,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);
      
      db.exec("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)");
      db.exec("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)");
      db.exec("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)");
      db.exec("CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(is_active)");
      
      console.log('✅ Tabla sessions creada');
    },
    down: async (db: Database) => {
      db.exec("DROP TABLE IF EXISTS sessions");
      console.log('✅ Tabla sessions eliminada');
    }
  },
  
  {
    version: 7,
    name: 'create_migration_history_table',
    up: async (db: Database) => {
      db.exec(`
        CREATE TABLE IF NOT EXISTS migration_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          version INTEGER UNIQUE NOT NULL,
          name TEXT NOT NULL,
          executed_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);
      
      console.log('✅ Tabla migration_history creada');
    },
    down: async (db: Database) => {
      db.exec("DROP TABLE IF EXISTS migration_history");
      console.log('✅ Tabla migration_history eliminada');
    }
  }
];

/**
 * Obtiene la versión actual de la base de datos
 */
async function getCurrentVersion(): Promise<number> {
  try {
    const db = getDatabase();
    const result = db.query(
      "SELECT MAX(version) as version FROM migration_history"
    ).get() as { version: number } | undefined;
    return result?.version || 0;
  } catch (error:any) {
    // Si la tabla no existe, estamos en versión 0
    return 0;
  }
}

/**
 * Registra una migración ejecutada
 */
async function recordMigration(version: number, name: string): Promise<void> {
  const db = getDatabase();
  db.query(
    "INSERT INTO migration_history (version, name) VALUES (?, ?)"
  ).run(version, name);
}

/**
 * Ejecuta todas las migraciones pendientes
 */
export async function runMigrations(): Promise<void> {
  console.log('🔄 Iniciando migraciones...');
  
  const db = getDatabase();
  
  // Crear tabla migration_history si no existe
  db.exec(`
    CREATE TABLE IF NOT EXISTS migration_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      version INTEGER UNIQUE NOT NULL,
      name TEXT NOT NULL,
      executed_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  const currentVersion = await getCurrentVersion();
  
  console.log(`📊 Versión actual de la base de datos: ${currentVersion}`);
  
  // Filtrar migraciones pendientes
  const pendingMigrations = migrations.filter(m => m.version > currentVersion);
  
  if (pendingMigrations.length === 0) {
    console.log('✅ No hay migraciones pendientes');
    return;
  }
  
  console.log(`📋 ${pendingMigrations.length} migraciones pendientes`);
  
  // Ejecutar migraciones en transacción
  try {
    db.exec("BEGIN TRANSACTION");
    
    for (const migration of pendingMigrations) {
      console.log(`⚡ Ejecutando migración ${migration.version}: ${migration.name}`);
      
      await migration.up(db);
      
      // Solo registrar la migración si no es la de migration_history
      if (migration.name !== 'create_migration_history_table') {
        await recordMigration(migration.version, migration.name);
      }
      
      console.log(`✅ Migración ${migration.version} completada`);
    }
    
    db.exec("COMMIT");
    console.log('🎉 Todas las migraciones completadas exitosamente');
    
  } catch (error:any) {
    db.exec("ROLLBACK");
    console.error('❌ Error durante las migraciones:', error);
    throw error;
  }
}

/**
 * Revierte migraciones hasta una versión específica
 */
export async function rollbackMigrations(targetVersion: number): Promise<void> {
  console.log(`🔄 Revirtiendo migraciones hasta la versión ${targetVersion}...`);
  
  const db = getDatabase();
  const currentVersion = await getCurrentVersion();
  
  if (targetVersion >= currentVersion) {
    console.log('✅ No hay migraciones para revertir');
    return;
  }
  
  // Filtrar migraciones a revertir (en orden descendente)
  const migrationsToRollback = migrations
    .filter(m => m.version > targetVersion && m.version <= currentVersion)
    .sort((a, b) => b.version - a.version);
  
  console.log(`📋 ${migrationsToRollback.length} migraciones a revertir`);
  
  try {
    db.exec("BEGIN TRANSACTION");
    
    for (const migration of migrationsToRollback) {
      console.log(`⚡ Revirtiendo migración ${migration.version}: ${migration.name}`);
      
      await migration.down(db);
      db.query("DELETE FROM migration_history WHERE version = ?").run(migration.version);
      
      console.log(`✅ Migración ${migration.version} revertida`);
    }
    
    db.exec("COMMIT");
    console.log('🎉 Rollback completado exitosamente');
    
  } catch (error:any) {
    db.exec("ROLLBACK");
    console.error('❌ Error durante el rollback:', error);
    throw error;
  }
}

/**
 * Obtiene el estado de las migraciones
 */
export async function getMigrationStatus(): Promise<{
  currentVersion: number;
  availableVersion: number;
  pendingMigrations: number;
  executedMigrations: Migration[];
}> {
  const currentVersion = await getCurrentVersion();
  const availableVersion = Math.max(...migrations.map(m => m.version));
  const pendingMigrations = migrations.filter(m => m.version > currentVersion).length;
  const executedMigrations = migrations.filter(m => m.version <= currentVersion);
  
  return {
    currentVersion,
    availableVersion,
    pendingMigrations,
    executedMigrations
  };
}

/**
 * Resetea completamente la base de datos
 */
export async function resetDatabase(): Promise<void> {
  console.log('🔄 Reseteando base de datos...');
  
  const db = getDatabase();
  
  try {
    db.exec("BEGIN TRANSACTION");
    
    // Revertir todas las migraciones
    const allMigrations = [...migrations].reverse();
    for (const migration of allMigrations) {
      try {
        await migration.down(db);
      } catch (error:any) {
        // Ignorar errores si la tabla no existe
        console.warn(`⚠️ Error al revertir ${migration.name}:`, error);
      }
    }
    
    // Limpiar historial de migraciones
    db.exec("DROP TABLE IF EXISTS migration_history");
    
    db.exec("COMMIT");
    console.log('✅ Base de datos reseteada');
    
    // Ejecutar migraciones nuevamente
    await runMigrations();
    
  } catch (error:any) {
    db.exec("ROLLBACK");
    console.error('❌ Error al resetear la base de datos:', error);
    throw error;
  }
}