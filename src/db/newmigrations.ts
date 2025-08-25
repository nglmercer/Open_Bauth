// src/db/migrations.ts
import { getDatabase } from './connection';
import type { Database } from 'bun:sqlite';
import { defaultLogger as logger } from '../logger';

/**
 * Inicializa la base de datos con todas las tablas necesarias
 * Esta función verifica y crea todas las tablas si no existen
 */
export async function initializeDatabase(): Promise<void> {
  logger.info('🔄 Inicializando base de datos...');
  
  const db = getDatabase();
  
  try {
    db.exec("BEGIN TRANSACTION");
    
    // Crear tabla users
    db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        first_name TEXT,
        last_name TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login_at DATETIME,
        is_active BOOLEAN DEFAULT 1
      )
    `);
    
    // Crear tabla roles
    db.exec(`
      CREATE TABLE IF NOT EXISTS roles (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        name TEXT UNIQUE NOT NULL,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1
      )
    `);
    
    // Crear tabla permissions
    db.exec(`
      CREATE TABLE IF NOT EXISTS permissions (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        name TEXT UNIQUE NOT NULL,
        resource TEXT NOT NULL,
        action TEXT NOT NULL,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Crear tabla user_roles
    db.exec(`
      CREATE TABLE IF NOT EXISTS user_roles (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        user_id TEXT NOT NULL,
        role_id TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
        UNIQUE(user_id, role_id)
      )
    `);
    
    // Crear tabla role_permissions
    db.exec(`
      CREATE TABLE IF NOT EXISTS role_permissions (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        role_id TEXT NOT NULL,
        permission_id TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
        FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
        UNIQUE(role_id, permission_id)
      )
    `);
    
    // Crear tabla sessions
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
    
    // Crear índices para optimizar consultas
    createIndexes(db);
    
    db.exec("COMMIT");
    logger.info('✅ Base de datos inicializada correctamente');
    
  } catch (error: any) {
    db.exec("ROLLBACK");
    console.error('❌ Error al inicializar la base de datos:', error);
    throw error;
  }
}

/**
 * Crea todos los índices necesarios para optimizar las consultas
 */
function createIndexes(db: Database): void {
  // Índices para users
  db.exec("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)");
  db.exec("CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active)");
  
  // Índices para roles
  db.exec("CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name)");
  
  // Índices para permissions
  db.exec("CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name)");
  db.exec("CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource)");
  db.exec("CREATE INDEX IF NOT EXISTS idx_permissions_action ON permissions(action)");
  
  // Índices para user_roles
  db.exec("CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id)");
  db.exec("CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id)");
  
  // Índices para role_permissions
  db.exec("CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id)");
  db.exec("CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id)");
  
  // Índices para sessions
  db.exec("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)");
  db.exec("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)");
  db.exec("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)");
  db.exec("CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(is_active)");
}

/**
 * Verifica si todas las tablas necesarias existen
 */
export async function checkDatabaseIntegrity(): Promise<boolean> {
  const db = getDatabase();
  
  const requiredTables = ['users', 'roles', 'permissions', 'user_roles', 'role_permissions', 'sessions'];
  
  try {
    for (const table of requiredTables) {
      const result = db.query(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
      ).get(table);
      
      if (!result) {
        logger.warn(`⚠️ Tabla faltante: ${table}`);
        return false;
      }
    }
    
    logger.info('✅ Integridad de la base de datos verificada');
    return true;
  } catch (error: any) {
    logger.error('❌ Error al verificar la integridad de la base de datos:', error);
    return false;
  }
}
export async function runMigrations() {
    return await checkDatabaseIntegrity().then(async (isIntact) => {
        if (!isIntact) {
            return await initializeDatabase();
        }
        return true;
    }).catch((error) => {
        logger.error('❌ Error al verificar la integridad de la base de datos:', error);
        return false;
    })
}
/**
 * Repara la base de datos creando las tablas faltantes
 */
export async function repairDatabase(): Promise<void> {
  logger.info('🔧 Reparando base de datos...');
  
  const isIntact = await checkDatabaseIntegrity();
  
  if (!isIntact) {
    await initializeDatabase();
    logger.info('✅ Base de datos reparada');
  } else {
    logger.info('✅ La base de datos no necesita reparación');
  }
}

/**
 * Resetea completamente la base de datos eliminando todas las tablas
 */
export async function resetDatabase(): Promise<void> {
  logger.info('🔄 Reseteando base de datos...');
  
  const db = getDatabase();
  
  try {
    db.exec("BEGIN TRANSACTION");
    
    // Eliminar todas las tablas
    db.exec("DROP TABLE IF EXISTS sessions");
    db.exec("DROP TABLE IF EXISTS role_permissions");
    db.exec("DROP TABLE IF EXISTS user_roles");
    db.exec("DROP TABLE IF EXISTS permissions");
    db.exec("DROP TABLE IF EXISTS roles");
    db.exec("DROP TABLE IF EXISTS users");
    
    db.exec("COMMIT");
    logger.info('✅ Base de datos reseteada');
    
    // Inicializar nuevamente
    await initializeDatabase();
    
  } catch (error: any) {
    db.exec("ROLLBACK");
    console.error('❌ Error al resetear la base de datos:', error);
    throw error;
  }
}