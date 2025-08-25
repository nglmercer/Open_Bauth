// src/db/connection.ts
import { Database } from "bun:sqlite";

/**
 * Instancia global de la base de datos SQLite
 */
let db: Database | null = null;

/**
 * Inicializa la conexión a la base de datos SQLite
 * @param dbPath Ruta al archivo de base de datos SQLite
 * @returns Instancia de la base de datos
 */
export function initDatabase(dbPath: string = "./auth.db"): Database {
  if (!db || isDatabaseClosed(db)) {
    try {
      // Close previous connection if it exists but is not properly closed
      if (db && !isDatabaseClosed(db)) {
        try {
          db.close();
        } catch (e) {
          // Ignore close errors on already closed database
        }
      }

      // Crear conexión a SQLite usando Bun Database
      db = new Database(dbPath);
      
      // Configure SQLite for better concurrency and performance
      db.exec("PRAGMA journal_mode = WAL;");
      db.exec("PRAGMA synchronous = NORMAL;");
      db.exec("PRAGMA cache_size = 1000;");
      db.exec("PRAGMA temp_store = memory;");
      db.exec("PRAGMA busy_timeout = 5000;");
      
      console.log(`✅ Base de datos SQLite inicializada: ${dbPath}`);
    } catch (error: any) {
      console.error(`❌ Error al inicializar la base de datos: ${error}`);
      throw new Error(`Failed to initialize database: ${error}`);
    }
  }
  return db;
}

/**
 * Verifica si la base de datos está cerrada
 * @param database - Instancia de la base de datos
 * @returns true si está cerrada
 */
function isDatabaseClosed(database: Database): boolean {
  try {
    // Try a simple operation to check if database is still open
    database.query("SELECT 1").get();
    return false;
  } catch (error: any) {
    // If error contains 'closed database' or similar, it's closed
    return error.message && (
      error.message.includes('closed database') ||
      error.message.includes('Database has closed') ||
      error.message.includes('database is closed')
    );
  }
}

/**
 * Obtiene la instancia actual de la base de datos
 * @returns Instancia de la base de datos
 * @throws Error si la base de datos no ha sido inicializada
 */
export function getDatabase(dbPath?: string): Database {
  if (!db || isDatabaseClosed(db)) {
    console.log("⚠️ Database not initialized or closed, auto-initializing...");
    initDatabase(dbPath);
  }
  
  // Double-check after initialization
  if (!db) {
    throw new Error("Failed to initialize database");
  }
  
  // Final verification that database is open
  if (isDatabaseClosed(db)) {
    throw new Error("Database is closed and could not be reopened");
  }
  
  return db;
}

export function forceReinitDatabase(dbPath?: string): Database {
  console.log("🔄 Force reinitializing database...");
  
  // Close existing connection if it exists
  if (db) {
    try {
      if (!isDatabaseClosed(db)) {
        db.close();
      }
    } catch (error) {
      // Ignore close errors
    }
  }
  
  db = null;
  
  // Reset transaction manager to use new database instance
  try {
    const { resetTransactionManager } = require('../database/transaction');
    resetTransactionManager();
  } catch (error) {
    // Ignore if transaction module is not available
  }
  
  initDatabase(dbPath);
  if (!db) {
    throw new Error("Failed to reinitialize database");
  }
  return db;
}

/**
 * Cierra la conexión a la base de datos
 */
export async function closeDatabase(): Promise<void> {
  if (db && !isDatabaseClosed(db)) {
    try {
      // First, cleanup any active transactions
      try {
        const { getTransactionManager } = require('../database/transaction');
        const manager = getTransactionManager();
        await manager.rollbackAll();
      } catch (error) {
        // Ignore if transaction module is not available
      }
      
      // Cerrar la conexión de la base de datos
      db.close();
      console.log("✅ Conexión a la base de datos cerrada");
    } catch (error: any) {
      console.error(`❌ Error al cerrar la base de datos: ${error}`);
      throw error;
    }
  }
  db = null;
}

/**
 * Verifica si la base de datos está inicializada
 * @returns true si la base de datos está inicializada
 */
export function isDatabaseInitialized(): boolean {
  return db !== null && !isDatabaseClosed(db);
}

/**
 * Ejecuta una consulta de prueba para verificar la conexión
 * @returns Promise que resuelve si la conexión es exitosa
 */
export async function testConnection(): Promise<boolean> {
  try {
    const database = getDatabase();
    database.query("SELECT 1 as test").get();
    console.log("✅ Conexión a la base de datos verificada");
    return true;
  } catch (error: any) {
    console.error(`❌ Error en la conexión a la base de datos: ${error}`);
    return false;
  }
}

/**
 * Habilita las claves foráneas en SQLite
 * Debe llamarse después de inicializar la base de datos
 */
export async function enableForeignKeys(): Promise<void> {
  try {
    const database = getDatabase();
    database.exec("PRAGMA foreign_keys = ON");
    console.log("✅ Claves foráneas habilitadas");
  } catch (error: any) {
    console.error(`❌ Error al habilitar claves foráneas: ${error}`);
    throw error;
  }
}

/**
 * Configura optimizaciones para SQLite
 */
export async function optimizeDatabase(): Promise<void> {
  try {
    const database = getDatabase();
    // Configuraciones de rendimiento para SQLite
    database.exec("PRAGMA journal_mode = WAL"); // Write-Ahead Logging para mejor concurrencia
    database.exec("PRAGMA synchronous = NORMAL"); // Balance entre seguridad y rendimiento
    database.exec("PRAGMA cache_size = 10000"); // Cache de 10MB aproximadamente
    database.exec("PRAGMA temp_store = memory"); // Usar memoria para tablas temporales
    database.exec("PRAGMA mmap_size = 268435456"); // 256MB de memory-mapped I/O
    
    console.log("✅ Optimizaciones de base de datos aplicadas");
  } catch (error: any) {
    console.error(`❌ Error al aplicar optimizaciones: ${error}`);
    throw error;
  }
}

/**
 * Obtiene información sobre la base de datos
 * @returns Información de la base de datos
 */
export async function getDatabaseInfo(): Promise<{
  version: string;
  pageSize: number;
  encoding: string;
  journalMode: string;
}> {
  try {
    const database = getDatabase();
    const versionResult = database.query("PRAGMA user_version").get() as { user_version: number } | undefined;
    const pageSizeResult = database.query("PRAGMA page_size").get() as { page_size: number } | undefined;
    const encodingResult = database.query("PRAGMA encoding").get() as { encoding: string } | undefined;
    const journalModeResult = database.query("PRAGMA journal_mode").get() as { journal_mode: string } | undefined;
    
    return {
      version: (versionResult?.user_version || 0).toString(),
      pageSize: pageSizeResult?.page_size || 0,
      encoding: encodingResult?.encoding || 'unknown',
      journalMode: journalModeResult?.journal_mode || 'unknown'
    };
  } catch (error: any) {
    console.error(`❌ Error al obtener información de la base de datos: ${error}`);
    throw error;
  }
}

/**
 * Ejecuta VACUUM para optimizar el archivo de base de datos
 */
export async function vacuumDatabase(): Promise<void> {
  try {
    const database = getDatabase();
    database.exec("VACUUM");
    console.log("✅ VACUUM ejecutado exitosamente");
  } catch (error: any) {
    console.error(`❌ Error al ejecutar VACUUM: ${error}`);
    throw error;
  }
}

/**
 * Verifica la integridad de la base de datos
 * @returns true si la base de datos está íntegra
 */
export async function checkIntegrity(): Promise<boolean> {
  try {
    const database = getDatabase();
    const result = database.query("PRAGMA integrity_check").all() as { integrity_check: string }[];
    const isOk = result.length === 1 && result[0].integrity_check === 'ok';
    
    if (isOk) {
      console.log("✅ Integridad de la base de datos verificada");
    } else {
      console.warn("⚠️ Problemas de integridad detectados:", result);
    }
    
    return isOk;
  } catch (error: any) {
    console.error(`❌ Error al verificar integridad: ${error}`);
    return false;
  }
}