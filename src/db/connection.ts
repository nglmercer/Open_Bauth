// src/db/connection.ts
import { Database } from "bun:sqlite";

/**
 * Instancia global de la base de datos SQLite
 */
let db: Database;

/**
 * Inicializa la conexión a la base de datos SQLite
 * @param dbPath Ruta al archivo de base de datos SQLite
 * @returns Instancia de la base de datos
 */
export function initDatabase(dbPath: string = "./auth.db"): Database {
  if (!db) {
    try {
      // Crear conexión a SQLite usando Bun Database
      db = new Database(dbPath);
      console.log(`✅ Base de datos SQLite inicializada: ${dbPath}`);
    } catch (error:any) {
      console.error(`❌ Error al inicializar la base de datos: ${error}`);
      throw new Error(`Failed to initialize database: ${error}`);
    }
  }
  return db;
}

/**
 * Obtiene la instancia actual de la base de datos
 * @returns Instancia de la base de datos
 * @throws Error si la base de datos no ha sido inicializada
 */
export function getDatabase(): Database {
  if (!db) {
    console.log("⚠️ Database not initialized, auto-initializing with test.db");
    initDatabase('./test.db');
  }
  
  return db;
}

export function forceReinitDatabase(): Database {
  console.log("🔄 Force reinitializing database...");
  db = null;
  initDatabase('./test.db');
  return db;
}

/**
 * Cierra la conexión a la base de datos
 */
export async function closeDatabase(): Promise<void> {
  if (db) {
    try {
      // Cerrar la conexión de la base de datos
      db.close();
      db = null as any;
      console.log("✅ Conexión a la base de datos cerrada");
    } catch (error:any) {
      console.error(`❌ Error al cerrar la base de datos: ${error}`);
      throw error;
    }
  }
}

/**
 * Verifica si la base de datos está inicializada
 * @returns true si la base de datos está inicializada
 */
export function isDatabaseInitialized(): boolean {
  return db !== undefined && db !== null;
}

/**
 * Ejecuta una consulta de prueba para verificar la conexión
 * @returns Promise que resuelve si la conexión es exitosa
 */
export async function testConnection(): Promise<boolean> {
  try {
    const db = getDatabase();
    db.query("SELECT 1 as test").get();
    console.log("✅ Conexión a la base de datos verificada");
    return true;
  } catch (error:any) {
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
    const db = getDatabase();
    db.exec("PRAGMA foreign_keys = ON");
    console.log("✅ Claves foráneas habilitadas");
  } catch (error:any) {
    console.error(`❌ Error al habilitar claves foráneas: ${error}`);
    throw error;
  }
}

/**
 * Configura optimizaciones para SQLite
 */
export async function optimizeDatabase(): Promise<void> {
  try {
    const db = getDatabase();
    
    // Configuraciones de rendimiento para SQLite
    db.exec("PRAGMA journal_mode = WAL"); // Write-Ahead Logging para mejor concurrencia
    db.exec("PRAGMA synchronous = NORMAL"); // Balance entre seguridad y rendimiento
    db.exec("PRAGMA cache_size = 10000"); // Cache de 10MB aproximadamente
    db.exec("PRAGMA temp_store = memory"); // Usar memoria para tablas temporales
    db.exec("PRAGMA mmap_size = 268435456"); // 256MB de memory-mapped I/O
    
    console.log("✅ Optimizaciones de base de datos aplicadas");
  } catch (error:any) {
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
    const db = getDatabase();
    
    const versionResult = db.query("PRAGMA user_version").get() as { user_version: number } | undefined;
    const pageSizeResult = db.query("PRAGMA page_size").get() as { page_size: number } | undefined;
    const encodingResult = db.query("PRAGMA encoding").get() as { encoding: string } | undefined;
    const journalModeResult = db.query("PRAGMA journal_mode").get() as { journal_mode: string } | undefined;
    
    return {
      version: (versionResult?.user_version || 0).toString(),
      pageSize: pageSizeResult?.page_size || 0,
      encoding: encodingResult?.encoding || 'unknown',
      journalMode: journalModeResult?.journal_mode || 'unknown'
    };
  } catch (error:any) {
    console.error(`❌ Error al obtener información de la base de datos: ${error}`);
    throw error;
  }
}

/**
 * Ejecuta VACUUM para optimizar el archivo de base de datos
 */
export async function vacuumDatabase(): Promise<void> {
  try {
    const db = getDatabase();
    db.exec("VACUUM");
    console.log("✅ VACUUM ejecutado exitosamente");
  } catch (error:any) {
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
    const db = getDatabase();
    const result = db.query("PRAGMA integrity_check").all() as { integrity_check: string }[];
    const isOk = result.length === 1 && result[0].integrity_check === 'ok';
    
    if (isOk) {
      console.log("✅ Integridad de la base de datos verificada");
    } else {
      console.warn("⚠️ Problemas de integridad detectados:", result);
    }
    
    return isOk;
  } catch (error:any) {
    console.error(`❌ Error al verificar integridad: ${error}`);
    return false;
  }
}