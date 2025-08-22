// tests/bun.config.ts
// Configuración específica de Bun para tests

import { beforeAll, afterAll, beforeEach, afterEach,test } from 'bun:test';
import { Database } from 'bun:sqlite';
import { unlink, mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';

// Configuración global de tests
export const testConfig = {
  // Base de datos de test
  testDbPath: process.env.TEST_DB_PATH || './tests/data/test.db',
  
  // JWT Secret para tests
  jwtSecret: process.env.JWT_SECRET || 'test-secret-key-for-development',
  
  // Timeouts
  defaultTimeout: 10000,
  longTimeout: 30000,
  
  // Configuración de performance
  performanceThresholds: {
    tokenGeneration: 100, // ms
    tokenVerification: 50, // ms
    passwordHashing: 1000, // ms
    databaseQuery: 200, // ms
  },
  
  // Configuración de concurrencia
  concurrency: {
    maxUsers: 100,
    maxConcurrentRequests: 50,
  },
  
  // Configuración de datos de test
  testData: {
    users: {
      admin: {
        email: 'admin@test.com',
        password: 'Admin123!',
        name: 'Test Admin'
      },
      user: {
        email: 'user@test.com',
        password: 'User123!',
        name: 'Test User'
      },
      moderator: {
        email: 'mod@test.com',
        password: 'Mod123!',
        name: 'Test Moderator'
      }
    },
    roles: {
      admin: 'admin',
      moderator: 'moderator',
      user: 'user'
    },
    permissions: {
      read: 'read',
      write: 'write',
      delete: 'delete',
      admin: 'admin'
    }
  }
};

// Utilidades específicas de Bun para tests
export class BunTestUtils {
  private static db: Database | null = null;
  
  /**
   * Inicializar base de datos de test con Bun SQLite
   */
  static async initTestDatabase(): Promise<Database> {
    try {
      // Crear directorio si no existe
      const dbDir = join(testConfig.testDbPath, '..');
      if (!existsSync(dbDir)) {
        await mkdir(dbDir, { recursive: true });
      }
      
      // Eliminar base de datos existente
      if (existsSync(testConfig.testDbPath)) {
        await unlink(testConfig.testDbPath);
      }
      
      // Crear nueva base de datos con Bun SQLite
      this.db = new Database(testConfig.testDbPath);
      
      // Configurar SQLite para tests
      this.db.exec('PRAGMA journal_mode = WAL');
      this.db.exec('PRAGMA synchronous = NORMAL');
      this.db.exec('PRAGMA cache_size = 2000');
      this.db.exec('PRAGMA temp_store = MEMORY');
      this.db.exec('PRAGMA busy_timeout = 5000');
      
      return this.db;
    } catch (error:any) {
      console.error('Error initializing test database:', error);
      throw error;
    }
  }
  
  /**
   * Obtener instancia de base de datos
   */
  static getDatabase(): Database {
    if (!this.db) {
      throw new Error('Test database not initialized');
    }
    return this.db;
  }
  
  /**
   * Limpiar base de datos de test
   */
  static async cleanDatabase(): Promise<void> {
    if (!this.db) return;
    
    try {
      // Obtener todas las tablas
      const tables = this.db.query(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
      ).all() as { name: string }[];
      
      // Limpiar cada tabla
      for (const table of tables) {
        this.db.exec(`DELETE FROM ${table.name}`);
      }
      
      // Resetear secuencias
      this.db.exec("DELETE FROM sqlite_sequence");
    } catch (error:any) {
      console.error('Error cleaning test database:', error);
      throw error;
    }
  }
  
  /**
   * Cerrar base de datos de test
   */
  static async closeDatabase(): Promise<void> {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
    
    // Eliminar archivo de base de datos
    try {
      if (existsSync(testConfig.testDbPath)) {
        await unlink(testConfig.testDbPath);
      }
    } catch (error:any) {
      console.warn('Warning: Could not delete test database file:', error);
    }
  }
  
  /**
   * Ejecutar migración específica
   */
  static async runMigration(migrationSql: string): Promise<void> {
    if (!this.db) {
      throw new Error('Test database not initialized');
    }
    
    try {
      this.db.exec(migrationSql);
    } catch (error:any) {
      console.error('Error running migration:', error);
      throw error;
    }
  }
  
  /**
   * Crear snapshot de base de datos para tests
   */
  static createSnapshot(): string {
    if (!this.db) {
      throw new Error('Test database not initialized');
    }
    
    try {
      const backup = this.db.serialize();
      return Buffer.from(backup).toString('base64');
    } catch (error:any) {
      console.error('Error creating database snapshot:', error);
      throw error;
    }
  }
  
  /**
   * Restaurar snapshot de base de datos
   */
  static restoreSnapshot(snapshot: string): void {
    if (!this.db) {
      throw new Error('Test database not initialized');
    }
    
    try {
      const backup = Buffer.from(snapshot, 'base64');
      this.db.close();
      this.db = new Database(':memory:');
      this.db.deserialize(backup);
    } catch (error:any) {
      console.error('Error restoring database snapshot:', error);
      throw error;
    }
  }
  
  /**
   * Medir tiempo de ejecución de función
   */
  static async measureTime<T>(fn: () => Promise<T> | T): Promise<{ result: T; time: number }> {
    const start = Bun.nanoseconds();
    const result = await fn();
    const end = Bun.nanoseconds();
    const time = (end - start) / 1_000_000; // Convertir a milisegundos
    
    return { result, time };
  }
  
  /**
   * Generar datos de test aleatorios
   */
  static generateRandomData() {
    return {
      email: `test-${Math.random().toString(36).substring(7)}@example.com`,
      password: `Pass${Math.random().toString(36).substring(7)}123!`,
      name: `Test User ${Math.random().toString(36).substring(7)}`,
      id: Math.floor(Math.random() * 1000000),
      timestamp: new Date().toISOString(),
      uuid: crypto.randomUUID(),
    };
  }
  
  /**
   * Crear múltiples usuarios de test
   */
  static async createTestUsers(count: number): Promise<any[]> {
    const users = [];
    
    for (let i = 0; i < count; i++) {
      const userData = this.generateRandomData();
      users.push(userData);
    }
    
    return users;
  }
  
  /**
   * Verificar memoria y performance
   */
  static getMemoryUsage() {
    if (typeof Bun !== 'undefined' && Bun.gc) {
      Bun.gc(true); // Forzar garbage collection
    }
    
    return {
      rss: process.memoryUsage().rss,
      heapUsed: process.memoryUsage().heapUsed,
      heapTotal: process.memoryUsage().heapTotal,
      external: process.memoryUsage().external,
    };
  }
  
  /**
   * Esperar condición con timeout
   */
  static async waitFor(
    condition: () => boolean | Promise<boolean>,
    timeout: number = 5000,
    interval: number = 100
  ): Promise<void> {
    const start = Date.now();
    
    while (Date.now() - start < timeout) {
      if (await condition()) {
        return;
      }
      await new Promise(resolve => setTimeout(resolve, interval));
    }
    
    throw new Error(`Condition not met within ${timeout}ms`);
  }
  
  /**
   * Crear mock de función con Bun
   */
  static createMock<T extends (...args: any[]) => any>(implementation?: T) {
    const mockFn = test.mock(implementation);
    
    // Agregar métodos adicionales específicos de Bun
    (mockFn as any).mockReturnValueOnce = (value: any) => {
      mockFn.mockImplementationOnce(() => value);
      return mockFn;
    };
    
    (mockFn as any).mockResolvedValueOnce = (value: any) => {
      mockFn.mockImplementationOnce(() => Promise.resolve(value));
      return mockFn;
    };
    
    (mockFn as any).mockRejectedValueOnce = (error: any) => {
      mockFn.mockImplementationOnce(() => Promise.reject(error));
      return mockFn;
    };
    
    return mockFn;
  }
  
  /**
   * Crear servidor de test temporal
   */
  static async createTestServer(port: number = 0): Promise<{ server: any; url: string; close: () => void }> {
    const server = Bun.serve({
      port,
      fetch(req) {
        return new Response('Test server', { status: 200 });
      },
    });
    
    const url = `http://localhost:${server.port}`;
    
    return {
      server,
      url,
      close: () => server.stop()
    };
  }
  
  /**
   * Validar estructura de respuesta JSON
   */
  static validateJsonStructure(obj: any, schema: any): boolean {
    try {
      for (const key in schema) {
        if (!(key in obj)) {
          return false;
        }
        
        const expectedType = schema[key];
        const actualType = typeof obj[key];
        
        if (expectedType === 'array' && !Array.isArray(obj[key])) {
          return false;
        } else if (expectedType !== 'array' && actualType !== expectedType) {
          return false;
        }
      }
      
      return true;
    } catch {
      return false;
    }
  }
}

// Configuración global de hooks para todos los tests
beforeAll(async () => {
  // Configurar variables de entorno
  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = testConfig.jwtSecret;
  process.env.TEST_DB_PATH = testConfig.testDbPath;
  
  // Inicializar base de datos de test
  // await BunTestUtils.initTestDatabase();
  
  console.log('🧪 Test environment initialized');
});

afterAll(async () => {
  // Limpiar y cerrar base de datos
  // await BunTestUtils.closeDatabase();
  
  console.log('🧹 Test environment cleaned up');
});

beforeEach(async () => {
  // Limpiar datos antes de cada test
  // await BunTestUtils.cleanDatabase();
});

afterEach(async () => {
  // Verificar memoria después de cada test
  const memUsage = BunTestUtils.getMemoryUsage();
  
  // Advertir si el uso de memoria es muy alto
  if (memUsage.heapUsed > 100 * 1024 * 1024) { // 100MB
    console.warn(`⚠️  High memory usage detected: ${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`);
  }
});

// Exportar configuración y utilidades
export { BunTestUtils as default };
export * from './setup';