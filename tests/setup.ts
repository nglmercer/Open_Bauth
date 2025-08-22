// tests/setup.ts
// Configuración global para tests con Bun

import { beforeAll, afterAll, beforeEach, afterEach, expect } from 'bun:test';
import { initDatabase, closeDatabase, getDatabase, isDatabaseInitialized } from '../src/db/connection';
import { runMigrations, resetDatabase } from '../src/db/migrations';
import { seedDatabase, cleanDatabase } from '../src/scripts/seed';
import { initJWTService } from '../src/services/jwt';

// Variables globales para tests
export const TEST_DB_PATH = './test.db';
export const TEST_JWT_SECRET = 'test-jwt-secret-key-for-testing-only';

// Configuración de entorno para tests
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = TEST_JWT_SECRET;
process.env.DATABASE_URL = TEST_DB_PATH;
process.env.BCRYPT_ROUNDS = '4'; // Menor para tests más rápidos

/**
 * Setup global antes de todos los tests
 */
beforeAll(async () => {
  console.log('🧪 Configurando entorno de tests...');
  
  try {
    // Inicializar base de datos en memoria
    initDatabase(TEST_DB_PATH);
    
    // Ejecutar migraciones
    await runMigrations();
    
    // Inicializar servicio JWT
    initJWTService(TEST_JWT_SECRET);
    
    console.log('✅ Entorno de tests configurado correctamente');
  } catch (error:any) {
    console.error('❌ Error configurando entorno de tests:', error);
    throw error;
  }
});

/**
 * Cleanup global después de todos los tests
 */
afterAll(async () => {
  console.log('🧹 Limpiando entorno de tests...');
  
  try {
    // No cerrar la base de datos aquí para evitar errores en tests posteriores
    // closeDatabase();
    console.log('✅ Entorno de tests limpiado correctamente');
  } catch (error:any) {
    console.error('❌ Error limpiando entorno de tests:', error);
  }
});

/**
 * Setup antes de cada test
 */
beforeEach(async () => {
  // Asegurar que la base de datos esté inicializada
  if (!isDatabaseInitialized()) {
    initDatabase(TEST_DB_PATH);
    await runMigrations();
  }
  
  // Limpiar datos antes de cada test
  await cleanDatabase();
});

/**
 * Cleanup después de cada test
 */
afterEach(async () => {
  // Opcional: limpiar datos después de cada test
  // await cleanDatabase();
});

/**
 * Utilidades para tests
 */
export const testUtils = {
  /**
   * Crear datos de prueba
   */
  async seedTestData() {
    await seedDatabase();
  },

  /**
   * Limpiar base de datos
   */
  async cleanTestData() {
    await cleanDatabase();
  },

  /**
   * Resetear base de datos completamente
   */
  async resetTestData() {
    await resetDatabase();
  },

  /**
   * Obtener instancia de base de datos para tests
   */
  getTestDatabase() {
    return getDatabase();
  },

  /**
   * Generar datos de usuario de prueba
   */
  generateTestUser(overrides = {}) {
    return {
      email: `test${Date.now()}@example.com`,
      password: 'TestPassword123!',
      firstName: 'Test',
      lastName: 'User',
      isActive: true,
      ...overrides
    };
  },

  /**
   * Generar datos de rol de prueba
   */
  generateTestRole(overrides = {}) {
    return {
      name: `test_role_${Date.now()}`,
      description: 'Test role for testing purposes',
      isActive: true,
      ...overrides
    };
  },

  /**
   * Generar datos de permiso de prueba
   */
  generateTestPermission(overrides = {}) {
    return {
      name: `test_permission_${Date.now()}`,
      description: 'Test permission for testing purposes',
      resource: 'test_resource',
      action: 'test_action',
      ...overrides
    };
  },

  /**
   * Esperar un tiempo determinado (para tests asíncronos)
   */
  async wait(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
  },

  /**
   * Generar JWT de prueba
   */
  async generateTestJWT(payload = {}) {
    try {
      const { JWTService } = require('../src/services/jwt');
      const jwtService = new JWTService(TEST_JWT_SECRET);
      
      // Create a proper User object for JWT generation
      const defaultUser = {
        id: 1,
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User',
        isActive: true,
        roles: [{ name: 'user' }],
        permissions: ['read'],
        createdAt: new Date(),
        updatedAt: new Date(),
        ...payload
      };
      
      return await jwtService.generateToken(defaultUser);
    } catch (error:any) {
      console.error('Error generating test JWT:', error);
      // Return a simple mock token for tests that don't need real JWT
      return 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSIsInJvbGVzIjpbInVzZXIiXSwiaWF0IjoxNjQwOTk1MjAwLCJleHAiOjE2NDA5OTg4MDB9.mock-signature';
    }
  },

  /**
   * Crear headers de autorización para tests
   */
  async createAuthHeaders(token?: string) {
    const authToken = token || await testUtils.generateTestJWT();
    return {
      'Authorization': `Bearer ${authToken}`,
      'Content-Type': 'application/json'
    };
  },

  /**
   * Validar estructura de respuesta de error
   */
  validateErrorResponse(response: any) {
    expect(response).toHaveProperty('success', false);
    expect(response).toHaveProperty('error');
    expect(response.error).toHaveProperty('type');
    expect(response.error).toHaveProperty('message');
  },

  /**
   * Validar estructura de respuesta exitosa
   */
  validateSuccessResponse(response: any) {
    expect(response).toHaveProperty('success', true);
    expect(response).toHaveProperty('data');
  },

  /**
   * Validar estructura de usuario
   */
  validateUserStructure(user: any) {
    expect(user).toHaveProperty('id');
    expect(user).toHaveProperty('email');
    expect(user).toHaveProperty('firstName');
    expect(user).toHaveProperty('lastName');
    expect(user).toHaveProperty('isActive');
    expect(user).toHaveProperty('createdAt');
    expect(user).toHaveProperty('updatedAt');
    // No debe incluir password
    expect(user).not.toHaveProperty('password');
  },

  /**
   * Validar estructura de rol
   */
  validateRoleStructure(role: any) {
    expect(role).toHaveProperty('id');
    expect(role).toHaveProperty('name');
    expect(role).toHaveProperty('description');
    expect(role).toHaveProperty('isActive');
    expect(role).toHaveProperty('createdAt');
    expect(role).toHaveProperty('updatedAt');
  },

  /**
   * Validar estructura de permiso
   */
  validatePermissionStructure(permission: any) {
    expect(permission).toHaveProperty('id');
    expect(permission).toHaveProperty('name');
    expect(permission).toHaveProperty('description');
    expect(permission).toHaveProperty('resource');
    expect(permission).toHaveProperty('action');
    expect(permission).toHaveProperty('createdAt');
    expect(permission).toHaveProperty('updatedAt');
  }
};

// Configuración de timeouts para tests
export const TEST_TIMEOUTS = {
  SHORT: 1000,    // 1 segundo
  MEDIUM: 5000,   // 5 segundos
  LONG: 10000,    // 10 segundos
  VERY_LONG: 30000 // 30 segundos
};

// Configuración de mocks
export const mockConfig = {
  // Mock para console.log en tests
  silentLogs: false,
  
  // Mock para Date.now() para tests determinísticos
  mockDate: false,
  fixedDate: new Date('2024-01-01T00:00:00.000Z')
};

// Aplicar mocks si están habilitados
if (mockConfig.silentLogs) {
  console = {
    ...console,
    log: () => {},
    info: () => {},
    warn: () => {},
    error: console.error // Mantener errores visibles
  };
}

if (mockConfig.mockDate) {
  Date.now = () => mockConfig.fixedDate.getTime();
}

console.log('🧪 Setup de tests cargado correctamente');