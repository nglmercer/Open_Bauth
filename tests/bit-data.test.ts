/**
 * Streamlined integration tests focusing on BIT type support and essential functionality
 * Eliminates redundant tests while maintaining comprehensive coverage
 * Run with: bun test tests/bit-type-integration.test.ts
 */

import { describe, test, expect } from 'bun:test';
import { Database } from 'bun:sqlite';
import { BaseController, ControllerResponse, type TableSchema } from '../src/database/base-controller';
import { DatabaseInitializer, SchemaRegistry } from '../src/database/database-initializer';

// Schema with BIT type for testing SQL Server compatibility
const bitTestSchema: TableSchema = {
  tableName: 'bit_test',
  columns: [
    { name: 'id', type: 'TEXT', primaryKey: true, defaultValue: '(lower(hex(randomblob(16))))' },
    { name: 'name', type: 'TEXT', notNull: true },
    { name: 'is_active', type: 'BIT', defaultValue: false },
    { name: 'is_premium', type: 'BIT', notNull: true },
    { name: 'is_verified', type: 'BOOLEAN', defaultValue: false }, // Standard boolean for comparison
    { name: 'created_at', type: 'DATETIME', defaultValue: 'CURRENT_TIMESTAMP' }
  ]
};

const userNotificationSchema: TableSchema = {
  tableName: 'user_notifications',
  columns: [
    { name: 'id', type: 'TEXT', primaryKey: true, defaultValue: '(lower(hex(randomblob(16))))' },
    { name: 'user_id', type: 'TEXT', notNull: true, references: { table: 'users', column: 'id' } },
    { name: 'title', type: 'TEXT', notNull: true },
    { name: 'read', type: 'BIT', defaultValue: 0 }, // Using BIT with numeric default
    { name: 'priority', type: 'BIT' } // Nullable BIT field
  ]
};

async function createTestUser(initializer: DatabaseInitializer) {
  const users = initializer.createController('users');
  const res = await users.create({
    email: `user_${Date.now()}@example.com`,
    password_hash: 'hashed',
    first_name: 'T',
    last_name: 'U'
  });
  expect(res.success).toBe(true);
  return res.data as any;
}

describe('BIT Type Integration Tests', () => {
  test('initializes BIT schema and handles basic CRUD with different boolean representations', async () => {
    const db = new Database(':memory:');
    const initializer = new DatabaseInitializer({ 
      database: db, 
      externalSchemas: [bitTestSchema],
    });

    const init = await initializer.initialize();
    expect(init.success).toBe(true);
    expect(init.tablesCreated).toContain('bit_test');

    const bitController = initializer.createController('bit_test');

    // Test creation with various boolean representations
    const testCases = [
      { name: 'boolean_true', is_premium: true, is_active: false },
      { name: 'number_bits', is_premium: 1, is_active: 0 },
      { name: 'uint8_bits', is_premium: new Uint8Array([1]), is_active: new Uint8Array([0]) },
      { name: 'buffer_bits', is_premium: Buffer.from([1]), is_active: Buffer.from([0]) }
    ];

    const createdRecords: (Record<string, any>)[] = [];
    for (const testCase of testCases) {
      const result = await bitController.create(testCase);
      expect(result.success).toBe(true);
      if (result.data) {
        createdRecords.push(result.data);
      }
    }

    // Test search with boolean true - should find all records where is_premium is truthy (1)
    const searchTrue = await bitController.search({ is_premium: true });
    expect(searchTrue.success).toBe(true);
    expect(searchTrue.data?.length).toBe(4); // All records have is_premium as true/1
    
    // Test search with boolean false - should find records where is_active is falsy (0)
    const searchActiveFalse = await bitController.search({ is_active: false });
    expect(searchActiveFalse.success).toBe(true);
    expect(searchActiveFalse.data?.length).toBe(4); // All records have is_active as false/0

    // Test search with numeric values
    const searchPremiumOne = await bitController.search({ is_premium: 1 });
    expect(searchPremiumOne.success).toBe(true);
    expect(searchPremiumOne.data?.length).toBe(4); // Should match boolean true

    const searchActiveZero = await bitController.search({ is_active: 0 });
    expect(searchActiveZero.success).toBe(true);
    expect(searchActiveZero.data?.length).toBe(4); // Should match boolean false

    // Test with different binary representations
    const searchUint8True = await bitController.search({ is_premium: new Uint8Array([1]) });
    expect(searchUint8True.success).toBe(true);
    expect(searchUint8True.data?.length).toBe(4);

    const searchBufferFalse = await bitController.search({ is_active: Buffer.from([0]) });
    expect(searchBufferFalse.success).toBe(true);
    expect(searchBufferFalse.data?.length).toBe(4);
  });

  test('BIT fields work with IN queries using mixed representations', async () => {
    const db = new Database(':memory:');
    const initializer = new DatabaseInitializer({ 
      database: db, 
      externalSchemas: [userNotificationSchema],
    });

    const init = await initializer.initialize();
    expect(init.success).toBe(true);

    const user = await createTestUser(initializer);
    const notifications = initializer.createController('user_notifications');

    // Create notifications with different BIT representations
    await notifications.create({ user_id: user.id, title: 'N1', read: false, priority: 0 });
    await notifications.create({ user_id: user.id, title: 'N2', read: true, priority: 1 });
    await notifications.create({ user_id: user.id, title: 'N3', read: new Uint8Array([0]), priority: new Uint8Array([1]) });
    await notifications.create({ user_id: user.id, title: 'N4', read: Buffer.from([1]), priority: Buffer.from([0]) });

    // Test IN query with mixed boolean representations for true values
    const mixedInSearch = await notifications.search({ 
      user_id: user.id, 
      read: [true, new Uint8Array([1]), Buffer.from([1])] 
    });
    expect(mixedInSearch.success).toBe(true);
    expect(mixedInSearch.data?.length).toBe(2); // N2 and N4 (both have read=true in different formats)

    // Test IN query for false values
    const falseInSearch = await notifications.search({ 
      user_id: user.id, 
      read: [false, 0, new Uint8Array([0])] 
    });
    expect(falseInSearch.success).toBe(true);
    expect(falseInSearch.data?.length).toBe(2); // N1 and N3 (both have read=false in different formats)

    // Verify precision - no overlap between true and false results
    const totalCount = await notifications.count({ user_id: user.id });
    expect(totalCount.data).toBe(4);
    expect((mixedInSearch.data?.length ?? 0) + (falseInSearch.data?.length ?? 0)).toBe(4);
  });

  test('BIT fields handle edge cases correctly (multi-byte arrays, null values)', async () => {
    const db = new Database(':memory:');
    const initializer = new DatabaseInitializer({ 
      database: db, 
      externalSchemas: [bitTestSchema],
    });

    await initializer.initialize();
    const bitController = initializer.createController('bit_test');

    // Create record with multi-byte array (should NOT be treated as boolean)
    const multiByteResult = await bitController.create({
      name: 'multi_byte_test',
      is_premium: new Uint8Array([1, 0, 1]), // Multi-byte, should be treated as BLOB
      is_active: true // Regular boolean
    });
    expect(multiByteResult.success).toBe(true);

    // Create record with single-byte boolean-like values
    const singleByteResult = await bitController.create({
      name: 'single_byte_test',
      is_premium: new Uint8Array([1]), // Single byte, should be treated as boolean
      is_active: new Uint8Array([0])
    });
    expect(singleByteResult.success).toBe(true);

    // Search for boolean true should NOT match multi-byte array
    const booleanTrueSearch = await bitController.search({ is_premium: true });
    expect(booleanTrueSearch.success).toBe(true);
    expect(booleanTrueSearch.data?.length).toBe(1); // Only single_byte_test
    expect(booleanTrueSearch.data?.[0].name).toBe('single_byte_test');

    // Test search with exact multi-byte array should only match that record
    const multiBytePreciseSearch = await bitController.search({ 
      is_premium: new Uint8Array([1, 0, 1]) as any 
    });
    expect(multiBytePreciseSearch.success).toBe(true);
    expect(multiBytePreciseSearch.data?.length).toBe(1);
    expect(multiBytePreciseSearch.data?.[0].name).toBe('multi_byte_test');

    // Verify total records
    const totalRecords = await bitController.count();
    expect(totalRecords.data).toBe(2);
  });

  test('BIT type updates and queries maintain data integrity across different representations', async () => {
    const db = new Database(':memory:');
    const initializer = new DatabaseInitializer({ 
      database: db, 
      externalSchemas: [userNotificationSchema],
    });

    await initializer.initialize();
    const user = await createTestUser(initializer);
    const notifications = initializer.createController('user_notifications');

    // Create notification with BIT field as false
    const createResult = await notifications.create({
      user_id: user.id,
      title: 'Update Test',
      read: false,
      priority: 0
    });
    expect(createResult.success).toBe(true);
    const notificationId = (createResult.data as any).id;

    // Update using different boolean representations
    const updateWithBoolean = await notifications.update(notificationId, { read: true });
    expect(updateWithBoolean.success).toBe(true);

    // Verify the update worked with boolean search
    let searchResult = await notifications.search({ user_id: user.id, read: true });
    expect(searchResult.success).toBe(true);
    expect(searchResult.data?.length).toBe(1);

    // Update using Uint8Array
    const updateWithUint8 = await notifications.update(notificationId, { 
      read: new Uint8Array([0]),
      priority: new Uint8Array([1])
    });
    expect(updateWithUint8.success).toBe(true);

    // Verify updates with different search methods
    searchResult = await notifications.search({ user_id: user.id, read: false });
    expect(searchResult.data?.length).toBe(1);

    searchResult = await notifications.search({ user_id: user.id, read: new Uint8Array([0]) });
    expect(searchResult.data?.length).toBe(1);

    searchResult = await notifications.search({ user_id: user.id, priority: 1 });
    expect(searchResult.data?.length).toBe(1);

    // Final update using Buffer
    const updateWithBuffer = await notifications.update(notificationId, { 
      read: Buffer.from([1])
    });
    expect(updateWithBuffer.success).toBe(true);

    // Final verification
    searchResult = await notifications.search({ user_id: user.id, read: Buffer.from([1]) });
    expect(searchResult.data?.length).toBe(1);

    searchResult = await notifications.search({ user_id: user.id, read: true });
    expect(searchResult.data?.length).toBe(1);
  });

  test('BIT schema registration and multi-table operations work correctly', async () => {
    const db = new Database(':memory:');
    
    // Test schema registry with BIT types
    const registry = new SchemaRegistry([bitTestSchema, userNotificationSchema]);
    const initializer = new DatabaseInitializer({ 
      database: db, 
      externalSchemas: registry.getAll(),
    });

    const init = await initializer.initialize();
    expect(init.success).toBe(true);
    expect(init.tablesCreated).toEqual(expect.arrayContaining(['bit_test', 'user_notifications']));

    // Create test data in both tables
    const user = await createTestUser(initializer);
    
    const bitTest = initializer.createController('bit_test');
    const notifications = initializer.createController('user_notifications');

    const bitRecord = await bitTest.create({
      name: 'Test User Status',
      is_active: true,
      is_premium: new Uint8Array([1])
    });
    expect(bitRecord.success).toBe(true);

    const notification = await notifications.create({
      user_id: user.id,
      title: 'Premium Activated',
      read: false,
      priority: Buffer.from([1])
    });
    expect(notification.success).toBe(true);

    // Cross-table verification with BIT fields
    const activeBitRecords = await bitTest.search({ is_active: true });
    expect(activeBitRecords.data?.length).toBe(1);

    const highPriorityNotifications = await notifications.search({ 
      priority: new Uint8Array([1]) 
    });
    expect(highPriorityNotifications.data?.length).toBe(1);

    // Verify different boolean representations return same results
    const premiumBitRecords1 = await bitTest.search({ is_premium: 1 });
    const premiumBitRecords2 = await bitTest.search({ is_premium: true });
    const premiumBitRecords3 = await bitTest.search({ is_premium: new Uint8Array([1]) });
    
    expect(premiumBitRecords1.data?.length).toBe(1);
    expect(premiumBitRecords2.data?.length).toBe(1);
    expect(premiumBitRecords3.data?.length).toBe(1);
  });
  test('search correctly finds records using simple numeric values for BIT fields', async () => {
    const db = new Database(':memory:');
    const initializer = new DatabaseInitializer({ 
      database: db, 
      externalSchemas: [bitTestSchema],
    });

    await initializer.initialize();
    const bitController = initializer.createController('bit_test');

    // Crear dos registros, uno activo y otro inactivo
    await bitController.create({ name: 'Active Item', is_premium: true, is_active: 1 });
    await bitController.create({ name: 'Inactive Item', is_premium: false, is_active: 0 });
    await bitController.create({ name: 'Active Premium Item', is_premium: true, is_active: true });

    // CASO 1: Buscar por `is_active: 1` (como en tu ejemplo de `findRecommended`)
    const searchActiveNumeric = await bitController.search({ is_active: 1 });
    expect(searchActiveNumeric.success).toBe(true);
    expect(searchActiveNumeric.data?.length).toBe(2);
    // Verificamos que los nombres de los encontrados sean los correctos
    const activeNames = searchActiveNumeric.data?.map(item => item.name).sort();
    expect(activeNames).toEqual(['Active Item', 'Active Premium Item']);

    // CASO 2: Buscar por `is_active: 0`
    const searchInactiveNumeric = await bitController.search({ is_active: 0 });
    expect(searchInactiveNumeric.success).toBe(true);
    expect(searchInactiveNumeric.data?.length).toBe(1);
    expect(searchInactiveNumeric.data?.[0].name).toBe('Inactive Item');
    
    // CASO 3: Búsqueda combinada con booleano y número
    const searchCombined = await bitController.search({ is_active: true, is_premium: 1 });
    expect(searchCombined.success).toBe(true);
    expect(searchCombined.data?.length).toBe(2);
  });
});

describe('Performance and Compatibility Tests', () => {
  test('BIT field operations are performant with large datasets', async () => {
    const db = new Database(':memory:');
    const initializer = new DatabaseInitializer({ 
      database: db, 
      externalSchemas: [bitTestSchema],
    });

    await initializer.initialize();
    const bitController = initializer.createController('bit_test');

    // Create multiple records with different boolean representations
    const batchSize = 100;
    const createPromises: Promise<ControllerResponse<Record<string, any>>>[] = [];

    for (let i = 0; i < batchSize; i++) {
      const isActive = i % 2 === 0;
      const isPremium = i % 3 === 0;
      
      createPromises.push(bitController.create({
        name: `User ${i}`,
        is_active: isActive ? new Uint8Array([1]) : Buffer.from([0]),
        is_premium: isPremium ? 1 : false,
        is_verified: i % 4 === 0 // Regular boolean for comparison
      }));
    }

    const results = await Promise.all(createPromises);
    const successCount = results.filter(r => r.success).length;
    expect(successCount).toBe(batchSize);

    // Test bulk queries with different boolean representations
    const activeUsers = await bitController.search({ is_active: true });
    const premiumUsers = await bitController.search({ is_premium: new Uint8Array([1]) });
    const verifiedUsers = await bitController.search({ is_verified: true });

    expect(activeUsers.success).toBe(true);
    expect(premiumUsers.success).toBe(true);
    expect(verifiedUsers.success).toBe(true);

    // Verify counts match expected distribution
    expect(activeUsers.data?.length).toBe(50); // Half should be active
    expect(premiumUsers.data?.length).toBe(Math.ceil(batchSize / 3)); // Every 3rd should be premium
    expect(verifiedUsers.data?.length).toBe(25); // Every 4th should be verified

    // Test complex queries with multiple BIT conditions
    const complexQuery = await bitController.search({ 
      is_active: true, 
      is_premium: 1,
      is_verified: false
    } as any);
    expect(complexQuery.success).toBe(true);
  });
});
describe('Advanced BIT Field Filtering (isTruthy, isFalsy, isSet)', () => {
    
  test('correctly filters nullable BIT fields using advanced filters', async () => {
    const db = new Database(':memory:');
    // FIX: The initializer must be given the schema for the table being tested.
    // It was [bitTestSchema], but it needs [userNotificationSchema].
    const initializer = new DatabaseInitializer({ 
      database: db, 
      externalSchemas: [userNotificationSchema], 
    });

    await initializer.initialize();
    const user = await createTestUser(initializer);
    const notifications = initializer.createController('user_notifications');

    // Crear un conjunto de datos de prueba para cubrir todos los casos del campo nullable 'priority'
    // 1. priority = 1 (Truthy)
    await notifications.create({ user_id: user.id, title: 'High Priority', priority: 1 });
    // 2. priority = 0 (Falsy, but not NULL)
    await notifications.create({ user_id: user.id, title: 'Low Priority', priority: 0 });
    // 3. priority = NULL (Falsy, and NULL)
    await notifications.create({ user_id: user.id, title: 'No Priority', priority: null });
    // 4. Otro registro para asegurar que no se mezclen resultados
    await notifications.create({ user_id: user.id, title: 'Another High Priority', priority: true });

    // --- TEST 1: isTruthy ---
    // Debería encontrar solo los registros donde priority es 1 (no 0, no NULL)
    const truthyResult = await notifications.search({ priority: { isTruthy: true } });
    expect(truthyResult.success).toBe(true);
    expect(truthyResult.data?.length).toBe(2);
    const truthyTitles = truthyResult.data?.map(n => n.title).sort();
    expect(truthyTitles).toEqual(['Another High Priority', 'High Priority']);

    // --- TEST 2: isFalsy ---
    // Debería encontrar registros donde priority es 0 O es NULL
    const falsyResult = await notifications.search({ priority: { isFalsy: true } });
    expect(falsyResult.success).toBe(true);
    expect(falsyResult.data?.length).toBe(2);
    const falsyTitles = falsyResult.data?.map(n => n.title).sort();
    expect(falsyTitles).toEqual(['Low Priority', 'No Priority']);
    
    // --- TEST 3: isSet: true ---
    // Debería encontrar registros donde priority NO es NULL (o sea, 1 y 0)
    const isSetResult = await notifications.search({ priority: { isSet: true } });
    expect(isSetResult.success).toBe(true);
    expect(isSetResult.data?.length).toBe(3);
    const setTitles = isSetResult.data?.map(n => n.title).sort();
    expect(setTitles).toEqual(['Another High Priority', 'High Priority', 'Low Priority']);

    // --- TEST 4: isSet: false ---
    // Debería encontrar solo el registro donde priority ES NULL
    const isNotSetResult = await notifications.search({ priority: { isSet: false } });
    expect(isNotSetResult.success).toBe(true);
    expect(isNotSetResult.data?.length).toBe(1);
    expect(isNotSetResult.data?.[0].title).toBe('No Priority');

    // --- TEST 5: Combinación de filtros ---
    // Asegurarse de que el filtro avanzado funciona junto con otros filtros simples
    const anotherUser = await createTestUser(initializer);
    await notifications.create({ user_id: anotherUser.id, title: 'Other User - High Priority', priority: 1 });

    const combinedResult = await notifications.search({
      user_id: user.id, // Filtro simple
      priority: { isTruthy: true } // Filtro avanzado
    });
    expect(combinedResult.success).toBe(true);
    // Solo debería encontrar los 2 del primer usuario, no el del segundo
    expect(combinedResult.data?.length).toBe(2);
    expect(combinedResult.data?.every(n => n.user_id === user.id)).toBe(true);
  });
});