/**
 * Integration tests for external schema registration with DatabaseInitializer
 * Run with: bun test tests/schema-extension.test.ts
 */

import { describe, test, expect } from 'bun:test';
import { Database } from 'bun:sqlite';
import { BaseController, type TableSchema } from '../src/database/base-controller';
import { DatabaseInitializer, SchemaRegistry } from '../src/database/database-initializer';

// Define example external schemas used across tests
const pointsSchema: TableSchema = {
  tableName: 'points',
  columns: [
    { name: 'id', type: 'TEXT', primaryKey: true, defaultValue: '(lower(hex(randomblob(16))))' },
    { name: 'user_id', type: 'TEXT', notNull: true, references: { table: 'users', column: 'id' } },
    { name: 'points', type: 'INTEGER', notNull: true, defaultValue: 0 },
    { name: 'reason', type: 'TEXT' },
    { name: 'created_at', type: 'DATETIME', defaultValue: 'CURRENT_TIMESTAMP' }
  ],
  indexes: [
    { name: 'idx_points_user_id', columns: ['user_id'] },
    { name: 'idx_points_created_at', columns: ['created_at'] }
  ]
};

const notificationsSchema: TableSchema = {
  tableName: 'notifications',
  columns: [
    { name: 'id', type: 'TEXT', primaryKey: true, defaultValue: '(lower(hex(randomblob(16))))' },
    { name: 'user_id', type: 'TEXT', notNull: true, references: { table: 'users', column: 'id' } },
    { name: 'title', type: 'TEXT', notNull: true },
    { name: 'body', type: 'TEXT' },
    { name: 'read', type: 'BOOLEAN', defaultValue: false },
    { name: 'created_at', type: 'DATETIME', defaultValue: 'CURRENT_TIMESTAMP' }
  ],
  indexes: [
    { name: 'idx_notifications_user_id', columns: ['user_id'] },
    { name: 'idx_notifications_read', columns: ['read'] }
  ]
};

const processesSchema: TableSchema = {
  tableName: 'processes',
  columns: [
    { name: 'id', type: 'TEXT', primaryKey: true, defaultValue: '(lower(hex(randomblob(16))))' },
    { name: 'name', type: 'TEXT', notNull: true, unique: true },
    { name: 'status', type: 'TEXT', notNull: true },
    { name: 'payload', type: 'TEXT' },
    { name: 'created_at', type: 'DATETIME', defaultValue: 'CURRENT_TIMESTAMP' },
    { name: 'updated_at', type: 'DATETIME', defaultValue: 'CURRENT_TIMESTAMP' }
  ],
  indexes: [
    { name: 'idx_processes_status', columns: ['status'] }
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

describe('Database schema extension integration', () => {
  test('initializes with externalSchemas in constructor and performs CRUD on external table', async () => {
    const db = new Database(':memory:');
    const initializer = new DatabaseInitializer({ database: db, externalSchemas: [pointsSchema] });

    const init = await initializer.initialize();
    expect(init.success).toBe(true);
    expect(init.tablesCreated).toContain('points');

    // Create a user (FK target) and then a points record
    const user = await createTestUser(initializer);

    const points = initializer.createController('points');
    const created = await points.create({ user_id: user.id, points: 50, reason: 'signup_bonus' });
    expect(created.success).toBe(true);

    // Query by user_id
    const list = await points.search({ user_id: user.id });
    expect(list.success).toBe(true);
    expect(list.data?.length).toBe(1);
    expect(list.data?.[0]).toMatchObject({ user_id: user.id, points: 50 });
  });

  test('registerSchemas() after construction adds external schema and allows operations', async () => {
    const db = new Database(':memory:');
    const initializer = new DatabaseInitializer({ database: db });

    // Register notifications externally and then initialize
    initializer.registerSchemas(notificationsSchema);
    const init = await initializer.initialize();
    expect(init.success).toBe(true);
    expect(init.tablesCreated).toContain('notifications');

    const user = await createTestUser(initializer);

    const notifications = initializer.createController('notifications');
    const created = await notifications.create({ user_id: user.id, title: 'Hello', body: 'World' });
    expect(created.success).toBe(true);

    const unread = await notifications.search({ user_id: user.id, read: false });
    expect(unread.success).toBe(true);
    expect(unread.data?.length).toBe(1);

    // Mark as read
    const updated = await notifications.update((created.data as any).id, { read: true });
    expect(updated.success).toBe(true);

    const readNow = await notifications.search({ user_id: user.id, read: true });
    expect(readNow.success).toBe(true);
    expect(readNow.data?.length).toBe(1);
  });

  test('SchemaRegistry merge + externalSchemas works with multiple external tables', async () => {
    const db = new Database(':memory:');

    const r1 = new SchemaRegistry([pointsSchema]);
    const r2 = new SchemaRegistry([processesSchema]);
    const merged = SchemaRegistry.merge(r1, r2);

    const initializer = new DatabaseInitializer({ database: db, externalSchemas: merged.getAll() });
    const init = await initializer.initialize();
    expect(init.success).toBe(true);
    expect(init.tablesCreated).toEqual(expect.arrayContaining(['points', 'processes']));

    // Create records in both external tables
    const user = await createTestUser(initializer);

    const points = initializer.createController('points');
    const p = await points.create({ user_id: user.id, points: 10, reason: 'test' });
    expect(p.success).toBe(true);

    const processes = initializer.createController('processes');
    const proc = await processes.create({ name: `proc_${Date.now()}`, status: 'queued' });
    expect(proc.success).toBe(true);

    const countPoints = await points.count();
    expect(countPoints.success).toBe(true);
    expect(countPoints.data).toBe(1);

    const countProcesses = await processes.count();
    expect(countProcesses.success).toBe(true);
    expect(countProcesses.data).toBe(1);
  });
});

  test('notifications.read filters accept Uint8Array/Buffer/boolean equivalents', async () => {
    const db = new Database(':memory:');
    const initializer = new DatabaseInitializer({ database: db });

    // Register notifications schema and initialize
    initializer.registerSchemas(notificationsSchema);
    const init = await initializer.initialize();
    expect(init.success).toBe(true);

    // Create a user and two notifications: one unread (default false) and one read using Uint8Array([1])
    const user = await createTestUser(initializer);
    const notifications = initializer.createController('notifications');

    const n1 = await notifications.create({ user_id: user.id, title: 'A', body: 'Unread default' });
    expect(n1.success).toBe(true);

    const n2 = await notifications.create({ user_id: user.id, title: 'B', body: 'Read via Uint8Array', read: new Uint8Array([1]) });
    expect(n2.success).toBe(true);

    // Search using Uint8Array([0]) should find the unread record
    const searchUnreadBytes = await notifications.search({ user_id: user.id, read: new Uint8Array([0]) });
    expect(searchUnreadBytes.success).toBe(true);
    expect(searchUnreadBytes.data?.length).toBeGreaterThanOrEqual(1);

    // Search using Uint8Array([1]) should find the read record
    const searchReadBytes = await notifications.search({ user_id: user.id, read: new Uint8Array([1]) });
    expect(searchReadBytes.success).toBe(true);
    expect(searchReadBytes.data?.length).toBeGreaterThanOrEqual(1);

    // Search using Buffer.from([1]) should also work
    const searchReadBuffer = await notifications.search({ user_id: user.id, read: Buffer.from([1]) });
    expect(searchReadBuffer.success).toBe(true);
    expect(searchReadBuffer.data?.length).toBeGreaterThanOrEqual(1);

    // Also verify boolean search works when stored as Uint8Array/Buffer
    const searchReadBool = await notifications.search({ user_id: user.id, read: true });
    expect(searchReadBool.success).toBe(true);
    expect(searchReadBool.data?.length).toBeGreaterThanOrEqual(1);

    const searchUnreadBool = await notifications.search({ user_id: user.id, read: false });
    expect(searchUnreadBool.success).toBe(true);
    expect(searchUnreadBool.data?.length).toBeGreaterThanOrEqual(1);

    // Update the unread record to read using Buffer.from([1]) and verify
    const updatedUnread = await notifications.update((n1.data as any).id, { read: Buffer.from([1]) });
    expect(updatedUnread.success).toBe(true);

    const readNowBytes = await notifications.search({ user_id: user.id, read: new Uint8Array([1]) });
    expect(readNowBytes.success).toBe(true);
    // After update, both records should be read
    expect(readNowBytes.data?.length).toBe(2);

    // And boolean search should return both as well
    const readNowBool = await notifications.search({ user_id: user.id, read: true });
    expect(readNowBool.success).toBe(true);
    expect(readNowBool.data?.length).toBe(2);
  });

  test('can search by IN with mixed boolean representations (boolean, Uint8Array, Buffer)', async () => {
    const db = new Database(':memory:');
    const initializer = new DatabaseInitializer({ database: db });

    initializer.registerSchemas(notificationsSchema);
    const init = await initializer.initialize();
    expect(init.success).toBe(true);

    const user = await createTestUser(initializer);
    const notifications = initializer.createController('notifications');

    const r1 = await notifications.create({ user_id: user.id, title: 'C', body: 'Unread default' });
    expect(r1.success).toBe(true);

    const r2 = await notifications.create({ user_id: user.id, title: 'D', body: 'Read via boolean', read: true });
    expect(r2.success).toBe(true);

    // Search using IN with [Uint8Array([0]), Buffer([1])] should return both records
    const mixedSearch = await notifications.search({ user_id: user.id, read: [new Uint8Array([0]), Buffer.from([1])] } as any);
    expect(mixedSearch.success).toBe(true);
    expect(mixedSearch.data?.length).toBe(2);
  });