import { TableSchema,SchemaRegistry } from '../../dist/index';
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
const r1 = new SchemaRegistry([pointsSchema]);
const r2 = new SchemaRegistry([processesSchema]);
const r3 = new SchemaRegistry([notificationsSchema]);
const merged = SchemaRegistry.merge(r1, r2, r3);
export { merged, pointsSchema, processesSchema, notificationsSchema };
