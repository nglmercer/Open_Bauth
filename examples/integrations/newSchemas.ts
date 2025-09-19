import { TableSchema,SchemaRegistry } from '../../dist/index';
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
const categoriesSchema: TableSchema = {
  tableName: 'categories',
  columns: [
    { name: 'id', type: 'TEXT', primaryKey: true, defaultValue: '(lower(hex(randomblob(16))))' },
    { name: 'name', type: 'TEXT', notNull: true, unique: true },
    { name: 'icon', type: 'TEXT' },
    { name: 'description', type: 'TEXT' },
    { name: 'is_active', type: 'BOOLEAN', defaultValue: true },
    { name: 'created_at', type: 'DATETIME', defaultValue: 'CURRENT_TIMESTAMP' },
    { name: 'updated_at', type: 'DATETIME', defaultValue: 'CURRENT_TIMESTAMP' }
  ],
  indexes: [
    { name: 'idx_categories_name', columns: ['name'] },
    { name: 'idx_categories_active', columns: ['is_active'] }
  ]
};

const productsSchema: TableSchema = {
  tableName: 'products',
  columns: [
    { name: 'id', type: 'TEXT', primaryKey: true, defaultValue: '(lower(hex(randomblob(16))))' },
    { name: 'name', type: 'TEXT', notNull: true },
    { name: 'description', type: 'TEXT' },
    { name: 'price', type: 'REAL', notNull: true },
    { name: 'category_id', type: 'TEXT', references: { table: 'categories', column: 'id' } },
    { name: 'image', type: 'TEXT' },
    { name: 'fallback', type: 'TEXT' },
    { name: 'is_available', type: 'BOOLEAN', defaultValue: true },
    { name: 'stock_quantity', type: 'INTEGER', defaultValue: 0 },
    { name: 'created_at', type: 'DATETIME', defaultValue: 'CURRENT_TIMESTAMP' },
    { name: 'updated_at', type: 'DATETIME', defaultValue: 'CURRENT_TIMESTAMP' }
  ],
  indexes: [
    { name: 'idx_products_category', columns: ['category_id'] },
    { name: 'idx_products_available', columns: ['is_available'] },
    { name: 'idx_products_name', columns: ['name'] }
  ]
};

const r2 = new SchemaRegistry([processesSchema]);
const r3 = new SchemaRegistry([notificationsSchema]);
const r4 = new SchemaRegistry([categoriesSchema]);
const r5 = new SchemaRegistry([productsSchema]);
const merged = SchemaRegistry.merge(r2, r3, r4, r5);
export { merged, processesSchema, notificationsSchema, categoriesSchema, productsSchema };
