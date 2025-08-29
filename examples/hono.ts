// dist/index.ts (FINAL VERSION)

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { Database } from 'bun:sqlite';

// Core Application Imports
import { DatabaseInitializer } from '../dist/index';
import { JWTService } from '../dist/index';
import { AuthService } from '../dist/index';
import { PermissionService,TableSchema } from '../dist/index';
import { AppContext, AppDependencies, Services } from './app';
import { createMiddlewareFactory } from './middleware/factory';

// Router Imports
import { createPublicRoutes } from './routers/public.routes';
import { createProtectedRoutes } from './routers/protected.routes';
import { createModeratorRoutes } from './routers/moderator.routes';
import { createAdminRoutes } from './routers/admin.routes';

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
// --- 1. Service Initialization ---
console.log('🚀 Initializing application...');
const db = new Database('auth.db');
const dbInitializer = new DatabaseInitializer({ database: db,externalSchemas: [pointsSchema] });
await dbInitializer.initialize();
await dbInitializer.seedDefaults();

const jwtService = new JWTService(process.env.JWT_SECRET || 'a-very-secret-key-for-hono');
const authService = new AuthService(dbInitializer, jwtService);
const permissionService = new PermissionService(dbInitializer);

// Create the services container
const services: Services = { jwtService, authService, permissionService };
console.log('✅ Services initialized.');


// --- 2. Dependency Container Setup ---
// Create the middleware factory using the initialized services
const middlewares = createMiddlewareFactory(services);

// --- 3. Hono Application Setup ---
const app = new Hono<AppContext>();

// Global middlewares
app.use('*', logger());
app.use('*', prettyJSON());
app.use('*', cors({
  origin: ['http://localhost:3000', 'http://localhost:5173', 'http://localhost:4321'], // Add your frontend URL
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

// Use the factory to create the global optional auth middleware
app.use('*', middlewares.optionalAuth());


// --- 4. Routers ---
// Create routers by passing the single dependency container
const publicRoutes = createPublicRoutes({ authService: services.authService });
const protectedRoutes = createProtectedRoutes({ requireAuth: middlewares.requireAuth() });
const moderatorRoutes = createModeratorRoutes({
  requireAuth: middlewares.requireAuth(),
  requireModeratorRole: middlewares.requireRole(['moderator']),
  requireEditPermission: middlewares.requirePermission(['edit:content'])
});
const adminRoutes = createAdminRoutes(
  { authService: services.authService, permissionService: permissionService },
  {
    requireAuth: middlewares.requireAuth(),
    requireAdminRole: middlewares.requireRole(['admin'])
  }
);

// Mount routers
app.route('/auth', publicRoutes);
app.route('/api', protectedRoutes);
app.route('/api/mod', moderatorRoutes);
app.route('/api/admin', adminRoutes);

console.log('✅ Routes configured.');


// --- 5. Export for Bun ---
export default app;

console.log('🔥 Hono server is running on http://localhost:3000');