// dist/index.ts (FINAL VERSION)

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { serveStatic } from 'hono/bun';
import { Database } from 'bun:sqlite';

// Core Application Imports
import { DatabaseInitializer } from '../dist/index';
import { JWTService } from '../dist/index';
import { AuthService } from '../dist/index';
import { PermissionService} from '../dist/index';
import { AppContext, AppDependencies, Services } from './app';
import { merged} from './integrations/newSchemas';
//,pointsSchema, processesSchema, notificationsSchema
import { createMiddlewareFactory } from './middleware/factory';

// Router Imports
import { createPublicRoutes } from './routers/public.routes';
import { createProtectedRoutes } from './routers/protected.routes';
import { createModeratorRoutes } from './routers/moderator.routes';
import { createAdminRoutes } from './routers/admin.routes';
import { createProductRoutes } from './routers/product.routes';


// --- 1. Service Initialization ---
const db = new Database('auth.db');
//new schemes with merged.getAll() or [pointsSchema, processesSchema, notificationsSchema]
const dbInitializer = new DatabaseInitializer({ database: db,externalSchemas: merged.getAll() });
await dbInitializer.initialize();
await dbInitializer.seedDefaults();

const jwtService = new JWTService(process.env.JWT_SECRET || 'a-very-secret-key-for-hono',process.env.JWT_EXPIRATION || '7d');
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

// Static file serving for images
app.use('/images/*', serveStatic({ root: './public' }));

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
const productRoutes = createProductRoutes({ dbInitializer });

// Mount routers
app.route('/auth', publicRoutes);
app.route('/api', protectedRoutes);
app.route('/api/mod', moderatorRoutes);
app.route('/api/admin', adminRoutes);
app.route('/products', productRoutes);
// --- 5. Export for Bun ---
export default app;