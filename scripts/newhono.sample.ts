// src/index.ts

import { Hono } from 'hono';
import { Database } from 'bun:sqlite';
import { DatabaseInitializer } from '../src';
import { JWTService } from '../src';
import { AuthService } from '../src';
import { PermissionService } from '../src';
import {
  createAuthMiddlewareForHono,
  createPermissionMiddlewareForHono,
  createRoleMiddlewareForHono,
} from './hono.adapter';
import type { AuthContext } from '../src';

// --- 1. Inicialización ---
console.log('🚀 Initializing application...');
const db = new Database('auth.db');
const dbInitializer = new DatabaseInitializer({ database: db });
await dbInitializer.initialize(); // Asegura que las tablas existan

const jwtService = new JWTService(process.env.JWT_SECRET || 'a-very-secret-key-for-hono');
const authService = new AuthService(dbInitializer, jwtService);
const permissionService = new PermissionService(dbInitializer);

const services = { jwtService, authService, permissionService };
console.log('✅ Services initialized.');

// --- 2. Creación de Middlewares ---
const requireAuth = createAuthMiddlewareForHono(services, true);
const optionalAuth = createAuthMiddlewareForHono(services, false);
const requireAdminRole = createRoleMiddlewareForHono(['admin']);
const requireModeratorRole = createRoleMiddlewareForHono(['moderator']);
const requireEditPermission = createPermissionMiddlewareForHono(['edit:content']);
console.log('✅ Middlewares created.');

// --- 3. Aplicación Hono ---
// Definir un tipo para el contexto de Hono para tener autocompletado de `c.get('auth')`
type AppContext = {
  Variables: {
    auth: AuthContext;
  }
}


const app = new Hono<AppContext>();

// Middleware global para intentar autenticar todas las peticiones
app.use('*', optionalAuth);


// --- Rutas Públicas ---
app.get('/', (c) => {
  const auth = c.get('auth');
  const message = auth.isAuthenticated
    ? `Welcome back, ${auth.user?.first_name}!`
    : 'Welcome, guest! Please log in.';
  return c.json({ message });
});

// Rutas de autenticación
app.post('/register', async (c) => {
  const body = await c.req.json();
  const result = await authService.register(body);
  if (!result.success) {
    return c.json(result, 400);
  }
  return c.json(result, 201);
});



app.post('/register-with-role', async (c) => {
  const body = await c.req.json();
  const { role_name, permission_names, ...registrationData } = body;

  const registrationResult = await authService.register(registrationData);
  if (!registrationResult.success) {
    return c.json(registrationResult, 400);
  }

  const user_id = registrationResult.user?.id;
  if (user_id) {
    if (role_name) {
      const roleAssignmentResult = await authService.assignRole(
        user_id,
        role_name,
      );
      if (!roleAssignmentResult.success) {
        return c.json(
          { ...registrationResult, message: 'User registered, but role assignment failed.', roleError: roleAssignmentResult.error },
          400,
        );
      }
    }
  }

  return c.json(registrationResult, 201);
});

app.post('/login', async (c) => {
  const body = await c.req.json();
  const result = await authService.login(body);
  if (!result.success) {
    return c.json(result, 401);
  }
  return c.json({ success: true, user: result.user, data: { token: result.token } });
});


// --- Rutas Protegidas ---

// Grupo de rutas que requieren estar logueado
const protectedRoutes = new Hono<AppContext>();
protectedRoutes.use('*', requireAuth);

protectedRoutes.get('/profile', (c) => {
  const auth = c.get('auth');
  return c.json({
    message: 'This is your private profile data.',
    user: auth.user,
    permissions: auth.permissions,
  });
});

// Grupo de rutas para moderadores (y administradores, por herencia de permisos)
const moderatorRoutes = new Hono<AppContext>();
moderatorRoutes.use('*', requireAuth, requireModeratorRole);

moderatorRoutes.get('/content', (c) => {
  return c.json({ message: 'Here is the content you can moderate.' });
});

moderatorRoutes.post('/content/edit', requireEditPermission, (c) => {
  return c.json({ message: 'Content edited successfully!' });
});


// Grupo de rutas solo para administradores
const adminRoutes = new Hono<AppContext>();
adminRoutes.use('*', requireAuth, requireAdminRole);

adminRoutes.get('/users', async (c) => {
  const { users, total } = await authService.getUsers();
  return c.json({ users, total });
});

// Montar los grupos de rutas en la app principal
app.route('/api', protectedRoutes);
app.route('/api/mod', moderatorRoutes);
app.route('/api/admin', adminRoutes);

console.log('✅ Routes configured.');

export { app };

export default {
  port: 3000,
  fetch: app.fetch,
};

console.log('🔥 Hono server is running on port 3000');