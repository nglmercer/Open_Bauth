import { Hono } from 'hono';
import type { AuthContext } from '../../src';
import type { AuthService } from '../../src';

// Define local AppContext type for Hono variables
export type AppContext = {
  Variables: {
    auth: AuthContext;
  };
};

export function createPublicRoutes(deps: { authService: AuthService }) {
  const { authService } = deps;
  const router = new Hono<AppContext>();

  // Public welcome route
  router.get('/', (c) => {
    const auth = c.get('auth');
    const message = auth?.isAuthenticated
      ? `Welcome back, ${auth.user?.first_name}!`
      : 'Welcome, guest! Please log in.';
    return c.json({ message });
  });

  // Register
  router.post('/register', async (c) => {
    const body = await c.req.json();
    const result = await authService.register(body);
    const user_id = result.user?.id;
    if (user_id) {
      await authService.assignRole(user_id, 'user');
    }
    if (!result.success) {
      return c.json(result, 400);
    }
    return c.json({ ...result, message: 'User registered successfully' }, 201);
  });
    router.post('/register/admin', async (c) => {
    const body = await c.req.json();
    const result = await authService.register(body);
    const user_id = result.user?.id;
    if (user_id) {
      await authService.assignRole(user_id, 'admin');
      await authService.assignRole(user_id,'moderator')
    }
    if (!result.success) {
      return c.json(result, 400);
    }
    return c.json({ ...result, message: 'User registered successfully' }, 201);
  });

  // Register with role
  router.post('/register-with-role', async (c) => {
    const body = await c.req.json();
    const { role_name, permission_names, ...registrationData } = body as any;

    const registrationResult = await authService.register(registrationData);
    if (!registrationResult.success) {
      return c.json(registrationResult, 400);
    }

    const user_id = registrationResult.user?.id;
    if (user_id && role_name) {
      const roleAssignmentResult = await authService.assignRole(user_id, role_name);
      if (!roleAssignmentResult.success) {
        return c.json(
          {
            ...registrationResult,
            message: 'User registered, but role assignment failed.',
            roleError: roleAssignmentResult.error,
          },
          400,
        );
      }
    }

    return c.json({ ...registrationResult, message: 'User registered successfully' }, 201);
  });

  // Login
  router.post('/login', async (c) => {
    const body = await c.req.json();
    const result = await authService.login(body);
    if (!result.success) {
      return c.json(result, 401);
    }
    return c.json({ success: true, message: 'Login successful', user: result.user, data: { token: result.token },token: result.token });
  });

  return router;
}