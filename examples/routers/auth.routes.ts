// src/routes/auth.routes.ts
import { Hono } from 'hono';
import { AuthController } from '../controllers/auth.controller';
import { AppContext, Services } from '../app'; // We'll define this type next
import { createAuthMiddlewareForHono } from '../middleware/auth.middleware';

export const createAuthRouter = (services: Services): Hono<AppContext> => {
  const router = new Hono<AppContext>();
  const authController = new AuthController(services.authService);
  const requireAuth = createAuthMiddlewareForHono(services, true);

  // Public routes
  router.post('/register', authController.register);
  router.post('/login', authController.login);
  
  // Protected routes
  router.get('/profile', requireAuth, authController.getProfile);

  return router;
};