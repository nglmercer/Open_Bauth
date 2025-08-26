// src/types/app.ts

import { MiddlewareHandler } from 'hono';
import { AuthContext } from '../src/index';
import { AuthService } from '../src/index';
import { JWTService } from '../src/index';
import { PermissionService } from '../src/index';

// Hono's context typing for this specific application
export type AppContext = {
  Variables: {
    auth: AuthContext;
  };
};

// A clear, explicit type for all application services
export type Services = {
  jwtService: JWTService;
  authService: AuthService;
  permissionService: PermissionService;
};

// The type for our middleware factory
export type MiddlewareFactory = {
  requireAuth: () => MiddlewareHandler<AppContext>;
  optionalAuth: () => MiddlewareHandler<AppContext>;
  requireRole: (roles: string[]) => MiddlewareHandler<AppContext>;
  requirePermission: (permissions: string[]) => MiddlewareHandler<AppContext>;
};

// The single dependency container to be passed around the application
export type AppDependencies = {
  services: Services;
  middlewares: MiddlewareFactory;
};