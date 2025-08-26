// src/middleware/factory.ts

import { Services, MiddlewareFactory } from '../app';
import {
  createAuthMiddlewareForHono,
  createPermissionMiddlewareForHono,
  createRoleMiddlewareForHono,
} from './auth.middleware';

export const createMiddlewareFactory = (services: Services): MiddlewareFactory => {
  return {
    requireAuth: () => createAuthMiddlewareForHono(services, true),
    optionalAuth: () => createAuthMiddlewareForHono(services, false),
    requireRole: (roles: string[]) => createRoleMiddlewareForHono(roles),
    requirePermission: (permissions: string[]) => createPermissionMiddlewareForHono(permissions),
  };
};