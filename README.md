# Framework-Agnostic Authentication Library

A comprehensive, framework-agnostic authentication and authorization library built with TypeScript, Bun, and SQLite. It provides JWT-based auth, RBAC (roles and permissions), framework-neutral middleware, and a flexible database layer.

- Runtime: Bun (Node.js compatible for most features)
- Storage: SQLite by default (via Bun), extensible to other SQL engines
- Language: TypeScript, with full type definitions

---

## Installation

Using Bun:

- Install as a dependency: `bun add open-bauth`
- Or clone this repository and work locally: `git clone https://github.com/nglmercer/open-bauth.git`

Build and test locally:

- Build: `bun run build`
- Test: `bun test`

---

## Quick Start

1) Initialize the database and seed defaults (users/roles/permissions tables):

```ts
import { Database } from 'bun:sqlite';
import { DatabaseInitializer } from 'open-bauth';

const db = new Database('auth.db');
const dbInitializer = new DatabaseInitializer({ database: db });
await dbInitializer.initialize();
await dbInitializer.seedDefaults();
```

2) Initialize services (JWT, Auth, Permissions):

```ts
import { JWTService, AuthService, PermissionService } from 'open-bauth';

const jwtService = new JWTService(process.env.JWT_SECRET || 'dev-secret', '24h');
const authService = new AuthService(dbInitializer, jwtService);
const permissionService = new PermissionService(dbInitializer);
```

3) Register and login:

```ts
const register = await authService.register({ email: 'user@example.com', password: 'StrongP@ssw0rd' });
if (!register.success) throw new Error(register.error?.message);

const login = await authService.login({ email: 'user@example.com', password: 'StrongP@ssw0rd' });
if (!login.success) throw new Error(login.error?.message);
console.log('JWT:', login.token);
```

4) Use framework-agnostic middleware (example with Hono):

```ts
import { Hono } from 'hono';
import { createAuthMiddleware, createPermissionMiddleware } from 'open-bauth';

const app = new Hono();

// Wire services into middleware
const authMw = createAuthMiddleware({ jwtService, authService, permissionService }, true);
const canEditContent = createPermissionMiddleware({ permissionService }, ['edit:content']);

app.use('*', async (c, next) => authMw(c, next));
app.get('/protected', async (c) => {
  if (!c.auth?.isAuthenticated) return c.json({ success: false }, 401);
  return c.json({ success: true, user: c.auth.user });
});
app.get('/moderate', async (c) => canEditContent(c));
```

---

## What’s Exported from the Library

This library’s public API is re-exported from the entrypoint so you can import from a single place.

- Middleware
  - authenticateRequest(request, services)
  - createAuthMiddleware(services, required?)
  - createPermissionMiddleware(services, requiredPermissions, options?)
  - createRoleMiddleware(requiredRoles)

- Services
  - AuthService
  - JWTService, initJWTService(secret, expiresIn?), getJWTService()
  - PermissionService

- Database
  - BaseController (generic CRUD + query helpers)
  - DatabaseInitializer (migrations, integrity checks, seeds, controllers)

- Logger
  - Logger class, getLogger(), defaultLogger, convenience log methods, configuration helpers

- Types (from src/types/auth)
  - User, Role, Permission, RegisterData, LoginData, UpdateUserData, AuthResult, AuthErrorType, AuthContext, AuthRequest, AuthResponse, PermissionOptions, AssignRoleData, JWTPayload, SessionInfo, and more


---

## Core Concepts and APIs

### AuthService
High-level auth flows: register, login, user lookup/update, role assignment, etc. Depends on the database layer and JWT service.

- register(data: RegisterData) -> AuthResult
- login(data: LoginData) -> AuthResult
- findUserById(id, options?) -> User | null
- assignRole(userId, roleName) / removeRole(userId, roleName)
- getUsers(page?, limit?, options?) -> { users, total }

### JWTService
Minimal, native Web Crypto–based JWT operations.

- generateToken(user)
- verifyToken(token)
- extractTokenFromHeader('Bearer ...')
- getTokenRemainingTime(token), isTokenExpired(token)
- refreshTokenIfNeeded(token, user, threshold?)

### PermissionService
Queries and helpers for roles and permissions (e.g., getRolePermissions, user permission checks).

### DatabaseInitializer and BaseController
- DatabaseInitializer handles table creation/migrations, integrity checks, seeding defaults, and creating controllers for tables.
- BaseController<T> provides CRUD and query utilities (findFirst, search, count, random, etc.).

---

## Middleware (Framework-Agnostic)

- authenticateRequest(request, { jwtService, authService, permissionService })
  - Verifies JWT from Authorization header, loads user and permissions, returns an AuthContext.
- createAuthMiddleware(services, required = true)
  - Attaches auth context to request. When required is true, rejects if unauthenticated.
- createPermissionMiddleware(services, permissions, { requireAll = false })
  - Ensures the user has at least one (or all) of the required permissions.
- createRoleMiddleware(requiredRoles)
  - Ensures the user has at least one required role.

---

## Logging

A simple yet flexible logger is included:
- getLogger(), defaultLogger, convenience log.debug/info/warn/error/fatal
- Configuration helpers via createConfig and ENVIRONMENT_CONFIGS

---

## Type Safety

The library ships with rich TypeScript types for requests, responses, entities, config, and utility types. Import what you need from the package to get end-to-end type safety in your app.

---

## Library Info

You can inspect metadata at runtime:

---

## License

MIT
