# Authentication Library Documentation

## Table of Contents

1. [Main AuthLibrary Class](#main-authlibrary-class)
2. [Core Services](#core-services)
3. [Framework Adapters](#framework-adapters)
4. [Framework-Agnostic Middleware](#framework-agnostic-middleware)
5. [TypeScript Types](#typescript-types)
6. [Database](#database)
7. [Configuration](#configuration)

---

## Main AuthLibrary Class

The `AuthLibrary` class is the main entry point for the authentication library. It provides a unified interface to access all services and functionalities.

### Public Methods

| Method | Parameters | Return | Description |
|--------|------------|--------|--------------|
| `constructor()` | `config: AuthConfig` | `AuthLibrary` | Initializes the library with the provided configuration |
| `initialize()` | - | `Promise<void>` | Initializes the database and runs migrations |
| `getAuthService()` | - | `AuthService` | Gets the authentication service instance |
| `getJWTService()` | - | `JWTService` | Gets the JWT service instance |
| `getPermissionService()` | - | `PermissionService` | Gets the permission service instance |
| `createHonoAdapter()` | `config?: AuthMiddlewareConfig` | `HonoAdapter` | Creates an adapter for the Hono framework |
| `createExpressAdapter()` | `config?: AuthMiddlewareConfig` | `ExpressAdapter` | Creates an adapter for the Express framework |
| `createWebSocketAdapter()` | `config?: AuthMiddlewareConfig` | `WebSocketAdapter` | Creates an adapter for WebSockets |

### Usage Example

```typescript
import { AuthLibrary } from './src/index';

const authLib = new AuthLibrary({
  jwtSecret: 'your-secret-key',
  jwtExpiration: '24h',
  database: {
    path: './auth.db'
  }
});

await authLib.initialize();

// Get services
const authService = authLib.getAuthService();
const jwtService = authLib.getJWTService();
const permissionService = authLib.getPermissionService();
```

---

## Core Services

### AuthService

Main service for authentication, registration, and user management.

| Method | Parameters | Return | Description |
|--------|------------|--------|--------------|
| `register()` | `data: RegisterData` | `Promise<AuthResult>` | Registers a new user in the system |
| `login()` | `data: LoginData` | `Promise<AuthResult>` | Authenticates a user with email and password |
| `findUserById()` | `id: string, options?: UserQueryOptions` | `Promise<User \| null>` | Finds a user by their ID |
| `findUserByEmail()` | `email: string, options?: UserQueryOptions` | `Promise<User \| null>` | Finds a user by their email |
| `updateUser()` | `userId: string, data: UpdateUserData` | `Promise<{success: boolean, user?: User, error?: AuthError}>` | Updates user data |
| `updatePassword()` | `userId: string, newPassword: string` | `Promise<{success: boolean, error?: AuthError}>` | Updates a user's password |
| `deactivateUser()` | `userId: string` | `Promise<{success: boolean, error?: AuthError}>` | Deactivates a user account |
| `activateUser()` | `userId: string` | `Promise<{success: boolean, error?: AuthError}>` | Activates a user account |
| `deleteUser()` | `userId: string` | `Promise<{success: boolean, error?: AuthError}>` | Permanently deletes a user |
| `assignRole()` | `userId: string, roleName: string` | `Promise<{success: boolean, error?: AuthError}>` | Assigns a role to a user |
| `removeRole()` | `userId: string, roleName: string` | `Promise<{success: boolean, error?: AuthError}>` | Removes a role from a user |
| `getUsers()` | `page?: number, limit?: number, options?: UserQueryOptions` | `Promise<{users: User[], total: number}>` | Gets a paginated list of users |
| `getUserRoles()` | `userId: string, includePermissions?: boolean` | `Promise<Role[]>` | Gets a user's roles |

### JWTService

Service for JWT token generation, verification, and management.

| Method | Parameters | Return | Description |
|--------|------------|--------|--------------|
| `generateToken()` | `user: User` | `Promise<string>` | Generates a JWT token for a user |
| `verifyToken()` | `token: string` | `Promise<JWTPayload>` | Verifies and decodes a JWT token |
| `extractTokenFromHeader()` | `authHeader: string` | `string \| null` | Extracts token from Authorization header (case-insensitive Bearer) |
| `isTokenExpired()` | `token: string` | `boolean` | Checks if a token has expired |
| `getTokenRemainingTime()` | `token: string` | `number` | Gets remaining time of a token in seconds |
| `refreshTokenIfNeeded()` | `token: string, user: User, refreshThreshold?: number` | `Promise<string>` | Refreshes a token if it's about to expire |
| `generateRefreshToken()` | `userId: number` | `Promise<string>` | Generates a refresh token |
| `verifyRefreshToken()` | `refreshToken: string` | `Promise<number>` | Verifies a refresh token |

### PermissionService

Service for role and permission management (RBAC).

| Method | Parameters | Return | Description |
|--------|------------|--------|--------------|
| `createPermission()` | `data: CreatePermissionData` | `Promise<PermissionResult>` | Creates a new permission |
| `createRole()` | `data: CreateRoleData` | `Promise<RoleResult>` | Creates a new role |
| `updatePermission()` | `permissionId: string, data: UpdatePermissionData` | `Promise<PermissionResult>` | Updates an existing permission |
| `updateRole()` | `roleId: string, data: UpdateRoleData` | `Promise<RoleResult>` | Updates an existing role |
| `deletePermission()` | `permissionId: string` | `Promise<PermissionResult>` | Deletes a permission |
| `deleteRole()` | `roleId: string` | `Promise<RoleResult>` | Deletes a role |
| `assignPermissionToRole()` | `roleId: string, permissionId: string` | `Promise<PermissionResult>` | Assigns a permission to a role |
| `removePermissionFromRole()` | `roleId: string, permissionId: string` | `Promise<PermissionResult>` | Removes a permission from a role |
| `findPermissionByName()` | `name: string` | `Promise<Permission \| null>` | Finds a permission by name |
| `findRoleByName()` | `name: string` | `Promise<Role \| null>` | Finds a role by name |
| `getAllPermissions()` | - | `Promise<Permission[]>` | Gets all permissions |
| `getAllRoles()` | - | `Promise<Role[]>` | Gets all roles |
| `getRolePermissions()` | `roleId: string` | `Promise<Permission[]>` | Gets permissions for a role |
| `userHasPermission()` | `userId: string, permissionName: string` | `Promise<boolean>` | Checks if a user has a specific permission |
| `userHasRole()` | `userId: string, roleName: string` | `Promise<boolean>` | Checks if a user has a specific role |
| `userCanAccessResource()` | `userId: string, resource: string, action: string` | `Promise<boolean>` | Checks if a user can access a resource |

---

## Framework Adapters

### Hono Adapter

Specific adapter for the Hono framework.

| Function | Parameters | Return | Description |
|----------|------------|--------|--------------|
| `honoAuthMiddleware()` | `config?: AuthMiddlewareConfig` | `MiddlewareHandler` | Main authentication middleware |
| `honoOptionalAuth()` | - | `MiddlewareHandler` | Optional authentication middleware |
| `honoRequireAuth()` | - | `MiddlewareHandler` | Middleware that requires authentication |
| `honoRequirePermissions()` | `permissions: string[], requireAll?: boolean` | `MiddlewareHandler` | Middleware that requires specific permissions |
| `honoRequireRoles()` | `roles: string[]` | `MiddlewareHandler` | Middleware that requires specific roles |
| `honoRequireAdmin()` | - | `MiddlewareHandler` | Middleware that requires admin role |
| `honoRequireModerator()` | - | `MiddlewareHandler` | Middleware that requires moderator role |
| `getHonoCurrentUser()` | `c: Context` | `User \| undefined` | Gets current user from context |
| `isHonoAuthenticated()` | `c: Context` | `boolean` | Checks if request is authenticated |
| `getHonoAuthContext()` | `c: Context` | `AuthContext` | Gets authentication context |
| `honoRequireOwnership()` | `getUserIdFromParams: (c: Context) => string` | `MiddlewareHandler` | Middleware that requires resource ownership |
| `honoRateLimit()` | `maxRequests?: number, windowMs?: number` | `MiddlewareHandler` | Rate limiting middleware |
| `honoCorsAuth()` | `origins?: string[]` | `MiddlewareHandler` | CORS middleware for authentication |
| `honoAuthLogger()` | - | `MiddlewareHandler` | Logging middleware for authentication |

### Express Adapter

Specific adapter for the Express framework.

| Function | Parameters | Return | Description |
|----------|------------|--------|--------------|
| `expressAuthMiddleware()` | `config?: AuthMiddlewareConfig` | `RequestHandler` | Main authentication middleware |
| `expressOptionalAuth()` | - | `RequestHandler` | Optional authentication middleware |
| `expressRequireAuth()` | - | `RequestHandler` | Middleware that requires authentication |
| `expressRequirePermissions()` | `permissions: string[], requireAll?: boolean` | `RequestHandler` | Middleware that requires specific permissions |
| `expressRequireRoles()` | `roles: string[]` | `RequestHandler` | Middleware that requires specific roles |
| `expressRequireAdmin()` | - | `RequestHandler` | Middleware that requires admin role |
| `expressRequireModerator()` | - | `RequestHandler` | Middleware that requires moderator role |
| `getExpressCurrentUser()` | `req: Request` | `User \| undefined` | Gets current user from request |
| `isExpressAuthenticated()` | `req: Request` | `boolean` | Checks if request is authenticated |
| `getExpressAuthContext()` | `req: Request` | `AuthContext` | Gets authentication context |
| `expressRequireOwnership()` | `getUserIdFromParams: (req: Request) => string` | `RequestHandler` | Middleware that requires resource ownership |
| `expressRateLimit()` | `maxRequests?: number, windowMs?: number` | `RequestHandler` | Rate limiting middleware |
| `expressCorsAuth()` | `origins?: string[]` | `RequestHandler` | CORS middleware for authentication |
| `expressAuthLogger()` | - | `RequestHandler` | Logging middleware for authentication |
| `expressAuthErrorHandler()` | - | `ErrorRequestHandler` | Error handling middleware |
| `expressJsonValidator()` | - | `RequestHandler` | JSON validation middleware |
| `expressSanitizer()` | - | `RequestHandler` | Data sanitization middleware |

### WebSocket Adapter

Adapter for WebSocket connection authentication.

| Function | Parameters | Return | Description |
|----------|------------|--------|--------------|
| `authenticateWebSocket()` | `ws: WebSocket, request: IncomingMessage` | `Promise<AuthenticatedWebSocket>` | Authenticates a WebSocket connection |
| `checkWebSocketPermissions()` | `ws: AuthenticatedWebSocket, permissions: string[]` | `boolean` | Checks permissions on WebSocket |
| `checkWebSocketRoles()` | `ws: AuthenticatedWebSocket, roles: string[]` | `boolean` | Checks roles on WebSocket |
| `getWebSocketUser()` | `ws: AuthenticatedWebSocket` | `User \| undefined` | Gets user from WebSocket connection |
| `isWebSocketAuthenticated()` | `ws: AuthenticatedWebSocket` | `boolean` | Checks if connection is authenticated |

---

## Framework-Agnostic Middleware

Middleware functions that work independently of the framework.

| Function | Parameters | Return | Description |
|----------|------------|--------|--------------|
| `authenticateRequest()` | `request: AuthRequest, config?: AuthMiddlewareConfig` | `Promise<AuthResult>` | Authenticates a framework-agnostic request |
| `getCurrentUser()` | `authContext: AuthContext` | `User \| undefined` | Gets current user from context |
| `createEmptyAuthContext()` | - | `AuthContext` | Creates an empty authentication context |
| `logAuthEvent()` | `event: string, userId?: string, metadata?: any` | `void` | Logs authentication events |
| `extractClientIP()` | `headers: Record<string, string>` | `string \| undefined` | Extracts client IP |
| `extractUserAgent()` | `headers: Record<string, string>` | `string \| undefined` | Extracts User-Agent |
| `validateAuthConfig()` | `config: AuthConfig` | `boolean` | Validates authentication configuration |
| `hashPassword()` | `password: string` | `Promise<string>` | Generates password hash using Bun |
| `verifyPassword()` | `password: string, hash: string` | `Promise<boolean>` | Verifies password using Bun |

---

## TypeScript Types

### Main Interfaces

| Interface | Description | Main Properties |
|-----------|-------------|------------------|
| `User` | Represents a system user | `id`, `email`, `roles`, `isActive`, `createdAt` |
| `Role` | Represents a system role | `id`, `name`, `permissions`, `description` |
| `Permission` | Represents a specific permission | `id`, `name`, `resource`, `action` |
| `AuthContext` | Authentication context | `user`, `token`, `permissions`, `isAuthenticated` |
| `AuthConfig` | System configuration | `jwtSecret`, `database`, `security`, `cors` |
| `AuthRequest` | Framework-agnostic request | `headers`, `url`, `method`, `auth` |
| `AuthResult` | Auth operation result | `success`, `user`, `token`, `error` |
| `JWTPayload` | JWT token payload | `userId`, `email`, `roles`, `iat`, `exp` |

### Data Types

| Type | Description | Fields |
|------|-------------|--------|
| `RegisterData` | Registration data | `email`, `password`, `firstName`, `lastName` |
| `LoginData` | Login data | `email`, `password` |
| `CreatePermissionData` | Permission creation data | `name`, `resource`, `action`, `description` |
| `CreateRoleData` | Role creation data | `name`, `description`, `permissionIds` |
| `UpdateUserData` | User update data | `email`, `isActive`, `firstName`, `lastName` |
| `UserQueryOptions` | Query options | `includeRoles`, `includePermissions`, `activeOnly` |

### Enums

| Enum | Values | Description |
|------|--------|-------------|
| `AuthErrorType` | `INVALID_CREDENTIALS`, `USER_NOT_FOUND`, `TOKEN_EXPIRED`, etc. | Authentication error types |

---

## Database

### Main Tables

| Table | Description | Main Fields |
|-------|-------------|-------------|
| `users` | Stores users | `id`, `email`, `password_hash`, `is_active`, `created_at` |
| `roles` | Stores roles | `id`, `name`, `description`, `is_active`, `created_at` |
| `permissions` | Stores permissions | `id`, `name`, `resource`, `action`, `created_at` |
| `user_roles` | User-role relationship | `user_id`, `role_id`, `assigned_at` |
| `role_permissions` | Role-permission relationship | `role_id`, `permission_id`, `assigned_at` |

### Database Methods

| Function | Parameters | Description |
|----------|------------|-------------|
| `initDatabase()` | `path?: string` | Initializes SQLite connection |
| `getDatabase()` | - | Gets database instance |
| `runMigrations()` | - | Runs pending migrations |
| `seedDatabase()` | - | Populates database with initial data |
| `closeDatabase()` | - | Closes database connection |

---

## Configuration

### AuthConfig

Main authentication system configuration.

```typescript
interface AuthConfig {
  jwtSecret: string;
  jwtExpiration: string;
  refreshTokenExpiration: string;
  database: DatabaseConfig;
  security: SecurityConfig;
  cors: CorsConfig;
  rateLimit: RateLimitConfig;
  logging: LoggingConfig;
}
```

### Specific Configurations

| Configuration | Properties | Description |
|---------------|------------|-------------|
| `DatabaseConfig` | `path`, `enableWAL`, `enableForeignKeys`, `busyTimeout` | SQLite configuration |
| `SecurityConfig` | `bcryptRounds`, `maxLoginAttempts`, `lockoutDuration` | Security configuration |
| `CorsConfig` | `origins`, `credentials`, `methods`, `headers` | CORS configuration |
| `RateLimitConfig` | `windowMs`, `maxRequests`, `skipSuccessfulRequests` | Rate limiting configuration |
| `LoggingConfig` | `level`, `enableConsole`, `enableFile`, `filePath` | Logging configuration |

### Utility Scripts

| Script | Description | Usage |
|--------|-------------|-------|
| `seed.ts` | Populates database with initial data | `bun run src/scripts/seed.ts` |
| `migrate.ts` | Runs database migrations | `bun run src/scripts/migrate.ts` |
| `reset.ts` | Resets database | `bun run src/scripts/reset.ts` |

---

## Usage Examples

### Basic Configuration

```typescript
import { AuthLibrary } from './src/index';

const authLib = new AuthLibrary({
  jwtSecret: process.env.JWT_SECRET!,
  jwtExpiration: '24h',
  refreshTokenExpiration: '7d',
  database: {
    path: './auth.db',
    enableWAL: true,
    enableForeignKeys: true,
    busyTimeout: 5000
  },
  security: {
    bcryptRounds: 12,
    maxLoginAttempts: 5,
    lockoutDuration: 900000, // 15 minutes
    sessionTimeout: 86400000, // 24 hours
    passwordMinLength: 8,
    passwordRequireUppercase: true,
    passwordRequireLowercase: true,
    passwordRequireNumbers: true,
    passwordRequireSymbols: false
  }
});

await authLib.initialize();
```

### Usage with Hono

```typescript
import { Hono } from 'hono';
import { honoAuthMiddleware, honoRequirePermissions } from './src/adapters/hono';

const app = new Hono();

// Global authentication middleware
app.use('*', honoAuthMiddleware());

// Protected route with permissions
app.get('/admin/users', 
  honoRequirePermissions(['users.read']),
  async (c) => {
    const authService = authLib.getAuthService();
    const users = await authService.getUsers();
    return c.json(users);
  }
);
```

### Usage with Express

```typescript
import express from 'express';
import { expressAuthMiddleware, expressRequireRoles } from './src/adapters/express';

const app = express();

// Global authentication middleware
app.use(expressAuthMiddleware());

// Protected route with roles
app.get('/admin/dashboard', 
  expressRequireRoles(['admin', 'moderator']),
  async (req, res) => {
    const permissionService = authLib.getPermissionService();
    const stats = await permissionService.getAuthStats();
    res.json(stats);
  }
);
```

---

## Key Features

- ✅ **Framework Agnostic**: Works with Hono, Express, WebSockets and more
- ✅ **TypeScript Native**: Complete and safe typing
- ✅ **SQLite with Bun**: Optimized embedded database
- ✅ **Secure JWT**: Native implementation with Web Crypto API
- ✅ **Complete RBAC**: Granular role and permission system
- ✅ **Flexible Middleware**: Optional and required authentication
- ✅ **Rate Limiting**: Protection against brute force attacks
- ✅ **Advanced Logging**: Detailed security event logging
- ✅ **Robust Validation**: Data sanitization and validation
- ✅ **Flexible Configuration**: Highly customizable

---

## Installation

```bash
# Install with Bun
bun install

# Initialize database
bun run src/scripts/migrate.ts

# Seed with initial data
bun run src/scripts/seed.ts
```

## Quick Start

```typescript
import { AuthLibrary } from './src/index';

// Initialize library
const auth = new AuthLibrary({
  jwtSecret: 'your-secret-key'
});

await auth.initialize();

// Register a user
const authService = auth.getAuthService();
const result = await authService.register({
  email: 'user@example.com',
  password: 'securepassword',
  firstName: 'John',
  lastName: 'Doe'
});

console.log('User registered:', result.success);
```

## License

MIT License - see LICENSE file for details.

#### changes:
- isDefault [] optional, not included on database,
  - default ever is user, implement change default userRole. only exist one(?)