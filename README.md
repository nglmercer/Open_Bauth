# Authentication Library Documentation

## Table of Contents

1. [Main AuthLibrary Class](#main-authlibrary-class)
2. [Core Services](#core-services)
3. [Framework Adapters](#framework-adapters)
4. [Framework-Agnostic Middleware](#framework-agnostic-middleware)
5. [TypeScript Types](#typescript-types)
6. [Database](#database)
7. [Configuration](#configuration)
8. [Convenience Functions](#convenience-functions)

---

## Main AuthLibrary Class

The `AuthLibrary` class is the main entry point for the authentication library. It provides a unified interface to access all services and functionalities.

### Public Methods

| Method | Parameters | Return | Description |
|--------|------------|--------|-------------|
| `constructor()` | `config?: Partial<AuthConfig>` | `AuthLibrary` | Initializes the library with optional configuration |
| `initialize()` | - | `Promise<void>` | Initializes the database and runs migrations |
| `getAuthService()` | - | `AuthService` | Gets the authentication service instance |
| `getJWTService()` | - | `JWTService` | Gets the JWT service instance |
| `getPermissionService()` | - | `PermissionService` | Gets the permission service instance |
| `getConfig()` | - | `AuthConfig` | Gets the current configuration |
| `updateConfig()` | `newConfig: Partial<AuthConfig>` | `void` | Updates the library configuration |
| `seed()` | - | `Promise<void>` | Populates database with initial data |
| `clean()` | - | `Promise<void>` | Cleans the database |
| `reset()` | - | `Promise<void>` | Resets the database |
| `checkStatus()` | - | `Promise<void>` | Checks database status |
| `close()` | - | `Promise<void>` | Closes connections and cleans up resources |

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
|--------|------------|--------|-------------|
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
|--------|------------|--------|-------------|
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
|--------|------------|--------|-------------|
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
|----------|------------|--------|-------------|
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
| `honoErrorResponse()` | `error: AuthError` | `Response` | Creates error response for Hono |
| `honoSuccessResponse()` | `data: any` | `Response` | Creates success response for Hono |

### Express Adapter

Specific adapter for the Express framework.

| Function | Parameters | Return | Description |
|----------|------------|--------|-------------|
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
| `expressErrorResponse()` | `error: AuthError` | `Response` | Creates error response for Express |
| `expressSuccessResponse()` | `data: any` | `Response` | Creates success response for Express |

### WebSocket Adapter

Adapter for WebSocket connection authentication.

| Function | Parameters | Return | Description |
|----------|------------|--------|-------------|
| `authenticateWebSocket()` | `ws: WebSocket, request: IncomingMessage` | `Promise<AuthenticatedWebSocket>` | Authenticates a WebSocket connection |
| `checkWebSocketPermissions()` | `ws: AuthenticatedWebSocket, permissions: string[]` | `boolean` | Checks permissions on WebSocket |
| `checkWebSocketRoles()` | `ws: AuthenticatedWebSocket, roles: string[]` | `boolean` | Checks roles on WebSocket |
| `getWebSocketCurrentUser()` | `ws: AuthenticatedWebSocket` | `User \| undefined` | Gets user from WebSocket connection |
| `isWebSocketAuthenticated()` | `ws: AuthenticatedWebSocket` | `boolean` | Checks if connection is authenticated |
| `getWebSocketAuthContext()` | `ws: AuthenticatedWebSocket` | `AuthContext` | Gets authentication context from WebSocket |
| `sendToUser()` | `userId: string, message: any` | `void` | Sends message to specific user |
| `sendToUsersWithPermissions()` | `permissions: string[], message: any` | `void` | Sends message to users with permissions |
| `sendToUsersWithRoles()` | `roles: string[], message: any` | `void` | Sends message to users with roles |
| `broadcastToAuthenticated()` | `message: any` | `void` | Broadcasts message to all authenticated connections |
| `getConnectionStats()` | - | `ConnectionStats` | Gets WebSocket connection statistics |
| `disconnectUser()` | `userId: string` | `void` | Disconnects specific user |
| `cleanupInactiveConnections()` | - | `void` | Cleans up inactive connections |
| `handleAuthenticatedMessage()` | `ws: AuthenticatedWebSocket, message: any` | `void` | Handles authenticated WebSocket messages |
| `createWebSocketResponse()` | `type: string, data: any` | `WebSocketResponse` | Creates WebSocket response |
| `initializeConnectionCleanup()` | `intervalMs?: number` | `void` | Initializes connection cleanup |

---

## Framework-Agnostic Middleware

Middleware functions that work independently of the framework.

| Function | Parameters | Return | Description |
|----------|------------|--------|-------------|
| `authenticateRequest()` | `request: AuthRequest, config?: AuthMiddlewareConfig` | `Promise<AuthResult>` | Authenticates a framework-agnostic request |
| `authorizeRequest()` | `authContext: AuthContext, permissions: string[]` | `Promise<boolean>` | Authorizes request based on permissions |
| `getCurrentUser()` | `authContext: AuthContext` | `User \| undefined` | Gets current user from context |
| `createEmptyAuthContext()` | - | `AuthContext` | Creates an empty authentication context |
| `logAuthEvent()` | `event: string, userId?: string, metadata?: any` | `void` | Logs authentication events |
| `extractClientIP()` | `headers: Record<string, string>` | `string \| undefined` | Extracts client IP |
| `extractUserAgent()` | `headers: Record<string, string>` | `string \| undefined` | Extracts User-Agent |
| `validateAuthConfig()` | `config: AuthConfig` | `boolean` | Validates authentication configuration |
| `hashPassword()` | `password: string` | `Promise<string>` | Generates password hash using Bun |
| `verifyPassword()` | `password: string, hash: string` | `Promise<boolean>` | Verifies password using Bun |

---

## Convenience Functions

The library provides convenience functions to easily create framework-specific authentication setups.

### createHonoAuth()

Creates a complete Hono authentication setup.

```typescript
import { createHonoAuth } from './src/index';

const honoAuth = createHonoAuth({
  jwtSecret: 'your-secret-key'
});

// Use the middleware
app.use('*', honoAuth.middleware());
app.get('/protected', honoAuth.required(), handler);
```

**Returns:**
- `middleware`: Main authentication middleware
- `optional`: Optional authentication middleware
- `required`: Required authentication middleware
- `permissions`: Permission-based middleware
- `roles`: Role-based middleware
- `admin`: Admin-only middleware
- `moderator`: Moderator-only middleware
- `ownership`: Ownership-based middleware
- `rateLimit`: Rate limiting middleware
- `cors`: CORS middleware
- `logger`: Logging middleware
- `library`: AuthLibrary instance

### createExpressAuth()

Creates a complete Express authentication setup.

```typescript
import { createExpressAuth } from './src/index';

const expressAuth = createExpressAuth({
  jwtSecret: 'your-secret-key'
});

// Use the middleware
app.use(expressAuth.middleware());
app.get('/protected', expressAuth.required(), handler);
```

**Returns:**
- `middleware`: Main authentication middleware
- `optional`: Optional authentication middleware
- `required`: Required authentication middleware
- `permissions`: Permission-based middleware
- `roles`: Role-based middleware
- `admin`: Admin-only middleware
- `moderator`: Moderator-only middleware
- `ownership`: Ownership-based middleware
- `rateLimit`: Rate limiting middleware
- `cors`: CORS middleware
- `logger`: Logging middleware
- `errorHandler`: Error handling middleware
- `jsonValidator`: JSON validation middleware
- `sanitizer`: Data sanitization middleware
- `library`: AuthLibrary instance

### createWebSocketAuth()

Creates a complete WebSocket authentication setup.

```typescript
import { createWebSocketAuth } from './src/index';

const wsAuth = createWebSocketAuth({
  jwtSecret: 'your-secret-key'
});

// Authenticate WebSocket connection
const authenticatedWs = await wsAuth.authenticate(ws, request);
```

**Returns:**
- `authenticate`: WebSocket authentication function
- `checkPermissions`: Permission checking function
- `checkRoles`: Role checking function
- `getCurrentUser`: Get current user function
- `isAuthenticated`: Authentication status function
- `getAuthContext`: Get authentication context function
- `sendToUser`: Send message to specific user
- `sendToUsersWithPermissions`: Send message to users with permissions
- `sendToUsersWithRoles`: Send message to users with roles
- `broadcast`: Broadcast message to all authenticated connections
- `getStats`: Get connection statistics
- `disconnect`: Disconnect specific user
- `cleanup`: Clean up inactive connections
- `handleMessage`: Handle authenticated messages
- `createResponse`: Create standardized WebSocket response
- `initCleanup`: Initialize connection cleanup
- `library`: AuthLibrary instance

---

## TypeScript Types

The library exports comprehensive TypeScript types organized into several categories:

### Authentication Types

| Type | Description | Key Properties |
|------|-------------|----------------|
| `User` | Represents a system user | `id`, `email`, `roles`, `isActive`, `createdAt` |
| `Role` | Represents a system role | `id`, `name`, `permissions`, `description` |
| `Permission` | Represents a specific permission | `id`, `name`, `resource`, `action` |
| `AuthContext` | Authentication context | `user`, `token`, `permissions`, `isAuthenticated` |
| `AuthConfig` | System configuration | `jwtSecret`, `database`, `security`, `cors` |
| `AuthRequest` | Framework-agnostic request | `headers`, `url`, `method`, `auth` |
| `AuthResponse` | Framework-agnostic response | `status`, `headers`, `body` |
| `AuthResult` | Auth operation result | `success`, `user`, `token`, `error` |
| `JWTPayload` | JWT token payload | `userId`, `email`, `roles`, `iat`, `exp` |
| `RegisterData` | Registration data | `email`, `password`, `firstName`, `lastName` |
| `LoginData` | Login data | `email`, `password` |
| `CreatePermissionData` | Permission creation data | `name`, `resource`, `action`, `description` |
| `CreateRoleData` | Role creation data | `name`, `description`, `permissionIds` |
| `UpdateUserData` | User update data | `email`, `isActive`, `firstName`, `lastName` |
| `UserQueryOptions` | Query options | `includeRoles`, `includePermissions`, `activeOnly` |
| `AuthStats` | Authentication statistics | `totalUsers`, `activeUsers`, `totalRoles` |
| `AuthEvent` | Authentication event | `type`, `userId`, `timestamp`, `metadata` |
| `SecurityConfig` | Security configuration | `rateLimiting`, `cors`, `helmet` |
| `SessionInfo` | Session information | `userId`, `sessionId`, `expiresAt` |

### Common Utility Types

| Type | Description | Usage |
|------|-------------|-------|
| `ApiResponse<T>` | Generic API response wrapper | `success`, `data`, `error`, `meta` |
| `PaginatedResponse<T>` | Paginated response interface | `items`, `pagination` |
| `BaseEntity` | Database entity base | `id`, `createdAt`, `updatedAt` |
| `SoftDeleteEntity` | Soft delete entity | `deletedAt`, `isDeleted` |
| `AuditFields` | Audit fields | `createdBy`, `updatedBy`, `deletedBy` |
| `QueryOptions` | Query options | `page`, `limit`, `sortBy`, `filters` |
| `ValidationResult` | Validation result | `isValid`, `errors`, `warnings` |
| `Optional<T, K>` | Make specific fields optional | Utility type |
| `RequiredFields<T, K>` | Make specific fields required | Utility type |
| `DeepPartial<T>` | Deep partial type | Utility type |
| `DeepRequired<T>` | Deep required type | Utility type |

### Service Types

| Type | Description | Purpose |
|------|-------------|----------|
| `BaseService` | Base service interface | Service foundation |
| `ServiceHealthStatus` | Service health status | Health monitoring |
| `AuthServiceInterface` | Auth service interface | Service contract |
| `RegisterServiceData` | Registration service data | Service input |
| `AuthServiceResult` | Auth service result | Service output |
| `TokenServiceResult` | Token service result | Token operations |

### Middleware Types

| Type | Description | Framework |
|------|-------------|----------|
| `ExtendedRequest` | Extended request object | Framework-agnostic |
| `ExtendedResponse` | Extended response object | Framework-agnostic |
| `MiddlewareFunction` | Middleware function type | Framework-agnostic |
| `ErrorMiddlewareFunction` | Error middleware function | Framework-agnostic |
| `AuthMiddlewareOptions` | Auth middleware options | Configuration |
| `AuthorizationOptions` | Authorization options | Permission checking |

### Database Types

| Type | Description | Usage |
|------|-------------|-------|
| `DatabaseConfig` | Database configuration | Connection setup |
| `DatabaseConnection` | Database connection | Connection management |
| `DatabaseTransaction` | Database transaction | Transaction handling |
| `QueryParams` | Query parameters | SQL queries |
| `QueryMetadata` | Query metadata | Query information |
| `PreparedStatement` | Prepared statement | SQL execution |
| `Migration` | Database migration | Schema changes |
| `MigrationStatus` | Migration status | Migration tracking |
| `BaseRepository<T>` | Base repository interface | Data access |
| `SoftDeleteRepository<T>` | Soft delete repository | Soft delete operations |

### API Request/Response Types

| Type | Description | HTTP Method |
|------|-------------|-------------|
| `RegisterRequest` | Registration request | POST |
| `LoginRequest` | Login request | POST |
| `RefreshTokenRequest` | Refresh token request | POST |
| `CreateUserRequest` | Create user request | POST |
| `UpdateUserRequest` | Update user request | PUT/PATCH |
| `CreateRoleRequest` | Create role request | POST |
| `LoginResponse` | Login response | POST |
| `RegisterResponse` | Registration response | POST |
| `GetUsersResponse` | Get users response | GET |
| `ValidationErrorResponse` | Validation error response | 400 |
| `AuthErrorResponse` | Auth error response | 401/403 |
| `NotFoundErrorResponse` | Not found error response | 404 |
| `RateLimitErrorResponse` | Rate limit error response | 429 |

### Error Types

| Type | Description | Usage |
|------|-------------|-------|
| `AuthError` | Base authentication error | Error handling |
| `ValidationError` | Validation error | Input validation |
| `AuthenticationError` | Authentication error | Login failures |
| `AuthorizationError` | Authorization error | Permission denied |
| `UserNotFoundError` | User not found error | User lookup |
| `DatabaseError` | Database error | Database operations |
| `TokenError` | Token error | JWT operations |
| `RateLimitError` | Rate limit error | Rate limiting |

### Enums

| Enum | Values | Description |
|------|--------|-------------|
| `AuthErrorType` | `INVALID_CREDENTIALS`, `USER_NOT_FOUND`, `TOKEN_EXPIRED`, etc. | Authentication error types |
| `HttpStatusCode` | `OK`, `CREATED`, `BAD_REQUEST`, `UNAUTHORIZED`, etc. | HTTP status codes |
| `Environment` | `development`, `test`, `staging`, `production` | Environment types |
| `LogLevel` | `debug`, `info`, `warn`, `error` | Logging levels |

### Brand Types

| Type | Description | Purpose |
|------|-------------|----------|
| `Email` | Email string type | Type safety |
| `HashedPassword` | Hashed password type | Security |
| `JWT` | JWT token type | Token handling |
| `RefreshToken` | Refresh token type | Token refresh |
| `EntityId` | Entity ID type | Entity identification |
| `UserId` | User ID type | User identification |
| `RoleId` | Role ID type | Role identification |
| `PermissionId` | Permission ID type | Permission identification |

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
| `testConnection()` | - | Tests database connection |
| `getDatabaseInfo()` | - | Gets database information |
| `rollbackMigrations()` | - | Rolls back migrations |
| `getMigrationStatus()` | - | Gets migration status |

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
| `dev.ts` | Development utilities | `bun run src/scripts/dev.ts` |

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
import { createHonoAuth } from './src/index';

const app = new Hono();
const auth = createHonoAuth({ jwtSecret: 'your-secret' });

// Global authentication middleware
app.use('*', auth.middleware());

// Protected route with permissions
app.get('/admin/users', 
  auth.permissions(['users.read']),
  async (c) => {
    const authService = auth.library.getAuthService();
    const users = await authService.getUsers();
    return c.json(users);
  }
);
```

### Usage with Express

```typescript
import express from 'express';
import { createExpressAuth } from './src/index';

const app = express();
const auth = createExpressAuth({ jwtSecret: 'your-secret' });

// Global authentication middleware
app.use(auth.middleware());

// Protected route with roles
app.get('/admin/dashboard', 
  auth.roles(['admin', 'moderator']),
  async (req, res) => {
    const permissionService = auth.library.getPermissionService();
    const stats = await permissionService.getAuthStats();
    res.json(stats);
  }
);
```

### Usage with WebSockets

```typescript
import { createWebSocketAuth } from './src/index';

const wsAuth = createWebSocketAuth({ jwtSecret: 'your-secret' });

// Initialize cleanup
wsAuth.initCleanup(30000); // 30 seconds

// Handle WebSocket connections
wss.on('connection', async (ws, request) => {
  try {
    const authenticatedWs = await wsAuth.authenticate(ws, request);
    
    // Check permissions
    if (wsAuth.checkPermissions(authenticatedWs, ['chat.read'])) {
      wsAuth.sendToUser(authenticatedWs.userId, { type: 'welcome' });
    }
  } catch (error) {
    ws.close(1008, 'Authentication failed');
  }
});
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
- ✅ **WebSocket Support**: Real-time authentication and authorization
- ✅ **Convenience Functions**: Easy framework integration
- ✅ **Database Utilities**: Migration and seeding tools

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

## Library Information

**Version:** 1.1.2  
**Runtime:** Bun  
**Database:** SQLite  
**License:** MIT  

### Supported Frameworks
- Hono
- Express
- WebSockets
- Socket.IO
- Fastify (via Express adapter)

### Security Features
- Bcrypt password hashing with Bun.password
- JWT token validation with Web Crypto API
- CSRF protection
- Rate limiting
- Input sanitization
- SQL injection prevention
- XSS protection

### Performance Features
- Optimized for Bun runtime
- Connection pooling
- Efficient SQLite queries
- Minimal memory footprint
- Fast startup time

---

## License

MIT License - see LICENSE file for details.

---

## Notes

- The library uses optional configuration parameters for maximum flexibility
- Default user role implementation allows for single default role per system
- All database operations are transactional for data integrity
- WebSocket connections are automatically cleaned up to prevent memory leaks