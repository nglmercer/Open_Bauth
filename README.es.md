# Documentación de la Librería de Autenticación

## Índice

1. [Clase Principal AuthLibrary](#clase-principal-authlibrary)
2. [Servicios Principales](#servicios-principales)
3. [Adaptadores de Frameworks](#adaptadores-de-frameworks)
4. [Middleware Agnóstico](#middleware-agnóstico)
5. [Tipos TypeScript](#tipos-typescript)
6. [Base de Datos](#base-de-datos)
7. [Configuración](#configuración)

---

## Clase Principal AuthLibrary

La clase `AuthLibrary` es el punto de entrada principal para la librería de autenticación. Proporciona una interfaz unificada para acceder a todos los servicios y funcionalidades.

### Métodos Públicos

| Método | Parámetros | Retorno | Descripción |
|--------|------------|---------|-------------|
| `constructor()` | `config: AuthConfig` | `AuthLibrary` | Inicializa la librería con la configuración proporcionada |
| `initialize()` | - | `Promise<void>` | Inicializa la base de datos y ejecuta migraciones |
| `getAuthService()` | - | `AuthService` | Obtiene la instancia del servicio de autenticación |
| `getJWTService()` | - | `JWTService` | Obtiene la instancia del servicio JWT |
| `getPermissionService()` | - | `PermissionService` | Obtiene la instancia del servicio de permisos |
| `createHonoAdapter()` | `config?: AuthMiddlewareConfig` | `HonoAdapter` | Crea un adaptador para el framework Hono |
| `createExpressAdapter()` | `config?: AuthMiddlewareConfig` | `ExpressAdapter` | Crea un adaptador para el framework Express |
| `createWebSocketAdapter()` | `config?: AuthMiddlewareConfig` | `WebSocketAdapter` | Crea un adaptador para WebSockets |

### Ejemplo de Uso

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

// Obtener servicios
const authService = authLib.getAuthService();
const jwtService = authLib.getJWTService();
const permissionService = authLib.getPermissionService();
```

---

## Servicios Principales

### AuthService

Servicio principal para manejo de autenticación, registro y gestión de usuarios.

| Método | Parámetros | Retorno | Descripción |
|--------|------------|---------|-------------|
| `register()` | `data: RegisterData` | `Promise<AuthResult>` | Registra un nuevo usuario en el sistema |
| `login()` | `data: LoginData` | `Promise<AuthResult>` | Autentica un usuario con email y contraseña |
| `findUserById()` | `id: string, options?: UserQueryOptions` | `Promise<User \| null>` | Busca un usuario por su ID |
| `findUserByEmail()` | `email: string, options?: UserQueryOptions` | `Promise<User \| null>` | Busca un usuario por su email |
| `updateUser()` | `userId: string, data: UpdateUserData` | `Promise<{success: boolean, user?: User, error?: AuthError}>` | Actualiza los datos de un usuario |
| `updatePassword()` | `userId: string, newPassword: string` | `Promise<{success: boolean, error?: AuthError}>` | Actualiza la contraseña de un usuario |
| `deactivateUser()` | `userId: string` | `Promise<{success: boolean, error?: AuthError}>` | Desactiva una cuenta de usuario |
| `activateUser()` | `userId: string` | `Promise<{success: boolean, error?: AuthError}>` | Activa una cuenta de usuario |
| `deleteUser()` | `userId: string` | `Promise<{success: boolean, error?: AuthError}>` | Elimina permanentemente un usuario |
| `assignRole()` | `userId: string, roleName: string` | `Promise<{success: boolean, error?: AuthError}>` | Asigna un rol a un usuario |
| `removeRole()` | `userId: string, roleName: string` | `Promise<{success: boolean, error?: AuthError}>` | Remueve un rol de un usuario |
| `getUsers()` | `page?: number, limit?: number, options?: UserQueryOptions` | `Promise<{users: User[], total: number}>` | Obtiene una lista paginada de usuarios |
| `getUserRoles()` | `userId: string, includePermissions?: boolean` | `Promise<Role[]>` | Obtiene los roles de un usuario |

### JWTService

Servicio para generación, verificación y manejo de tokens JWT.

| Método | Parámetros | Retorno | Descripción |
|--------|------------|---------|-------------|
| `generateToken()` | `user: User` | `Promise<string>` | Genera un token JWT para un usuario |
| `verifyToken()` | `token: string` | `Promise<JWTPayload>` | Verifica y decodifica un token JWT |
| `extractTokenFromHeader()` | `authHeader: string` | `string \| null` | Extrae el token del header Authorization (case-insensitive Bearer) |
| `isTokenExpired()` | `token: string` | `boolean` | Verifica si un token ha expirado |
| `getTokenRemainingTime()` | `token: string` | `number` | Obtiene el tiempo restante de un token en segundos |
| `refreshTokenIfNeeded()` | `token: string, user: User, refreshThreshold?: number` | `Promise<string>` | Refresca un token si está próximo a expirar |
| `generateRefreshToken()` | `userId: number` | `Promise<string>` | Genera un token de refresco |
| `verifyRefreshToken()` | `refreshToken: string` | `Promise<number>` | Verifica un token de refresco |

### PermissionService

Servicio para gestión de roles y permisos (RBAC).

| Método | Parámetros | Retorno | Descripción |
|--------|------------|---------|-------------|
| `createPermission()` | `data: CreatePermissionData` | `Promise<PermissionResult>` | Crea un nuevo permiso |
| `createRole()` | `data: CreateRoleData` | `Promise<RoleResult>` | Crea un nuevo rol |
| `updatePermission()` | `permissionId: string, data: UpdatePermissionData` | `Promise<PermissionResult>` | Actualiza un permiso existente |
| `updateRole()` | `roleId: string, data: UpdateRoleData` | `Promise<RoleResult>` | Actualiza un rol existente |
| `deletePermission()` | `permissionId: string` | `Promise<PermissionResult>` | Elimina un permiso |
| `deleteRole()` | `roleId: string` | `Promise<RoleResult>` | Elimina un rol |
| `assignPermissionToRole()` | `roleId: string, permissionId: string` | `Promise<PermissionResult>` | Asigna un permiso a un rol |
| `removePermissionFromRole()` | `roleId: string, permissionId: string` | `Promise<PermissionResult>` | Remueve un permiso de un rol |
| `findPermissionByName()` | `name: string` | `Promise<Permission \| null>` | Busca un permiso por nombre |
| `findRoleByName()` | `name: string` | `Promise<Role \| null>` | Busca un rol por nombre |
| `getAllPermissions()` | - | `Promise<Permission[]>` | Obtiene todos los permisos |
| `getAllRoles()` | - | `Promise<Role[]>` | Obtiene todos los roles |
| `getRolePermissions()` | `roleId: string` | `Promise<Permission[]>` | Obtiene los permisos de un rol |
| `userHasPermission()` | `userId: string, permissionName: string` | `Promise<boolean>` | Verifica si un usuario tiene un permiso específico |
| `userHasRole()` | `userId: string, roleName: string` | `Promise<boolean>` | Verifica si un usuario tiene un rol específico |
| `userCanAccessResource()` | `userId: string, resource: string, action: string` | `Promise<boolean>` | Verifica si un usuario puede acceder a un recurso |

---

## Adaptadores de Frameworks

### Adaptador Hono

Adaptador específico para el framework Hono.

| Función | Parámetros | Retorno | Descripción |
|---------|------------|---------|-------------|
| `honoAuthMiddleware()` | `config?: AuthMiddlewareConfig` | `MiddlewareHandler` | Middleware principal de autenticación |
| `honoOptionalAuth()` | - | `MiddlewareHandler` | Middleware de autenticación opcional |
| `honoRequireAuth()` | - | `MiddlewareHandler` | Middleware que requiere autenticación |
| `honoRequirePermissions()` | `permissions: string[], requireAll?: boolean` | `MiddlewareHandler` | Middleware que requiere permisos específicos |
| `honoRequireRoles()` | `roles: string[]` | `MiddlewareHandler` | Middleware que requiere roles específicos |
| `honoRequireAdmin()` | - | `MiddlewareHandler` | Middleware que requiere rol de administrador |
| `honoRequireModerator()` | - | `MiddlewareHandler` | Middleware que requiere rol de moderador |
| `getHonoCurrentUser()` | `c: Context` | `User \| undefined` | Obtiene el usuario actual del contexto |
| `isHonoAuthenticated()` | `c: Context` | `boolean` | Verifica si la request está autenticada |
| `getHonoAuthContext()` | `c: Context` | `AuthContext` | Obtiene el contexto de autenticación |
| `honoRequireOwnership()` | `getUserIdFromParams: (c: Context) => string` | `MiddlewareHandler` | Middleware que requiere propiedad del recurso |
| `honoRateLimit()` | `maxRequests?: number, windowMs?: number` | `MiddlewareHandler` | Middleware de limitación de velocidad |
| `honoCorsAuth()` | `origins?: string[]` | `MiddlewareHandler` | Middleware CORS para autenticación |
| `honoAuthLogger()` | - | `MiddlewareHandler` | Middleware de logging para autenticación |

### Adaptador Express

Adaptador específico para el framework Express.

| Función | Parámetros | Retorno | Descripción |
|---------|------------|---------|-------------|
| `expressAuthMiddleware()` | `config?: AuthMiddlewareConfig` | `RequestHandler` | Middleware principal de autenticación |
| `expressOptionalAuth()` | - | `RequestHandler` | Middleware de autenticación opcional |
| `expressRequireAuth()` | - | `RequestHandler` | Middleware que requiere autenticación |
| `expressRequirePermissions()` | `permissions: string[], requireAll?: boolean` | `RequestHandler` | Middleware que requiere permisos específicos |
| `expressRequireRoles()` | `roles: string[]` | `RequestHandler` | Middleware que requiere roles específicos |
| `expressRequireAdmin()` | - | `RequestHandler` | Middleware que requiere rol de administrador |
| `expressRequireModerator()` | - | `RequestHandler` | Middleware que requiere rol de moderador |
| `getExpressCurrentUser()` | `req: Request` | `User \| undefined` | Obtiene el usuario actual de la request |
| `isExpressAuthenticated()` | `req: Request` | `boolean` | Verifica si la request está autenticada |
| `getExpressAuthContext()` | `req: Request` | `AuthContext` | Obtiene el contexto de autenticación |
| `expressRequireOwnership()` | `getUserIdFromParams: (req: Request) => string` | `RequestHandler` | Middleware que requiere propiedad del recurso |
| `expressRateLimit()` | `maxRequests?: number, windowMs?: number` | `RequestHandler` | Middleware de limitación de velocidad |
| `expressCorsAuth()` | `origins?: string[]` | `RequestHandler` | Middleware CORS para autenticación |
| `expressAuthLogger()` | - | `RequestHandler` | Middleware de logging para autenticación |
| `expressAuthErrorHandler()` | - | `ErrorRequestHandler` | Middleware de manejo de errores |
| `expressJsonValidator()` | - | `RequestHandler` | Middleware de validación JSON |
| `expressSanitizer()` | - | `RequestHandler` | Middleware de sanitización de datos |

### Adaptador WebSocket

Adaptador para autenticación en conexiones WebSocket.

| Función | Parámetros | Retorno | Descripción |
|---------|------------|---------|-------------|
| `authenticateWebSocket()` | `ws: WebSocket, request: IncomingMessage` | `Promise<AuthenticatedWebSocket>` | Autentica una conexión WebSocket |
| `checkWebSocketPermissions()` | `ws: AuthenticatedWebSocket, permissions: string[]` | `boolean` | Verifica permisos en WebSocket |
| `checkWebSocketRoles()` | `ws: AuthenticatedWebSocket, roles: string[]` | `boolean` | Verifica roles en WebSocket |
| `getWebSocketUser()` | `ws: AuthenticatedWebSocket` | `User \| undefined` | Obtiene el usuario de la conexión WebSocket |
| `isWebSocketAuthenticated()` | `ws: AuthenticatedWebSocket` | `boolean` | Verifica si la conexión está autenticada |

---

## Middleware Agnóstico

Funciones de middleware que funcionan independientemente del framework.

| Función | Parámetros | Retorno | Descripción |
|---------|------------|---------|-------------|
| `authenticateRequest()` | `request: AuthRequest, config?: AuthMiddlewareConfig` | `Promise<AuthResult>` | Autentica una request agnóstica |
| `getCurrentUser()` | `authContext: AuthContext` | `User \| undefined` | Obtiene el usuario actual del contexto |
| `createEmptyAuthContext()` | - | `AuthContext` | Crea un contexto de autenticación vacío |
| `logAuthEvent()` | `event: string, userId?: string, metadata?: any` | `void` | Registra eventos de autenticación |
| `extractClientIP()` | `headers: Record<string, string>` | `string \| undefined` | Extrae la IP del cliente |
| `extractUserAgent()` | `headers: Record<string, string>` | `string \| undefined` | Extrae el User-Agent |
| `validateAuthConfig()` | `config: AuthConfig` | `boolean` | Valida la configuración de autenticación |
| `hashPassword()` | `password: string` | `Promise<string>` | Genera hash de contraseña usando Bun |
| `verifyPassword()` | `password: string, hash: string` | `Promise<boolean>` | Verifica contraseña usando Bun |

---

## Tipos TypeScript

### Interfaces Principales

| Interface | Descripción | Propiedades Principales |
|-----------|-------------|------------------------|
| `User` | Representa un usuario del sistema | `id`, `email`, `roles`, `isActive`, `createdAt` |
| `Role` | Representa un rol en el sistema | `id`, `name`, `permissions`, `description` |
| `Permission` | Representa un permiso específico | `id`, `name`, `resource`, `action` |
| `AuthContext` | Contexto de autenticación | `user`, `token`, `permissions`, `isAuthenticated` |
| `AuthConfig` | Configuración del sistema | `jwtSecret`, `database`, `security`, `cors` |
| `AuthRequest` | Request agnóstica | `headers`, `url`, `method`, `auth` |
| `AuthResult` | Resultado de operaciones auth | `success`, `user`, `token`, `error` |
| `JWTPayload` | Payload del token JWT | `userId`, `email`, `roles`, `iat`, `exp` |

### Tipos de Datos

| Tipo | Descripción | Campos |
|------|-------------|--------|
| `RegisterData` | Datos para registro | `email`, `password`, `firstName`, `lastName` |
| `LoginData` | Datos para login | `email`, `password` |
| `CreatePermissionData` | Datos para crear permiso | `name`, `resource`, `action`, `description` |
| `CreateRoleData` | Datos para crear rol | `name`, `description`, `permissionIds` |
| `UpdateUserData` | Datos para actualizar usuario | `email`, `isActive`, `firstName`, `lastName` |
| `UserQueryOptions` | Opciones de consulta | `includeRoles`, `includePermissions`, `activeOnly` |

### Enums

| Enum | Valores | Descripción |
|------|---------|-------------|
| `AuthErrorType` | `INVALID_CREDENTIALS`, `USER_NOT_FOUND`, `TOKEN_EXPIRED`, etc. | Tipos de errores de autenticación |

---

## Base de Datos

### Tablas Principales

| Tabla | Descripción | Campos Principales |
|-------|-------------|-------------------|
| `users` | Almacena usuarios | `id`, `email`, `password_hash`, `is_active`, `created_at` |
| `roles` | Almacena roles | `id`, `name`, `description`, `is_active`, `created_at` |
| `permissions` | Almacena permisos | `id`, `name`, `resource`, `action`, `created_at` |
| `user_roles` | Relación usuario-rol | `user_id`, `role_id`, `assigned_at` |
| `role_permissions` | Relación rol-permiso | `role_id`, `permission_id`, `assigned_at` |

### Métodos de Base de Datos

| Función | Parámetros | Descripción |
|---------|------------|-------------|
| `initDatabase()` | `path?: string` | Inicializa la conexión a SQLite |
| `getDatabase()` | - | Obtiene la instancia de la base de datos |
| `runMigrations()` | - | Ejecuta las migraciones pendientes |
| `seedDatabase()` | - | Pobla la base de datos con datos iniciales |
| `closeDatabase()` | - | Cierra la conexión a la base de datos |

---

## Configuración

### AuthConfig

Configuración principal del sistema de autenticación.

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

### Configuraciones Específicas

| Configuración | Propiedades | Descripción |
|---------------|-------------|-------------|
| `DatabaseConfig` | `path`, `enableWAL`, `enableForeignKeys`, `busyTimeout` | Configuración de SQLite |
| `SecurityConfig` | `bcryptRounds`, `maxLoginAttempts`, `lockoutDuration` | Configuración de seguridad |
| `CorsConfig` | `origins`, `credentials`, `methods`, `headers` | Configuración CORS |
| `RateLimitConfig` | `windowMs`, `maxRequests`, `skipSuccessfulRequests` | Configuración de rate limiting |
| `LoggingConfig` | `level`, `enableConsole`, `enableFile`, `filePath` | Configuración de logging |

### Scripts de Utilidad

| Script | Descripción | Uso |
|--------|-------------|-----|
| `seed.ts` | Pobla la base de datos con datos iniciales | `bun run src/scripts/seed.ts` |
| `migrate.ts` | Ejecuta migraciones de base de datos | `bun run src/scripts/migrate.ts` |
| `reset.ts` | Reinicia la base de datos | `bun run src/scripts/reset.ts` |

---

## Ejemplos de Uso

### Configuración Básica

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
    lockoutDuration: 900000, // 15 minutos
    sessionTimeout: 86400000, // 24 horas
    passwordMinLength: 8,
    passwordRequireUppercase: true,
    passwordRequireLowercase: true,
    passwordRequireNumbers: true,
    passwordRequireSymbols: false
  }
});

await authLib.initialize();
```

### Uso con Hono

```typescript
import { Hono } from 'hono';
import { honoAuthMiddleware, honoRequirePermissions } from './src/adapters/hono';

const app = new Hono();

// Middleware global de autenticación
app.use('*', honoAuthMiddleware());

// Ruta protegida con permisos
app.get('/admin/users', 
  honoRequirePermissions(['users.read']),
  async (c) => {
    const authService = authLib.getAuthService();
    const users = await authService.getUsers();
    return c.json(users);
  }
);
```

### Uso con Express

```typescript
import express from 'express';
import { expressAuthMiddleware, expressRequireRoles } from './src/adapters/express';

const app = express();

// Middleware global de autenticación
app.use(expressAuthMiddleware());

// Ruta protegida con roles
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

## Características Principales

- ✅ **Framework Agnóstico**: Funciona con Hono, Express, WebSockets y más
- ✅ **TypeScript Nativo**: Tipado completo y seguro
- ✅ **SQLite con Bun**: Base de datos embebida optimizada
- ✅ **JWT Seguro**: Implementación nativa con Web Crypto API
- ✅ **RBAC Completo**: Sistema de roles y permisos granular
- ✅ **Middleware Flexible**: Autenticación opcional y requerida
- ✅ **Rate Limiting**: Protección contra ataques de fuerza bruta
- ✅ **Logging Avanzado**: Registro detallado de eventos de seguridad
- ✅ **Validación Robusta**: Sanitización y validación de datos
- ✅ **Configuración Flexible**: Altamente personalizable

---

*Documentación generada automáticamente para la Librería de Autenticación v1.0.0*