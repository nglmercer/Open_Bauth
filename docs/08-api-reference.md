# 📖 API Reference

Referencia completa de la API de la librería de autenticación, incluyendo todas las clases, interfaces, tipos y métodos disponibles.

## 📋 Índice

- [🏗️ AuthLibrary](#️-authlibrary)
- [🔐 AuthService](#-authservice)
- [🎫 JWTService](#-jwtservice)
- [🛡️ PermissionService](#️-permissionservice)
- [📝 AuditService](#-auditservice)
- [🔌 Framework Adapters](#-framework-adapters)
- [🔧 Interfaces y Tipos](#-interfaces-y-tipos)
- [⚙️ Configuración](#️-configuración)
- [🚨 Errores](#-errores)

---

## 🏗️ AuthLibrary

Clase principal que gestiona toda la funcionalidad de autenticación.

### Constructor

```typescript
new AuthLibrary(config: AuthConfig)
```

#### Parámetros

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `config` | `AuthConfig` | Configuración de la librería |

### Métodos

#### `initialize(): Promise<void>`

Inicializa la librería y establece conexiones con la base de datos.

```typescript
const authLib = new AuthLibrary(config);
await authLib.initialize();
```

**Throws:** `AuthLibraryError` si falla la inicialización

#### `getAuthService(): AuthService`

Obtiene la instancia del servicio de autenticación.

```typescript
const authService = authLib.getAuthService();
```

**Returns:** `AuthService` - Instancia del servicio de autenticación

#### `getJWTService(): JWTService`

Obtiene la instancia del servicio JWT.

```typescript
const jwtService = authLib.getJWTService();
```

**Returns:** `JWTService` - Instancia del servicio JWT

#### `getPermissionService(): PermissionService`

Obtiene la instancia del servicio de permisos.

```typescript
const permissionService = authLib.getPermissionService();
```

**Returns:** `PermissionService` - Instancia del servicio de permisos

#### `getAuditService(): AuditService`

Obtiene la instancia del servicio de auditoría.

```typescript
const auditService = authLib.getAuditService();
```

**Returns:** `AuditService` - Instancia del servicio de auditoría

#### `close(): Promise<void>`

Cierra todas las conexiones y limpia recursos.

```typescript
await authLib.close();
```

---

## 🔐 AuthService

Servicio principal para operaciones de autenticación y gestión de usuarios.

### Métodos de Autenticación

#### `register(userData: RegisterData): Promise<User>`

Registra un nuevo usuario en el sistema.

```typescript
const user = await authService.register({
  email: 'user@example.com',
  password: 'securePassword123',
  profile: {
    name: 'John Doe',
    phone: '+1234567890'
  }
});
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `userData` | `RegisterData` | Datos del usuario a registrar |

**Returns:** `Promise<User>` - Usuario creado

**Throws:** 
- `ValidationError` - Datos inválidos
- `ConflictError` - Email ya existe
- `AuthServiceError` - Error interno

#### `login(email: string, password: string): Promise<LoginResult>`

Autentica un usuario con email y contraseña.

```typescript
const result = await authService.login('user@example.com', 'password123');
if (result.success) {
  console.log('Usuario autenticado:', result.user);
} else {
  console.log('Error:', result.message);
}
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `email` | `string` | Email del usuario |
| `password` | `string` | Contraseña del usuario |

**Returns:** `Promise<LoginResult>` - Resultado del login

#### `logout(userId: string): Promise<void>`

Cierra la sesión de un usuario.

```typescript
await authService.logout(user.id);
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `userId` | `string` | ID del usuario |

### Métodos de Gestión de Usuarios

#### `getUserById(id: string): Promise<User | null>`

Obtiene un usuario por su ID.

```typescript
const user = await authService.getUserById('user-id-123');
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `id` | `string` | ID del usuario |

**Returns:** `Promise<User | null>` - Usuario encontrado o null

#### `getUserByEmail(email: string): Promise<User | null>`

Obtiene un usuario por su email.

```typescript
const user = await authService.getUserByEmail('user@example.com');
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `email` | `string` | Email del usuario |

**Returns:** `Promise<User | null>` - Usuario encontrado o null

#### `updateUser(id: string, updates: Partial<User>): Promise<User>`

Actualiza los datos de un usuario.

```typescript
const updatedUser = await authService.updateUser('user-id-123', {
  profile: {
    name: 'New Name',
    phone: '+9876543210'
  }
});
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `id` | `string` | ID del usuario |
| `updates` | `Partial<User>` | Datos a actualizar |

**Returns:** `Promise<User>` - Usuario actualizado

#### `changePassword(userId: string, currentPassword: string, newPassword: string): Promise<PasswordChangeResult>`

Cambia la contraseña de un usuario.

```typescript
const result = await authService.changePassword(
  'user-id-123',
  'currentPassword',
  'newSecurePassword'
);
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `userId` | `string` | ID del usuario |
| `currentPassword` | `string` | Contraseña actual |
| `newPassword` | `string` | Nueva contraseña |

**Returns:** `Promise<PasswordChangeResult>` - Resultado del cambio

#### `resetPassword(email: string): Promise<ResetPasswordResult>`

Inicia el proceso de recuperación de contraseña.

```typescript
const result = await authService.resetPassword('user@example.com');
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `email` | `string` | Email del usuario |

**Returns:** `Promise<ResetPasswordResult>` - Resultado del reset

#### `deactivateUser(id: string): Promise<void>`

Desactiva un usuario.

```typescript
await authService.deactivateUser('user-id-123');
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `id` | `string` | ID del usuario |

### Métodos de Consulta

#### `getUsers(options?: GetUsersOptions): Promise<PaginatedResult<User>>`

Obtiene una lista paginada de usuarios.

```typescript
const users = await authService.getUsers({
  page: 1,
  limit: 10,
  search: 'john',
  role: 'admin'
});
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `options` | `GetUsersOptions` | Opciones de filtrado y paginación |

**Returns:** `Promise<PaginatedResult<User>>` - Resultado paginado

---

## 🎫 JWTService

Servicio para gestión de tokens JWT.

### Métodos de Generación

#### `generateToken(payload: TokenPayload, options?: TokenOptions): Promise<string>`

Genera un token JWT.

```typescript
const token = await jwtService.generateToken({
  userId: 'user-id-123',
  email: 'user@example.com',
  roles: ['user']
}, {
  expiresIn: '2h'
});
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `payload` | `TokenPayload` | Datos a incluir en el token |
| `options` | `TokenOptions` | Opciones del token (opcional) |

**Returns:** `Promise<string>` - Token JWT generado

#### `generateRefreshToken(payload: RefreshTokenPayload): Promise<string>`

Genera un refresh token.

```typescript
const refreshToken = await jwtService.generateRefreshToken({
  userId: 'user-id-123'
});
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `payload` | `RefreshTokenPayload` | Datos del refresh token |

**Returns:** `Promise<string>` - Refresh token generado

### Métodos de Verificación

#### `verifyToken(token: string): Promise<TokenPayload | null>`

Verifica y decodifica un token JWT.

```typescript
const payload = await jwtService.verifyToken(token);
if (payload) {
  console.log('Token válido para usuario:', payload.userId);
}
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `token` | `string` | Token a verificar |

**Returns:** `Promise<TokenPayload | null>` - Payload del token o null si es inválido

#### `verifyRefreshToken(token: string): Promise<RefreshTokenPayload | null>`

Verifica un refresh token.

```typescript
const payload = await jwtService.verifyRefreshToken(refreshToken);
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `token` | `string` | Refresh token a verificar |

**Returns:** `Promise<RefreshTokenPayload | null>` - Payload o null

### Métodos de Gestión

#### `invalidateToken(token: string): Promise<void>`

Invalida un token (lo añade a la blacklist).

```typescript
await jwtService.invalidateToken(token);
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `token` | `string` | Token a invalidar |

#### `isTokenBlacklisted(token: string): Promise<boolean>`

Verifica si un token está en la blacklist.

```typescript
const isBlacklisted = await jwtService.isTokenBlacklisted(token);
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `token` | `string` | Token a verificar |

**Returns:** `Promise<boolean>` - true si está en blacklist

---

## 🛡️ PermissionService

Servicio para gestión de roles y permisos.

### Métodos de Roles

#### `createRole(roleData: CreateRoleData): Promise<Role>`

Crea un nuevo rol.

```typescript
const role = await permissionService.createRole({
  name: 'editor',
  description: 'Editor de contenido',
  permissions: ['content.read', 'content.write']
});
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `roleData` | `CreateRoleData` | Datos del rol |

**Returns:** `Promise<Role>` - Rol creado

#### `assignRole(userId: string, roleName: string): Promise<void>`

Asigna un rol a un usuario.

```typescript
await permissionService.assignRole('user-id-123', 'editor');
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `userId` | `string` | ID del usuario |
| `roleName` | `string` | Nombre del rol |

#### `removeRole(userId: string, roleName: string): Promise<void>`

Remueve un rol de un usuario.

```typescript
await permissionService.removeRole('user-id-123', 'editor');
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `userId` | `string` | ID del usuario |
| `roleName` | `string` | Nombre del rol |

#### `getUserRoles(userId: string): Promise<string[]>`

Obtiene los roles de un usuario.

```typescript
const roles = await permissionService.getUserRoles('user-id-123');
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `userId` | `string` | ID del usuario |

**Returns:** `Promise<string[]>` - Lista de roles

### Métodos de Permisos

#### `createPermission(permissionData: CreatePermissionData): Promise<Permission>`

Crea un nuevo permiso.

```typescript
const permission = await permissionService.createPermission({
  name: 'content.publish',
  description: 'Publicar contenido',
  resource: 'content',
  action: 'publish'
});
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `permissionData` | `CreatePermissionData` | Datos del permiso |

**Returns:** `Promise<Permission>` - Permiso creado

#### `hasPermission(userId: string, permission: string): Promise<boolean>`

Verifica si un usuario tiene un permiso específico.

```typescript
const hasPermission = await permissionService.hasPermission(
  'user-id-123',
  'content.publish'
);
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `userId` | `string` | ID del usuario |
| `permission` | `string` | Nombre del permiso |

**Returns:** `Promise<boolean>` - true si tiene el permiso

#### `getUserPermissions(userId: string): Promise<string[]>`

Obtiene todos los permisos de un usuario.

```typescript
const permissions = await permissionService.getUserPermissions('user-id-123');
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `userId` | `string` | ID del usuario |

**Returns:** `Promise<string[]>` - Lista de permisos

#### `checkPermissions(userId: string, permissions: string[]): Promise<PermissionCheckResult>`

Verifica múltiples permisos a la vez.

```typescript
const result = await permissionService.checkPermissions(
  'user-id-123',
  ['content.read', 'content.write', 'content.publish']
);
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `userId` | `string` | ID del usuario |
| `permissions` | `string[]` | Lista de permisos a verificar |

**Returns:** `Promise<PermissionCheckResult>` - Resultado de la verificación

---

## 📝 AuditService

Servicio para auditoría y logging de acciones.

### Métodos de Logging

#### `log(entry: AuditEntry): Promise<void>`

Registra una entrada de auditoría.

```typescript
await auditService.log({
  userId: 'user-id-123',
  action: 'user_login',
  resource: 'auth',
  metadata: {
    ip: '192.168.1.1',
    userAgent: 'Mozilla/5.0...'
  }
});
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `entry` | `AuditEntry` | Entrada de auditoría |

#### `logError(error: AuditError): Promise<void>`

Registra un error en el sistema de auditoría.

```typescript
await auditService.logError({
  userId: 'user-id-123',
  error: 'Database connection failed',
  stack: error.stack,
  metadata: {
    operation: 'user_creation',
    timestamp: new Date()
  }
});
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `error` | `AuditError` | Error a registrar |

### Métodos de Consulta

#### `getAuditLogs(options: AuditQueryOptions): Promise<PaginatedResult<AuditLog>>`

Obtiene logs de auditoría con filtros.

```typescript
const logs = await auditService.getAuditLogs({
  userId: 'user-id-123',
  action: 'user_login',
  startDate: new Date('2024-01-01'),
  endDate: new Date('2024-01-31'),
  page: 1,
  limit: 50
});
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `options` | `AuditQueryOptions` | Opciones de consulta |

**Returns:** `Promise<PaginatedResult<AuditLog>>` - Logs paginados

#### `getUserActivity(userId: string, options?: ActivityOptions): Promise<UserActivity[]>`

Obtiene la actividad de un usuario específico.

```typescript
const activity = await auditService.getUserActivity('user-id-123', {
  limit: 20,
  includeErrors: true
});
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `userId` | `string` | ID del usuario |
| `options` | `ActivityOptions` | Opciones de consulta (opcional) |

**Returns:** `Promise<UserActivity[]>` - Actividad del usuario

---

## 🔌 Framework Adapters

### Express Adapter

#### `createExpressAdapter(authLib: AuthLibrary): ExpressAuthAdapter`

Crea un adaptador para Express.js.

```typescript
import { createExpressAdapter } from '@Open_Bauth/express';

const auth = createExpressAdapter(authLib);
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `authLib` | `AuthLibrary` | Instancia de AuthLibrary |

**Returns:** `ExpressAuthAdapter` - Adaptador configurado

#### ExpressAuthAdapter Methods

##### `middleware: RequestHandler`

Middleware base para autenticación.

```typescript
app.use(auth.middleware);
```

##### `required: RequestHandler`

Middleware que requiere autenticación.

```typescript
app.get('/protected', auth.required, (req, res) => {
  res.json({ user: req.user });
});
```

##### `optional: RequestHandler`

Middleware de autenticación opcional.

```typescript
app.get('/public', auth.optional, (req, res) => {
  if (req.user) {
    res.json({ message: 'Authenticated user', user: req.user });
  } else {
    res.json({ message: 'Anonymous user' });
  }
});
```

##### `permissions(permissions: string[]): RequestHandler`

Middleware para verificar permisos específicos.

```typescript
app.post('/admin', auth.permissions(['admin.access']), (req, res) => {
  res.json({ message: 'Admin access granted' });
});
```

##### `roles(roles: string[]): RequestHandler`

Middleware para verificar roles específicos.

```typescript
app.get('/manager', auth.roles(['manager', 'admin']), (req, res) => {
  res.json({ message: 'Manager access granted' });
});
```

### Hono Adapter

#### `createHonoAdapter(authLib: AuthLibrary): HonoAuthAdapter`

Crea un adaptador para Hono.

```typescript
import { createHonoAdapter } from '@Open_Bauth/hono';

const auth = createHonoAdapter(authLib);
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `authLib` | `AuthLibrary` | Instancia de AuthLibrary |

**Returns:** `HonoAuthAdapter` - Adaptador configurado

#### HonoAuthAdapter Methods

##### `middleware(): MiddlewareHandler`

Middleware base para Hono.

```typescript
app.use('*', auth.middleware());
```

##### `required(): MiddlewareHandler`

Middleware que requiere autenticación.

```typescript
app.get('/protected', auth.required(), (c) => {
  return c.json({ user: c.get('user') });
});
```

---

## 🔧 Interfaces y Tipos

### Core Types

#### `User`

```typescript
interface User {
  id: string;
  email: string;
  passwordHash: string;
  profile: UserProfile;
  active: boolean;
  emailVerified: boolean;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt?: Date;
}
```

#### `UserProfile`

```typescript
interface UserProfile {
  name: string;
  phone?: string;
  avatar?: string;
  bio?: string;
  preferences?: Record<string, any>;
}
```

#### `Role`

```typescript
interface Role {
  id: string;
  name: string;
  description?: string;
  permissions: string[];
  createdAt: Date;
  updatedAt: Date;
}
```

#### `Permission`

```typescript
interface Permission {
  id: string;
  name: string;
  description?: string;
  resource: string;
  action: string;
  createdAt: Date;
}
```

### Request/Response Types

#### `RegisterData`

```typescript
interface RegisterData {
  email: string;
  password: string;
  profile: Partial<UserProfile>;
}
```

#### `LoginResult`

```typescript
interface LoginResult {
  success: boolean;
  user?: User;
  message?: string;
  attempts?: number;
  lockedUntil?: Date;
}
```

#### `TokenPayload`

```typescript
interface TokenPayload {
  userId: string;
  email: string;
  roles?: string[];
  permissions?: string[];
  iat?: number;
  exp?: number;
}
```

#### `RefreshTokenPayload`

```typescript
interface RefreshTokenPayload {
  userId: string;
  tokenId: string;
  iat?: number;
  exp?: number;
}
```

#### `PasswordChangeResult`

```typescript
interface PasswordChangeResult {
  success: boolean;
  message?: string;
}
```

#### `ResetPasswordResult`

```typescript
interface ResetPasswordResult {
  success: boolean;
  resetToken?: string;
  expiresAt?: Date;
  message?: string;
}
```

### Query Types

#### `GetUsersOptions`

```typescript
interface GetUsersOptions {
  page?: number;
  limit?: number;
  search?: string;
  role?: string;
  active?: boolean;
  sortBy?: 'name' | 'email' | 'createdAt' | 'lastLoginAt';
  sortOrder?: 'asc' | 'desc';
}
```

#### `PaginatedResult<T>`

```typescript
interface PaginatedResult<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}
```

#### `PermissionCheckResult`

```typescript
interface PermissionCheckResult {
  hasAllPermissions: boolean;
  permissions: {
    [permission: string]: boolean;
  };
  missingPermissions: string[];
}
```

### Audit Types

#### `AuditEntry`

```typescript
interface AuditEntry {
  userId?: string;
  action: string;
  resource?: string;
  resourceId?: string;
  metadata?: Record<string, any>;
  ip?: string;
  userAgent?: string;
}
```

#### `AuditLog`

```typescript
interface AuditLog {
  id: string;
  userId?: string;
  action: string;
  resource?: string;
  resourceId?: string;
  metadata?: Record<string, any>;
  ip?: string;
  userAgent?: string;
  timestamp: Date;
}
```

#### `AuditError`

```typescript
interface AuditError {
  userId?: string;
  error: string;
  stack?: string;
  metadata?: Record<string, any>;
}
```

#### `AuditQueryOptions`

```typescript
interface AuditQueryOptions {
  userId?: string;
  action?: string;
  resource?: string;
  startDate?: Date;
  endDate?: Date;
  page?: number;
  limit?: number;
  sortOrder?: 'asc' | 'desc';
}
```

#### `UserActivity`

```typescript
interface UserActivity {
  action: string;
  resource?: string;
  timestamp: Date;
  metadata?: Record<string, any>;
  success: boolean;
}
```

---

## ⚙️ Configuración

### `AuthConfig`

```typescript
interface AuthConfig {
  database: DatabaseConfig;
  jwt: JWTConfig;
  security?: SecurityConfig;
  redis?: RedisConfig;
  email?: EmailConfig;
  logging?: LoggingConfig;
}
```

### `DatabaseConfig`

```typescript
interface DatabaseConfig {
  type: 'postgresql' | 'mysql' | 'sqlite' | 'mongodb';
  host?: string;
  port?: number;
  database: string;
  username?: string;
  password?: string;
  ssl?: boolean;
  poolSize?: number;
  connectionTimeout?: number;
}
```

### `JWTConfig`

```typescript
interface JWTConfig {
  secret: string;
  expiresIn?: string | number;
  refreshExpiresIn?: string | number;
  algorithm?: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512';
  issuer?: string;
  audience?: string;
}
```

### `SecurityConfig`

```typescript
interface SecurityConfig {
  bcryptRounds?: number;
  maxLoginAttempts?: number;
  lockoutDuration?: number;
  passwordMinLength?: number;
  passwordRequireUppercase?: boolean;
  passwordRequireLowercase?: boolean;
  passwordRequireNumbers?: boolean;
  passwordRequireSymbols?: boolean;
  sessionTimeout?: number;
  enableTwoFactor?: boolean;
}
```

### `RedisConfig`

```typescript
interface RedisConfig {
  host: string;
  port?: number;
  password?: string;
  database?: number;
  keyPrefix?: string;
  connectTimeout?: number;
  lazyConnect?: boolean;
}
```

### `EmailConfig`

```typescript
interface EmailConfig {
  provider: 'smtp' | 'sendgrid' | 'mailgun' | 'ses';
  smtp?: {
    host: string;
    port: number;
    secure?: boolean;
    auth: {
      user: string;
      pass: string;
    };
  };
  apiKey?: string;
  from: string;
  templates?: {
    welcome?: string;
    resetPassword?: string;
    emailVerification?: string;
  };
}
```

### `LoggingConfig`

```typescript
interface LoggingConfig {
  level: 'error' | 'warn' | 'info' | 'debug';
  format: 'json' | 'text';
  destination?: 'console' | 'file' | 'database';
  filePath?: string;
  maxFileSize?: string;
  maxFiles?: number;
}
```

---

## 🚨 Errores

### Jerarquía de Errores

```typescript
class AuthLibraryError extends Error {
  code: string;
  statusCode: number;
}

class ValidationError extends AuthLibraryError {
  details: ValidationDetail[];
}

class AuthenticationError extends AuthLibraryError {}

class AuthorizationError extends AuthLibraryError {
  requiredPermissions?: string[];
  userPermissions?: string[];
}

class ConflictError extends AuthLibraryError {}

class NotFoundError extends AuthLibraryError {}

class RateLimitError extends AuthLibraryError {
  retryAfter: number;
}

class TokenError extends AuthLibraryError {
  tokenType: 'access' | 'refresh';
}
```

### Códigos de Error

| Código | Descripción | Status Code |
|--------|-------------|-------------|
| `AUTH_001` | Credenciales inválidas | 401 |
| `AUTH_002` | Token expirado | 401 |
| `AUTH_003` | Token inválido | 401 |
| `AUTH_004` | Usuario no encontrado | 404 |
| `AUTH_005` | Email ya existe | 409 |
| `AUTH_006` | Permisos insuficientes | 403 |
| `AUTH_007` | Cuenta bloqueada | 423 |
| `AUTH_008` | Demasiados intentos | 429 |
| `VALID_001` | Datos de entrada inválidos | 400 |
| `VALID_002` | Email inválido | 400 |
| `VALID_003` | Contraseña débil | 400 |
| `DB_001` | Error de conexión a BD | 500 |
| `DB_002` | Error de consulta | 500 |
| `REDIS_001` | Error de conexión a Redis | 500 |

### Manejo de Errores

```typescript
try {
  const user = await authService.login(email, password);
} catch (error) {
  if (error instanceof AuthenticationError) {
    console.log('Error de autenticación:', error.message);
  } else if (error instanceof ValidationError) {
    console.log('Errores de validación:', error.details);
  } else if (error instanceof RateLimitError) {
    console.log(`Demasiados intentos. Reintentar en ${error.retryAfter} segundos`);
  } else {
    console.log('Error inesperado:', error.message);
  }
}
```

---

## 🔗 Enlaces Relacionados

- **[Guía de Inicio Rápido](./01-quick-start.md)** - Primeros pasos
- **[Ejemplos Prácticos](./07-examples.md)** - Implementaciones completas
- **[Troubleshooting](./09-troubleshooting.md)** - Solución de problemas
- **[Configuración](./02-installation-config.md)** - Configuración detallada

---

[⬅️ Ejemplos](./07-examples.md) | [🏠 Índice](./README.md) | [➡️ Troubleshooting](./09-troubleshooting.md)