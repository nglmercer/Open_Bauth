# 🔧 Servicios Principales

Los servicios principales de la librería proporcionan toda la funcionalidad de autenticación, autorización y gestión de tokens. Cada servicio tiene responsabilidades específicas y trabajan en conjunto para ofrecer una solución completa.

## 📋 Índice

1. [Descripción General](#descripción-general)
2. [AuthService](#authservice)
3. [JWTService](#jwtservice)
4. [PermissionService](#permissionservice)
5. [Integración entre Servicios](#integración-entre-servicios)
6. [Ejemplos Prácticos](#ejemplos-prácticos)
7. [Mejores Prácticas](#mejores-prácticas)

## 🎯 Descripción General

### Arquitectura de Servicios

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AuthService   │    │   JWTService    │    │PermissionService│
│                 │    │                 │    │                 │
│ • Registro      │    │ • Generar JWT   │    │ • Roles         │
│ • Login         │    │ • Verificar JWT │    │ • Permisos      │
│ • Gestión Users │    │ • Refresh Token │    │ • Autorización  │
│ • Validaciones  │    │ • Expiración    │    │ • RBAC          │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   AuthLibrary   │
                    │   (Coordinador) │
                    └─────────────────┘
```

### Responsabilidades

- **AuthService**: Autenticación, registro, gestión de usuarios
- **JWTService**: Generación, verificación y gestión de tokens JWT
- **PermissionService**: Autorización, roles, permisos y control de acceso

---

## 🔐 AuthService

El `AuthService` maneja toda la lógica de autenticación y gestión de usuarios.

### Métodos Principales

#### `register(userData: RegisterData): Promise<AuthResult>`

Registra un nuevo usuario en el sistema.

```typescript
interface RegisterData {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  metadata?: Record<string, any>;
}

interface AuthResult {
  success: boolean;
  user?: User;
  token?: string;
  refreshToken?: string;
  error?: AuthError;
}

// Ejemplo de uso
const authService = authLib.getAuthService();

const result = await authService.register({
  email: 'usuario@ejemplo.com',
  password: 'MiPassword123!',
  firstName: 'Juan',
  lastName: 'Pérez',
  metadata: {
    department: 'IT',
    position: 'Developer'
  }
});

if (result.success) {
  console.log('Usuario registrado:', result.user);
  console.log('Token generado:', result.token);
} else {
  console.error('Error:', result.error?.message);
}
```

**Validaciones automáticas:**
- Email único en el sistema
- Formato de email válido
- Contraseña cumple requisitos de seguridad
- Campos requeridos presentes

**Proceso interno:**
1. Valida datos de entrada
2. Verifica que el email no exista
3. Hashea la contraseña con bcrypt
4. Crea el usuario en la base de datos
5. Asigna rol por defecto ('user')
6. Genera token JWT
7. Retorna resultado

#### `login(credentials: LoginData): Promise<AuthResult>`

Autentica un usuario existente.

```typescript
interface LoginData {
  email: string;
  password: string;
  rememberMe?: boolean;
}

// Ejemplo de uso
const result = await authService.login({
  email: 'usuario@ejemplo.com',
  password: 'MiPassword123!',
  rememberMe: true
});

if (result.success) {
  console.log('Login exitoso');
  console.log('Usuario:', result.user);
  console.log('Token:', result.token);
  
  // Si rememberMe es true, también se incluye refreshToken
  if (result.refreshToken) {
    console.log('Refresh Token:', result.refreshToken);
  }
} else {
  console.error('Login fallido:', result.error?.message);
}
```

**Características de seguridad:**
- Protección contra ataques de fuerza bruta
- Bloqueo temporal después de intentos fallidos
- Registro de intentos de login
- Validación de contraseña con bcrypt

**Proceso interno:**
1. Busca usuario por email
2. Verifica que la cuenta no esté bloqueada
3. Compara contraseña con hash almacenado
4. Actualiza último login
5. Resetea contador de intentos fallidos
6. Genera tokens JWT
7. Retorna resultado

#### `refreshToken(refreshToken: string): Promise<AuthResult>`

Renueva un token JWT usando un refresh token.

```typescript
// Ejemplo de uso
const result = await authService.refreshToken(storedRefreshToken);

if (result.success) {
  console.log('Token renovado:', result.token);
  // Actualizar token en el cliente
  localStorage.setItem('authToken', result.token!);
} else {
  console.error('Refresh token inválido');
  // Redirigir a login
}
```

#### `logout(token: string): Promise<void>`

Cierra sesión invalidando el token.

```typescript
// Ejemplo de uso
await authService.logout(currentToken);
console.log('Sesión cerrada');

// Limpiar tokens del cliente
localStorage.removeItem('authToken');
localStorage.removeItem('refreshToken');
```

#### `changePassword(userId: string, oldPassword: string, newPassword: string): Promise<boolean>`

Cambia la contraseña de un usuario.

```typescript
// Ejemplo de uso
const success = await authService.changePassword(
  user.id,
  'passwordActual',
  'nuevoPassword123!'
);

if (success) {
  console.log('Contraseña cambiada exitosamente');
} else {
  console.error('Error cambiando contraseña');
}
```

#### `resetPassword(email: string): Promise<string>`

Inicia proceso de recuperación de contraseña.

```typescript
// Ejemplo de uso
const resetToken = await authService.resetPassword('usuario@ejemplo.com');

// En una aplicación real, enviarías este token por email
console.log('Token de reset:', resetToken);

// El usuario usaría este token para establecer nueva contraseña
const success = await authService.confirmPasswordReset(
  resetToken,
  'nuevaPassword123!'
);
```

### Gestión de Usuarios

#### `getUsers(options?: GetUsersOptions): Promise<User[]>`

Obtiene lista de usuarios con opciones de filtrado.

```typescript
interface GetUsersOptions {
  limit?: number;
  offset?: number;
  search?: string;
  role?: string;
  active?: boolean;
  sortBy?: 'email' | 'firstName' | 'lastName' | 'createdAt';
  sortOrder?: 'asc' | 'desc';
}

// Ejemplos de uso

// Obtener todos los usuarios
const allUsers = await authService.getUsers();

// Búsqueda paginada
const users = await authService.getUsers({
  limit: 10,
  offset: 0,
  search: 'juan',
  sortBy: 'firstName',
  sortOrder: 'asc'
});

// Filtrar por rol
const admins = await authService.getUsers({
  role: 'admin',
  active: true
});
```

#### `findUserById(id: string): Promise<User | null>`

```typescript
const user = await authService.findUserById('user-123');
if (user) {
  console.log('Usuario encontrado:', user.email);
}
```

#### `findUserByEmail(email: string): Promise<User | null>`

```typescript
const user = await authService.findUserByEmail('usuario@ejemplo.com');
if (user) {
  console.log('Usuario encontrado:', user.firstName);
}
```

#### `updateUser(id: string, updates: Partial<User>): Promise<User | null>`

```typescript
const updatedUser = await authService.updateUser('user-123', {
  firstName: 'Juan Carlos',
  metadata: {
    department: 'Engineering',
    position: 'Senior Developer'
  }
});
```

#### `deleteUser(id: string): Promise<boolean>`

```typescript
const deleted = await authService.deleteUser('user-123');
if (deleted) {
  console.log('Usuario eliminado');
}
```

#### `activateUser(id: string): Promise<boolean>`

```typescript
const activated = await authService.activateUser('user-123');
```

#### `deactivateUser(id: string): Promise<boolean>`

```typescript
const deactivated = await authService.deactivateUser('user-123');
```

---

## 🎫 JWTService

El `JWTService` maneja toda la lógica relacionada con tokens JWT.

### Métodos Principales

#### `generateToken(user: User, options?: TokenOptions): Promise<string>`

Genera un token JWT para un usuario.

```typescript
interface TokenOptions {
  expiresIn?: string;
  audience?: string;
  issuer?: string;
  subject?: string;
  includePermissions?: boolean;
}

// Ejemplo básico
const jwtService = authLib.getJWTService();
const token = await jwtService.generateToken(user);

// Con opciones personalizadas
const customToken = await jwtService.generateToken(user, {
  expiresIn: '2h',
  audience: 'my-app',
  includePermissions: true
});

console.log('Token generado:', customToken);
```

**Payload del token incluye:**
- `userId`: ID del usuario
- `email`: Email del usuario
- `roles`: Roles asignados
- `permissions`: Permisos (si se solicita)
- `iat`: Timestamp de emisión
- `exp`: Timestamp de expiración
- `aud`: Audiencia (si se especifica)
- `iss`: Emisor (si se especifica)
- `sub`: Sujeto (si se especifica)

#### `verifyToken(token: string): Promise<JWTPayload>`

Verifica y decodifica un token JWT.

```typescript
interface JWTPayload {
  userId: string;
  email: string;
  roles: string[];
  permissions?: string[];
  iat: number;
  exp: number;
  aud?: string;
  iss?: string;
  sub?: string;
}

// Ejemplo de uso
try {
  const payload = await jwtService.verifyToken(token);
  console.log('Token válido para usuario:', payload.email);
  console.log('Roles:', payload.roles);
  console.log('Expira en:', new Date(payload.exp * 1000));
} catch (error) {
  console.error('Token inválido:', error.message);
  // Manejar token inválido o expirado
}
```

**Validaciones automáticas:**
- Firma del token
- Fecha de expiración
- Formato del payload
- Algoritmo de firma

#### `refreshToken(refreshToken: string): Promise<string>`

Genera un nuevo token usando un refresh token.

```typescript
// Ejemplo de uso
try {
  const newToken = await jwtService.refreshToken(storedRefreshToken);
  console.log('Nuevo token:', newToken);
  
  // Actualizar en el cliente
  localStorage.setItem('authToken', newToken);
} catch (error) {
  console.error('Refresh token inválido');
  // Redirigir a login
}
```

#### `isTokenExpired(token: string): boolean`

Verifica si un token ha expirado sin validar la firma.

```typescript
// Ejemplo de uso
const token = localStorage.getItem('authToken');

if (token && jwtService.isTokenExpired(token)) {
  console.log('Token expirado, intentando renovar...');
  
  const refreshToken = localStorage.getItem('refreshToken');
  if (refreshToken) {
    try {
      const newToken = await jwtService.refreshToken(refreshToken);
      localStorage.setItem('authToken', newToken);
    } catch (error) {
      // Redirigir a login
      window.location.href = '/login';
    }
  }
}
```

#### `extractTokenFromHeader(authHeader: string): string | null`

Extrae el token de un header de autorización.

```typescript
// Ejemplo de uso
const authHeader = request.headers.authorization; // "Bearer eyJhbGciOiJIUzI1NiIs..."
const token = jwtService.extractTokenFromHeader(authHeader);

if (token) {
  try {
    const payload = await jwtService.verifyToken(token);
    // Procesar request autenticado
  } catch (error) {
    // Token inválido
  }
} else {
  // Header inválido o token no presente
}
```

#### `decodeToken(token: string): JWTPayload | null`

Decodifica un token sin verificar la firma.

```typescript
// Ejemplo de uso (útil para debugging)
const payload = jwtService.decodeToken(token);
if (payload) {
  console.log('Token info:', {
    userId: payload.userId,
    email: payload.email,
    expiresAt: new Date(payload.exp * 1000)
  });
}
```

#### `revokeToken(token: string): Promise<void>`

Revoca un token específico.

```typescript
// Ejemplo de uso
await jwtService.revokeToken(token);
console.log('Token revocado');

// El token ya no será válido en futuras verificaciones
```

### Configuración de JWT

```typescript
// Configuración en AuthLibrary
const authLib = new AuthLibrary({
  jwtSecret: process.env.JWT_SECRET!,
  jwtExpiration: '24h',
  refreshTokenExpiration: '7d',
  
  // Configuración avanzada de JWT
  jwt: {
    algorithm: 'HS256',
    issuer: 'mi-aplicacion',
    audience: 'mi-app-users',
    clockTolerance: 30, // 30 segundos de tolerancia
    ignoreExpiration: false,
    ignoreNotBefore: false
  }
});
```

---

## 🛡️ PermissionService

El `PermissionService` maneja la autorización, roles y permisos del sistema.

### Gestión de Roles

#### `createRole(roleData: CreateRoleData): Promise<Role>`

Crea un nuevo rol en el sistema.

```typescript
interface CreateRoleData {
  name: string;
  description?: string;
  permissions?: string[];
}

interface Role {
  id: string;
  name: string;
  description?: string;
  createdAt: Date;
  updatedAt: Date;
}

// Ejemplo de uso
const permissionService = authLib.getPermissionService();

const adminRole = await permissionService.createRole({
  name: 'admin',
  description: 'Administrador del sistema',
  permissions: ['users.read', 'users.write', 'users.delete']
});

console.log('Rol creado:', adminRole);
```

#### `getAllRoles(): Promise<Role[]>`

```typescript
const roles = await permissionService.getAllRoles();
console.log('Roles disponibles:', roles.map(r => r.name));
```

#### `getRoleByName(name: string): Promise<Role | null>`

```typescript
const adminRole = await permissionService.getRoleByName('admin');
if (adminRole) {
  console.log('Rol admin encontrado:', adminRole.description);
}
```

#### `updateRole(id: string, updates: Partial<Role>): Promise<Role | null>`

```typescript
const updatedRole = await permissionService.updateRole(roleId, {
  description: 'Administrador del sistema con acceso completo'
});
```

#### `deleteRole(id: string): Promise<boolean>`

```typescript
const deleted = await permissionService.deleteRole(roleId);
if (deleted) {
  console.log('Rol eliminado');
}
```

### Gestión de Permisos

#### `createPermission(permissionData: CreatePermissionData): Promise<Permission>`

```typescript
interface CreatePermissionData {
  name: string;
  resource: string;
  action: string;
  description?: string;
}

interface Permission {
  id: string;
  name: string;
  resource: string;
  action: string;
  description?: string;
  createdAt: Date;
}

// Ejemplo de uso
const permission = await permissionService.createPermission({
  name: 'users.read',
  resource: 'users',
  action: 'read',
  description: 'Leer información de usuarios'
});

console.log('Permiso creado:', permission);
```

#### `getAllPermissions(): Promise<Permission[]>`

```typescript
const permissions = await permissionService.getAllPermissions();
console.log('Permisos disponibles:', permissions.map(p => p.name));
```

#### `getPermissionsByResource(resource: string): Promise<Permission[]>`

```typescript
const userPermissions = await permissionService.getPermissionsByResource('users');
console.log('Permisos de usuarios:', userPermissions);
```

### Asignación de Roles y Permisos

#### `assignRoleToUser(userId: string, roleName: string): Promise<boolean>`

```typescript
// Asignar rol a usuario
const assigned = await permissionService.assignRoleToUser(user.id, 'admin');
if (assigned) {
  console.log('Rol admin asignado al usuario');
}
```

#### `removeRoleFromUser(userId: string, roleName: string): Promise<boolean>`

```typescript
// Remover rol de usuario
const removed = await permissionService.removeRoleFromUser(user.id, 'moderator');
if (removed) {
  console.log('Rol moderator removido del usuario');
}
```

#### `getUserRoles(userId: string): Promise<Role[]>`

```typescript
const userRoles = await permissionService.getUserRoles(user.id);
console.log('Roles del usuario:', userRoles.map(r => r.name));
```

#### `addPermissionToRole(roleId: string, permissionName: string): Promise<boolean>`

```typescript
// Agregar permiso a rol
const added = await permissionService.addPermissionToRole(
  adminRole.id, 
  'reports.read'
);
if (added) {
  console.log('Permiso agregado al rol admin');
}
```

#### `removePermissionFromRole(roleId: string, permissionName: string): Promise<boolean>`

```typescript
// Remover permiso de rol
const removed = await permissionService.removePermissionFromRole(
  userRole.id, 
  'users.delete'
);
if (removed) {
  console.log('Permiso removido del rol user');
}
```

### Verificación de Permisos

#### `userHasPermission(userId: string, permission: string): Promise<boolean>`

```typescript
// Verificar si usuario tiene permiso específico
const canRead = await permissionService.userHasPermission(
  user.id, 
  'users.read'
);

if (canRead) {
  console.log('Usuario puede leer usuarios');
} else {
  console.log('Usuario no tiene permiso para leer usuarios');
}
```

#### `userHasRole(userId: string, roleName: string): Promise<boolean>`

```typescript
// Verificar si usuario tiene rol específico
const isAdmin = await permissionService.userHasRole(user.id, 'admin');

if (isAdmin) {
  console.log('Usuario es administrador');
}
```

#### `userHasAnyRole(userId: string, roleNames: string[]): Promise<boolean>`

```typescript
// Verificar si usuario tiene alguno de los roles
const hasModeratorRole = await permissionService.userHasAnyRole(
  user.id, 
  ['admin', 'moderator']
);

if (hasModeratorRole) {
  console.log('Usuario tiene permisos de moderación');
}
```

#### `getUserPermissions(userId: string): Promise<Permission[]>`

```typescript
// Obtener todos los permisos del usuario (a través de roles)
const userPermissions = await permissionService.getUserPermissions(user.id);
console.log('Permisos del usuario:', userPermissions.map(p => p.name));
```

---

## 🔗 Integración entre Servicios

### Flujo de Autenticación Completo

```typescript
async function authenticateAndAuthorize(
  email: string, 
  password: string, 
  requiredPermission: string
) {
  const authService = authLib.getAuthService();
  const jwtService = authLib.getJWTService();
  const permissionService = authLib.getPermissionService();
  
  // 1. Autenticar usuario
  const loginResult = await authService.login({ email, password });
  
  if (!loginResult.success) {
    throw new Error('Credenciales inválidas');
  }
  
  // 2. Verificar token
  const payload = await jwtService.verifyToken(loginResult.token!);
  
  // 3. Verificar permisos
  const hasPermission = await permissionService.userHasPermission(
    payload.userId, 
    requiredPermission
  );
  
  if (!hasPermission) {
    throw new Error('Permisos insuficientes');
  }
  
  return {
    user: loginResult.user!,
    token: loginResult.token!,
    permissions: await permissionService.getUserPermissions(payload.userId)
  };
}

// Uso
try {
  const result = await authenticateAndAuthorize(
    'admin@ejemplo.com',
    'password123',
    'users.read'
  );
  
  console.log('Autenticación y autorización exitosa');
  console.log('Usuario:', result.user.email);
  console.log('Permisos:', result.permissions.map(p => p.name));
} catch (error) {
  console.error('Error:', error.message);
}
```

### Middleware de Autorización

```typescript
// Crear middleware que usa todos los servicios
function createAuthMiddleware(requiredPermissions: string[] = []) {
  return async (req: any, res: any, next: any) => {
    try {
      const authService = authLib.getAuthService();
      const jwtService = authLib.getJWTService();
      const permissionService = authLib.getPermissionService();
      
      // 1. Extraer token
      const token = jwtService.extractTokenFromHeader(
        req.headers.authorization
      );
      
      if (!token) {
        return res.status(401).json({ error: 'Token requerido' });
      }
      
      // 2. Verificar token
      const payload = await jwtService.verifyToken(token);
      
      // 3. Obtener usuario actual
      const user = await authService.findUserById(payload.userId);
      
      if (!user || !user.active) {
        return res.status(401).json({ error: 'Usuario inválido' });
      }
      
      // 4. Verificar permisos si se requieren
      if (requiredPermissions.length > 0) {
        const userPermissions = await permissionService.getUserPermissions(user.id);
        const userPermissionNames = userPermissions.map(p => p.name);
        
        const hasRequiredPermissions = requiredPermissions.every(
          permission => userPermissionNames.includes(permission)
        );
        
        if (!hasRequiredPermissions) {
          return res.status(403).json({ error: 'Permisos insuficientes' });
        }
      }
      
      // 5. Agregar información al request
      req.user = user;
      req.permissions = await permissionService.getUserPermissions(user.id);
      req.roles = await permissionService.getUserRoles(user.id);
      
      next();
    } catch (error) {
      console.error('Error en middleware de auth:', error);
      return res.status(401).json({ error: 'Token inválido' });
    }
  };
}

// Uso del middleware
app.get('/admin/users', 
  createAuthMiddleware(['users.read']), 
  async (req, res) => {
    const users = await authLib.getAuthService().getUsers();
    res.json(users);
  }
);

app.delete('/admin/users/:id', 
  createAuthMiddleware(['users.delete']), 
  async (req, res) => {
    const deleted = await authLib.getAuthService().deleteUser(req.params.id);
    res.json({ success: deleted });
  }
);
```

---

## 💡 Ejemplos Prácticos

### Sistema de Roles Jerárquicos

```typescript
// Configurar sistema de roles con jerarquía
async function setupRoleHierarchy() {
  const permissionService = authLib.getPermissionService();
  
  // Crear permisos básicos
  const permissions = [
    { name: 'posts.read', resource: 'posts', action: 'read' },
    { name: 'posts.write', resource: 'posts', action: 'write' },
    { name: 'posts.delete', resource: 'posts', action: 'delete' },
    { name: 'users.read', resource: 'users', action: 'read' },
    { name: 'users.write', resource: 'users', action: 'write' },
    { name: 'users.delete', resource: 'users', action: 'delete' },
    { name: 'admin.access', resource: 'admin', action: 'access' }
  ];
  
  for (const perm of permissions) {
    await permissionService.createPermission(perm);
  }
  
  // Crear roles con diferentes niveles
  const guestRole = await permissionService.createRole({
    name: 'guest',
    description: 'Usuario invitado',
    permissions: ['posts.read']
  });
  
  const userRole = await permissionService.createRole({
    name: 'user',
    description: 'Usuario registrado',
    permissions: ['posts.read', 'posts.write']
  });
  
  const moderatorRole = await permissionService.createRole({
    name: 'moderator',
    description: 'Moderador',
    permissions: ['posts.read', 'posts.write', 'posts.delete', 'users.read']
  });
  
  const adminRole = await permissionService.createRole({
    name: 'admin',
    description: 'Administrador',
    permissions: [
      'posts.read', 'posts.write', 'posts.delete',
      'users.read', 'users.write', 'users.delete',
      'admin.access'
    ]
  });
  
  console.log('Sistema de roles configurado');
}

// Función para verificar jerarquía
async function checkUserAccess(userId: string, resource: string, action: string) {
  const permissionService = authLib.getPermissionService();
  const requiredPermission = `${resource}.${action}`;
  
  const hasPermission = await permissionService.userHasPermission(
    userId, 
    requiredPermission
  );
  
  if (hasPermission) {
    console.log(`✅ Usuario tiene permiso: ${requiredPermission}`);
    return true;
  } else {
    console.log(`❌ Usuario NO tiene permiso: ${requiredPermission}`);
    return false;
  }
}
```

### Sistema de Refresh Token Automático

```typescript
class TokenManager {
  private authLib: AuthLibrary;
  private currentToken: string | null = null;
  private refreshToken: string | null = null;
  private refreshTimer: NodeJS.Timeout | null = null;
  
  constructor(authLib: AuthLibrary) {
    this.authLib = authLib;
  }
  
  async login(email: string, password: string): Promise<boolean> {
    const authService = this.authLib.getAuthService();
    
    const result = await authService.login({
      email,
      password,
      rememberMe: true
    });
    
    if (result.success) {
      this.currentToken = result.token!;
      this.refreshToken = result.refreshToken!;
      
      // Configurar renovación automática
      this.scheduleTokenRefresh();
      
      return true;
    }
    
    return false;
  }
  
  private scheduleTokenRefresh(): void {
    if (!this.currentToken) return;
    
    const jwtService = this.authLib.getJWTService();
    const payload = jwtService.decodeToken(this.currentToken);
    
    if (!payload) return;
    
    // Renovar 5 minutos antes de que expire
    const expirationTime = payload.exp * 1000;
    const refreshTime = expirationTime - (5 * 60 * 1000);
    const timeUntilRefresh = refreshTime - Date.now();
    
    if (timeUntilRefresh > 0) {
      this.refreshTimer = setTimeout(() => {
        this.performTokenRefresh();
      }, timeUntilRefresh);
      
      console.log(`Token se renovará en ${Math.round(timeUntilRefresh / 1000)} segundos`);
    }
  }
  
  private async performTokenRefresh(): Promise<void> {
    if (!this.refreshToken) {
      console.log('No hay refresh token disponible');
      return;
    }
    
    try {
      const authService = this.authLib.getAuthService();
      const result = await authService.refreshToken(this.refreshToken);
      
      if (result.success) {
        this.currentToken = result.token!;
        console.log('✅ Token renovado automáticamente');
        
        // Programar siguiente renovación
        this.scheduleTokenRefresh();
        
        // Notificar a la aplicación del nuevo token
        this.onTokenRefreshed?.(this.currentToken);
      } else {
        console.log('❌ Error renovando token, requiere re-login');
        this.onTokenExpired?.();
      }
    } catch (error) {
      console.error('Error renovando token:', error);
      this.onTokenExpired?.();
    }
  }
  
  getCurrentToken(): string | null {
    return this.currentToken;
  }
  
  logout(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
    
    this.currentToken = null;
    this.refreshToken = null;
  }
  
  // Callbacks para la aplicación
  onTokenRefreshed?: (newToken: string) => void;
  onTokenExpired?: () => void;
}

// Uso
const tokenManager = new TokenManager(authLib);

// Configurar callbacks
tokenManager.onTokenRefreshed = (newToken) => {
  // Actualizar token en headers de HTTP client
  httpClient.defaults.headers.common['Authorization'] = `Bearer ${newToken}`;
};

tokenManager.onTokenExpired = () => {
  // Redirigir a login
  window.location.href = '/login';
};

// Login
const success = await tokenManager.login('user@example.com', 'password');
if (success) {
  console.log('Login exitoso, renovación automática configurada');
}
```

### Auditoría de Acciones

```typescript
// Wrapper para auditar acciones de los servicios
class AuditedAuthService {
  private authService: AuthService;
  private auditLog: Array<{
    action: string;
    userId?: string;
    email?: string;
    timestamp: Date;
    success: boolean;
    details?: any;
  }> = [];
  
  constructor(authLib: AuthLibrary) {
    this.authService = authLib.getAuthService();
  }
  
  async register(userData: any): Promise<any> {
    const startTime = Date.now();
    
    try {
      const result = await this.authService.register(userData);
      
      this.auditLog.push({
        action: 'register',
        email: userData.email,
        timestamp: new Date(),
        success: result.success,
        details: {
          duration: Date.now() - startTime,
          firstName: userData.firstName,
          lastName: userData.lastName
        }
      });
      
      return result;
    } catch (error) {
      this.auditLog.push({
        action: 'register',
        email: userData.email,
        timestamp: new Date(),
        success: false,
        details: {
          duration: Date.now() - startTime,
          error: error.message
        }
      });
      
      throw error;
    }
  }
  
  async login(credentials: any): Promise<any> {
    const startTime = Date.now();
    
    try {
      const result = await this.authService.login(credentials);
      
      this.auditLog.push({
        action: 'login',
        email: credentials.email,
        userId: result.user?.id,
        timestamp: new Date(),
        success: result.success,
        details: {
          duration: Date.now() - startTime,
          rememberMe: credentials.rememberMe
        }
      });
      
      return result;
    } catch (error) {
      this.auditLog.push({
        action: 'login',
        email: credentials.email,
        timestamp: new Date(),
        success: false,
        details: {
          duration: Date.now() - startTime,
          error: error.message
        }
      });
      
      throw error;
    }
  }
  
  getAuditLog(): any[] {
    return [...this.auditLog];
  }
  
  getFailedLogins(timeWindow: number = 3600000): any[] {
    const cutoff = new Date(Date.now() - timeWindow);
    
    return this.auditLog.filter(entry => 
      entry.action === 'login' && 
      !entry.success && 
      entry.timestamp > cutoff
    );
  }
  
  getLoginsByUser(userId: string): any[] {
    return this.auditLog.filter(entry => 
      entry.action === 'login' && 
      entry.userId === userId
    );
  }
}

// Uso
const auditedAuth = new AuditedAuthService(authLib);

// Usar como servicio normal
const result = await auditedAuth.login({
  email: 'user@example.com',
  password: 'password'
});

// Revisar auditoría
const recentFailures = auditedAuth.getFailedLogins();
console.log('Intentos fallidos recientes:', recentFailures.length);

const fullLog = auditedAuth.getAuditLog();
console.log('Log completo:', fullLog);
```

## 🎯 Mejores Prácticas

### 1. Gestión de Errores

```typescript
// ✅ Buena práctica: Manejo específico de errores
async function safeLogin(email: string, password: string) {
  try {
    const result = await authService.login({ email, password });
    
    if (result.success) {
      return { success: true, data: result };
    } else {
      // Manejar diferentes tipos de errores
      switch (result.error?.code) {
        case 'INVALID_CREDENTIALS':
          return { success: false, error: 'Email o contraseña incorrectos' };
        case 'ACCOUNT_LOCKED':
          return { success: false, error: 'Cuenta bloqueada por intentos fallidos' };
        case 'ACCOUNT_INACTIVE':
          return { success: false, error: 'Cuenta desactivada' };
        default:
          return { success: false, error: 'Error de autenticación' };
      }
    }
  } catch (error) {
    console.error('Error inesperado en login:', error);
    return { success: false, error: 'Error interno del servidor' };
  }
}
```

### 2. Validación de Entrada

```typescript
// ✅ Buena práctica: Validar datos antes de enviar a servicios
function validateRegistrationData(data: any): string[] {
  const errors: string[] = [];
  
  if (!data.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) {
    errors.push('Email inválido');
  }
  
  if (!data.password || data.password.length < 8) {
    errors.push('Contraseña debe tener al menos 8 caracteres');
  }
  
  if (!data.firstName || data.firstName.trim().length === 0) {
    errors.push('Nombre es requerido');
  }
  
  if (!data.lastName || data.lastName.trim().length === 0) {
    errors.push('Apellido es requerido');
  }
  
  return errors;
}

async function registerUser(data: any) {
  const validationErrors = validateRegistrationData(data);
  
  if (validationErrors.length > 0) {
    return {
      success: false,
      errors: validationErrors
    };
  }
  
  return await authService.register(data);
}
```

### 3. Caching de Permisos

```typescript
// ✅ Buena práctica: Cache de permisos para mejor rendimiento
class CachedPermissionService {
  private permissionService: PermissionService;
  private cache = new Map<string, { permissions: string[], expiry: number }>();
  private cacheTimeout = 5 * 60 * 1000; // 5 minutos
  
  constructor(authLib: AuthLibrary) {
    this.permissionService = authLib.getPermissionService();
  }
  
  async getUserPermissions(userId: string): Promise<string[]> {
    const cached = this.cache.get(userId);
    
    if (cached && cached.expiry > Date.now()) {
      return cached.permissions;
    }
    
    const permissions = await this.permissionService.getUserPermissions(userId);
    const permissionNames = permissions.map(p => p.name);
    
    this.cache.set(userId, {
      permissions: permissionNames,
      expiry: Date.now() + this.cacheTimeout
    });
    
    return permissionNames;
  }
  
  async userHasPermission(userId: string, permission: string): Promise<boolean> {
    const permissions = await this.getUserPermissions(userId);
    return permissions.includes(permission);
  }
  
  invalidateUserCache(userId: string): void {
    this.cache.delete(userId);
  }
  
  clearCache(): void {
    this.cache.clear();
  }
}
```

### 4. Rate Limiting

```typescript
// ✅ Buena práctica: Rate limiting para operaciones sensibles
class RateLimitedAuthService {
  private authService: AuthService;
  private attempts = new Map<string, { count: number, resetTime: number }>();
  private maxAttempts = 5;
  private windowMs = 15 * 60 * 1000; // 15 minutos
  
  constructor(authLib: AuthLibrary) {
    this.authService = authLib.getAuthService();
  }
  
  async login(credentials: any): Promise<any> {
    const key = credentials.email.toLowerCase();
    
    // Verificar rate limit
    if (this.isRateLimited(key)) {
      return {
        success: false,
        error: {
          code: 'RATE_LIMITED',
          message: 'Demasiados intentos, intenta más tarde'
        }
      };
    }
    
    const result = await this.authService.login(credentials);
    
    if (!result.success) {
      this.recordFailedAttempt(key);
    } else {
      this.clearAttempts(key);
    }
    
    return result;
  }
  
  private isRateLimited(key: string): boolean {
    const attempts = this.attempts.get(key);
    
    if (!attempts) {
      return false;
    }
    
    if (attempts.resetTime < Date.now()) {
      this.attempts.delete(key);
      return false;
    }
    
    return attempts.count >= this.maxAttempts;
  }
  
  private recordFailedAttempt(key: string): void {
    const existing = this.attempts.get(key);
    
    if (!existing || existing.resetTime < Date.now()) {
      this.attempts.set(key, {
        count: 1,
        resetTime: Date.now() + this.windowMs
      });
    } else {
      existing.count++;
    }
  }
  
  private clearAttempts(key: string): void {
    this.attempts.delete(key);
  }
}
```

## 🔗 Enlaces Relacionados

- **[Clase AuthLibrary](./03-auth-library.md)** - Documentación de la clase principal
- **[Adaptadores de Framework](./05-framework-adapters.md)** - Integración con frameworks
- **[Middleware](./06-middleware.md)** - Middleware y utilidades
- **[Ejemplos Prácticos](./07-examples.md)** - Implementaciones completas
- **[API Reference](./08-api-reference.md)** - Referencia completa de la API

---

[⬅️ AuthLibrary](./03-auth-library.md) | [🏠 Índice](./README.md) | [➡️ Adaptadores](./05-framework-adapters.md)