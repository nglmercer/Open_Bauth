# Librería de Autenticación y Permisos - Framework Agnóstico

## Descripción General

Esta librería proporciona un sistema completo de autenticación y autorización que es agnóstico al framework web utilizado. Puede funcionar con Express, Hono, Fastify, WebSockets, Socket.IO, y cualquier otro framework de Node.js/Bun.

## Características Principales

- ✅ **Framework Agnóstico**: Compatible con cualquier framework web
- ✅ **TypeScript**: Completamente tipado para mejor DX
- ✅ **SQLite**: Base de datos ligera usando Bun SQL nativo
- ✅ **JWT**: Autenticación basada en tokens
- ✅ **RBAC**: Control de acceso basado en roles
- ✅ **Middlewares**: Fácil integración con middlewares
- ✅ **Ligero**: Mínimas dependencias

## Arquitectura

```
src/
├── auth/
│   ├── core/
│   │   ├── auth-service.ts      # Servicio principal de autenticación
│   │   ├── permission-service.ts # Gestión de permisos
│   │   └── jwt-service.ts       # Manejo de JWT
│   ├── models/
│   │   ├── user.ts              # Modelo de usuario
│   │   ├── role.ts              # Modelo de rol
│   │   └── permission.ts        # Modelo de permiso
│   ├── middlewares/
│   │   ├── auth-middleware.ts   # Middleware de autenticación
│   │   └── permission-middleware.ts # Middleware de permisos
│   └── adapters/
│       ├── express-adapter.ts   # Adaptador para Express
│       ├── hono-adapter.ts      # Adaptador para Hono
│       └── fastify-adapter.ts   # Adaptador para Fastify
├── db/
│   ├── connection.ts            # Conexión a SQLite
│   ├── migrations.ts            # Migraciones de BD
│   └── schemas.sql              # Esquemas SQL
└── types/
    └── auth.ts                  # Tipos TypeScript
```

## Instalación y Configuración

### 1. Dependencias

```bash
bun add jsonwebtoken bcryptjs
bun add -d @types/jsonwebtoken @types/bcryptjs
```

### 2. Variables de Entorno

```env
JWT_SECRET=tu_jwt_secret_muy_seguro
JWT_EXPIRES_IN=7d
DB_PATH=./auth.db
```

## Implementación

### 1. Tipos Base

```typescript
// src/types/auth.ts
export interface User {
  id: string;
  email: string;
  password_hash: string;
  roles: Role[];
  created_at: Date;
  updated_at: Date;
  is_active: boolean;
}

export interface Role {
  id: string;
  name: string;
  permissions: Permission[];
  created_at: Date;
}

export interface Permission {
  id: string;
  name: string;
  resource: string;
  action: string;
  created_at: Date;
}

export interface AuthContext {
  user?: User;
  token?: string;
  permissions: string[];
}

export interface AuthConfig {
  jwtSecret: string;
  jwtExpiresIn: string;
  dbPath: string;
}
```

### 2. Conexión a Base de Datos

```typescript
// src/db/connection.ts
import { SQL } from "bun";

let db: SQL;

export function initDatabase(dbPath: string = "./auth.db"): SQL {
  if (!db) {
    db = new SQL(`sqlite://${dbPath}`);
  }
  return db;
}

export function getDatabase(): SQL {
  if (!db) {
    throw new Error("Database not initialized. Call initDatabase() first.");
  }
  return db;
}
```

### 3. Migraciones

```typescript
// src/db/migrations.ts
import { getDatabase } from "./connection";

export async function runMigrations() {
  const db = getDatabase();

  // Tabla de usuarios
  await db`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      is_active BOOLEAN DEFAULT 1
    )
  `;

  // Tabla de roles
  await db`
    CREATE TABLE IF NOT EXISTS roles (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `;

  // Tabla de permisos
  await db`
    CREATE TABLE IF NOT EXISTS permissions (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      resource TEXT NOT NULL,
      action TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `;

  // Tabla de relación usuario-rol
  await db`
    CREATE TABLE IF NOT EXISTS user_roles (
      user_id TEXT,
      role_id TEXT,
      PRIMARY KEY (user_id, role_id),
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (role_id) REFERENCES roles(id)
    )
  `;

  // Tabla de relación rol-permiso
  await db`
    CREATE TABLE IF NOT EXISTS role_permissions (
      role_id TEXT,
      permission_id TEXT,
      PRIMARY KEY (role_id, permission_id),
      FOREIGN KEY (role_id) REFERENCES roles(id),
      FOREIGN KEY (permission_id) REFERENCES permissions(id)
    )
  `;

  console.log("✅ Migraciones ejecutadas correctamente");
}
```

### 4. Servicio JWT

```typescript
// src/auth/core/jwt-service.ts
import jwt from "jsonwebtoken";
import type { User } from "../../types/auth";

export class JWTService {
  constructor(private secret: string, private expiresIn: string) {}

  generateToken(user: User): string {
    const payload = {
      userId: user.id,
      email: user.email,
      roles: user.roles.map(r => r.name)
    };

    return jwt.sign(payload, this.secret, { expiresIn: this.expiresIn });
  }

  verifyToken(token: string): any {
    try {
      return jwt.verify(token, this.secret);
    } catch (error:any) {
      throw new Error("Token inválido");
    }
  }

  extractTokenFromHeader(authHeader?: string): string | null {
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return null;
    }
    return authHeader.substring(7);
  }
}
```

### 5. Servicio de Autenticación

```typescript
// src/auth/core/auth-service.ts
import bcrypt from "bcryptjs";
import { getDatabase } from "../../db/connection";
import { JWTService } from "./jwt-service";
import type { User, AuthConfig } from "../../types/auth";

export class AuthService {
  private jwtService: JWTService;
  private db = getDatabase();

  constructor(config: AuthConfig) {
    this.jwtService = new JWTService(config.jwtSecret, config.jwtExpiresIn);
  }

  async register(email: string, password: string): Promise<{ user: User; token: string }> {
    // Verificar si el usuario ya existe
    const existingUser = await this.db`
      SELECT * FROM users WHERE email = ${email}
    `;

    if (existingUser.length > 0) {
      throw new Error("El usuario ya existe");
    }

    // Hash de la contraseña
    const passwordHash = await bcrypt.hash(password, 12);
    const userId = crypto.randomUUID();

    // Crear usuario
    await this.db`
      INSERT INTO users (id, email, password_hash)
      VALUES (${userId}, ${email}, ${passwordHash})
    `;

    // Obtener usuario completo
    const user = await this.getUserById(userId);
    const token = this.jwtService.generateToken(user);

    return { user, token };
  }

  async login(email: string, password: string): Promise<{ user: User; token: string }> {
    // Buscar usuario
    const users = await this.db`
      SELECT * FROM users WHERE email = ${email} AND is_active = 1
    `;

    if (users.length === 0) {
      throw new Error("Credenciales inválidas");
    }

    const userData = users[0];

    // Verificar contraseña
    const isValidPassword = await bcrypt.compare(password, userData.password_hash);
    if (!isValidPassword) {
      throw new Error("Credenciales inválidas");
    }

    // Obtener usuario completo con roles
    const user = await this.getUserById(userData.id);
    const token = this.jwtService.generateToken(user);

    return { user, token };
  }

  async getUserById(userId: string): Promise<User> {
    const users = await this.db`
      SELECT u.*, r.id as role_id, r.name as role_name,
             p.id as permission_id, p.name as permission_name,
             p.resource, p.action
      FROM users u
      LEFT JOIN user_roles ur ON u.id = ur.user_id
      LEFT JOIN roles r ON ur.role_id = r.id
      LEFT JOIN role_permissions rp ON r.id = rp.role_id
      LEFT JOIN permissions p ON rp.permission_id = p.id
      WHERE u.id = ${userId}
    `;

    if (users.length === 0) {
      throw new Error("Usuario no encontrado");
    }

    // Agrupar datos
    const userData = users[0];
    const rolesMap = new Map();

    users.forEach(row => {
      if (row.role_id && !rolesMap.has(row.role_id)) {
        rolesMap.set(row.role_id, {
          id: row.role_id,
          name: row.role_name,
          permissions: []
        });
      }

      if (row.permission_id && rolesMap.has(row.role_id)) {
        const role = rolesMap.get(row.role_id);
        if (!role.permissions.find(p => p.id === row.permission_id)) {
          role.permissions.push({
            id: row.permission_id,
            name: row.permission_name,
            resource: row.resource,
            action: row.action,
            created_at: new Date()
          });
        }
      }
    });

    return {
      id: userData.id,
      email: userData.email,
      password_hash: userData.password_hash,
      roles: Array.from(rolesMap.values()),
      created_at: new Date(userData.created_at),
      updated_at: new Date(userData.updated_at),
      is_active: Boolean(userData.is_active)
    };
  }

  async verifyToken(token: string): Promise<User> {
    const payload = this.jwtService.verifyToken(token);
    return await this.getUserById(payload.userId);
  }
}
```

### 6. Servicio de Permisos

```typescript
// src/auth/core/permission-service.ts
import { getDatabase } from "../../db/connection";
import type { User, Permission } from "../../types/auth";

export class PermissionService {
  private db = getDatabase();

  async getUserPermissions(userId: string): Promise<string[]> {
    const permissions = await this.db`
      SELECT DISTINCT p.name
      FROM permissions p
      JOIN role_permissions rp ON p.id = rp.permission_id
      JOIN roles r ON rp.role_id = r.id
      JOIN user_roles ur ON r.id = ur.role_id
      WHERE ur.user_id = ${userId}
    `;

    return permissions.map(p => p.name);
  }

  async hasPermission(user: User, permission: string): Promise<boolean> {
    const userPermissions = await this.getUserPermissions(user.id);
    return userPermissions.includes(permission);
  }

  async hasAnyPermission(user: User, permissions: string[]): Promise<boolean> {
    const userPermissions = await this.getUserPermissions(user.id);
    return permissions.some(p => userPermissions.includes(p));
  }

  async hasAllPermissions(user: User, permissions: string[]): Promise<boolean> {
    const userPermissions = await this.getUserPermissions(user.id);
    return permissions.every(p => userPermissions.includes(p));
  }

  async createPermission(name: string, resource: string, action: string): Promise<Permission> {
    const id = crypto.randomUUID();
    
    await this.db`
      INSERT INTO permissions (id, name, resource, action)
      VALUES (${id}, ${name}, ${resource}, ${action})
    `;

    return {
      id,
      name,
      resource,
      action,
      created_at: new Date()
    };
  }
}
```

### 7. Middleware Agnóstico

```typescript
// src/auth/middlewares/auth-middleware.ts
import { AuthService } from "../core/auth-service";
import { PermissionService } from "../core/permission-service";
import type { AuthContext, AuthConfig } from "../../types/auth";

export interface AuthRequest {
  headers: Record<string, string>;
  auth?: AuthContext;
}

export interface AuthResponse {
  status: (code: number) => AuthResponse;
  json: (data: any) => void;
}

export class AuthMiddleware {
  private authService: AuthService;
  private permissionService: PermissionService;

  constructor(config: AuthConfig) {
    this.authService = new AuthService(config);
    this.permissionService = new PermissionService();
  }

  // Middleware agnóstico que retorna una función
  authenticate() {
    return async (req: AuthRequest, res: AuthResponse, next?: () => void) => {
      try {
        const authHeader = req.headers.authorization || req.headers.Authorization;
        
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
          return res.status(401).json({ error: "Token de acceso requerido" });
        }

        const token = authHeader.substring(7);
        const user = await this.authService.verifyToken(token);
        const permissions = await this.permissionService.getUserPermissions(user.id);

        // Agregar contexto de auth al request
        req.auth = {
          user,
          token,
          permissions
        };

        if (next) next();
      } catch (error:any) {
        return res.status(401).json({ error: "Token inválido" });
      }
    };
  }

  requirePermission(permission: string) {
    return async (req: AuthRequest, res: AuthResponse, next?: () => void) => {
      if (!req.auth?.user) {
        return res.status(401).json({ error: "No autenticado" });
      }

      const hasPermission = await this.permissionService.hasPermission(
        req.auth.user,
        permission
      );

      if (!hasPermission) {
        return res.status(403).json({ error: "Permisos insuficientes" });
      }

      if (next) next();
    };
  }

  requireAnyPermission(permissions: string[]) {
    return async (req: AuthRequest, res: AuthResponse, next?: () => void) => {
      if (!req.auth?.user) {
        return res.status(401).json({ error: "No autenticado" });
      }

      const hasAnyPermission = await this.permissionService.hasAnyPermission(
        req.auth.user,
        permissions
      );

      if (!hasAnyPermission) {
        return res.status(403).json({ error: "Permisos insuficientes" });
      }

      if (next) next();
    };
  }
}
```

### 8. Adaptadores para Frameworks

#### Adaptador para Hono

```typescript
// src/auth/adapters/hono-adapter.ts
import { Context, Next } from "hono";
import { AuthMiddleware } from "../middlewares/auth-middleware";
import type { AuthConfig } from "../../types/auth";

export class HonoAuthAdapter {
  private authMiddleware: AuthMiddleware;

  constructor(config: AuthConfig) {
    this.authMiddleware = new AuthMiddleware(config);
  }

  authenticate() {
    return async (c: Context, next: Next) => {
      const req = {
        headers: Object.fromEntries(c.req.header())
      };

      const res = {
        status: (code: number) => ({ json: (data: any) => c.json(data, code) })
      };

      let nextCalled = false;
      const mockNext = () => { nextCalled = true; };

      await this.authMiddleware.authenticate()(req, res as any, mockNext);

      if (nextCalled) {
        c.set('auth', req.auth);
        await next();
      }
    };
  }

  requirePermission(permission: string) {
    return async (c: Context, next: Next) => {
      const auth = c.get('auth');
      const req = { auth, headers: {} };
      const res = {
        status: (code: number) => ({ json: (data: any) => c.json(data, code) })
      };

      let nextCalled = false;
      const mockNext = () => { nextCalled = true; };

      await this.authMiddleware.requirePermission(permission)(req, res as any, mockNext);

      if (nextCalled) {
        await next();
      }
    };
  }
}
```

#### Adaptador para Express

```typescript
// src/auth/adapters/express-adapter.ts
import { Request, Response, NextFunction } from "express";
import { AuthMiddleware } from "../middlewares/auth-middleware";
import type { AuthConfig } from "../../types/auth";

export class ExpressAuthAdapter {
  private authMiddleware: AuthMiddleware;

  constructor(config: AuthConfig) {
    this.authMiddleware = new AuthMiddleware(config);
  }

  authenticate() {
    return async (req: Request, res: Response, next: NextFunction) => {
      const authReq = {
        headers: req.headers as Record<string, string>
      };

      const authRes = {
        status: (code: number) => ({ json: (data: any) => res.status(code).json(data) })
      };

      let nextCalled = false;
      const mockNext = () => { nextCalled = true; };

      await this.authMiddleware.authenticate()(authReq, authRes as any, mockNext);

      if (nextCalled) {
        (req as any).auth = authReq.auth;
        next();
      }
    };
  }

  requirePermission(permission: string) {
    return async (req: Request, res: Response, next: NextFunction) => {
      const authReq = {
        auth: (req as any).auth,
        headers: {}
      };

      const authRes = {
        status: (code: number) => ({ json: (data: any) => res.status(code).json(data) })
      };

      let nextCalled = false;
      const mockNext = () => { nextCalled = true; };

      await this.authMiddleware.requirePermission(permission)(authReq, authRes as any, mockNext);

      if (nextCalled) {
        next();
      }
    };
  }
}
```

## Uso de la Librería

### 1. Inicialización

```typescript
// src/auth/index.ts
import { initDatabase, runMigrations } from "../db/connection";
import { AuthService } from "./core/auth-service";
import { PermissionService } from "./core/permission-service";
import { HonoAuthAdapter } from "./adapters/hono-adapter";
import type { AuthConfig } from "../types/auth";

export async function initAuth(config: AuthConfig) {
  // Inicializar base de datos
  initDatabase(config.dbPath);
  await runMigrations();

  // Crear servicios
  const authService = new AuthService(config);
  const permissionService = new PermissionService();
  const honoAdapter = new HonoAuthAdapter(config);

  return {
    authService,
    permissionService,
    honoAdapter
  };
}
```

### 2. Uso con Hono

```typescript
// src/index.ts
import { Hono } from 'hono';
import { initAuth } from './auth';

const app = new Hono();

// Configuración
const authConfig = {
  jwtSecret: process.env.JWT_SECRET || "tu_secret_muy_seguro",
  jwtExpiresIn: "7d",
  dbPath: "./auth.db"
};

// Inicializar auth
const { authService, honoAdapter } = await initAuth(authConfig);

// Rutas públicas
app.post('/auth/register', async (c) => {
  const { email, password } = await c.req.json();
  try {
    const result = await authService.register(email, password);
    return c.json(result);
  } catch (error:any) {
    return c.json({ error: error.message }, 400);
  }
});

app.post('/auth/login', async (c) => {
  const { email, password } = await c.req.json();
  try {
    const result = await authService.login(email, password);
    return c.json(result);
  } catch (error:any) {
    return c.json({ error: error.message }, 401);
  }
});

// Rutas protegidas
app.use('/api/*', honoAdapter.authenticate());

app.get('/api/profile', (c) => {
  const auth = c.get('auth');
  return c.json({ user: auth.user });
});

// Rutas con permisos específicos
app.use('/api/admin/*', honoAdapter.requirePermission('admin.access'));

app.get('/api/admin/users', (c) => {
  return c.json({ message: 'Lista de usuarios - Solo admins' });
});

export default app;
```

### 3. Uso con Express

```typescript
// Ejemplo con Express
import express from 'express';
import { initAuth } from './auth';
import { ExpressAuthAdapter } from './auth/adapters/express-adapter';

const app = express();
app.use(express.json());

const authConfig = {
  jwtSecret: process.env.JWT_SECRET || "tu_secret_muy_seguro",
  jwtExpiresIn: "7d",
  dbPath: "./auth.db"
};

const { authService } = await initAuth(authConfig);
const expressAdapter = new ExpressAuthAdapter(authConfig);

// Rutas protegidas
app.use('/api', expressAdapter.authenticate());
app.use('/api/admin', expressAdapter.requirePermission('admin.access'));

app.get('/api/profile', (req, res) => {
  res.json({ user: (req as any).auth.user });
});
```

### 4. Uso con WebSockets

```typescript
// src/auth/adapters/websocket-adapter.ts
import { AuthService } from "../core/auth-service";
import type { AuthConfig } from "../../types/auth";

export class WebSocketAuthAdapter {
  private authService: AuthService;

  constructor(config: AuthConfig) {
    this.authService = new AuthService(config);
  }

  async authenticateSocket(token: string) {
    try {
      const user = await this.authService.verifyToken(token);
      return { success: true, user };
    } catch (error:any) {
      return { success: false, error: error.message };
    }
  }
}

// Uso con Socket.IO
import { Server } from 'socket.io';
import { WebSocketAuthAdapter } from './auth/adapters/websocket-adapter';

const io = new Server(server);
const wsAdapter = new WebSocketAuthAdapter(authConfig);

io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  const auth = await wsAdapter.authenticateSocket(token);
  
  if (auth.success) {
    socket.data.user = auth.user;
    next();
  } else {
    next(new Error('Authentication failed'));
  }
});
```

## Scripts de Utilidad

### Seeder para Datos Iniciales

```typescript
// scripts/seed.ts
import { initDatabase, runMigrations } from "../src/db/connection";
import { getDatabase } from "../src/db/connection";

async function seed() {
  initDatabase();
  await runMigrations();
  
  const db = getDatabase();
  
  // Crear permisos básicos
  const permissions = [
    { name: 'user.read', resource: 'user', action: 'read' },
    { name: 'user.write', resource: 'user', action: 'write' },
    { name: 'admin.access', resource: 'admin', action: 'access' },
  ];
  
  for (const perm of permissions) {
    await db`
      INSERT OR IGNORE INTO permissions (id, name, resource, action)
      VALUES (${crypto.randomUUID()}, ${perm.name}, ${perm.resource}, ${perm.action})
    `;
  }
  
  // Crear roles
  const userRoleId = crypto.randomUUID();
  const adminRoleId = crypto.randomUUID();
  
  await db`INSERT OR IGNORE INTO roles (id, name) VALUES (${userRoleId}, 'user')`;
  await db`INSERT OR IGNORE INTO roles (id, name) VALUES (${adminRoleId}, 'admin')`;
  
  console.log('✅ Datos iniciales creados');
}

seed().catch(console.error);
```

## Testing

```typescript
// tests/auth.test.ts
import { describe, test, expect, beforeAll } from "bun:test";
import { initAuth } from "../src/auth";

const testConfig = {
  jwtSecret: "test_secret",
  jwtExpiresIn: "1h",
  dbPath: ":memory:"
};

describe("Auth Service", () => {
  let authService: any;
  
  beforeAll(async () => {
    const auth = await initAuth(testConfig);
    authService = auth.authService;
  });
  
  test("should register user", async () => {
    const result = await authService.register("test@example.com", "password123");
    expect(result.user.email).toBe("test@example.com");
    expect(result.token).toBeDefined();
  });
  
  test("should login user", async () => {
    const result = await authService.login("test@example.com", "password123");
    expect(result.user.email).toBe("test@example.com");
    expect(result.token).toBeDefined();
  });
});
```

## Comandos de Desarrollo

```json
{
  "scripts": {
    "dev": "bun run --hot src/index.ts",
    "build": "bun build src/index.ts --outdir ./dist",
    "test": "bun test",
    "seed": "bun run scripts/seed.ts",
    "migrate": "bun run scripts/migrate.ts"
  }
}
```

## Ventajas de esta Implementación

1. **Framework Agnóstico**: Funciona con cualquier framework web
2. **TypeScript Nativo**: Completamente tipado
3. **Ligero**: Pocas dependencias, usando Bun SQL nativo
4. **Escalable**: Arquitectura modular y extensible
5. **Seguro**: JWT + bcrypt + validaciones
6. **Flexible**: Sistema de roles y permisos granular
7. **Testeable**: Fácil de testear con Bun test
8. **Performante**: SQLite + Bun para máximo rendimiento

## Próximos Pasos

- [ ] Implementar refresh tokens
- [ ] Agregar rate limiting
- [ ] Implementar 2FA
- [ ] Agregar logging y auditoría
- [ ] Crear CLI para gestión de usuarios
- [ ] Documentación API con OpenAPI
- [ ] Implementar caché con Redis (opcional)
- [ ] Agregar webhooks para eventos de auth

Esta librería proporciona una base sólida y extensible para cualquier aplicación que necesite autenticación y autorización robusta.