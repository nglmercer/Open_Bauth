# 📚 Ejemplos Prácticos y Casos de Uso

Esta guía presenta implementaciones completas y casos de uso reales de la librería de autenticación, desde aplicaciones básicas hasta sistemas empresariales complejos.

## 📋 Índice

- [🚀 Aplicación Web Básica](#-aplicación-web-básica)
- [🏢 Sistema Empresarial](#-sistema-empresarial)
- [🔄 API con Microservicios](#-api-con-microservicios)
- [📱 Aplicación SPA + API](#-aplicación-spa--api)
- [🌐 Sistema Multi-tenant](#-sistema-multi-tenant)
- [🔐 Autenticación Social](#-autenticación-social)
- [📊 Dashboard Administrativo](#-dashboard-administrativo)
- [🛡️ Sistema de Auditoría](#️-sistema-de-auditoría)

---

## 🚀 Aplicación Web Básica

### Descripción
Una aplicación web simple con autenticación básica, registro de usuarios y protección de rutas.

### Estructura del Proyecto

```
basic-web-app/
├── src/
│   ├── index.ts          # Punto de entrada
│   ├── config/
│   │   └── auth.ts       # Configuración de autenticación
│   ├── routes/
│   │   ├── auth.ts       # Rutas de autenticación
│   │   ├── users.ts      # Rutas de usuarios
│   │   └── protected.ts  # Rutas protegidas
│   └── middleware/
│       └── auth.ts       # Middleware personalizado
├── views/
│   ├── login.html
│   ├── register.html
│   └── dashboard.html
└── package.json
```

### Implementación

#### 1. Configuración Principal (`src/index.ts`)

```typescript
import express from 'express';
import { AuthLibrary } from '@open-bauth/core';
import { createExpressAdapter } from '@open-bauth/express';
import authRoutes from './routes/auth';
import userRoutes from './routes/users';
import protectedRoutes from './routes/protected';

const app = express();

// Configurar la librería de autenticación
const authLib = new AuthLibrary({
  database: {
    type: 'sqlite',
    database: './data/app.db'
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'your-secret-key',
    expiresIn: '24h'
  },
  security: {
    bcryptRounds: 12,
    maxLoginAttempts: 5,
    lockoutDuration: 15 * 60 * 1000 // 15 minutos
  }
});

// Inicializar la librería
await authLib.initialize();

// Crear adaptador para Express
const auth = createExpressAdapter(authLib);

// Middleware básico
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Middleware de autenticación
app.use(auth.middleware);

// Rutas
app.use('/auth', authRoutes(auth));
app.use('/api/users', userRoutes(auth));
app.use('/dashboard', protectedRoutes(auth));

// Página principal
app.get('/', (req, res) => {
  if (req.user) {
    res.redirect('/dashboard');
  } else {
    res.sendFile(__dirname + '/views/login.html');
  }
});

// Manejo de errores
app.use((err: any, req: any, res: any, next: any) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Error interno del servidor' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en puerto ${PORT}`);
});
```

#### 2. Rutas de Autenticación (`src/routes/auth.ts`)

```typescript
import { Router } from 'express';
import { ExpressAuthAdapter } from '@open-bauth/express';

export default function createAuthRoutes(auth: ExpressAuthAdapter) {
  const router = Router();

  // Registro de usuario
  router.post('/register', async (req, res) => {
    try {
      const { email, password, name } = req.body;
      
      // Validar datos
      if (!email || !password || !name) {
        return res.status(400).json({ 
          error: 'Email, contraseña y nombre son requeridos' 
        });
      }

      // Crear usuario
      const user = await auth.authService.register({
        email,
        password,
        profile: { name }
      });

      // Generar token
      const token = await auth.jwtService.generateToken({ 
        userId: user.id,
        email: user.email 
      });

      res.status(201).json({
        message: 'Usuario registrado exitosamente',
        user: {
          id: user.id,
          email: user.email,
          name: user.profile.name
        },
        token
      });
    } catch (error: any) {
      if (error.message.includes('already exists')) {
        return res.status(409).json({ error: 'El email ya está registrado' });
      }
      res.status(500).json({ error: 'Error al registrar usuario' });
    }
  });

  // Inicio de sesión
  router.post('/login', async (req, res) => {
    try {
      const { email, password } = req.body;
      
      if (!email || !password) {
        return res.status(400).json({ 
          error: 'Email y contraseña son requeridos' 
        });
      }

      // Autenticar usuario
      const result = await auth.authService.login(email, password);
      
      if (!result.success) {
        return res.status(401).json({ 
          error: result.message || 'Credenciales inválidas' 
        });
      }

      // Generar token
      const token = await auth.jwtService.generateToken({ 
        userId: result.user!.id,
        email: result.user!.email 
      });

      res.json({
        message: 'Inicio de sesión exitoso',
        user: {
          id: result.user!.id,
          email: result.user!.email,
          name: result.user!.profile.name
        },
        token
      });
    } catch (error) {
      res.status(500).json({ error: 'Error al iniciar sesión' });
    }
  });

  // Cerrar sesión
  router.post('/logout', auth.required, async (req, res) => {
    try {
      // Invalidar token (si se usa blacklist) - Usa el método mejorado
      const token = auth.jwtService.extractTokenFromHeader(req.headers.authorization);
      if (token) {
        await auth.jwtService.invalidateToken(token);
      }

      res.json({ message: 'Sesión cerrada exitosamente' });
    } catch (error) {
      res.status(500).json({ error: 'Error al cerrar sesión' });
    }
  });

  // Verificar token
  router.get('/verify', auth.required, (req, res) => {
    res.json({
      valid: true,
      user: {
        id: req.user.id,
        email: req.user.email,
        name: req.user.profile?.name
      }
    });
  });

  return router;
}
```

#### 3. Rutas Protegidas (`src/routes/protected.ts`)

```typescript
import { Router } from 'express';
import { ExpressAuthAdapter } from '@open-bauth/express';

export default function createProtectedRoutes(auth: ExpressAuthAdapter) {
  const router = Router();

  // Aplicar autenticación a todas las rutas
  router.use(auth.required);

  // Dashboard principal
  router.get('/', (req, res) => {
    res.sendFile(__dirname + '/../../views/dashboard.html');
  });

  // Perfil del usuario
  router.get('/profile', (req, res) => {
    res.json({
      user: {
        id: req.user.id,
        email: req.user.email,
        name: req.user.profile?.name,
        created_at: req.user.created_at
      }
    });
  });

  // Actualizar perfil
  router.put('/profile', async (req, res) => {
    try {
      const { name } = req.body;
      
      const updatedUser = await auth.authService.updateUser(req.user.id, {
        profile: { ...req.user.profile, name }
      });

      res.json({
        message: 'Perfil actualizado exitosamente',
        user: {
          id: updatedUser.id,
          email: updatedUser.email,
          name: updatedUser.profile.name
        }
      });
    } catch (error) {
      res.status(500).json({ error: 'Error al actualizar perfil' });
    }
  });

  // Cambiar contraseña
  router.put('/password', async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;
      
      if (!currentPassword || !newPassword) {
        return res.status(400).json({ 
          error: 'Contraseña actual y nueva son requeridas' 
        });
      }

      const result = await auth.authService.changePassword(
        req.user.id,
        currentPassword,
        newPassword
      );

      if (!result.success) {
        return res.status(400).json({ error: result.message });
      }

      res.json({ message: 'Contraseña actualizada exitosamente' });
    } catch (error) {
      res.status(500).json({ error: 'Error al cambiar contraseña' });
    }
  });

  return router;
}
```

---

## 🏢 Sistema Empresarial

### Descripción
Sistema empresarial con roles jerárquicos, permisos granulares y múltiples niveles de acceso.

### Características
- Roles jerárquicos (Admin, Manager, Employee)
- Permisos granulares por módulo
- Auditoría completa de acciones
- Gestión de equipos y departamentos

### Implementación

#### 1. Configuración de Roles y Permisos

```typescript
// config/permissions.ts
export const PERMISSIONS = {
  // Gestión de usuarios
  USERS: {
    CREATE: 'users.create',
    READ: 'users.read',
    UPDATE: 'users.update',
    DELETE: 'users.delete',
    MANAGE_ROLES: 'users.manage_roles'
  },
  
  // Gestión de proyectos
  PROJECTS: {
    CREATE: 'projects.create',
    READ: 'projects.read',
    UPDATE: 'projects.update',
    DELETE: 'projects.delete',
    ASSIGN_MEMBERS: 'projects.assign_members'
  },
  
  // Reportes y analytics
  REPORTS: {
    VIEW: 'reports.view',
    EXPORT: 'reports.export',
    ADMIN: 'reports.admin'
  },
  
  // Configuración del sistema
  SYSTEM: {
    CONFIG: 'system.config',
    AUDIT: 'system.audit',
    BACKUP: 'system.backup'
  }
};

export const ROLES = {
  ADMIN: {
    name: 'admin',
    permissions: Object.values(PERMISSIONS).flatMap(p => Object.values(p))
  },
  
  MANAGER: {
    name: 'manager',
    permissions: [
      ...Object.values(PERMISSIONS.USERS),
      ...Object.values(PERMISSIONS.PROJECTS),
      PERMISSIONS.REPORTS.VIEW,
      PERMISSIONS.REPORTS.EXPORT
    ]
  },
  
  EMPLOYEE: {
    name: 'employee',
    permissions: [
      PERMISSIONS.USERS.READ,
      PERMISSIONS.PROJECTS.READ,
      PERMISSIONS.PROJECTS.UPDATE,
      PERMISSIONS.REPORTS.VIEW
    ]
  }
};
```

#### 2. Middleware de Autorización Avanzada

```typescript
// middleware/authorization.ts
import { Request, Response, NextFunction } from 'express';
import { ExpressAuthAdapter } from '@open-bauth/express';

interface AuthorizedRequest extends Request {
  user: any;
  permissions: string[];
}

export function createAdvancedAuthMiddleware(auth: ExpressAuthAdapter) {
  return {
    // Verificar permisos específicos
    requirePermissions: (permissions: string[]) => {
      return async (req: AuthorizedRequest, res: Response, next: NextFunction) => {
        try {
          // Verificar autenticación
          if (!req.user) {
            return res.status(401).json({ error: 'No autenticado' });
          }

          // Obtener permisos del usuario
          const userPermissions = await auth.permissionService.getUserPermissions(req.user.id);
          
          // Verificar si tiene todos los permisos requeridos
          const hasPermissions = permissions.every(permission => 
            userPermissions.includes(permission)
          );

          if (!hasPermissions) {
            // Auditar intento de acceso no autorizado
            await auth.auditService.log({
              userId: req.user.id,
              action: 'unauthorized_access_attempt',
              resource: req.path,
              metadata: {
                requiredPermissions: permissions,
                userPermissions,
                ip: req.ip,
                userAgent: req.headers['user-agent']
              }
            });

            return res.status(403).json({ 
              error: 'Permisos insuficientes',
              required: permissions
            });
          }

          req.permissions = userPermissions;
          next();
        } catch (error) {
          res.status(500).json({ error: 'Error al verificar permisos' });
        }
      };
    },

    // Verificar rol específico
    requireRole: (roles: string[]) => {
      return async (req: AuthorizedRequest, res: Response, next: NextFunction) => {
        try {
          if (!req.user) {
            return res.status(401).json({ error: 'No autenticado' });
          }

          const userRoles = await auth.permissionService.getUserRoles(req.user.id);
          const hasRole = roles.some(role => userRoles.includes(role));

          if (!hasRole) {
            return res.status(403).json({ 
              error: 'Rol insuficiente',
              required: roles,
              current: userRoles
            });
          }

          next();
        } catch (error) {
          res.status(500).json({ error: 'Error al verificar rol' });
        }
      };
    },

    // Verificar propiedad del recurso
    requireOwnership: (resourceIdParam: string = 'id') => {
      return async (req: AuthorizedRequest, res: Response, next: NextFunction) => {
        try {
          const resourceId = req.params[resourceIdParam];
          const userId = req.user.id;

          // Verificar si el usuario es propietario del recurso
          const isOwner = await auth.permissionService.isResourceOwner(
            userId,
            resourceId,
            req.baseUrl
          );

          if (!isOwner) {
            // Verificar si tiene permisos administrativos
            const hasAdminPermission = req.permissions?.includes('admin.override');
            
            if (!hasAdminPermission) {
              return res.status(403).json({ 
                error: 'Solo el propietario puede acceder a este recurso' 
              });
            }
          }

          next();
        } catch (error) {
          res.status(500).json({ error: 'Error al verificar propiedad' });
        }
      };
    }
  };
}
```

#### 3. Rutas de Gestión de Usuarios

```typescript
// routes/admin/users.ts
import { Router } from 'express';
import { ExpressAuthAdapter } from '@open-bauth/express';
import { PERMISSIONS } from '../../config/permissions';
import { createAdvancedAuthMiddleware } from '../../middleware/authorization';

export default function createUserManagementRoutes(auth: ExpressAuthAdapter) {
  const router = Router();
  const authMiddleware = createAdvancedAuthMiddleware(auth);

  // Listar usuarios (solo managers y admins)
  router.get('/', 
    auth.required,
    authMiddleware.requirePermissions([PERMISSIONS.USERS.READ]),
    async (req, res) => {
      try {
        const { page = 1, limit = 10, search, role } = req.query;
        
        const users = await auth.authService.getUsers({
          page: Number(page),
          limit: Number(limit),
          search: search as string,
          role: role as string
        });

        // Auditar consulta
        await auth.auditService.log({
          userId: req.user.id,
          action: 'users_list_viewed',
          metadata: { filters: { search, role, page, limit } }
        });

        res.json(users);
      } catch (error) {
        res.status(500).json({ error: 'Error al obtener usuarios' });
      }
    }
  );

  // Crear usuario (solo admins)
  router.post('/',
    auth.required,
    authMiddleware.requirePermissions([PERMISSIONS.USERS.CREATE]),
    async (req, res) => {
      try {
        const { email, password, name, role, department } = req.body;
        
        // Validar datos
        if (!email || !password || !name || !role) {
          return res.status(400).json({ 
            error: 'Email, contraseña, nombre y rol son requeridos' 
          });
        }

        // Crear usuario
        const user = await auth.authService.register({
          email,
          password,
          profile: { name, department }
        });

        // Asignar rol
        await auth.permissionService.assignRole(user.id, role);

        // Auditar creación
        await auth.auditService.log({
          userId: req.user.id,
          action: 'user_created',
          targetUserId: user.id,
          metadata: { email, role, department }
        });

        res.status(201).json({
          message: 'Usuario creado exitosamente',
          user: {
            id: user.id,
            email: user.email,
            name: user.profile.name,
            role
          }
        });
      } catch (error: any) {
        if (error.message.includes('already exists')) {
          return res.status(409).json({ error: 'El email ya está registrado' });
        }
        res.status(500).json({ error: 'Error al crear usuario' });
      }
    }
  );

  // Actualizar usuario
  router.put('/:id',
    auth.required,
    authMiddleware.requirePermissions([PERMISSIONS.USERS.UPDATE]),
    async (req, res) => {
      try {
        const { id } = req.params;
        const { name, department, active } = req.body;
        
        const updatedUser = await auth.authService.updateUser(id, {
          profile: { name, department },
          active
        });

        // Auditar actualización
        await auth.auditService.log({
          userId: req.user.id,
          action: 'user_updated',
          targetUserId: id,
          metadata: { changes: { name, department, active } }
        });

        res.json({
          message: 'Usuario actualizado exitosamente',
          user: updatedUser
        });
      } catch (error) {
        res.status(500).json({ error: 'Error al actualizar usuario' });
      }
    }
  );

  // Cambiar rol de usuario (solo admins)
  router.put('/:id/role',
    auth.required,
    authMiddleware.requirePermissions([PERMISSIONS.USERS.MANAGE_ROLES]),
    async (req, res) => {
      try {
        const { id } = req.params;
        const { role } = req.body;
        
        if (!role) {
          return res.status(400).json({ error: 'Rol es requerido' });
        }

        // Obtener rol actual
        const currentRoles = await auth.permissionService.getUserRoles(id);
        
        // Remover roles actuales y asignar nuevo
        await auth.permissionService.removeAllRoles(id);
        await auth.permissionService.assignRole(id, role);

        // Auditar cambio de rol
        await auth.auditService.log({
          userId: req.user.id,
          action: 'user_role_changed',
          targetUserId: id,
          metadata: { 
            previousRoles: currentRoles,
            newRole: role
          }
        });

        res.json({ message: 'Rol actualizado exitosamente' });
      } catch (error) {
        res.status(500).json({ error: 'Error al cambiar rol' });
      }
    }
  );

  // Desactivar usuario
  router.delete('/:id',
    auth.required,
    authMiddleware.requirePermissions([PERMISSIONS.USERS.DELETE]),
    async (req, res) => {
      try {
        const { id } = req.params;
        
        // No permitir auto-eliminación
        if (id === req.user.id) {
          return res.status(400).json({ 
            error: 'No puedes desactivar tu propia cuenta' 
          });
        }

        await auth.authService.deactivateUser(id);

        // Auditar desactivación
        await auth.auditService.log({
          userId: req.user.id,
          action: 'user_deactivated',
          targetUserId: id
        });

        res.json({ message: 'Usuario desactivado exitosamente' });
      } catch (error) {
        res.status(500).json({ error: 'Error al desactivar usuario' });
      }
    }
  );

  return router;
}
```

---

## 🔄 API con Microservicios

### Descripción
Arquitectura de microservicios con autenticación centralizada y comunicación entre servicios.

### Arquitectura

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Auth Service  │    │  User Service   │    │ Order Service   │
│   (Port 3001)   │    │   (Port 3002)   │    │   (Port 3003)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │  API Gateway    │
                    │   (Port 3000)   │
                    └─────────────────┘
```

### Implementación

#### 1. Servicio de Autenticación (`auth-service/index.ts`)

```typescript
import express from 'express';
import { AuthLibrary } from '@open-bauth/core';
import { createExpressAdapter } from '@open-bauth/express';

const app = express();

// Configurar librería de autenticación
const authLib = new AuthLibrary({
  database: {
    type: 'postgresql',
    host: process.env.DB_HOST || 'localhost',
    port: 5432,
    database: 'auth_service',
    username: process.env.DB_USER,
    password: process.env.DB_PASSWORD
  },
  jwt: {
    secret: process.env.JWT_SECRET!,
    expiresIn: '1h',
    refreshExpiresIn: '7d'
  },
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: 6379,
    password: process.env.REDIS_PASSWORD
  }
});

await authLib.initialize();
const auth = createExpressAdapter(authLib);

app.use(express.json());

// Rutas de autenticación
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const result = await auth.authService.login(email, password);
    
    if (!result.success) {
      return res.status(401).json({ error: result.message });
    }

    // Generar tokens
    const accessToken = await auth.jwtService.generateToken({
      userId: result.user!.id,
      email: result.user!.email,
      roles: await auth.permissionService.getUserRoles(result.user!.id)
    });

    const refreshToken = await auth.jwtService.generateRefreshToken({
      userId: result.user!.id
    });

    res.json({
      accessToken,
      refreshToken,
      user: {
        id: result.user!.id,
        email: result.user!.email,
        name: result.user!.profile.name
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Error en autenticación' });
  }
});

// Verificar token (para otros servicios)
app.post('/auth/verify', async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ error: 'Token requerido' });
    }

    const payload = await auth.jwtService.verifyToken(token);
    
    if (!payload) {
      return res.status(401).json({ error: 'Token inválido' });
    }

    // Obtener información actualizada del usuario
    const user = await auth.authService.getUserById(payload.userId);
    const permissions = await auth.permissionService.getUserPermissions(payload.userId);

    res.json({
      valid: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.profile.name,
        roles: payload.roles,
        permissions
      }
    });
  } catch (error) {
    res.status(401).json({ error: 'Token inválido' });
  }
});

// Refresh token
app.post('/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    const payload = await auth.jwtService.verifyRefreshToken(refreshToken);
    
    if (!payload) {
      return res.status(401).json({ error: 'Refresh token inválido' });
    }

    // Generar nuevo access token
    const user = await auth.authService.getUserById(payload.userId);
    const roles = await auth.permissionService.getUserRoles(payload.userId);
    
    const newAccessToken = await auth.jwtService.generateToken({
      userId: user.id,
      email: user.email,
      roles
    });

    res.json({ accessToken: newAccessToken });
  } catch (error) {
    res.status(401).json({ error: 'Error al renovar token' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'auth-service' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Auth Service ejecutándose en puerto ${PORT}`);
});
```

#### 2. Middleware para Microservicios

```typescript
// shared/middleware/auth.ts
import axios from 'axios';
import { Request, Response, NextFunction } from 'express';

interface AuthenticatedRequest extends Request {
  user?: any;
}

export function createMicroserviceAuthMiddleware(authServiceUrl: string) {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      const authHeader = req.headers.authorization;
      
      // Verificación case-insensitive mejorada
      if (!authHeader || !authHeader.trim().toLowerCase().startsWith('bearer ')) {
        return res.status(401).json({ error: 'Token de autorización requerido' });
      }

      // Extracción mejorada del token
      const token = authHeader.trim().substring(7);
      
      // Verificar token con el servicio de autenticación
      const response = await axios.post(`${authServiceUrl}/auth/verify`, {
        token
      }, {
        timeout: 5000 // 5 segundos de timeout
      });

      if (response.data.valid) {
        req.user = response.data.user;
        next();
      } else {
        res.status(401).json({ error: 'Token inválido' });
      }
    } catch (error: any) {
      if (error.code === 'ECONNREFUSED') {
        return res.status(503).json({ 
          error: 'Servicio de autenticación no disponible' 
        });
      }
      
      if (error.response?.status === 401) {
        return res.status(401).json({ error: 'Token inválido' });
      }
      
      res.status(500).json({ error: 'Error al verificar autenticación' });
    }
  };
}

// Middleware para verificar permisos
export function requirePermissions(permissions: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'No autenticado' });
    }

    const userPermissions = req.user.permissions || [];
    const hasPermissions = permissions.every(permission => 
      userPermissions.includes(permission)
    );

    if (!hasPermissions) {
      return res.status(403).json({ 
        error: 'Permisos insuficientes',
        required: permissions,
        current: userPermissions
      });
    }

    next();
  };
}
```

#### 3. Servicio de Usuarios (`user-service/index.ts`)

```typescript
import express from 'express';
import { createMicroserviceAuthMiddleware, requirePermissions } from '../shared/middleware/auth';

const app = express();
app.use(express.json());

// Configurar middleware de autenticación
const authMiddleware = createMicroserviceAuthMiddleware(
  process.env.AUTH_SERVICE_URL || 'http://localhost:3001'
);

// Aplicar autenticación a todas las rutas
app.use(authMiddleware);

// Obtener perfil del usuario
app.get('/profile', (req, res) => {
  res.json({
    user: req.user
  });
});

// Listar usuarios (requiere permisos)
app.get('/users', 
  requirePermissions(['users.read']),
  async (req, res) => {
    try {
      // Lógica para obtener usuarios
      const users = await getUsersFromDatabase();
      res.json(users);
    } catch (error) {
      res.status(500).json({ error: 'Error al obtener usuarios' });
    }
  }
);

// Crear usuario (requiere permisos de admin)
app.post('/users',
  requirePermissions(['users.create']),
  async (req, res) => {
    try {
      // Lógica para crear usuario
      const newUser = await createUserInDatabase(req.body);
      res.status(201).json(newUser);
    } catch (error) {
      res.status(500).json({ error: 'Error al crear usuario' });
    }
  }
);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'user-service' });
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`User Service ejecutándose en puerto ${PORT}`);
});

// Funciones de base de datos (implementar según tu ORM)
async function getUsersFromDatabase() {
  // Implementar lógica de base de datos
  return [];
}

async function createUserInDatabase(userData: any) {
  // Implementar lógica de base de datos
  return userData;
}
```

#### 4. API Gateway (`api-gateway/index.ts`)

```typescript
import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

const app = express();

// Seguridad
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // máximo 100 requests por ventana
  message: 'Demasiadas solicitudes, intenta más tarde'
});
app.use(limiter);

// Middleware de logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Proxy para servicio de autenticación
app.use('/api/auth', createProxyMiddleware({
  target: process.env.AUTH_SERVICE_URL || 'http://localhost:3001',
  changeOrigin: true,
  pathRewrite: {
    '^/api/auth': '/auth'
  },
  onError: (err, req, res) => {
    console.error('Error en proxy de auth:', err);
    res.status(503).json({ error: 'Servicio de autenticación no disponible' });
  }
}));

// Proxy para servicio de usuarios
app.use('/api/users', createProxyMiddleware({
  target: process.env.USER_SERVICE_URL || 'http://localhost:3002',
  changeOrigin: true,
  pathRewrite: {
    '^/api/users': ''
  },
  onError: (err, req, res) => {
    console.error('Error en proxy de users:', err);
    res.status(503).json({ error: 'Servicio de usuarios no disponible' });
  }
}));

// Proxy para servicio de órdenes
app.use('/api/orders', createProxyMiddleware({
  target: process.env.ORDER_SERVICE_URL || 'http://localhost:3003',
  changeOrigin: true,
  pathRewrite: {
    '^/api/orders': ''
  },
  onError: (err, req, res) => {
    console.error('Error en proxy de orders:', err);
    res.status(503).json({ error: 'Servicio de órdenes no disponible' });
  }
}));

// Health check del gateway
app.get('/health', async (req, res) => {
  const services = [
    { name: 'auth', url: process.env.AUTH_SERVICE_URL || 'http://localhost:3001' },
    { name: 'users', url: process.env.USER_SERVICE_URL || 'http://localhost:3002' },
    { name: 'orders', url: process.env.ORDER_SERVICE_URL || 'http://localhost:3003' }
  ];

  const healthChecks = await Promise.allSettled(
    services.map(async (service) => {
      try {
        const response = await fetch(`${service.url}/health`, { 
          signal: AbortSignal.timeout(5000) 
        });
        return { 
          service: service.name, 
          status: response.ok ? 'healthy' : 'unhealthy' 
        };
      } catch (error) {
        return { 
          service: service.name, 
          status: 'unhealthy' 
        };
      }
    })
  );

  const results = healthChecks.map(result => 
    result.status === 'fulfilled' ? result.value : { 
      service: 'unknown', 
      status: 'error' 
    }
  );

  const allHealthy = results.every(result => result.status === 'healthy');

  res.status(allHealthy ? 200 : 503).json({
    status: allHealthy ? 'healthy' : 'degraded',
    services: results,
    timestamp: new Date().toISOString()
  });
});

// Manejo de rutas no encontradas
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Ruta no encontrada' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API Gateway ejecutándose en puerto ${PORT}`);
});
```

---

## 🔗 Enlaces Relacionados

- **[Middleware y Configuración](./06-middleware.md)** - Configuración avanzada
- **[API Reference](./08-api-reference.md)** - Referencia completa de la API
- **[Troubleshooting](./09-troubleshooting.md)** - Solución de problemas
- **[Instalación](./02-installation-config.md)** - Configuración inicial

---

[⬅️ Middleware](./06-middleware.md) | [🏠 Índice](./README.md) | [➡️ API Reference](./08-api-reference.md)