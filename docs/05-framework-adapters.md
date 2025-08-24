# 🔌 Adaptadores de Framework

La librería de autenticación incluye adaptadores específicos para diferentes frameworks web, proporcionando integración nativa y middleware optimizado para cada uno.

## 📋 Índice

1. [Descripción General](#descripción-general)
2. [Adaptador Hono](#adaptador-hono)
3. [Adaptador Express](#adaptador-express)
4. [Adaptador WebSocket](#adaptador-websocket)
5. [Crear Adaptador Personalizado](#crear-adaptador-personalizado)
6. [Comparación de Adaptadores](#comparación-de-adaptadores)
7. [Mejores Prácticas](#mejores-prácticas)

## 🎯 Descripción General

### ¿Qué son los Adaptadores?

Los adaptadores son capas de integración que permiten usar la librería de autenticación con diferentes frameworks web de manera nativa, respetando las convenciones y patrones de cada framework.

### Características Comunes

Todos los adaptadores proporcionan:

- **Middleware de autenticación** automático
- **Extracción de tokens** desde headers
- **Validación de permisos** integrada
- **Manejo de errores** específico del framework
- **Inyección de usuario** en el contexto de request
- **Configuración flexible** por ruta

### Arquitectura

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Hono Adapter   │    │ Express Adapter │    │WebSocket Adapter│
│                 │    │                 │    │                 │
│ • HonoAuth      │    │ • ExpressAuth   │    │ • WSAuth        │
│ • Middleware    │    │ • Middleware    │    │ • Connection    │
│ • Context       │    │ • Request/Res   │    │ • Events        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   AuthLibrary   │
                    │   (Core Logic)  │
                    └─────────────────┘
```

---

## 🚀 Adaptador Hono

El adaptador para Hono proporciona middleware nativo y funciones de utilidad optimizadas para este framework ultrarrápido.

### Instalación y Configuración

```typescript
import { Hono } from 'hono';
import { AuthLibrary, createHonoAuth } from '@open-bauth/core';

// Configurar AuthLibrary
const authLib = new AuthLibrary({
  jwtSecret: process.env.JWT_SECRET!,
  database: { path: './auth.db' }
});

await authLib.initialize();

// Crear adaptador Hono
const auth = createHonoAuth(authLib);

// Crear aplicación Hono
const app = new Hono();
```

### Middleware Básico

#### `auth.middleware`

Middleware global que extrae y valida tokens en todas las rutas con soporte mejorado para múltiples métodos de autenticación.

```typescript
// Aplicar middleware global
app.use('*', auth.middleware);

// Ahora todas las rutas tienen acceso a información de autenticación
app.get('/profile', (c) => {
  const user = auth.getCurrentUser(c);
  
  if (!user) {
    return c.json({ error: 'No autenticado' }, 401);
  }
  
  return c.json({ user });
});
```

**Métodos de Autenticación Soportados:**

1. **Authorization Header (Bearer Token)** - Case-insensitive:
   ```
   Authorization: Bearer <token>
   Authorization: bearer <token>
   Authorization: BEARER <token>
   ```

2. **Custom Headers:**
   ```
   X-Auth-Token: <token>
   X-API-Key: <token>
   ```

3. **Query Parameters:**
   ```
   GET /api/data?token=<token>
   GET /api/data?access_token=<token>
   GET /api/data?auth_token=<token>
   ```

4. **URL Parameters:**
   ```
   GET /api/data/:token
   ```

#### `auth.required`

Middleware que requiere autenticación obligatoria.

```typescript
// Ruta que requiere autenticación
app.get('/dashboard', auth.required, (c) => {
  const user = auth.getCurrentUser(c);
  return c.json({ 
    message: `Bienvenido ${user.firstName}`,
    user 
  });
});

// Múltiples rutas protegidas
app.use('/api/protected/*', auth.required);

app.get('/api/protected/data', (c) => {
  // Usuario garantizado aquí
  const user = auth.getCurrentUser(c);
  return c.json({ data: 'información sensible', user: user.email });
});
```

#### `auth.optional`

Middleware que permite autenticación opcional.

```typescript
// Ruta con autenticación opcional
app.get('/posts', auth.optional, (c) => {
  const user = auth.getCurrentUser(c);
  
  if (user) {
    // Usuario autenticado - mostrar posts personalizados
    return c.json({ 
      posts: getPersonalizedPosts(user.id),
      user: user.email 
    });
  } else {
    // Usuario anónimo - mostrar posts públicos
    return c.json({ 
      posts: getPublicPosts() 
    });
  }
});
```

### Middleware de Permisos

#### `auth.permissions(requiredPermissions)`

Middleware que verifica permisos específicos.

```typescript
// Ruta que requiere permisos específicos
app.get('/admin/users', 
  auth.permissions(['users.read']), 
  (c) => {
    return c.json({ users: getAllUsers() });
  }
);

// Múltiples permisos requeridos
app.delete('/admin/users/:id', 
  auth.permissions(['users.delete', 'admin.access']), 
  (c) => {
    const userId = c.req.param('id');
    return c.json({ success: deleteUser(userId) });
  }
);

// Permisos con lógica OR (cualquiera de los permisos)
app.get('/moderation', 
  auth.permissions(['admin.access', 'moderator.access'], { requireAll: false }), 
  (c) => {
    return c.json({ message: 'Acceso de moderación' });
  }
);
```

#### `auth.roles(requiredRoles)`

Middleware que verifica roles específicos.

```typescript
// Ruta solo para administradores
app.get('/admin/settings', 
  auth.roles(['admin']), 
  (c) => {
    return c.json({ settings: getAdminSettings() });
  }
);

// Múltiples roles permitidos
app.get('/staff/dashboard', 
  auth.roles(['admin', 'moderator', 'staff']), 
  (c) => {
    const user = auth.getCurrentUser(c);
    return c.json({ 
      message: `Dashboard para ${user.roles.join(', ')}`,
      user 
    });
  }
);
```

### Funciones de Utilidad

#### `auth.getCurrentUser(c)`

Obtiene el usuario actual del contexto.

```typescript
app.get('/me', auth.required, (c) => {
  const user = auth.getCurrentUser(c);
  
  return c.json({
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    roles: user.roles,
    permissions: user.permissions
  });
});
```

#### `auth.getUserPermissions(c)`

Obtiene los permisos del usuario actual.

```typescript
app.get('/permissions', auth.required, (c) => {
  const permissions = auth.getUserPermissions(c);
  
  return c.json({ 
    permissions: permissions.map(p => p.name),
    count: permissions.length 
  });
});
```

#### `auth.getUserRoles(c)`

Obtiene los roles del usuario actual.

```typescript
app.get('/roles', auth.required, (c) => {
  const roles = auth.getUserRoles(c);
  
  return c.json({ 
    roles: roles.map(r => r.name),
    count: roles.length 
  });
});
```

#### `auth.hasPermission(c, permission)`

Verifica si el usuario tiene un permiso específico.

```typescript
app.get('/conditional-feature', auth.required, (c) => {
  const canManageUsers = auth.hasPermission(c, 'users.manage');
  const canViewReports = auth.hasPermission(c, 'reports.view');
  
  return c.json({
    features: {
      userManagement: canManageUsers,
      reports: canViewReports
    }
  });
});
```

### Rutas de Autenticación

```typescript
// Registro de usuario
app.post('/auth/register', async (c) => {
  try {
    const data = await c.req.json();
    const result = await authLib.getAuthService().register(data);
    
    if (result.success) {
      return c.json({
        message: 'Usuario registrado exitosamente',
        user: result.user,
        token: result.token
      }, 201);
    } else {
      return c.json({
        error: result.error?.message || 'Error en el registro'
      }, 400);
    }
  } catch (error) {
    return c.json({ error: 'Error interno del servidor' }, 500);
  }
});

// Login de usuario
app.post('/auth/login', async (c) => {
  try {
    const credentials = await c.req.json();
    const result = await authLib.getAuthService().login(credentials);
    
    if (result.success) {
      return c.json({
        message: 'Login exitoso',
        user: result.user,
        token: result.token,
        refreshToken: result.refreshToken
      });
    } else {
      return c.json({
        error: result.error?.message || 'Credenciales inválidas'
      }, 401);
    }
  } catch (error) {
    return c.json({ error: 'Error interno del servidor' }, 500);
  }
});

// Refresh token
app.post('/auth/refresh', async (c) => {
  try {
    const { refreshToken } = await c.req.json();
    const result = await authLib.getAuthService().refreshToken(refreshToken);
    
    if (result.success) {
      return c.json({
        token: result.token,
        user: result.user
      });
    } else {
      return c.json({ error: 'Refresh token inválido' }, 401);
    }
  } catch (error) {
    return c.json({ error: 'Error interno del servidor' }, 500);
  }
});

// Logout
app.post('/auth/logout', auth.required, async (c) => {
  try {
    const token = auth.getTokenFromContext(c);
    await authLib.getAuthService().logout(token);
    
    return c.json({ message: 'Logout exitoso' });
  } catch (error) {
    return c.json({ error: 'Error en logout' }, 500);
  }
});
```

### Configuración Avanzada

```typescript
// Crear adaptador con configuración personalizada
const auth = createHonoAuth(authLib, {
  // Configuración de tokens
  tokenExtraction: {
    fromHeader: true,
    fromCookie: true,
    fromQuery: false,
    headerName: 'Authorization',
    cookieName: 'auth-token',
    queryParam: 'token'
  },
  
  // Configuración de errores
  errorHandling: {
    sendStackTrace: process.env.NODE_ENV === 'development',
    customErrorMessages: {
      unauthorized: 'Acceso no autorizado',
      forbidden: 'Permisos insuficientes',
      tokenExpired: 'Token expirado',
      tokenInvalid: 'Token inválido'
    }
  },
  
  // Configuración de CORS
  cors: {
    enabled: true,
    origins: ['http://localhost:3000'],
    credentials: true
  },
  
  // Rate limiting
  rateLimit: {
    enabled: true,
    windowMs: 15 * 60 * 1000, // 15 minutos
    maxRequests: 100,
    skipSuccessfulRequests: true
  }
});
```

### Ejemplo Completo con Hono

```typescript
// server.ts
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { AuthLibrary, createHonoAuth } from '@open-bauth/core';

// Configurar AuthLibrary
const authLib = new AuthLibrary({
  jwtSecret: process.env.JWT_SECRET!,
  database: { path: './auth.db' },
  security: {
    bcryptRounds: 12,
    maxLoginAttempts: 5
  }
});

await authLib.initialize();

// Crear adaptador
const auth = createHonoAuth(authLib);

// Crear aplicación
const app = new Hono();

// Middleware global
app.use('*', logger());
app.use('*', cors({
  origin: ['http://localhost:3000'],
  credentials: true
}));
app.use('*', auth.middleware);

// Rutas públicas
app.get('/', (c) => c.json({ message: 'API funcionando' }));

// Rutas de autenticación
const authRoutes = new Hono();

authRoutes.post('/register', async (c) => {
  const data = await c.req.json();
  const result = await authLib.getAuthService().register(data);
  
  if (result.success) {
    return c.json({ user: result.user, token: result.token }, 201);
  }
  return c.json({ error: result.error?.message }, 400);
});

authRoutes.post('/login', async (c) => {
  const credentials = await c.req.json();
  const result = await authLib.getAuthService().login(credentials);
  
  if (result.success) {
    return c.json({ user: result.user, token: result.token });
  }
  return c.json({ error: result.error?.message }, 401);
});

app.route('/auth', authRoutes);

// Rutas protegidas
const protectedRoutes = new Hono();
protectedRoutes.use('*', auth.required);

protectedRoutes.get('/profile', (c) => {
  const user = auth.getCurrentUser(c);
  return c.json({ user });
});

protectedRoutes.put('/profile', async (c) => {
  const user = auth.getCurrentUser(c);
  const updates = await c.req.json();
  
  const updatedUser = await authLib.getAuthService().updateUser(user.id, updates);
  return c.json({ user: updatedUser });
});

app.route('/api', protectedRoutes);

// Rutas de administración
const adminRoutes = new Hono();
adminRoutes.use('*', auth.permissions(['admin.access']));

adminRoutes.get('/users', async (c) => {
  const users = await authLib.getAuthService().getUsers();
  return c.json({ users });
});

adminRoutes.delete('/users/:id', async (c) => {
  const userId = c.req.param('id');
  const deleted = await authLib.getAuthService().deleteUser(userId);
  return c.json({ success: deleted });
});

app.route('/admin', adminRoutes);

// Manejo de errores global
app.onError((err, c) => {
  console.error('Error:', err);
  return c.json({ error: 'Error interno del servidor' }, 500);
});

// Iniciar servidor
export default {
  port: 3000,
  fetch: app.fetch,
};

console.log('🚀 Servidor Hono corriendo en puerto 3000');
```

---

## 🌐 Adaptador Express

El adaptador para Express proporciona middleware compatible con el ecosistema Express y frameworks derivados.

### Instalación y Configuración

```typescript
import express from 'express';
import { AuthLibrary, createExpressAuth } from '@open-bauth/core';

// Configurar AuthLibrary
const authLib = new AuthLibrary({
  jwtSecret: process.env.JWT_SECRET!,
  database: { path: './auth.db' }
});

await authLib.initialize();

// Crear adaptador Express
const auth = createExpressAuth(authLib);

// Crear aplicación Express
const app = express();

// Middleware básico
app.use(express.json());
app.use(auth.middleware);
```

### Middleware de Express

#### `auth.middleware`

Middleware global para Express con soporte mejorado para extracción de tokens.

```typescript
// Aplicar middleware global
app.use(auth.middleware);

// Ahora req.user está disponible en todas las rutas
app.get('/profile', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'No autenticado' });
  }
  
  res.json({ user: req.user });
});
```

**Métodos de Autenticación Soportados:**

1. **Authorization Header (Bearer Token)** - Case-insensitive:
   ```
   Authorization: Bearer <token>
   Authorization: bearer <token>
   Authorization: BEARER <token>
   ```

2. **Custom Headers:**
   ```
   X-Auth-Token: <token>
   X-API-Key: <token>
   ```

3. **Query Parameters:**
   ```
   GET /api/data?token=<token>
   GET /api/data?access_token=<token>
   GET /api/data?auth_token=<token>
   ```

4. **URL Parameters:**
   ```
   GET /api/data/:token
   ```

#### `auth.required`

Middleware que requiere autenticación.

```typescript
// Ruta que requiere autenticación
app.get('/dashboard', auth.required, (req, res) => {
  // req.user está garantizado aquí
  res.json({ 
    message: `Bienvenido ${req.user.firstName}`,
    user: req.user 
  });
});

// Aplicar a múltiples rutas
app.use('/api/protected', auth.required);

app.get('/api/protected/data', (req, res) => {
  res.json({ 
    data: 'información sensible', 
    user: req.user.email 
  });
});
```

#### `auth.permissions(requiredPermissions)`

Middleware de permisos para Express.

```typescript
// Ruta con permisos específicos
app.get('/admin/users', 
  auth.permissions(['users.read']), 
  (req, res) => {
    res.json({ users: getAllUsers() });
  }
);

// Múltiples permisos
app.delete('/admin/users/:id', 
  auth.permissions(['users.delete', 'admin.access']), 
  (req, res) => {
    const success = deleteUser(req.params.id);
    res.json({ success });
  }
);
```

#### `auth.roles(requiredRoles)`

Middleware de roles para Express.

```typescript
// Solo administradores
app.get('/admin/settings', 
  auth.roles(['admin']), 
  (req, res) => {
    res.json({ settings: getAdminSettings() });
  }
);

// Múltiples roles
app.get('/staff/dashboard', 
  auth.roles(['admin', 'moderator', 'staff']), 
  (req, res) => {
    res.json({ 
      message: `Dashboard para ${req.user.roles.join(', ')}`,
      user: req.user 
    });
  }
);
```

### Extensión de Request

El adaptador de Express extiende el objeto `Request` con propiedades adicionales:

```typescript
// Tipos TypeScript extendidos
declare global {
  namespace Express {
    interface Request {
      user?: User;
      permissions?: Permission[];
      roles?: Role[];
      authToken?: string;
      isAuthenticated: boolean;
    }
  }
}

// Uso en rutas
app.get('/user-info', auth.required, (req, res) => {
  res.json({
    user: req.user,
    permissions: req.permissions?.map(p => p.name),
    roles: req.roles?.map(r => r.name),
    isAuthenticated: req.isAuthenticated
  });
});
```

### Rutas de Autenticación con Express

```typescript
// Registro
app.post('/auth/register', async (req, res) => {
  try {
    const result = await authLib.getAuthService().register(req.body);
    
    if (result.success) {
      res.status(201).json({
        message: 'Usuario registrado',
        user: result.user,
        token: result.token
      });
    } else {
      res.status(400).json({ error: result.error?.message });
    }
  } catch (error) {
    res.status(500).json({ error: 'Error interno' });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const result = await authLib.getAuthService().login(req.body);
    
    if (result.success) {
      res.json({
        message: 'Login exitoso',
        user: result.user,
        token: result.token
      });
    } else {
      res.status(401).json({ error: result.error?.message });
    }
  } catch (error) {
    res.status(500).json({ error: 'Error interno' });
  }
});

// Logout
app.post('/auth/logout', auth.required, async (req, res) => {
  try {
    await authLib.getAuthService().logout(req.authToken!);
    res.json({ message: 'Logout exitoso' });
  } catch (error) {
    res.status(500).json({ error: 'Error en logout' });
  }
});
```

### Manejo de Errores con Express

```typescript
// Middleware de manejo de errores de autenticación
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (err.name === 'AuthenticationError') {
    return res.status(401).json({
      error: 'Token inválido o expirado',
      code: 'AUTHENTICATION_FAILED'
    });
  }
  
  if (err.name === 'AuthorizationError') {
    return res.status(403).json({
      error: 'Permisos insuficientes',
      code: 'AUTHORIZATION_FAILED',
      required: err.requiredPermissions
    });
  }
  
  console.error('Error no manejado:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
});
```

### Ejemplo Completo con Express

```typescript
// app.ts
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { AuthLibrary, createExpressAuth } from '@open-bauth/core';

// Configurar AuthLibrary
const authLib = new AuthLibrary({
  jwtSecret: process.env.JWT_SECRET!,
  database: { path: './auth.db' }
});

await authLib.initialize();

// Crear adaptador
const auth = createExpressAuth(authLib);

// Crear aplicación
const app = express();

// Middleware de seguridad
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:3000'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100 // máximo 100 requests por ventana
});
app.use(limiter);

// Middleware básico
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Middleware de autenticación
app.use(auth.middleware);

// Rutas públicas
app.get('/', (req, res) => {
  res.json({ message: 'API funcionando', version: '1.0.0' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Rutas de autenticación
const authRouter = express.Router();

authRouter.post('/register', async (req, res) => {
  const result = await authLib.getAuthService().register(req.body);
  
  if (result.success) {
    res.status(201).json({ user: result.user, token: result.token });
  } else {
    res.status(400).json({ error: result.error?.message });
  }
});

authRouter.post('/login', async (req, res) => {
  const result = await authLib.getAuthService().login(req.body);
  
  if (result.success) {
    res.json({ user: result.user, token: result.token });
  } else {
    res.status(401).json({ error: result.error?.message });
  }
});

app.use('/auth', authRouter);

// Rutas protegidas
const apiRouter = express.Router();
apiRouter.use(auth.required);

apiRouter.get('/profile', (req, res) => {
  res.json({ user: req.user });
});

apiRouter.put('/profile', async (req, res) => {
  const updatedUser = await authLib.getAuthService().updateUser(
    req.user!.id, 
    req.body
  );
  res.json({ user: updatedUser });
});

app.use('/api', apiRouter);

// Rutas de administración
const adminRouter = express.Router();
adminRouter.use(auth.permissions(['admin.access']));

adminRouter.get('/users', async (req, res) => {
  const users = await authLib.getAuthService().getUsers();
  res.json({ users });
});

adminRouter.delete('/users/:id', async (req, res) => {
  const deleted = await authLib.getAuthService().deleteUser(req.params.id);
  res.json({ success: deleted });
});

app.use('/admin', adminRouter);

// Manejo de errores
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// Ruta 404
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint no encontrado' });
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor Express corriendo en puerto ${PORT}`);
});

export default app;
```

---

## 🔌 Adaptador WebSocket

El adaptador WebSocket permite autenticación en tiempo real para conexiones WebSocket.

### Configuración Básica

```typescript
import { WebSocketServer } from 'ws';
import { AuthLibrary, createWebSocketAuth } from '@open-bauth/core';

// Configurar AuthLibrary
const authLib = new AuthLibrary({
  jwtSecret: process.env.JWT_SECRET!,
  database: { path: './auth.db' }
});

await authLib.initialize();

// Crear adaptador WebSocket
const wsAuth = createWebSocketAuth(authLib);

// Crear servidor WebSocket
const wss = new WebSocketServer({ port: 8080 });

// Manejar conexiones
wss.on('connection', async (ws, req) => {
  try {
    // Autenticar conexión
    const authResult = await wsAuth.authenticateConnection(req);
    
    if (!authResult.success) {
      ws.close(1008, 'Autenticación requerida');
      return;
    }
    
    // Conexión autenticada
    const user = authResult.user!;
    console.log(`Usuario conectado: ${user.email}`);
    
    // Agregar información de usuario a la conexión
    (ws as any).user = user;
    (ws as any).permissions = authResult.permissions;
    
    // Manejar mensajes
    ws.on('message', async (data) => {
      await wsAuth.handleMessage(ws, data, user);
    });
    
    // Manejar desconexión
    ws.on('close', () => {
      console.log(`Usuario desconectado: ${user.email}`);
    });
    
  } catch (error) {
    console.error('Error en conexión WebSocket:', error);
    ws.close(1011, 'Error interno');
  }
});
```

### Autenticación por Token

```typescript
// Cliente WebSocket con token
const token = localStorage.getItem('authToken');
const ws = new WebSocket(`ws://localhost:8080?token=${token}`);

// O por header
const ws = new WebSocket('ws://localhost:8080', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
```

### Manejo de Mensajes Autenticados

```typescript
// Servidor WebSocket con manejo de permisos
wss.on('connection', async (ws, req) => {
  const authResult = await wsAuth.authenticateConnection(req);
  
  if (!authResult.success) {
    ws.close(1008, 'Autenticación requerida');
    return;
  }
  
  const user = authResult.user!;
  
  ws.on('message', async (data) => {
    try {
      const message = JSON.parse(data.toString());
      
      switch (message.type) {
        case 'chat_message':
          // Verificar permiso para enviar mensajes
          if (await wsAuth.userHasPermission(user.id, 'chat.send')) {
            // Procesar mensaje de chat
            broadcastMessage(message, user);
          } else {
            ws.send(JSON.stringify({
              type: 'error',
              message: 'Sin permisos para enviar mensajes'
            }));
          }
          break;
          
        case 'admin_command':
          // Solo administradores
          if (await wsAuth.userHasRole(user.id, 'admin')) {
            // Procesar comando de administración
            handleAdminCommand(message, user);
          } else {
            ws.send(JSON.stringify({
              type: 'error',
              message: 'Comando solo para administradores'
            }));
          }
          break;
          
        default:
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Tipo de mensaje no reconocido'
          }));
      }
    } catch (error) {
      console.error('Error procesando mensaje:', error);
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Error procesando mensaje'
      }));
    }
  });
});
```

### Sistema de Salas con Permisos

```typescript
class AuthenticatedChatServer {
  private wss: WebSocketServer;
  private wsAuth: any;
  private rooms = new Map<string, Set<any>>();
  
  constructor(authLib: AuthLibrary) {
    this.wsAuth = createWebSocketAuth(authLib);
    this.wss = new WebSocketServer({ port: 8080 });
    this.setupServer();
  }
  
  private setupServer(): void {
    this.wss.on('connection', async (ws, req) => {
      const authResult = await this.wsAuth.authenticateConnection(req);
      
      if (!authResult.success) {
        ws.close(1008, 'Autenticación requerida');
        return;
      }
      
      const user = authResult.user!;
      (ws as any).user = user;
      (ws as any).rooms = new Set<string>();
      
      ws.on('message', (data) => this.handleMessage(ws, data));
      ws.on('close', () => this.handleDisconnection(ws));
      
      // Enviar mensaje de bienvenida
      ws.send(JSON.stringify({
        type: 'welcome',
        user: { id: user.id, email: user.email }
      }));
    });
  }
  
  private async handleMessage(ws: any, data: any): Promise<void> {
    try {
      const message = JSON.parse(data.toString());
      const user = ws.user;
      
      switch (message.type) {
        case 'join_room':
          await this.handleJoinRoom(ws, message.room);
          break;
          
        case 'leave_room':
          await this.handleLeaveRoom(ws, message.room);
          break;
          
        case 'send_message':
          await this.handleSendMessage(ws, message);
          break;
          
        case 'private_message':
          await this.handlePrivateMessage(ws, message);
          break;
      }
    } catch (error) {
      console.error('Error:', error);
      ws.send(JSON.stringify({ type: 'error', message: 'Error procesando mensaje' }));
    }
  }
  
  private async handleJoinRoom(ws: any, roomName: string): Promise<void> {
    const user = ws.user;
    
    // Verificar permisos para la sala
    const canJoin = await this.wsAuth.userHasPermission(
      user.id, 
      `rooms.${roomName}.join`
    ) || await this.wsAuth.userHasPermission(user.id, 'rooms.join_any');
    
    if (!canJoin) {
      ws.send(JSON.stringify({
        type: 'error',
        message: `Sin permisos para unirse a la sala ${roomName}`
      }));
      return;
    }
    
    // Agregar a la sala
    if (!this.rooms.has(roomName)) {
      this.rooms.set(roomName, new Set());
    }
    
    this.rooms.get(roomName)!.add(ws);
    ws.rooms.add(roomName);
    
    // Notificar a la sala
    this.broadcastToRoom(roomName, {
      type: 'user_joined',
      user: { id: user.id, email: user.email },
      room: roomName
    }, ws);
    
    // Confirmar al usuario
    ws.send(JSON.stringify({
      type: 'room_joined',
      room: roomName
    }));
  }
  
  private async handleSendMessage(ws: any, message: any): Promise<void> {
    const user = ws.user;
    const roomName = message.room;
    
    // Verificar que esté en la sala
    if (!ws.rooms.has(roomName)) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'No estás en esa sala'
      }));
      return;
    }
    
    // Verificar permisos para enviar mensajes
    const canSend = await this.wsAuth.userHasPermission(
      user.id, 
      `rooms.${roomName}.send`
    ) || await this.wsAuth.userHasPermission(user.id, 'chat.send');
    
    if (!canSend) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Sin permisos para enviar mensajes'
      }));
      return;
    }
    
    // Enviar mensaje a la sala
    this.broadcastToRoom(roomName, {
      type: 'chat_message',
      user: { id: user.id, email: user.email },
      message: message.content,
      room: roomName,
      timestamp: new Date().toISOString()
    });
  }
  
  private broadcastToRoom(roomName: string, message: any, exclude?: any): void {
    const room = this.rooms.get(roomName);
    if (!room) return;
    
    const messageStr = JSON.stringify(message);
    
    room.forEach(ws => {
      if (ws !== exclude && ws.readyState === ws.OPEN) {
        ws.send(messageStr);
      }
    });
  }
  
  private handleDisconnection(ws: any): void {
    const user = ws.user;
    
    // Remover de todas las salas
    ws.rooms.forEach((roomName: string) => {
      const room = this.rooms.get(roomName);
      if (room) {
        room.delete(ws);
        
        // Notificar a la sala
        this.broadcastToRoom(roomName, {
          type: 'user_left',
          user: { id: user.id, email: user.email },
          room: roomName
        });
        
        // Limpiar sala vacía
        if (room.size === 0) {
          this.rooms.delete(roomName);
        }
      }
    });
    
    console.log(`Usuario desconectado: ${user.email}`);
  }
}

// Uso
const chatServer = new AuthenticatedChatServer(authLib);
console.log('🚀 Servidor de chat WebSocket corriendo en puerto 8080');
```

---

## 🛠️ Crear Adaptador Personalizado

Puedes crear adaptadores personalizados para otros frameworks o casos de uso específicos.

### Estructura Base

```typescript
import { AuthLibrary, User, Permission, Role } from '@open-bauth/core';

interface CustomAdapterOptions {
  tokenExtraction?: {
    fromHeader?: boolean;
    fromCookie?: boolean;
    fromQuery?: boolean;
    headerName?: string;
    cookieName?: string;
    queryParam?: string;
  };
  errorHandling?: {
    sendStackTrace?: boolean;
    customErrorMessages?: Record<string, string>;
  };
}

class CustomFrameworkAdapter {
  private authLib: AuthLibrary;
  private options: CustomAdapterOptions;
  
  constructor(authLib: AuthLibrary, options: CustomAdapterOptions = {}) {
    this.authLib = authLib;
    this.options = {
      tokenExtraction: {
        fromHeader: true,
        fromCookie: false,
        fromQuery: false,
        headerName: 'Authorization',
        cookieName: 'auth-token',
        queryParam: 'token',
        ...options.tokenExtraction
      },
      errorHandling: {
        sendStackTrace: false,
        customErrorMessages: {},
        ...options.errorHandling
      }
    };
  }
  
  // Método para extraer token del contexto del framework
  private extractToken(context: any): string | null {
    const { tokenExtraction } = this.options;
    
    // Intentar desde header
    if (tokenExtraction?.fromHeader) {
      const authHeader = context.headers?.[tokenExtraction.headerName!.toLowerCase()];
      if (authHeader && authHeader.startsWith('Bearer ')) {
        return authHeader.substring(7);
      }
    }
    
    // Intentar desde cookie
    if (tokenExtraction?.fromCookie) {
      const token = context.cookies?.[tokenExtraction.cookieName!];
      if (token) return token;
    }
    
    // Intentar desde query parameter
    if (tokenExtraction?.fromQuery) {
      const token = context.query?.[tokenExtraction.queryParam!];
      if (token) return token;
    }
    
    return null;
  }
  
  // Middleware básico
  middleware = async (context: any, next: Function) => {
    try {
      const token = this.extractToken(context);
      
      if (token) {
        try {
          const payload = await this.authLib.getJWTService().verifyToken(token);
          const user = await this.authLib.getAuthService().findUserById(payload.userId);
          
          if (user && user.active) {
            context.user = user;
            context.authToken = token;
            context.isAuthenticated = true;
            
            // Cargar permisos y roles
            context.permissions = await this.authLib.getPermissionService().getUserPermissions(user.id);
            context.roles = await this.authLib.getPermissionService().getUserRoles(user.id);
          }
        } catch (error) {
          // Token inválido, continuar sin autenticación
          context.isAuthenticated = false;
        }
      } else {
        context.isAuthenticated = false;
      }
      
      await next();
    } catch (error) {
      throw error;
    }
  };
  
  // Middleware que requiere autenticación
  required = async (context: any, next: Function) => {
    await this.middleware(context, () => {});
    
    if (!context.isAuthenticated) {
      throw new Error('Autenticación requerida');
    }
    
    await next();
  };
  
  // Middleware de permisos
  permissions = (requiredPermissions: string[], options: { requireAll?: boolean } = {}) => {
    return async (context: any, next: Function) => {
      await this.required(context, () => {});
      
      const userPermissions = context.permissions?.map((p: Permission) => p.name) || [];
      
      const hasPermissions = options.requireAll !== false
        ? requiredPermissions.every(perm => userPermissions.includes(perm))
        : requiredPermissions.some(perm => userPermissions.includes(perm));
      
      if (!hasPermissions) {
        throw new Error('Permisos insuficientes');
      }
      
      await next();
    };
  };
  
  // Middleware de roles
  roles = (requiredRoles: string[]) => {
    return async (context: any, next: Function) => {
      await this.required(context, () => {});
      
      const userRoles = context.roles?.map((r: Role) => r.name) || [];
      const hasRole = requiredRoles.some(role => userRoles.includes(role));
      
      if (!hasRole) {
        throw new Error('Rol insuficiente');
      }
      
      await next();
    };
  };
  
  // Funciones de utilidad
  getCurrentUser(context: any): User | null {
    return context.user || null;
  }
  
  getUserPermissions(context: any): Permission[] {
    return context.permissions || [];
  }
  
  getUserRoles(context: any): Role[] {
    return context.roles || [];
  }
  
  hasPermission(context: any, permission: string): boolean {
    const permissions = this.getUserPermissions(context);
    return permissions.some(p => p.name === permission);
  }
  
  hasRole(context: any, role: string): boolean {
    const roles = this.getUserRoles(context);
    return roles.some(r => r.name === role);
  }
}

// Factory function
export function createCustomFrameworkAuth(
  authLib: AuthLibrary, 
  options?: CustomAdapterOptions
): CustomFrameworkAdapter {
  return new CustomFrameworkAdapter(authLib, options);
}
```

### Ejemplo de Uso del Adaptador Personalizado

```typescript
// Usar con un framework hipotético
import { createCustomFrameworkAuth } from './custom-adapter';

const auth = createCustomFrameworkAuth(authLib, {
  tokenExtraction: {
    fromHeader: true,
    fromCookie: true,
    headerName: 'X-Auth-Token'
  }
});

// Aplicar middleware
app.use(auth.middleware);

// Rutas protegidas
app.get('/protected', auth.required, (context) => {
  const user = auth.getCurrentUser(context);
  return { message: `Hola ${user.firstName}` };
});

// Rutas con permisos
app.get('/admin', auth.permissions(['admin.access']), (context) => {
  return { message: 'Panel de administración' };
});
```

---

## 📊 Comparación de Adaptadores

| Característica | Hono | Express | WebSocket | Personalizado |
|----------------|------|---------|-----------|---------------|
| **Rendimiento** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Facilidad de uso** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| **Funcionalidades** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Ecosistema** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| **Tiempo real** | ❌ | ❌ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| **TypeScript** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

### Cuándo Usar Cada Adaptador

**Hono:**
- APIs REST ultrarrápidas
- Aplicaciones serverless
- Proyectos nuevos con TypeScript
- Cuando el rendimiento es crítico

**Express:**
- Aplicaciones existentes con Express
- Ecosistema maduro requerido
- Equipos familiarizados con Express
- Integración con middleware existente

**WebSocket:**
- Aplicaciones en tiempo real
- Chat, notificaciones, gaming
- Colaboración en tiempo real
- Streaming de datos

**Personalizado:**
- Frameworks no soportados
- Requisitos específicos
- Integración con sistemas legacy
- Control total sobre la implementación

---

## 🎯 Mejores Prácticas

### 1. Configuración de Seguridad

```typescript
// ✅ Buena práctica: Configuración segura
const auth = createHonoAuth(authLib, {
  tokenExtraction: {
    fromHeader: true,
    fromCookie: false, // Evitar cookies en APIs públicas
    fromQuery: false   // Nunca en query params para producción
  },
  errorHandling: {
    sendStackTrace: process.env.NODE_ENV === 'development',
    customErrorMessages: {
      unauthorized: 'Acceso denegado',
      forbidden: 'Permisos insuficientes'
    }
  }
});
```

### 2. Manejo de Errores Consistente

```typescript
// ✅ Buena práctica: Manejo de errores unificado
function createErrorHandler(framework: 'hono' | 'express') {
  if (framework === 'hono') {
    return (err: any, c: any) => {
      console.error('Auth Error:', err);
      
      if (err.name === 'AuthenticationError') {
        return c.json({ error: 'Token inválido' }, 401);
      }
      
      if (err.name === 'AuthorizationError') {
        return c.json({ error: 'Permisos insuficientes' }, 403);
      }
      
      return c.json({ error: 'Error interno' }, 500);
    };
  } else {
    return (err: any, req: any, res: any, next: any) => {
      console.error('Auth Error:', err);
      
      if (err.name === 'AuthenticationError') {
        return res.status(401).json({ error: 'Token inválido' });
      }
      
      if (err.name === 'AuthorizationError') {
        return res.status(403).json({ error: 'Permisos insuficientes' });
      }
      
      return res.status(500).json({ error: 'Error interno' });
    };
  }
}
```

### 3. Logging y Auditoría

```typescript
// ✅ Buena práctica: Logging de eventos de autenticación
function createAuditMiddleware(authAdapter: any) {
  return async (context: any, next: Function) => {
    const startTime = Date.now();
    const ip = context.req?.ip || context.request?.ip;
    const userAgent = context.req?.headers?.['user-agent'];
    
    try {
      await authAdapter.middleware(context, next);
      
      // Log exitoso
      if (context.isAuthenticated) {
        console.log('Auth Success:', {
          userId: context.user?.id,
          email: context.user?.email,
          ip,
          userAgent,
          duration: Date.now() - startTime
        });
      }
    } catch (error) {
      // Log error
      console.log('Auth Failure:', {
        error: error.message,
        ip,
        userAgent,
        duration: Date.now() - startTime
      });
      
      throw error;
    }
  };
}
```

### 4. Testing de Adaptadores

```typescript
// ✅ Buena práctica: Tests para adaptadores
import { describe, it, expect, beforeEach } from 'vitest';
import { createTestAuthLibrary } from '../test-utils';
import { createHonoAuth } from '../adapters/hono';

describe('Hono Adapter', () => {
  let authLib: AuthLibrary;
  let auth: any;
  
  beforeEach(async () => {
    authLib = createTestAuthLibrary();
    await authLib.initialize();
    auth = createHonoAuth(authLib);
  });
  
  it('should authenticate valid token', async () => {
    // Crear usuario de prueba
    const result = await authLib.getAuthService().register({
      email: 'test@example.com',
      password: 'password123',
      firstName: 'Test',
      lastName: 'User'
    });
    
    // Simular contexto de Hono
    const mockContext = {
      req: {
        header: (name: string) => {
          if (name === 'authorization') {
            return `Bearer ${result.token}`;
          }
          return undefined;
        }
      }
    };
    
    let nextCalled = false;
    await auth.middleware(mockContext, () => {
      nextCalled = true;
    });
    
    expect(nextCalled).toBe(true);
    expect(mockContext.isAuthenticated).toBe(true);
    expect(mockContext.user?.email).toBe('test@example.com');
  });
  
  it('should reject invalid token', async () => {
    const mockContext = {
      req: {
        header: () => 'Bearer invalid-token'
      }
    };
    
    let nextCalled = false;
    await auth.middleware(mockContext, () => {
      nextCalled = true;
    });
    
    expect(nextCalled).toBe(true);
    expect(mockContext.isAuthenticated).toBe(false);
    expect(mockContext.user).toBeUndefined();
  });
});
```

## 🔗 Enlaces Relacionados

- **[Servicios Principales](./04-services.md)** - Documentación de servicios
- **[Middleware](./06-middleware.md)** - Middleware y utilidades
- **[Ejemplos Prácticos](./07-examples.md)** - Implementaciones completas
- **[API Reference](./08-api-reference.md)** - Referencia completa de la API
- **[Troubleshooting](./09-troubleshooting.md)** - Solución de problemas

---

[⬅️ Servicios](./04-services.md) | [🏠 Índice](./README.md) | [➡️ Middleware](./06-middleware.md)