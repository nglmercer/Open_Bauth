# 🏛️ Clase Principal AuthLibrary

La clase `AuthLibrary` es el corazón de la librería de autenticación. Proporciona una interfaz unificada para acceder a todos los servicios y funcionalidades.

## 📋 Índice

1. [Descripción General](#descripción-general)
2. [Constructor y Configuración](#constructor-y-configuración)
3. [Métodos Principales](#métodos-principales)
4. [Ciclo de Vida](#ciclo-de-vida)
5. [Gestión de Servicios](#gestión-de-servicios)
6. [Ejemplos Prácticos](#ejemplos-prácticos)
7. [Mejores Prácticas](#mejores-prácticas)

## 🎯 Descripción General

La clase `AuthLibrary` actúa como:

- **Punto de entrada único** para toda la funcionalidad de autenticación
- **Gestor de configuración** centralizado
- **Factory de servicios** (AuthService, JWTService, PermissionService)
- **Coordinador de inicialización** de base de datos y migraciones
- **Gestor de ciclo de vida** de la aplicación

```typescript
import { AuthLibrary } from '@open-bauth/core';

// Instancia única de la librería
const authLib = new AuthLibrary(config);
```

## 🔧 Constructor y Configuración

### Constructor

```typescript
constructor(config?: Partial<AuthConfig>)
```

**Parámetros:**
- `config` (opcional): Configuración personalizada que se fusiona con la configuración por defecto

**Comportamiento:**
1. Carga la configuración por defecto
2. Fusiona la configuración personalizada
3. Valida la configuración resultante
4. Inicializa los servicios internos
5. Lanza error si la configuración es inválida

### Ejemplo de Configuración

```typescript
import { AuthLibrary, AuthConfig } from '@open-bauth/core';

// Configuración básica
const authLib = new AuthLibrary({
  jwtSecret: 'mi-clave-secreta',
  jwtExpiration: '24h',
  database: {
    path: './mi-auth.db'
  }
});

// Configuración avanzada
const authLibAdvanced = new AuthLibrary({
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
    passwordHashAlgorithm: 'argon2id', // Bun.password usa Argon2id por defecto
    maxLoginAttempts: 5,
    lockoutDuration: 900000, // 15 minutos
    sessionTimeout: 86400000, // 24 horas
    passwordMinLength: 8,
    passwordRequireUppercase: true,
    passwordRequireLowercase: true,
    passwordRequireNumbers: true,
    passwordRequireSymbols: false
  },
  
  cors: {
    origins: ['http://localhost:3000', 'https://mi-app.com'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    headers: ['Content-Type', 'Authorization']
  },
  
  rateLimit: {
    windowMs: 900000, // 15 minutos
    maxRequests: 100,
    skipSuccessfulRequests: true
  },
  
  logging: {
    level: 'info',
    enableConsole: true,
    enableFile: true,
    filePath: './logs/auth.log'
  }
});
```

## 🛠️ Métodos Principales

### Inicialización

#### `initialize(): Promise<void>`

Inicializa la librería y prepara todos los componentes.

```typescript
/**
 * Inicializar la librería
 * - Conecta a la base de datos
 * - Ejecuta migraciones pendientes
 * - Configura servicios
 * - Valida configuración
 */
await authLib.initialize();
```

**Proceso interno:**
1. Inicializa conexión a SQLite
2. Ejecuta migraciones de base de datos
3. Configura servicios internos
4. Valida que todo esté funcionando
5. Registra evento de inicialización

**Errores comunes:**
- `DatabaseConnectionError`: No se puede conectar a la base de datos
- `MigrationError`: Error ejecutando migraciones
- `ConfigurationError`: Configuración inválida

### Gestión de Servicios

#### `getAuthService(): AuthService`

Obtiene la instancia del servicio de autenticación.

```typescript
const authService = authLib.getAuthService();

// Registrar usuario
const result = await authService.register({
  email: 'usuario@ejemplo.com',
  password: 'password123',
  first_name: 'Juan',
  last_name: 'Pérez'
});

// Hacer login
const loginResult = await authService.login({
  email: 'usuario@ejemplo.com',
  password: 'password123'
});
```

#### `getJWTService(): JWTService`

Obtiene la instancia del servicio JWT.

```typescript
const jwtService = authLib.getJWTService();

// Generar token
const token = await jwtService.generateToken(user);

// Verificar token
const payload = await jwtService.verifyToken(token);

// Verificar si el token ha expirado
const isExpired = jwtService.isTokenExpired(token);
```

#### `getPermissionService(): PermissionService`

Obtiene la instancia del servicio de permisos.

```typescript
const permissionService = authLib.getPermissionService();

// Crear permiso
const permission = await permissionService.createPermission({
  name: 'users.read',
  resource: 'users',
  action: 'read',
  description: 'Leer usuarios'
});

// Verificar si usuario tiene permiso
const hasPermission = await permissionService.userHasPermission(
  userId, 
  'users.read'
);
```

### Configuración

#### `getConfig(): AuthConfig`

Obtiene una copia de la configuración actual.

```typescript
const config = authLib.getConfig();
console.log('JWT Expiration:', config.jwtExpiration);
console.log('Database Path:', config.database.path);
```

#### `updateConfig(newConfig: Partial<AuthConfig>): void`

Actualiza la configuración en tiempo de ejecución.

```typescript
// Actualizar configuración
authLib.updateConfig({
  jwtExpiration: '12h',
  security: {
    maxLoginAttempts: 3
  }
});

// La configuración se valida automáticamente
// Si es inválida, se lanza un error
```

**⚠️ Nota:** Algunos cambios requieren reinicializar servicios.

### Utilidades de Base de Datos

#### `seed(): Promise<void>`

Pobla la base de datos con datos iniciales.

```typescript
// Poblar con datos de ejemplo
await authLib.seed();

// Esto crea:
// - Roles por defecto (admin, moderator, user)
// - Permisos básicos
// - Usuario administrador por defecto
```

#### `clean(): Promise<void>`

Limpia todos los datos de la base de datos.

```typescript
// Limpiar todos los datos (mantiene estructura)
await authLib.clean();
```

#### `reset(): Promise<void>`

Reinicia completamente la base de datos.

```typescript
// Reiniciar base de datos (elimina todo y recrea)
await authLib.reset();
```

#### `checkStatus(): Promise<void>`

Verifica el estado de la base de datos y servicios.

```typescript
// Verificar estado
await authLib.checkStatus();
// Imprime información sobre:
// - Estado de la base de datos
// - Migraciones aplicadas
// - Número de usuarios, roles, permisos
// - Estado de los servicios
```

### Cierre y Limpieza

#### `close(): Promise<void>`

Cierra todas las conexiones y libera recursos.

```typescript
// Cerrar librería correctamente
await authLib.close();

// Esto:
// - Cierra conexión a la base de datos
// - Libera recursos de memoria
// - Cancela timers activos
// - Registra evento de cierre
```

## 🔄 Ciclo de Vida

### Inicialización Completa

```typescript
import { AuthLibrary } from '@open-bauth/core';

async function setupAuth() {
  // 1. Crear instancia
  const authLib = new AuthLibrary({
    jwtSecret: process.env.JWT_SECRET!,
    database: { path: './auth.db' }
  });
  
  try {
    // 2. Inicializar
    await authLib.initialize();
    console.log('✅ Auth Library inicializada');
    
    // 3. Verificar estado
    await authLib.checkStatus();
    
    // 4. Poblar datos iniciales (solo en desarrollo)
    if (process.env.NODE_ENV === 'development') {
      await authLib.seed();
      console.log('✅ Datos iniciales cargados');
    }
    
    return authLib;
    
  } catch (error) {
    console.error('❌ Error inicializando Auth Library:', error);
    await authLib.close();
    throw error;
  }
}

// Usar en la aplicación
const authLib = await setupAuth();

// Manejar cierre graceful
process.on('SIGINT', async () => {
  console.log('\n🛑 Cerrando aplicación...');
  await authLib.close();
  process.exit(0);
});
```

### Patrón Singleton

```typescript
// auth-singleton.ts
import { AuthLibrary, AuthConfig } from '@open-bauth/core';

class AuthManager {
  private static instance: AuthLibrary | null = null;
  private static initialized = false;
  
  static async getInstance(config?: Partial<AuthConfig>): Promise<AuthLibrary> {
    if (!this.instance) {
      this.instance = new AuthLibrary(config);
    }
    
    if (!this.initialized) {
      await this.instance.initialize();
      this.initialized = true;
    }
    
    return this.instance;
  }
  
  static async close(): Promise<void> {
    if (this.instance) {
      await this.instance.close();
      this.instance = null;
      this.initialized = false;
    }
  }
}

export default AuthManager;

// Uso
const authLib = await AuthManager.getInstance({
  jwtSecret: process.env.JWT_SECRET!
});
```

## 🎯 Gestión de Servicios

### Acceso a Servicios

```typescript
const authLib = new AuthLibrary(config);
await authLib.initialize();

// Obtener servicios
const authService = authLib.getAuthService();
const jwtService = authLib.getJWTService();
const permissionService = authLib.getPermissionService();

// Los servicios están completamente configurados y listos para usar
```

### Servicios Compartidos

Todos los servicios comparten:
- La misma configuración
- La misma conexión a base de datos
- El mismo sistema de logging
- Las mismas validaciones

```typescript
// Ejemplo de flujo completo
const authLib = new AuthLibrary(config);
await authLib.initialize();

// 1. Registrar usuario
const authService = authLib.getAuthService();
const registerResult = await authService.register(userData);

if (registerResult.success) {
  // 2. Generar token
  const jwtService = authLib.getJWTService();
  const token = await jwtService.generateToken(registerResult.user!);
  
  // 3. Asignar rol
  const permissionService = authLib.getPermissionService();
  await authService.assignRole(registerResult.user!.id, 'user');
  
  console.log('Usuario registrado y configurado completamente');
}
```

## 💡 Ejemplos Prácticos

### Aplicación Web Básica

```typescript
// server.ts
import { Hono } from 'hono';
import { AuthLibrary, createHonoAuth } from '@open-bauth/core';

const app = new Hono();

// Configurar autenticación
const authLib = new AuthLibrary({
  jwtSecret: process.env.JWT_SECRET!,
  database: { path: './auth.db' }
});

await authLib.initialize();
const auth = createHonoAuth();

// Middleware global
app.use('*', auth.middleware);

// Rutas de autenticación
app.post('/register', async (c) => {
  const data = await c.req.json();
  const result = await authLib.getAuthService().register(data);
  
  if (result.success) {
    return c.json({ 
      message: 'Usuario registrado',
      token: result.token 
    });
  }
  
  return c.json({ error: result.error?.message }, 400);
});

app.post('/login', async (c) => {
  const data = await c.req.json();
  const result = await authLib.getAuthService().login(data);
  
  if (result.success) {
    return c.json({ 
      message: 'Login exitoso',
      token: result.token,
      user: result.user 
    });
  }
  
  return c.json({ error: result.error?.message }, 401);
});

// Rutas protegidas
app.get('/profile', auth.required, async (c) => {
  const user = auth.getCurrentUser(c);
  return c.json({ user });
});

app.get('/admin/stats', 
  auth.permissions(['admin.read']), 
  async (c) => {
    const stats = {
      users: await authLib.getAuthService().getUsers(),
      roles: await authLib.getPermissionService().getAllRoles(),
      permissions: await authLib.getPermissionService().getAllPermissions()
    };
    return c.json(stats);
  }
);

export default app;
```

### Microservicio de Autenticación

```typescript
// auth-microservice.ts
import { AuthLibrary } from '@open-bauth/core';
import { createServer } from 'http';

class AuthMicroservice {
  private authLib: AuthLibrary;
  private server: any;
  
  constructor(config: any) {
    this.authLib = new AuthLibrary(config);
  }
  
  async start(port: number = 3001): Promise<void> {
    // Inicializar librería
    await this.authLib.initialize();
    console.log('✅ Auth Library inicializada');
    
    // Crear servidor HTTP
    this.server = createServer(this.handleRequest.bind(this));
    
    this.server.listen(port, () => {
      console.log(`🚀 Microservicio de autenticación corriendo en puerto ${port}`);
    });
  }
  
  private async handleRequest(req: any, res: any): Promise<void> {
    // Manejar CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }
    
    try {
      const url = new URL(req.url, `http://${req.headers.host}`);
      const path = url.pathname;
      
      // Enrutar requests
      switch (path) {
        case '/health':
          await this.handleHealth(req, res);
          break;
        case '/register':
          await this.handleRegister(req, res);
          break;
        case '/login':
          await this.handleLogin(req, res);
          break;
        case '/verify':
          await this.handleVerify(req, res);
          break;
        default:
          res.writeHead(404);
          res.end(JSON.stringify({ error: 'Endpoint no encontrado' }));
      }
    } catch (error) {
      console.error('Error manejando request:', error);
      res.writeHead(500);
      res.end(JSON.stringify({ error: 'Error interno del servidor' }));
    }
  }
  
  private async handleHealth(req: any, res: any): Promise<void> {
    await this.authLib.checkStatus();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      status: 'healthy',
      timestamp: new Date().toISOString()
    }));
  }
  
  private async handleRegister(req: any, res: any): Promise<void> {
    const body = await this.getRequestBody(req);
    const result = await this.authLib.getAuthService().register(body);
    
    if (result.success) {
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ 
        message: 'Usuario registrado',
        token: result.token 
      }));
    } else {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: result.error?.message }));
    }
  }
  
  private async handleLogin(req: any, res: any): Promise<void> {
    const body = await this.getRequestBody(req);
    const result = await this.authLib.getAuthService().login(body);
    
    if (result.success) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ 
        message: 'Login exitoso',
        token: result.token,
        user: result.user 
      }));
    } else {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: result.error?.message }));
    }
  }
  
  private async handleVerify(req: any, res: any): Promise<void> {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Token requerido' }));
      return;
    }
    
    try {
      const token = this.authLib.getJWTService().extractTokenFromHeader(authHeader);
      if (!token) {
        throw new Error('Token inválido');
      }
      
      const payload = await this.authLib.getJWTService().verifyToken(token);
      const user = await this.authLib.getAuthService().findUserById(payload.userId);
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ 
        valid: true,
        user: user 
      }));
    } catch (error) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ 
        valid: false,
        error: 'Token inválido' 
      }));
    }
  }
  
  private async getRequestBody(req: any): Promise<any> {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', (chunk: any) => {
        body += chunk.toString();
      });
      req.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (error) {
          reject(error);
        }
      });
    });
  }
  
  async stop(): Promise<void> {
    if (this.server) {
      this.server.close();
    }
    await this.authLib.close();
    console.log('✅ Microservicio cerrado');
  }
}

// Uso
const microservice = new AuthMicroservice({
  jwtSecret: process.env.JWT_SECRET!,
  database: { path: './auth-microservice.db' }
});

await microservice.start(3001);

// Manejar cierre graceful
process.on('SIGINT', async () => {
  await microservice.stop();
  process.exit(0);
});
```

## 🎯 Mejores Prácticas

### 1. Gestión de Configuración

```typescript
// ✅ Buena práctica: Configuración por entorno
const getConfig = () => {
  const baseConfig = {
    jwtSecret: process.env.JWT_SECRET!,
    database: { path: './auth.db' }
  };
  
  if (process.env.NODE_ENV === 'production') {
    return {
      ...baseConfig,
      security: {
        bcryptRounds: 14,
        maxLoginAttempts: 3
      },
      logging: {
        level: 'warn',
        enableFile: true
      }
    };
  }
  
  return baseConfig;
};

const authLib = new AuthLibrary(getConfig());
```

### 2. Manejo de Errores

```typescript
// ✅ Buena práctica: Manejo robusto de errores
async function initializeAuthWithRetry(config: any, maxRetries = 3): Promise<AuthLibrary> {
  let lastError: Error;
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      const authLib = new AuthLibrary(config);
      await authLib.initialize();
      return authLib;
    } catch (error) {
      lastError = error as Error;
      console.warn(`Intento ${i + 1} fallido:`, error);
      
      if (i < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
      }
    }
  }
  
  throw new Error(`No se pudo inicializar después de ${maxRetries} intentos: ${lastError!.message}`);
}
```

### 3. Logging y Monitoreo

```typescript
// ✅ Buena práctica: Logging estructurado
class AuthLibraryWrapper {
  private authLib: AuthLibrary;
  private logger: any; // Tu logger preferido
  
  constructor(config: any, logger: any) {
    this.authLib = new AuthLibrary(config);
    this.logger = logger;
  }
  
  async initialize(): Promise<void> {
    const startTime = Date.now();
    
    try {
      await this.authLib.initialize();
      
      this.logger.info('AuthLibrary initialized successfully', {
        duration: Date.now() - startTime,
        config: this.authLib.getConfig()
      });
    } catch (error) {
      this.logger.error('AuthLibrary initialization failed', {
        duration: Date.now() - startTime,
        error: error.message
      });
      throw error;
    }
  }
  
  getAuthService() {
    this.logger.debug('AuthService accessed');
    return this.authLib.getAuthService();
  }
  
  // ... otros métodos con logging
}
```

### 4. Testing

```typescript
// ✅ Buena práctica: Configuración para tests
export function createTestAuthLibrary(): AuthLibrary {
  return new AuthLibrary({
    jwtSecret: 'test-secret-key',
    database: { path: ':memory:' }, // Base de datos en memoria
    security: {
      bcryptRounds: 4 // Más rápido para tests
    },
    logging: {
      level: 'error', // Solo errores en tests
      enableConsole: false
    }
  });
}

// En tus tests
describe('AuthLibrary', () => {
  let authLib: AuthLibrary;
  
  beforeEach(async () => {
    authLib = createTestAuthLibrary();
    await authLib.initialize();
  });
  
  afterEach(async () => {
    await authLib.close();
  });
  
  it('should register user successfully', async () => {
    const result = await authLib.getAuthService().register({
      email: 'test@example.com',
      password: 'password123',
      first_name: 'Test',
      last_name: 'User'
    });
    
    expect(result.success).toBe(true);
    expect(result.user).toBeDefined();
    expect(result.token).toBeDefined();
  });
});
```

## 🔗 Enlaces Relacionados

- **[Servicios Principales](./04-services.md)** - Documentación detallada de servicios
- **[Adaptadores de Framework](./05-framework-adapters.md)** - Integración con frameworks
- **[Ejemplos Prácticos](./07-examples.md)** - Implementaciones completas
- **[Troubleshooting](./09-troubleshooting.md)** - Solución de problemas

---

[⬅️ Instalación](./02-installation-config.md) | [🏠 Índice](./README.md) | [➡️ Servicios](./04-services.md)