# ⚙️ Middleware y Configuración Avanzada

Esta sección cubre el middleware agnóstico de framework, configuraciones avanzadas y funciones de utilidad que proporciona la librería de autenticación.

## 📋 Índice

1. [Middleware Agnóstico](#middleware-agnóstico)
2. [Configuración Avanzada](#configuración-avanzada)
3. [Funciones de Utilidad](#funciones-de-utilidad)
4. [Rate Limiting](#rate-limiting)
5. [Logging y Auditoría](#logging-y-auditoría)
6. [Validación y Sanitización](#validación-y-sanitización)
7. [Cache y Optimización](#cache-y-optimización)
8. [Seguridad Avanzada](#seguridad-avanzada)
9. [Monitoreo y Métricas](#monitoreo-y-métricas)
10. [Mejores Prácticas](#mejores-prácticas)

---

## 🔧 Middleware Agnóstico

La librería incluye middleware que funciona independientemente del framework web utilizado.

### Middleware Base

#### `createAuthMiddleware`

Crea middleware de autenticación personalizable para cualquier framework.

```typescript
import { createAuthMiddleware, AuthLibrary } from '@open-bauth/core';

// Configurar AuthLibrary
const authLib = new AuthLibrary({
  jwtSecret: process.env.JWT_SECRET!,
  database: { path: './auth.db' }
});

await authLib.initialize();

// Crear middleware agnóstico
const authMiddleware = createAuthMiddleware(authLib, {
  // Configuración del middleware
  extractToken: (req: any) => {
    // Lógica personalizada para extraer token
    // El middleware ahora soporta múltiples métodos automáticamente:
    
    // 1. Authorization Header (case-insensitive)
    const authHeader = req.headers?.authorization;
    if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
      return authHeader.substring(7);
    }
    
    // 2. Custom Headers
    if (req.headers?.['x-auth-token']) {
      return req.headers['x-auth-token'];
    }
    
    // 3. Query Parameters
    if (req.query?.token || req.query?.access_token || req.query?.auth_token) {
      return req.query.token || req.query.access_token || req.query.auth_token;
    }
    
    // 4. URL Parameters
    if (req.params?.token) {
      return req.params.token;
    }
    
    return null;
  },
  
  onAuthenticated: (user, req) => {
    // Callback cuando la autenticación es exitosa
    console.log(`Usuario autenticado: ${user.email}`);
    req.user = user;
    req.isAuthenticated = true;
  },
  
  onAuthenticationFailed: (error, req) => {
    // Callback cuando la autenticación falla
    console.log(`Autenticación fallida: ${error.message}`);
    req.isAuthenticated = false;
  },
  
  onError: (error, req) => {
    // Callback para errores generales
    console.error('Error en middleware de autenticación:', error);
  }
});

// Usar con cualquier framework
app.use(authMiddleware);
```

### 🔍 Extracción Automática de Tokens

El middleware de autenticación ahora incluye extracción automática de tokens mejorada que soporta múltiples métodos sin configuración adicional:

#### Métodos Soportados

1. **Authorization Header (Case-Insensitive)**
   ```
   Authorization: Bearer <token>
   Authorization: bearer <token>
   Authorization: BEARER <token>
   ```

2. **Custom Headers**
   ```
   X-Auth-Token: <token>
   X-API-Key: <token>
   X-Access-Token: <token>
   ```

3. **Query Parameters**
   ```
   GET /api/data?token=<token>
   GET /api/data?access_token=<token>
   GET /api/data?auth_token=<token>
   ```

4. **URL Parameters**
   ```
   GET /api/data/:token
   ```

#### Orden de Prioridad

El middleware busca tokens en el siguiente orden:
1. Authorization header (Bearer token)
2. Custom headers (X-Auth-Token, X-API-Key, etc.)
3. Query parameters (token, access_token, auth_token)
4. URL parameters (token)

#### Configuración Personalizada

Puedes sobrescribir la lógica de extracción usando la función `extractToken`:

```typescript
const authMiddleware = createAuthMiddleware(authLib, {
  extractToken: (req: any) => {
    // Tu lógica personalizada aquí
    return customTokenExtraction(req);
  }
});
```

#### `createPermissionMiddleware`

Middleware para verificación de permisos.

```typescript
const permissionMiddleware = createPermissionMiddleware(authLib, {
  requiredPermissions: ['users.read'],
  requireAll: true, // Requiere todos los permisos (AND) vs cualquiera (OR)
  
  onPermissionGranted: (user, permissions, req) => {
    console.log(`Acceso concedido a ${user.email}`);
  },
  
  onPermissionDenied: (user, requiredPermissions, userPermissions, req) => {
    console.log(`Acceso denegado a ${user.email}. Requiere: ${requiredPermissions.join(', ')}`);
  },
  
  customPermissionCheck: async (user, requiredPermissions) => {
    // Lógica personalizada de verificación de permisos
    if (user.email === 'admin@example.com') {
      return true; // Admin tiene todos los permisos
    }
    
    // Verificación estándar
    return null;
  }
});
```

#### `createRoleMiddleware`

Middleware para verificación de roles.

```typescript
const roleMiddleware = createRoleMiddleware(authLib, {
  requiredRoles: ['admin', 'moderator'],
  requireAll: false, // Cualquier rol es suficiente
  
  onRoleGranted: (user, roles, req) => {
    console.log(`Rol verificado para ${user.email}: ${roles.join(', ')}`);
  },
  
  onRoleDenied: (user, requiredRoles, userRoles, req) => {
    console.log(`Rol insuficiente para ${user.email}`);
  },
  
  customRoleCheck: async (user, requiredRoles) => {
    // Lógica personalizada de verificación de roles
    if (user.isSuperAdmin) {
      return true;
    }
    
    return null;
  }
});
```

### Middleware Compuesto

#### `createAuthChain`

Combina múltiples middleware de autenticación en una cadena.

```typescript
const authChain = createAuthChain([
  // 1. Autenticación básica
  authMiddleware,
  
  // 2. Rate limiting
  createRateLimitMiddleware({
    windowMs: 15 * 60 * 1000, // 15 minutos
    maxRequests: 100,
    keyGenerator: (req) => req.user?.id || req.ip
  }),
  
  // 3. Logging de auditoría
  createAuditMiddleware({
    logSuccessfulAuth: true,
    logFailedAuth: true,
    logPermissionChecks: true
  }),
  
  // 4. Verificación de permisos
  permissionMiddleware
]);

// Usar la cadena completa
app.use('/api/protected', authChain);
```

### Middleware Condicional

#### `createConditionalMiddleware`

Aplica middleware basado en condiciones.

```typescript
const conditionalAuth = createConditionalMiddleware({
  condition: (req) => {
    // Solo aplicar autenticación a rutas que no sean públicas
    const publicRoutes = ['/health', '/docs', '/auth/login', '/auth/register'];
    return !publicRoutes.includes(req.path);
  },
  
  middleware: authMiddleware,
  
  onSkipped: (req) => {
    console.log(`Autenticación omitida para ruta pública: ${req.path}`);
  }
});

app.use(conditionalAuth);
```

---

## ⚙️ Configuración Avanzada

### Configuración de Seguridad

```typescript
const authLib = new AuthLibrary({
  jwtSecret: process.env.JWT_SECRET!,
  
  // Configuración de base de datos
  database: {
    path: './auth.db',
    // Configuración de conexión para bases de datos externas
    connection: {
      host: process.env.DB_HOST,
      port: parseInt(process.env.DB_PORT || '5432'),
      database: process.env.DB_NAME,
      username: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      ssl: process.env.NODE_ENV === 'production'
    },
    // Pool de conexiones
    pool: {
      min: 2,
      max: 10,
      acquireTimeoutMillis: 30000,
      idleTimeoutMillis: 30000
    }
  },
  
  // Configuración de seguridad
  security: {
    // Configuración de bcrypt
    bcryptRounds: 12,
    
    // Configuración de JWT
    jwt: {
      accessTokenExpiry: '15m',
      refreshTokenExpiry: '7d',
      issuer: 'open-bauth',
      audience: 'api-users',
      algorithm: 'HS256'
    },
    
    // Configuración de intentos de login
    loginAttempts: {
      maxAttempts: 5,
      lockoutDuration: 15 * 60 * 1000, // 15 minutos
      resetAfter: 24 * 60 * 60 * 1000   // 24 horas
    },
    
    // Configuración de sesiones
    sessions: {
      maxConcurrentSessions: 3,
      sessionTimeout: 30 * 60 * 1000, // 30 minutos
      extendOnActivity: true
    },
    
    // Configuración de CORS
    cors: {
      origins: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
      credentials: true,
      maxAge: 86400 // 24 horas
    },
    
    // Configuración de rate limiting
    rateLimit: {
      enabled: true,
      windowMs: 15 * 60 * 1000,
      maxRequests: 100,
      skipSuccessfulRequests: false,
      skipFailedRequests: false
    }
  },
  
  // Configuración de logging
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    format: 'json',
    destination: process.env.LOG_FILE || 'stdout',
    
    // Configuración específica de eventos
    events: {
      authentication: true,
      authorization: true,
      userRegistration: true,
      passwordChanges: true,
      loginAttempts: true,
      tokenRefresh: true
    }
  },
  
  // Configuración de cache
  cache: {
    enabled: true,
    provider: 'memory', // 'memory' | 'redis' | 'custom'
    
    // Configuración de Redis (si se usa)
    redis: {
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD,
      db: parseInt(process.env.REDIS_DB || '0')
    },
    
    // TTL para diferentes tipos de cache
    ttl: {
      users: 5 * 60 * 1000,        // 5 minutos
      permissions: 10 * 60 * 1000,  // 10 minutos
      roles: 15 * 60 * 1000,       // 15 minutos
      sessions: 30 * 60 * 1000     // 30 minutos
    }
  },
  
  // Configuración de validación
  validation: {
    email: {
      allowDisposable: false,
      requireVerification: true,
      customDomains: ['company.com'] // Solo permitir ciertos dominios
    },
    
    password: {
      minLength: 8,
      maxLength: 128,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecialChars: true,
      forbiddenPasswords: ['password', '123456', 'qwerty'],
      preventReuse: 5 // No reutilizar las últimas 5 contraseñas
    },
    
    usernames: {
      minLength: 3,
      maxLength: 30,
      allowedChars: /^[a-zA-Z0-9_-]+$/,
      reservedNames: ['admin', 'root', 'system']
    }
  },
  
  // Configuración de notificaciones
  notifications: {
    email: {
      enabled: true,
      provider: 'smtp', // 'smtp' | 'sendgrid' | 'ses' | 'custom'
      
      smtp: {
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT || '587'),
        secure: false,
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      },
      
      templates: {
        welcome: './templates/welcome.html',
        passwordReset: './templates/password-reset.html',
        emailVerification: './templates/email-verification.html'
      }
    },
    
    sms: {
      enabled: false,
      provider: 'twilio',
      
      twilio: {
        accountSid: process.env.TWILIO_ACCOUNT_SID,
        authToken: process.env.TWILIO_AUTH_TOKEN,
        fromNumber: process.env.TWILIO_FROM_NUMBER
      }
    }
  }
});
```

### Configuración por Entorno

```typescript
// config/auth.config.ts
interface AuthConfig {
  development: AuthLibraryOptions;
  production: AuthLibraryOptions;
  test: AuthLibraryOptions;
}

const authConfig: AuthConfig = {
  development: {
    jwtSecret: 'dev-secret-key',
    database: { path: './dev-auth.db' },
    security: {
      bcryptRounds: 4, // Más rápido para desarrollo
      loginAttempts: {
        maxAttempts: 10,
        lockoutDuration: 5 * 60 * 1000
      }
    },
    logging: {
      level: 'debug',
      format: 'pretty'
    }
  },
  
  production: {
    jwtSecret: process.env.JWT_SECRET!,
    database: {
      connection: {
        host: process.env.DB_HOST!,
        port: parseInt(process.env.DB_PORT!),
        database: process.env.DB_NAME!,
        username: process.env.DB_USER!,
        password: process.env.DB_PASSWORD!,
        ssl: true
      }
    },
    security: {
      bcryptRounds: 12,
      loginAttempts: {
        maxAttempts: 3,
        lockoutDuration: 30 * 60 * 1000
      },
      rateLimit: {
        enabled: true,
        maxRequests: 50
      }
    },
    logging: {
      level: 'warn',
      format: 'json',
      destination: '/var/log/auth.log'
    }
  },
  
  test: {
    jwtSecret: 'test-secret-key',
    database: { path: ':memory:' },
    security: {
      bcryptRounds: 1, // Mínimo para tests
      loginAttempts: {
        maxAttempts: 100
      }
    },
    logging: {
      level: 'silent'
    }
  }
};

// Usar configuración por entorno
const env = process.env.NODE_ENV || 'development';
const config = authConfig[env as keyof AuthConfig];

const authLib = new AuthLibrary(config);
```

---

## 🛠️ Funciones de Utilidad

### Utilidades de Token

```typescript
import { TokenUtils } from '@open-bauth/core';

// Generar token personalizado
const customToken = TokenUtils.generateCustomToken({
  payload: { userId: '123', role: 'admin' },
  secret: 'custom-secret',
  expiresIn: '1h',
  issuer: 'my-app'
});

// Verificar token personalizado
const verified = TokenUtils.verifyCustomToken(customToken, 'custom-secret');

// Extraer información sin verificar (útil para debugging)
const decoded = TokenUtils.decodeToken(customToken);
console.log('Token info:', decoded);

// Verificar si un token está expirado
const isExpired = TokenUtils.isTokenExpired(customToken);

// Obtener tiempo restante del token
const timeLeft = TokenUtils.getTokenTimeLeft(customToken);
console.log(`Token expira en ${timeLeft}ms`);

// Generar token de un solo uso
const oneTimeToken = TokenUtils.generateOneTimeToken({
  userId: '123',
  action: 'password-reset',
  expiresIn: '15m'
});
```

### Utilidades de Validación

```typescript
import { ValidationUtils } from '@open-bauth/core';

// Validar email
const emailValidation = ValidationUtils.validateEmail('user@example.com');
if (!emailValidation.isValid) {
  console.log('Errores de email:', emailValidation.errors);
}

// Validar contraseña
const passwordValidation = ValidationUtils.validatePassword('MyPassword123!');
if (!passwordValidation.isValid) {
  console.log('Errores de contraseña:', passwordValidation.errors);
}

// Validar nombre de usuario
const usernameValidation = ValidationUtils.validateUsername('john_doe');

// Sanitizar entrada de usuario
const sanitized = ValidationUtils.sanitizeInput(userInput);

// Validar estructura de datos completa
const userValidation = ValidationUtils.validateUserData({
  email: 'user@example.com',
  password: 'password123',
  firstName: 'John',
  lastName: 'Doe'
});

// Validar permisos
const permissionValidation = ValidationUtils.validatePermissions([
  'users.read',
  'users.write',
  'admin.access'
]);
```

### Utilidades de Hash

```typescript
import { HashUtils } from '@open-bauth/core';

// Hash de contraseña con salt personalizado
const hashedPassword = await HashUtils.hashPassword('password123', 12);

// Verificar contraseña
const isValid = await HashUtils.verifyPassword('password123', hashedPassword);

// Generar hash seguro para tokens
const tokenHash = HashUtils.generateSecureHash('sensitive-data');

// Generar salt aleatorio
const salt = HashUtils.generateSalt(16);

// Hash con algoritmo específico
const sha256Hash = HashUtils.hashWithAlgorithm('data', 'sha256');

// Verificar integridad de datos
const isIntact = HashUtils.verifyIntegrity('data', sha256Hash, 'sha256');
```

### Utilidades de Tiempo

```typescript
import { TimeUtils } from '@open-bauth/core';

// Convertir duración a milisegundos
const ms = TimeUtils.parseTimeString('15m'); // 900000
const hours = TimeUtils.parseTimeString('2h'); // 7200000
const days = TimeUtils.parseTimeString('7d'); // 604800000

// Formatear duración
const formatted = TimeUtils.formatDuration(900000); // "15 minutos"

// Verificar si una fecha está expirada
const isExpired = TimeUtils.isExpired(new Date('2024-01-01'));

// Obtener tiempo hasta expiración
const timeUntilExpiry = TimeUtils.getTimeUntilExpiry(futureDate);

// Generar timestamp seguro
const timestamp = TimeUtils.generateSecureTimestamp();

// Validar rango de fechas
const isInRange = TimeUtils.isDateInRange(
  new Date(),
  new Date('2024-01-01'),
  new Date('2024-12-31')
);
```

---

## 🚦 Rate Limiting

### Rate Limiting Básico

```typescript
import { createRateLimitMiddleware } from '@open-bauth/core';

// Rate limiting global
const globalRateLimit = createRateLimitMiddleware({
  windowMs: 15 * 60 * 1000, // 15 minutos
  maxRequests: 100,
  
  keyGenerator: (req) => {
    // Usar IP como clave por defecto
    return req.ip || req.connection.remoteAddress;
  },
  
  onLimitReached: (req, info) => {
    console.log(`Rate limit alcanzado para ${info.key}: ${info.current}/${info.limit}`);
  },
  
  skipSuccessfulRequests: false,
  skipFailedRequests: false,
  
  // Headers de respuesta
  headers: {
    remaining: 'X-RateLimit-Remaining',
    reset: 'X-RateLimit-Reset',
    total: 'X-RateLimit-Limit'
  }
});

// Rate limiting por usuario autenticado
const userRateLimit = createRateLimitMiddleware({
  windowMs: 5 * 60 * 1000, // 5 minutos
  maxRequests: 50,
  
  keyGenerator: (req) => {
    // Usar ID de usuario si está autenticado, sino IP
    return req.user?.id || req.ip;
  },
  
  // Rate limit más estricto para usuarios no autenticados
  dynamicLimit: (req) => {
    return req.user ? 50 : 10;
  }
});

// Rate limiting específico para login
const loginRateLimit = createRateLimitMiddleware({
  windowMs: 15 * 60 * 1000,
  maxRequests: 5, // Solo 5 intentos de login por IP
  
  keyGenerator: (req) => `login:${req.ip}`,
  
  onLimitReached: (req, info) => {
    console.log(`Demasiados intentos de login desde ${req.ip}`);
    // Opcional: notificar al sistema de seguridad
  }
});

// Aplicar rate limiting
app.use(globalRateLimit);
app.use('/api', userRateLimit);
app.use('/auth/login', loginRateLimit);
```

### Rate Limiting Avanzado

```typescript
// Rate limiting con múltiples niveles
const tieredRateLimit = createTieredRateLimitMiddleware({
  tiers: [
    {
      name: 'burst',
      windowMs: 1 * 60 * 1000, // 1 minuto
      maxRequests: 20
    },
    {
      name: 'sustained',
      windowMs: 15 * 60 * 1000, // 15 minutos
      maxRequests: 100
    },
    {
      name: 'daily',
      windowMs: 24 * 60 * 60 * 1000, // 24 horas
      maxRequests: 1000
    }
  ],
  
  keyGenerator: (req) => req.user?.id || req.ip,
  
  onTierLimitReached: (req, tier, info) => {
    console.log(`Límite ${tier.name} alcanzado para ${info.key}`);
  }
});

// Rate limiting con whitelist/blacklist
const smartRateLimit = createSmartRateLimitMiddleware({
  windowMs: 15 * 60 * 1000,
  maxRequests: 100,
  
  whitelist: {
    ips: ['127.0.0.1', '::1'],
    userIds: ['admin-user-id'],
    apiKeys: ['trusted-api-key']
  },
  
  blacklist: {
    ips: ['192.168.1.100'], // IPs bloqueadas
    userIds: ['banned-user-id']
  },
  
  dynamicRules: async (req) => {
    // Reglas dinámicas basadas en el usuario
    if (req.user?.roles?.includes('premium')) {
      return { maxRequests: 500 }; // Usuarios premium tienen más límite
    }
    
    if (req.user?.roles?.includes('admin')) {
      return { skip: true }; // Admins sin límite
    }
    
    return null; // Usar configuración por defecto
  }
});
```

### Rate Limiting con Redis

```typescript
// Rate limiting distribuido con Redis
const distributedRateLimit = createDistributedRateLimitMiddleware({
  windowMs: 15 * 60 * 1000,
  maxRequests: 100,
  
  store: {
    type: 'redis',
    connection: {
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD
    },
    keyPrefix: 'rate_limit:'
  },
  
  keyGenerator: (req) => req.user?.id || req.ip,
  
  // Configuración de sliding window
  slidingWindow: true,
  
  // Configuración de burst allowance
  burstAllowance: {
    enabled: true,
    maxBurst: 10,
    refillRate: 1 // tokens por segundo
  }
});
```

---

## 📊 Logging y Auditoría

### Sistema de Logging

```typescript
import { createAuditLogger, LogLevel } from '@open-bauth/core';

// Configurar logger de auditoría
const auditLogger = createAuditLogger({
  level: LogLevel.INFO,
  format: 'json',
  
  // Múltiples destinos
  transports: [
    {
      type: 'file',
      filename: './logs/auth-audit.log',
      maxSize: '10MB',
      maxFiles: 5,
      compress: true
    },
    {
      type: 'console',
      format: 'pretty' // Para desarrollo
    },
    {
      type: 'database',
      table: 'audit_logs',
      connection: databaseConnection
    },
    {
      type: 'webhook',
      url: 'https://security-monitoring.company.com/webhook',
      headers: {
        'Authorization': 'Bearer webhook-token'
      }
    }
  ],
  
  // Configuración de eventos
  events: {
    authentication: {
      enabled: true,
      level: LogLevel.INFO,
      includeUserAgent: true,
      includeIP: true
    },
    authorization: {
      enabled: true,
      level: LogLevel.WARN,
      includePermissions: true
    },
    userRegistration: {
      enabled: true,
      level: LogLevel.INFO,
      includePII: false // No incluir información personal
    },
    passwordChanges: {
      enabled: true,
      level: LogLevel.WARN,
      includeOldPasswordHash: false
    },
    loginAttempts: {
      enabled: true,
      level: LogLevel.WARN,
      includeFailureReason: true
    },
    suspiciousActivity: {
      enabled: true,
      level: LogLevel.ERROR,
      alertThreshold: 5 // Alertar después de 5 eventos sospechosos
    }
  },
  
  // Filtros de logs
  filters: {
    excludeHealthChecks: true,
    excludeOptions: true,
    excludePaths: ['/favicon.ico', '/robots.txt'],
    
    // Filtro personalizado
    custom: (logEntry) => {
      // No loggear requests internos
      return !logEntry.userAgent?.includes('internal-service');
    }
  },
  
  // Configuración de privacidad
  privacy: {
    maskEmails: true,
    maskIPs: false,
    hashUserIds: true,
    excludeHeaders: ['authorization', 'cookie']
  }
});

// Middleware de auditoría
const auditMiddleware = createAuditMiddleware(auditLogger, {
  logAllRequests: false, // Solo loggear eventos de autenticación
  includeRequestBody: false, // Por seguridad
  includeResponseBody: false,
  
  // Eventos personalizados
  customEvents: {
    'user.profile.updated': {
      level: LogLevel.INFO,
      message: 'Usuario actualizó su perfil'
    },
    'admin.user.deleted': {
      level: LogLevel.WARN,
      message: 'Administrador eliminó usuario'
    }
  }
});

app.use(auditMiddleware);
```

### Logging de Eventos Específicos

```typescript
// En el servicio de autenticación
class AuthService {
  private auditLogger: AuditLogger;
  
  constructor(auditLogger: AuditLogger) {
    this.auditLogger = auditLogger;
  }
  
  async login(credentials: LoginCredentials, context: RequestContext): Promise<LoginResult> {
    const startTime = Date.now();
    
    try {
      // Intentar login
      const result = await this.performLogin(credentials);
      
      if (result.success) {
        // Log login exitoso
        this.auditLogger.logAuthenticationSuccess({
          userId: result.user!.id,
          email: result.user!.email,
          ip: context.ip,
          userAgent: context.userAgent,
          duration: Date.now() - startTime,
          method: 'password',
          timestamp: new Date()
        });
      } else {
        // Log login fallido
        this.auditLogger.logAuthenticationFailure({
          email: credentials.email,
          reason: result.error?.message || 'Unknown',
          ip: context.ip,
          userAgent: context.userAgent,
          duration: Date.now() - startTime,
          timestamp: new Date()
        });
      }
      
      return result;
    } catch (error) {
      // Log error
      this.auditLogger.logError({
        event: 'authentication.error',
        error: error.message,
        stack: error.stack,
        context: {
          email: credentials.email,
          ip: context.ip
        },
        timestamp: new Date()
      });
      
      throw error;
    }
  }
  
  async updateUserPermissions(adminUserId: string, targetUserId: string, permissions: string[]): Promise<void> {
    // Log cambio de permisos
    this.auditLogger.logPermissionChange({
      adminUserId,
      targetUserId,
      action: 'permissions.updated',
      oldPermissions: await this.getUserPermissions(targetUserId),
      newPermissions: permissions,
      timestamp: new Date()
    });
    
    await this.performPermissionUpdate(targetUserId, permissions);
  }
}
```

### Análisis de Logs

```typescript
// Utilidades para análisis de logs de auditoría
class AuditAnalyzer {
  private auditLogger: AuditLogger;
  
  constructor(auditLogger: AuditLogger) {
    this.auditLogger = auditLogger;
  }
  
  // Detectar actividad sospechosa
  async detectSuspiciousActivity(timeWindow: number = 24 * 60 * 60 * 1000): Promise<SuspiciousActivity[]> {
    const logs = await this.auditLogger.getLogs({
      since: new Date(Date.now() - timeWindow),
      events: ['authentication.failure', 'authorization.denied']
    });
    
    const suspicious: SuspiciousActivity[] = [];
    
    // Detectar múltiples fallos de login desde la misma IP
    const failuresByIP = this.groupBy(logs, 'ip');
    for (const [ip, failures] of Object.entries(failuresByIP)) {
      if (failures.length >= 10) {
        suspicious.push({
          type: 'multiple_login_failures',
          ip,
          count: failures.length,
          timespan: timeWindow,
          severity: 'high'
        });
      }
    }
    
    // Detectar acceso desde ubicaciones inusuales
    const locationChanges = await this.detectUnusualLocations(logs);
    suspicious.push(...locationChanges);
    
    // Detectar patrones de fuerza bruta
    const bruteForceAttempts = await this.detectBruteForcePatterns(logs);
    suspicious.push(...bruteForceAttempts);
    
    return suspicious;
  }
  
  // Generar reporte de seguridad
  async generateSecurityReport(period: 'daily' | 'weekly' | 'monthly'): Promise<SecurityReport> {
    const timeWindow = this.getTimeWindow(period);
    const logs = await this.auditLogger.getLogs({
      since: new Date(Date.now() - timeWindow)
    });
    
    return {
      period,
      totalEvents: logs.length,
      successfulLogins: logs.filter(l => l.event === 'authentication.success').length,
      failedLogins: logs.filter(l => l.event === 'authentication.failure').length,
      uniqueUsers: new Set(logs.map(l => l.userId).filter(Boolean)).size,
      uniqueIPs: new Set(logs.map(l => l.ip).filter(Boolean)).size,
      topFailureReasons: this.getTopFailureReasons(logs),
      suspiciousActivity: await this.detectSuspiciousActivity(timeWindow),
      recommendations: this.generateRecommendations(logs)
    };
  }
  
  private groupBy<T>(array: T[], key: keyof T): Record<string, T[]> {
    return array.reduce((groups, item) => {
      const group = String(item[key]);
      groups[group] = groups[group] || [];
      groups[group].push(item);
      return groups;
    }, {} as Record<string, T[]>);
  }
}
```

---

## ✅ Validación y Sanitización

### Validación de Entrada

```typescript
import { createValidationMiddleware, ValidationSchema } from '@open-bauth/core';

// Esquemas de validación
const userRegistrationSchema: ValidationSchema = {
  email: {
    type: 'email',
    required: true,
    maxLength: 255,
    customValidation: async (email: string) => {
      // Verificar que el dominio no esté en lista negra
      const domain = email.split('@')[1];
      const blacklistedDomains = ['tempmail.com', '10minutemail.com'];
      
      if (blacklistedDomains.includes(domain)) {
        throw new Error('Dominio de email no permitido');
      }
      
      // Verificar que el email no esté ya registrado
      const existingUser = await authLib.getAuthService().findUserByEmail(email);
      if (existingUser) {
        throw new Error('Email ya registrado');
      }
    }
  },
  
  password: {
    type: 'password',
    required: true,
    minLength: 8,
    maxLength: 128,
    patterns: [
      {
        regex: /[A-Z]/,
        message: 'Debe contener al menos una mayúscula'
      },
      {
        regex: /[a-z]/,
        message: 'Debe contener al menos una minúscula'
      },
      {
        regex: /[0-9]/,
        message: 'Debe contener al menos un número'
      },
      {
        regex: /[!@#$%^&*(),.?":{}|<>]/,
        message: 'Debe contener al menos un carácter especial'
      }
    ],
    forbiddenValues: [
      'password', '123456', 'qwerty', 'admin', 'letmein'
    ]
  },
  
  firstName: {
    type: 'string',
    required: true,
    minLength: 1,
    maxLength: 50,
    pattern: /^[a-zA-ZÀ-ÿ\s]+$/,
    sanitize: true
  },
  
  lastName: {
    type: 'string',
    required: true,
    minLength: 1,
    maxLength: 50,
    pattern: /^[a-zA-ZÀ-ÿ\s]+$/,
    sanitize: true
  },
  
  dateOfBirth: {
    type: 'date',
    required: false,
    minDate: new Date('1900-01-01'),
    maxDate: new Date(), // No fechas futuras
    customValidation: (date: Date) => {
      const age = new Date().getFullYear() - date.getFullYear();
      if (age < 13) {
        throw new Error('Debe ser mayor de 13 años');
      }
    }
  },
  
  phoneNumber: {
    type: 'phone',
    required: false,
    format: 'international', // +1234567890
    countries: ['US', 'CA', 'MX'] // Solo ciertos países
  }
};

// Middleware de validación
const validateRegistration = createValidationMiddleware(userRegistrationSchema, {
  abortEarly: false, // Mostrar todos los errores
  stripUnknown: true, // Remover campos no definidos
  sanitize: true,     // Sanitizar automáticamente
  
  onValidationError: (errors, req) => {
    console.log(`Errores de validación para ${req.ip}:`, errors);
  }
});

// Aplicar validación
app.post('/auth/register', validateRegistration, async (req, res) => {
  // req.body ya está validado y sanitizado
  const result = await authLib.getAuthService().register(req.body);
  res.json(result);
});
```

### Sanitización Avanzada

```typescript
import { createSanitizationMiddleware, SanitizationRules } from '@open-bauth/core';

// Reglas de sanitización
const sanitizationRules: SanitizationRules = {
  // Sanitización global
  global: {
    trimWhitespace: true,
    removeNullBytes: true,
    normalizeUnicode: true,
    maxLength: 10000 // Límite global de longitud
  },
  
  // Reglas por tipo de campo
  fieldTypes: {
    email: {
      toLowerCase: true,
      removeSpaces: true,
      maxLength: 255
    },
    
    name: {
      capitalizeWords: true,
      removeExtraSpaces: true,
      removeSpecialChars: /[^a-zA-ZÀ-ÿ\s]/g,
      maxLength: 50
    },
    
    username: {
      toLowerCase: true,
      removeSpaces: true,
      allowedChars: /[^a-zA-Z0-9_-]/g,
      maxLength: 30
    },
    
    description: {
      removeHtml: true,
      removeScripts: true,
      maxLength: 1000
    }
  },
  
  // Reglas por campo específico
  fields: {
    'user.bio': {
      removeHtml: true,
      allowedTags: ['b', 'i', 'u', 'br'],
      maxLength: 500
    },
    
    'user.website': {
      validateUrl: true,
      allowedProtocols: ['http', 'https'],
      maxLength: 255
    }
  }
};

// Middleware de sanitización
const sanitizeInput = createSanitizationMiddleware(sanitizationRules, {
  logSanitization: true,
  
  onSanitized: (field, originalValue, sanitizedValue) => {
    if (originalValue !== sanitizedValue) {
      console.log(`Campo ${field} sanitizado:`, {
        original: originalValue,
        sanitized: sanitizedValue
      });
    }
  }
});

app.use(sanitizeInput);
```

### Validación de Archivos

```typescript
import { createFileValidationMiddleware } from '@open-bauth/core';

// Validación de archivos subidos
const validateFileUpload = createFileValidationMiddleware({
  maxFileSize: 5 * 1024 * 1024, // 5MB
  allowedMimeTypes: [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp'
  ],
  allowedExtensions: ['.jpg', '.jpeg', '.png', '.gif', '.webp'],
  
  // Validación de contenido
  validateContent: true,
  scanForMalware: true,
  
  // Configuración de imagen
  imageValidation: {
    maxWidth: 2048,
    maxHeight: 2048,
    minWidth: 100,
    minHeight: 100
  },
  
  // Sanitización de nombres de archivo
  sanitizeFilename: true,
  
  onFileRejected: (file, reason) => {
    console.log(`Archivo rechazado: ${file.originalname} - ${reason}`);
  }
});

app.post('/upload/avatar', 
  auth.required,
  validateFileUpload,
  async (req, res) => {
    // Archivo ya validado
    const file = req.file;
    const userId = req.user.id;
    
    const avatarUrl = await uploadService.saveAvatar(userId, file);
    res.json({ avatarUrl });
  }
);
```

---

## 🚀 Cache y Optimización

### Sistema de Cache

```typescript
import { createCacheMiddleware, CacheProvider } from '@open-bauth/core';

// Configurar proveedor de cache
const cacheProvider: CacheProvider = {
  type: 'redis',
  connection: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379'),
    password: process.env.REDIS_PASSWORD
  },
  
  // Configuración de fallback
  fallback: {
    type: 'memory',
    maxSize: 100 * 1024 * 1024 // 100MB
  }
};

// Cache para usuarios
const userCache = createCacheMiddleware(cacheProvider, {
  keyGenerator: (req) => `user:${req.user?.id}`,
  ttl: 5 * 60 * 1000, // 5 minutos
  
  shouldCache: (req, res) => {
    // Solo cachear respuestas exitosas
    return res.statusCode === 200 && req.user;
  },
  
  invalidateOn: [
    'user.updated',
    'user.permissions.changed',
    'user.roles.changed'
  ]
});

// Cache para permisos
const permissionCache = createCacheMiddleware(cacheProvider, {
  keyGenerator: (req) => `permissions:${req.user?.id}`,
  ttl: 10 * 60 * 1000, // 10 minutos
  
  // Cache más agresivo para permisos
  staleWhileRevalidate: true,
  maxStaleTime: 30 * 60 * 1000, // 30 minutos
  
  onCacheHit: (key, data) => {
    console.log(`Cache hit para permisos: ${key}`);
  },
  
  onCacheMiss: (key) => {
    console.log(`Cache miss para permisos: ${key}`);
  }
});

// Aplicar cache
app.get('/api/user/profile', auth.required, userCache, (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/user/permissions', auth.required, permissionCache, async (req, res) => {
  const permissions = await authLib.getPermissionService().getUserPermissions(req.user.id);
  res.json({ permissions });
});
```

### Cache Inteligente

```typescript
// Cache con invalidación inteligente
class SmartCache {
  private cache: Map<string, CacheEntry> = new Map();
  private dependencies: Map<string, Set<string>> = new Map();
  
  // Cachear con dependencias
  async set(key: string, value: any, ttl: number, dependencies: string[] = []): Promise<void> {
    const entry: CacheEntry = {
      value,
      expires: Date.now() + ttl,
      dependencies: new Set(dependencies)
    };
    
    this.cache.set(key, entry);
    
    // Registrar dependencias
    dependencies.forEach(dep => {
      if (!this.dependencies.has(dep)) {
        this.dependencies.set(dep, new Set());
      }
      this.dependencies.get(dep)!.add(key);
    });
  }
  
  // Obtener del cache
  async get(key: string): Promise<any | null> {
    const entry = this.cache.get(key);
    
    if (!entry) {
      return null;
    }
    
    if (Date.now() > entry.expires) {
      this.cache.delete(key);
      return null;
    }
    
    return entry.value;
  }
  
  // Invalidar por dependencia
  async invalidate(dependency: string): Promise<void> {
    const dependentKeys = this.dependencies.get(dependency);
    
    if (dependentKeys) {
      dependentKeys.forEach(key => {
        this.cache.delete(key);
      });
      
      this.dependencies.delete(dependency);
    }
  }
  
  // Invalidar múltiples dependencias
  async invalidateMultiple(dependencies: string[]): Promise<void> {
    await Promise.all(dependencies.map(dep => this.invalidate(dep)));
  }
}

// Uso del cache inteligente
const smartCache = new SmartCache();

// Cachear usuario con dependencias
const cacheUser = async (userId: string, user: User) => {
  await smartCache.set(
    `user:${userId}`,
    user,
    5 * 60 * 1000, // 5 minutos
    [`user:${userId}`, 'users', `user:${userId}:profile`]
  );
};

// Cachear permisos con dependencias
const cacheUserPermissions = async (userId: string, permissions: Permission[]) => {
  await smartCache.set(
    `permissions:${userId}`,
    permissions,
    10 * 60 * 1000, // 10 minutos
    [`user:${userId}`, 'permissions', `user:${userId}:permissions`]
  );
};

// Invalidar cuando el usuario se actualiza
const onUserUpdated = async (userId: string) => {
  await smartCache.invalidateMultiple([
    `user:${userId}`,
    `user:${userId}:profile`,
    `user:${userId}:permissions`
  ]);
};
```

### Optimización de Consultas

```typescript
// Middleware de optimización de consultas
const optimizeQueries = createQueryOptimizationMiddleware({
  // Batching de consultas
  enableBatching: true,
  batchWindow: 10, // 10ms
  maxBatchSize: 50,
  
  // Prefetching inteligente
  enablePrefetching: true,
  prefetchRules: [
    {
      trigger: 'user.loaded',
      prefetch: ['user.permissions', 'user.roles'],
      condition: (user) => user.active
    },
    {
      trigger: 'permissions.checked',
      prefetch: ['user.roles'],
      condition: (context) => context.checkRoles
    }
  ],
  
  // Deduplicación de consultas
  enableDeduplication: true,
  deduplicationWindow: 100, // 100ms
  
  onOptimization: (type, details) => {
    console.log(`Optimización ${type}:`, details);
  }
});

app.use(optimizeQueries);
```

---

## 🔒 Seguridad Avanzada

### Protección CSRF

```typescript
import { createCSRFProtection } from '@open-bauth/core';

// Protección CSRF
const csrfProtection = createCSRFProtection({
  secret: process.env.CSRF_SECRET || 'csrf-secret',
  
  // Configuración de cookies
  cookie: {
    name: '_csrf',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000 // 24 horas
  },
  
  // Métodos que requieren protección CSRF
  methods: ['POST', 'PUT', 'DELETE', 'PATCH'],
  
  // Rutas excluidas
  excludePaths: ['/auth/login', '/auth/register', '/webhook'],
  
  // Verificación de origen
  verifyOrigin: true,
  allowedOrigins: ['https://myapp.com', 'https://www.myapp.com'],
  
  onCSRFError: (req, res) => {
    console.log(`Intento de CSRF detectado desde ${req.ip}`);
    res.status(403).json({ error: 'Token CSRF inválido' });
  }
});

app.use(csrfProtection);
```

### Protección XSS

```typescript
import { createXSSProtection } from '@open-bauth/core';

// Protección XSS
const xssProtection = createXSSProtection({
  // Sanitización automática
  autoSanitize: true,
  
  // Configuración de Content Security Policy
  csp: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    },
    reportOnly: process.env.NODE_ENV === 'development'
  },
  
  // Headers de seguridad
  securityHeaders: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  },
  
  // Filtros personalizados
  customFilters: [
    {
      name: 'script-injection',
      pattern: /<script[^>]*>.*?<\/script>/gi,
      replacement: '',
      logViolation: true
    },
    {
      name: 'event-handlers',
      pattern: /on\w+\s*=/gi,
      replacement: '',
      logViolation: true
    }
  ],
  
  onXSSAttempt: (req, violation) => {
    console.log(`Intento de XSS detectado:`, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      violation
    });
  }
});

app.use(xssProtection);
```

### Detección de Anomalías

```typescript
// Sistema de detección de anomalías
class AnomalyDetector {
  private patterns: Map<string, UserPattern> = new Map();
  private alerts: AnomalyAlert[] = [];
  
  // Analizar comportamiento del usuario
  async analyzeUserBehavior(userId: string, activity: UserActivity): Promise<AnomalyResult> {
    const pattern = this.patterns.get(userId) || this.createNewPattern(userId);
    
    const anomalies: Anomaly[] = [];
    
    // Detectar ubicación inusual
    if (this.isUnusualLocation(pattern, activity.location)) {
      anomalies.push({
        type: 'unusual_location',
        severity: 'medium',
        details: {
          currentLocation: activity.location,
          usualLocations: pattern.locations
        }
      });
    }
    
    // Detectar horario inusual
    if (this.isUnusualTime(pattern, activity.timestamp)) {
      anomalies.push({
        type: 'unusual_time',
        severity: 'low',
        details: {
          currentTime: activity.timestamp,
          usualTimes: pattern.activeTimes
        }
      });
    }
    
    // Detectar dispositivo nuevo
    if (this.isNewDevice(pattern, activity.deviceFingerprint)) {
      anomalies.push({
        type: 'new_device',
        severity: 'high',
        details: {
          deviceFingerprint: activity.deviceFingerprint,
          knownDevices: pattern.devices
        }
      });
    }
    
    // Detectar velocidad imposible
    if (this.isImpossibleTravel(pattern, activity)) {
      anomalies.push({
        type: 'impossible_travel',
        severity: 'high',
        details: {
          previousLocation: pattern.lastLocation,
          currentLocation: activity.location,
          timeDifference: activity.timestamp - pattern.lastActivity
        }
      });
    }
    
    // Actualizar patrón
    this.updatePattern(pattern, activity);
    
    // Generar alertas si es necesario
    if (anomalies.length > 0) {
      await this.generateAlerts(userId, anomalies);
    }
    
    return {
      userId,
      anomalies,
      riskScore: this.calculateRiskScore(anomalies),
      recommendedActions: this.getRecommendedActions(anomalies)
    };
  }
  
  private calculateRiskScore(anomalies: Anomaly[]): number {
    const severityWeights = {
      low: 1,
      medium: 3,
      high: 5,
      critical: 10
    };
    
    return anomalies.reduce((score, anomaly) => {
      return score + severityWeights[anomaly.severity];
    }, 0);
  }
  
  private getRecommendedActions(anomalies: Anomaly[]): string[] {
    const actions: string[] = [];
    
    const hasHighSeverity = anomalies.some(a => a.severity === 'high' || a.severity === 'critical');
    
    if (hasHighSeverity) {
      actions.push('require_additional_authentication');
      actions.push('notify_user_via_email');
    }
    
    if (anomalies.some(a => a.type === 'new_device')) {
      actions.push('require_device_verification');
    }
    
    if (anomalies.some(a => a.type === 'impossible_travel')) {
      actions.push('temporary_account_lock');
      actions.push('notify_security_team');
    }
    
    return actions;
  }
}

// Middleware de detección de anomalías
const anomalyDetection = createAnomalyDetectionMiddleware(new AnomalyDetector(), {
  enableRealTimeDetection: true,
  
  onAnomalyDetected: async (result) => {
    if (result.riskScore >= 5) {
      // Riesgo alto - tomar acciones inmediatas
      await securityService.handleHighRiskActivity(result);
    }
  },
  
  autoActions: {
    enabled: true,
    thresholds: {
      requireMFA: 3,
      lockAccount: 8,
      notifyAdmin: 5
    }
  }
});

app.use(auth.required, anomalyDetection);
```

---

## 📊 Monitoreo y Métricas

### Sistema de Métricas

```typescript
import { createMetricsMiddleware, MetricsCollector } from '@open-bauth/core';

// Configurar colector de métricas
const metricsCollector = new MetricsCollector({
  // Configuración de almacenamiento
  storage: {
    type: 'prometheus', // 'prometheus' | 'statsd' | 'custom'
    endpoint: 'http://prometheus:9090',
    pushGateway: 'http://pushgateway:9091'
  },
  
  // Métricas a recopilar
  metrics: {
    // Contadores
    counters: [
      'auth.login.attempts',
      'auth.login.success',
      'auth.login.failures',
      'auth.registration.attempts',
      'auth.token.issued',
      'auth.token.refreshed',
      'auth.permission.checks',
      'auth.permission.denied'
    ],
    
    // Histogramas (para medir duración)
    histograms: [
      'auth.login.duration',
      'auth.token.verification.duration',
      'auth.permission.check.duration',
      'auth.database.query.duration'
    ],
    
    // Gauges (para valores actuales)
    gauges: [
      'auth.active.sessions',
      'auth.concurrent.users',
      'auth.cache.hit.rate',
      'auth.database.connections'
    ]
  },
  
  // Etiquetas por defecto
  defaultLabels: {
    service: 'auth-service',
    version: process.env.APP_VERSION || '1.1.1',
    environment: process.env.NODE_ENV || 'development'
  }
});

// Middleware de métricas
const metricsMiddleware = createMetricsMiddleware(metricsCollector, {
  // Métricas automáticas
  autoMetrics: {
    requestDuration: true,
    requestCount: true,
    errorRate: true,
    responseSize: true
  },
  
  // Etiquetas personalizadas
  customLabels: (req) => ({
    method: req.method,
    route: req.route?.path || req.path,
    user_type: req.user?.roles?.[0] || 'anonymous',
    ip_country: req.geoip?.country || 'unknown'
  }),
  
  // Filtros
  excludePaths: ['/health', '/metrics', '/favicon.ico'],
  
  onMetricCollected: (metric, value, labels) => {
    // Log métricas importantes
    if (metric === 'auth.login.failures' && value > 10) {
      console.warn(`Alto número de fallos de login: ${value}`);
    }
  }
});

app.use(metricsMiddleware);

// Endpoint de métricas
app.get('/metrics', (req, res) => {
  const metrics = metricsCollector.getMetrics();
  res.set('Content-Type', 'text/plain');
  res.send(metrics);
});
```

### Dashboard de Monitoreo

```typescript
// Servicio de dashboard
class AuthDashboard {
  private metricsCollector: MetricsCollector;
  private auditLogger: AuditLogger;
  
  constructor(metricsCollector: MetricsCollector, auditLogger: AuditLogger) {
    this.metricsCollector = metricsCollector;
    this.auditLogger = auditLogger;
  }
  
  // Obtener estadísticas en tiempo real
  async getRealTimeStats(): Promise<DashboardStats> {
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
    
    return {
      activeUsers: await this.getActiveUserCount(),
      loginRate: await this.getLoginRate(oneHourAgo, now),
      errorRate: await this.getErrorRate(oneHourAgo, now),
      averageResponseTime: await this.getAverageResponseTime(oneHourAgo, now),
      topErrors: await this.getTopErrors(oneHourAgo, now),
      securityAlerts: await this.getSecurityAlerts(oneHourAgo, now),
      systemHealth: await this.getSystemHealth()
    };
  }
  
  // Generar reporte de rendimiento
  async generatePerformanceReport(period: 'hour' | 'day' | 'week' | 'month'): Promise<PerformanceReport> {
    const timeRange = this.getTimeRange(period);
    
    const metrics = await this.metricsCollector.getMetricsInRange(
      timeRange.start,
      timeRange.end
    );
    
    return {
      period,
      timeRange,
      summary: {
        totalRequests: metrics.get('auth.requests.total'),
        successRate: this.calculateSuccessRate(metrics),
        averageResponseTime: metrics.get('auth.response.time.avg'),
        peakConcurrentUsers: metrics.get('auth.concurrent.users.max'),
        errorCount: metrics.get('auth.errors.total')
      },
      trends: {
        requestVolume: this.calculateTrend(metrics, 'auth.requests.total'),
        responseTime: this.calculateTrend(metrics, 'auth.response.time.avg'),
        errorRate: this.calculateTrend(metrics, 'auth.error.rate')
      },
      topEndpoints: await this.getTopEndpoints(timeRange),
      recommendations: this.generateRecommendations(metrics)
    };
  }
  
  private generateRecommendations(metrics: Map<string, number>): string[] {
    const recommendations: string[] = [];
    
    const errorRate = metrics.get('auth.error.rate') || 0;
    if (errorRate > 0.05) { // 5%
      recommendations.push('La tasa de errores es alta. Revisar logs de errores.');
    }
    
    const avgResponseTime = metrics.get('auth.response.time.avg') || 0;
    if (avgResponseTime > 1000) { // 1 segundo
      recommendations.push('Tiempo de respuesta alto. Considerar optimización de consultas.');
    }
    
    const cacheHitRate = metrics.get('auth.cache.hit.rate') || 0;
    if (cacheHitRate < 0.8) { // 80%
      recommendations.push('Baja tasa de aciertos de cache. Revisar estrategia de cache.');
    }
    
    return recommendations;
  }
}

// Endpoint del dashboard
app.get('/admin/dashboard', auth.permissions(['admin.dashboard']), async (req, res) => {
  const dashboard = new AuthDashboard(metricsCollector, auditLogger);
  const stats = await dashboard.getRealTimeStats();
  res.json(stats);
});

app.get('/admin/reports/:period', auth.permissions(['admin.reports']), async (req, res) => {
  const dashboard = new AuthDashboard(metricsCollector, auditLogger);
  const report = await dashboard.generatePerformanceReport(req.params.period as any);
  res.json(report);
});
```

### Alertas Automáticas

```typescript
// Sistema de alertas
class AlertSystem {
  private rules: AlertRule[] = [];
  private channels: AlertChannel[] = [];
  
  constructor() {
    this.setupDefaultRules();
    this.setupDefaultChannels();
  }
  
  private setupDefaultRules(): void {
    this.rules = [
      {
        name: 'high_error_rate',
        condition: (metrics) => metrics.get('auth.error.rate') > 0.1, // 10%
        severity: 'critical',
        message: 'Tasa de errores de autenticación muy alta',
        cooldown: 5 * 60 * 1000 // 5 minutos
      },
      {
        name: 'slow_response_time',
        condition: (metrics) => metrics.get('auth.response.time.avg') > 2000, // 2 segundos
        severity: 'warning',
        message: 'Tiempo de respuesta de autenticación lento',
        cooldown: 10 * 60 * 1000 // 10 minutos
      },
      {
        name: 'multiple_failed_logins',
        condition: (metrics) => metrics.get('auth.login.failures.rate') > 50, // 50 fallos por minuto
        severity: 'high',
        message: 'Posible ataque de fuerza bruta detectado',
        cooldown: 2 * 60 * 1000 // 2 minutos
      },
      {
        name: 'database_connection_issues',
        condition: (metrics) => metrics.get('auth.database.errors.rate') > 0.05, // 5%
        severity: 'critical',
        message: 'Problemas de conexión con la base de datos',
        cooldown: 1 * 60 * 1000 // 1 minuto
      }
    ];
  }
  
  private setupDefaultChannels(): void {
    this.channels = [
      {
        name: 'email',
        type: 'email',
        config: {
          recipients: ['admin@company.com', 'security@company.com'],
          smtp: {
            host: process.env.SMTP_HOST,
            port: 587,
            auth: {
              user: process.env.SMTP_USER,
              pass: process.env.SMTP_PASS
            }
          }
        },
        severities: ['critical', 'high']
      },
      {
        name: 'slack',
        type: 'webhook',
        config: {
          url: process.env.SLACK_WEBHOOK_URL,
          channel: '#security-alerts'
        },
        severities: ['critical', 'high', 'warning']
      },
      {
        name: 'pagerduty',
        type: 'pagerduty',
        config: {
          integrationKey: process.env.PAGERDUTY_INTEGRATION_KEY
        },
        severities: ['critical']
      }
    ];
  }
  
  async checkAlerts(metrics: Map<string, number>): Promise<void> {
    for (const rule of this.rules) {
      if (rule.condition(metrics)) {
        await this.triggerAlert(rule, metrics);
      }
    }
  }
  
  private async triggerAlert(rule: AlertRule, metrics: Map<string, number>): Promise<void> {
    // Verificar cooldown
    const lastTriggered = this.getLastTriggered(rule.name);
    if (lastTriggered && Date.now() - lastTriggered < rule.cooldown) {
      return;
    }
    
    // Marcar como disparado
    this.setLastTriggered(rule.name, Date.now());
    
    // Enviar alertas a canales apropiados
    const channels = this.channels.filter(c => c.severities.includes(rule.severity));
    
    await Promise.all(channels.map(channel => 
      this.sendAlert(channel, rule, metrics)
    ));
  }
  
  private async sendAlert(channel: AlertChannel, rule: AlertRule, metrics: Map<string, number>): Promise<void> {
    const alert = {
      rule: rule.name,
      severity: rule.severity,
      message: rule.message,
      timestamp: new Date().toISOString(),
      metrics: Object.fromEntries(metrics),
      environment: process.env.NODE_ENV
    };
    
    switch (channel.type) {
      case 'email':
        await this.sendEmailAlert(channel, alert);
        break;
      case 'webhook':
        await this.sendWebhookAlert(channel, alert);
        break;
      case 'pagerduty':
        await this.sendPagerDutyAlert(channel, alert);
        break;
    }
  }
}

// Middleware de alertas
const alertSystem = new AlertSystem();

const alertMiddleware = createAlertMiddleware(alertSystem, {
  checkInterval: 60 * 1000, // Verificar cada minuto
  
  onAlertTriggered: (alert) => {
    console.log(`Alerta disparada: ${alert.rule} - ${alert.message}`);
  }
});

app.use(alertMiddleware);
```

---

## 🎯 Mejores Prácticas

### 1. Configuración de Middleware

```typescript
// ✅ Buena práctica: Orden correcto de middleware
app.use(helmet()); // Seguridad primero
app.use(cors(corsOptions)); // CORS
app.use(express.json({ limit: '10mb' })); // Parsing
app.use(rateLimitMiddleware); // Rate limiting
app.use(auth.middleware); // Autenticación
app.use(auditMiddleware); // Auditoría
app.use(metricsMiddleware); // Métricas

// ❌ Mala práctica: Orden incorrecto
app.use(auth.middleware); // Muy temprano
app.use(helmet()); // Muy tarde
```

### 2. Manejo de Errores

```typescript
// ✅ Buena práctica: Manejo centralizado de errores
const errorHandler = (err: any, req: any, res: any, next: any) => {
  // Log del error
  auditLogger.logError({
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.headers['user-agent'],
    userId: req.user?.id
  });
  
  // Respuesta según el tipo de error
  if (err.name === 'AuthenticationError') {
    return res.status(401).json({ error: 'Token inválido' });
  }
  
  if (err.name === 'AuthorizationError') {
    return res.status(403).json({ error: 'Permisos insuficientes' });
  }
  
  if (err.name === 'ValidationError') {
    return res.status(400).json({ 
      error: 'Datos inválidos',
      details: err.details 
    });
  }
  
  // Error genérico
  res.status(500).json({ error: 'Error interno del servidor' });
};

app.use(errorHandler);
```

### 3. Testing de Middleware

```typescript
// ✅ Buena práctica: Tests comprehensivos
import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';

describe('Auth Middleware', () => {
  let app: Express;
  let authLib: AuthLibrary;
  
  beforeEach(async () => {
    authLib = createTestAuthLibrary();
    await authLib.initialize();
    
    app = express();
    app.use(express.json());
    app.use(createAuthMiddleware(authLib));
    
    app.get('/protected', auth.required, (req, res) => {
      res.json({ user: req.user });
    });
  });
  
  it('should allow access with valid token', async () => {
    const user = await createTestUser();
    const token = await authLib.getJWTService().generateToken({ userId: user.id });
    
    const response = await request(app)
      .get('/protected')
      .set('Authorization', `Bearer ${token}`);
    
    expect(response.status).toBe(200);
    expect(response.body.user.id).toBe(user.id);
  });
  
  it('should reject invalid token', async () => {
    const response = await request(app)
      .get('/protected')
      .set('Authorization', 'Bearer invalid-token');
    
    expect(response.status).toBe(401);
  });
  
  it('should handle missing token', async () => {
    const response = await request(app)
      .get('/protected');
    
    expect(response.status).toBe(401);
  });
});
```

### 4. Monitoreo y Observabilidad

```typescript
// ✅ Buena práctica: Observabilidad completa
const observabilityMiddleware = createObservabilityMiddleware({
  // Tracing distribuido
  tracing: {
    enabled: true,
    serviceName: 'auth-service',
    jaegerEndpoint: process.env.JAEGER_ENDPOINT
  },
  
  // Métricas
  metrics: {
    enabled: true,
    prefix: 'auth_',
    labels: ['method', 'route', 'status_code']
  },
  
  // Logging estructurado
  logging: {
    enabled: true,
    level: 'info',
    format: 'json',
    includeRequestId: true
  },
  
  // Health checks
  healthChecks: {
    enabled: true,
    endpoint: '/health',
    checks: [
      'database',
      'redis',
      'external_apis'
    ]
  }
});

app.use(observabilityMiddleware);
```

## 🔗 Enlaces Relacionados

- **[Adaptadores de Framework](./05-framework-adapters.md)** - Integración con frameworks
- **[Ejemplos Prácticos](./07-examples.md)** - Implementaciones completas
- **[API Reference](./08-api-reference.md)** - Referencia de la API
- **[Troubleshooting](./09-troubleshooting.md)** - Solución de problemas
- **[Configuración](./02-installation-config.md)** - Configuración inicial

---

[⬅️ Adaptadores](./05-framework-adapters.md) | [🏠 Índice](./README.md) | [➡️ Ejemplos](./07-examples.md)