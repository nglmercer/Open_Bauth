# 🔧 Troubleshooting y FAQ

Guía completa para resolver problemas comunes y preguntas frecuentes sobre la librería de autenticación.

## 📋 Índice

- [🚨 Problemas Comunes](#-problemas-comunes)
- [❓ Preguntas Frecuentes (FAQ)](#-preguntas-frecuentes-faq)
- [🔍 Diagnóstico](#-diagnóstico)
- [📊 Monitoreo](#-monitoreo)
- [🛠️ Herramientas de Debug](#️-herramientas-de-debug)
- [📞 Soporte](#-soporte)

---

## 🚨 Problemas Comunes

### 🔌 Problemas de Conexión

#### Error: "Database connection failed"

**Síntomas:**
```
AuthLibraryError: Database connection failed
Code: DB_001
```

**Causas posibles:**
- Credenciales de base de datos incorrectas
- Base de datos no disponible
- Configuración de red/firewall
- Pool de conexiones agotado

**Soluciones:**

1. **Verificar credenciales:**
```typescript
// Verificar configuración
const config = {
  database: {
    type: 'postgresql',
    host: 'localhost', // ✓ Host correcto
    port: 5432,        // ✓ Puerto correcto
    database: 'auth_db',
    username: 'user',   // ✓ Usuario correcto
    password: 'pass'    // ✓ Contraseña correcta
  }
};
```

2. **Probar conexión manualmente:**
```bash
# PostgreSQL
psql -h localhost -p 5432 -U user -d auth_db

# MySQL
mysql -h localhost -P 3306 -u user -p auth_db
```

3. **Verificar disponibilidad del servicio:**
```bash
# Verificar si el puerto está abierto
telnet localhost 5432

# Verificar logs del servicio
docker logs postgres-container
```

4. **Ajustar configuración de pool:**
```typescript
const config = {
  database: {
    // ... otras configuraciones
    poolSize: 10,
    connectionTimeout: 30000,
    idleTimeout: 600000
  }
};
```

#### Error: "Redis connection failed"

**Síntomas:**
```
AuthLibraryError: Redis connection failed
Code: REDIS_001
```

**Soluciones:**

1. **Verificar servicio Redis:**
```bash
# Verificar si Redis está corriendo
redis-cli ping
# Respuesta esperada: PONG
```

2. **Configuración correcta:**
```typescript
const config = {
  redis: {
    host: 'localhost',
    port: 6379,
    password: 'redis-password', // Si está configurado
    database: 0,
    connectTimeout: 10000,
    lazyConnect: true
  }
};
```

### 🔐 Problemas de Autenticación

#### Error: "Invalid credentials"

**Síntomas:**
```
AuthenticationError: Invalid credentials
Code: AUTH_001
```

**Diagnóstico:**

1. **Verificar hash de contraseña:**
```typescript
// Debug: Verificar si la contraseña se está hasheando correctamente
const isValid = await Bun.password.verify(plainPassword, hashedPassword);
console.log('Password valid:', isValid);

// Verificar algoritmo usado
console.log('Hash algorithm:', hashedPassword.startsWith('$argon2') ? 'argon2' : 'other');
```

2. **Verificar usuario en base de datos:**
```sql
-- Verificar si el usuario existe
SELECT id, email, password_hash, active 
FROM users 
WHERE email = 'user@example.com';
```

3. **Verificar configuración de hash:**
```typescript
const config = {
  security: {
    passwordHashAlgorithm: 'argon2id' // Algoritmo usado por Bun.password
  }
};

// Verificar que Bun.password esté disponible
console.log('Bun.password available:', typeof Bun?.password?.hash === 'function');
```

#### Error: "Token expired"

**Síntomas:**
```
TokenError: Token expired
Code: AUTH_002
```

**Soluciones:**

1. **Implementar refresh token:**
```typescript
// Interceptor para renovar tokens automáticamente
const refreshToken = async (expiredToken) => {
  try {
    const refreshToken = localStorage.getItem('refreshToken');
    const response = await fetch('/auth/refresh', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${refreshToken}` }
    });
    const { accessToken } = await response.json();
    localStorage.setItem('accessToken', accessToken);
    return accessToken;
  } catch (error) {
    // Redirigir a login
    window.location.href = '/login';
  }
};
```

2. **Ajustar tiempo de expiración:**
```typescript
const config = {
  jwt: {
    expiresIn: '2h',           // Token de acceso
    refreshExpiresIn: '7d'     // Refresh token
  }
};
```

### 🛡️ Problemas de Permisos

#### Error: "Insufficient permissions"

**Síntomas:**
```
AuthorizationError: Insufficient permissions
Code: AUTH_006
Required: ['admin.access']
User has: ['user.read', 'user.write']
```

**Diagnóstico:**

1. **Verificar roles del usuario:**
```typescript
// Debug: Verificar roles y permisos
const userRoles = await permissionService.getUserRoles(userId);
const userPermissions = await permissionService.getUserPermissions(userId);
console.log('User roles:', userRoles);
console.log('User permissions:', userPermissions);
```

2. **Verificar configuración de roles:**
```sql
-- Verificar roles y permisos en BD
SELECT r.name as role_name, p.name as permission_name
FROM user_roles ur
JOIN roles r ON ur.role_id = r.id
JOIN role_permissions rp ON r.id = rp.role_id
JOIN permissions p ON rp.permission_id = p.id
WHERE ur.user_id = 'user-id-123';
```

### 📊 Problemas de Rendimiento

#### Lentitud en autenticación

**Síntomas:**
- Tiempos de respuesta > 2 segundos
- Timeouts en requests

**Soluciones:**

1. **Optimizar consultas de base de datos:**
```sql
-- Crear índices necesarios
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
```

2. **Implementar caché:**
```typescript
// Configurar caché para permisos
const config = {
  redis: {
    // ... configuración Redis
  },
  caching: {
    permissions: {
      ttl: 300, // 5 minutos
      enabled: true
    },
    roles: {
      ttl: 600, // 10 minutos
      enabled: true
    }
  }
};
```

3. **Pool de conexiones optimizado:**
```typescript
const config = {
  database: {
    poolSize: 20,
    maxWaitingClients: 10,
    acquireTimeoutMillis: 30000,
    idleTimeoutMillis: 600000
  }
};
```

---

## ❓ Preguntas Frecuentes (FAQ)

### 🔧 Configuración

**Q: ¿Puedo usar múltiples bases de datos?**

A: Sí, puedes configurar diferentes bases de datos para diferentes propósitos:

```typescript
const config = {
  database: {
    // Base de datos principal para usuarios
    type: 'postgresql',
    host: 'localhost',
    database: 'auth_users'
  },
  auditDatabase: {
    // Base de datos separada para auditoría
    type: 'mongodb',
    host: 'localhost',
    database: 'auth_audit'
  }
};
```

**Q: ¿Cómo cambio el algoritmo de JWT?**

A: Modifica la configuración JWT:

```typescript
const config = {
  jwt: {
    algorithm: 'RS256', // Cambiar de HS256 a RS256
    publicKey: process.env.JWT_PUBLIC_KEY,
    privateKey: process.env.JWT_PRIVATE_KEY
  }
};
```

**Q: ¿Puedo usar sin Redis?**

A: Sí, Redis es opcional. Sin Redis:
- No habrá caché de permisos
- No habrá blacklist de tokens
- No habrá rate limiting distribuido

```typescript
// Configuración sin Redis
const config = {
  database: { /* ... */ },
  jwt: { /* ... */ }
  // No incluir configuración de Redis
};
```

### 🔐 Seguridad

**Q: ¿Cómo implemento 2FA?**

A: Ejemplo básico con TOTP:

```typescript
import speakeasy from 'speakeasy';

// Generar secret para el usuario
const secret = speakeasy.generateSecret({
  name: 'Mi App',
  account: user.email
});

// Guardar secret en el usuario
await authService.updateUser(userId, {
  twoFactorSecret: secret.base32
});

// Verificar código TOTP
const verified = speakeasy.totp.verify({
  secret: user.twoFactorSecret,
  encoding: 'base32',
  token: userProvidedToken,
  window: 2
});
```

**Q: ¿Cómo implemento rate limiting?**

A: Configuración de rate limiting:

```typescript
const config = {
  security: {
    rateLimiting: {
      enabled: true,
      windowMs: 15 * 60 * 1000, // 15 minutos
      maxAttempts: 5,
      skipSuccessfulRequests: true
    }
  }
};
```

**Q: ¿Cómo manejo el logout en múltiples dispositivos?**

A: Implementa invalidación de tokens:

```typescript
// Logout de todos los dispositivos
const logoutAllDevices = async (userId: string) => {
  // Invalidar todos los tokens del usuario
  await jwtService.invalidateAllUserTokens(userId);
  
  // Eliminar todas las sesiones
  await authService.clearAllUserSessions(userId);
  
  // Log de auditoría
  await auditService.log({
    userId,
    action: 'logout_all_devices',
    metadata: { reason: 'user_requested' }
  });
};
```

### 🏗️ Arquitectura

**Q: ¿Puedo usar en microservicios?**

A: Sí, ejemplo de configuración para microservicios:

```typescript
// Servicio de autenticación
const authService = new AuthLibrary({
  database: { /* config */ },
  jwt: { 
    secret: process.env.JWT_SECRET,
    issuer: 'auth-service'
  }
});

// Otros microservicios (solo verificación)
const otherService = new AuthLibrary({
  jwt: {
    secret: process.env.JWT_SECRET,
    issuer: 'auth-service',
    verifyOnly: true // Solo verificar, no generar
  }
});
```

**Q: ¿Cómo escalo horizontalmente?**

A: Configuración para escalado:

```typescript
const config = {
  database: {
    // Usar pool de conexiones
    poolSize: 20
  },
  redis: {
    // Redis para estado compartido
    host: 'redis-cluster.example.com'
  },
  jwt: {
    // Tokens stateless
    stateless: true
  },
  session: {
    // Sesiones en Redis, no en memoria
    store: 'redis'
  }
};
```

### 🔄 Migración

**Q: ¿Cómo migro desde otra librería?**

A: Script de migración ejemplo:

```typescript
const migrateFromOldSystem = async () => {
  // 1. Migrar usuarios
  const oldUsers = await oldSystem.getAllUsers();
  
  for (const oldUser of oldUsers) {
    await authService.register({
      email: oldUser.email,
      password: oldUser.hashedPassword, // Ya hasheada
      profile: {
        name: oldUser.name,
        phone: oldUser.phone
      }
    }, { skipPasswordHashing: true });
  }
  
  // 2. Migrar roles
  const oldRoles = await oldSystem.getAllRoles();
  
  for (const oldRole of oldRoles) {
    await permissionService.createRole({
      name: oldRole.name,
      permissions: oldRole.permissions
    });
  }
  
  // 3. Asignar roles
  const userRoleMappings = await oldSystem.getUserRoles();
  
  for (const mapping of userRoleMappings) {
    await permissionService.assignRole(
      mapping.userId,
      mapping.roleName
    );
  }
};
```

---

## 🔍 Diagnóstico

### 🔧 Herramientas de Debug

#### Habilitar Logging Detallado

```typescript
const config = {
  logging: {
    level: 'debug',
    format: 'json',
    destination: 'console'
  }
};

// O usando variables de entorno
process.env.AUTH_LOG_LEVEL = 'debug';
process.env.AUTH_LOG_FORMAT = 'json';
```

#### Script de Diagnóstico

```typescript
// scripts/diagnose.ts
import { AuthLibrary } from '../src';

const diagnose = async () => {
  console.log('🔍 Iniciando diagnóstico...');
  
  try {
    // 1. Verificar configuración
    console.log('✅ Configuración cargada');
    
    // 2. Probar conexión a BD
    const authLib = new AuthLibrary(config);
    await authLib.initialize();
    console.log('✅ Conexión a base de datos exitosa');
    
    // 3. Probar conexión a Redis
    if (config.redis) {
      // Test Redis connection
      console.log('✅ Conexión a Redis exitosa');
    }
    
    // 4. Verificar servicios
    const authService = authLib.getAuthService();
    const jwtService = authLib.getJWTService();
    const permissionService = authLib.getPermissionService();
    console.log('✅ Servicios inicializados');
    
    // 5. Probar operaciones básicas
    const testToken = await jwtService.generateToken({
      userId: 'test',
      email: 'test@example.com'
    });
    
    const decoded = await jwtService.verifyToken(testToken);
    console.log('✅ Generación y verificación de tokens');
    
    await authLib.close();
    console.log('🎉 Diagnóstico completado exitosamente');
    
  } catch (error) {
    console.error('❌ Error en diagnóstico:', error);
    process.exit(1);
  }
};

diagnose();
```

#### Verificación de Salud (Health Check)

```typescript
// Endpoint de health check
app.get('/health', async (req, res) => {
  const health = {
    status: 'ok',
    timestamp: new Date().toISOString(),
    services: {}
  };
  
  try {
    // Verificar base de datos
    await authLib.getAuthService().getUserById('health-check');
    health.services.database = 'ok';
  } catch (error) {
    health.services.database = 'error';
    health.status = 'degraded';
  }
  
  try {
    // Verificar Redis
    if (config.redis) {
      await redisClient.ping();
      health.services.redis = 'ok';
    }
  } catch (error) {
    health.services.redis = 'error';
    health.status = 'degraded';
  }
  
  res.status(health.status === 'ok' ? 200 : 503).json(health);
});
```

### 📊 Métricas y Monitoreo

#### Métricas Básicas

```typescript
// Middleware para métricas
const metricsMiddleware = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    
    // Registrar métricas
    metrics.increment('auth.requests.total', {
      method: req.method,
      status: res.statusCode,
      endpoint: req.route?.path
    });
    
    metrics.histogram('auth.request.duration', duration, {
      endpoint: req.route?.path
    });
  });
  
  next();
};
```

#### Dashboard de Monitoreo

```typescript
// Endpoint de métricas
app.get('/metrics', async (req, res) => {
  const metrics = {
    users: {
      total: await authService.getUserCount(),
      active: await authService.getActiveUserCount(),
      newToday: await authService.getNewUsersToday()
    },
    authentication: {
      successfulLogins: await auditService.getLoginCount('success', '24h'),
      failedLogins: await auditService.getLoginCount('failed', '24h'),
      activeTokens: await jwtService.getActiveTokenCount()
    },
    performance: {
      avgResponseTime: await getAverageResponseTime(),
      errorRate: await getErrorRate()
    }
  };
  
  res.json(metrics);
});
```

---

## 🛠️ Herramientas de Debug

### CLI de Administración

```bash
# Crear usuario admin
npx auth-cli user create --email admin@example.com --role admin

# Listar usuarios
npx auth-cli user list --role admin

# Verificar permisos
npx auth-cli permissions check --user user@example.com --permission admin.access

# Limpiar tokens expirados
npx auth-cli tokens cleanup

# Generar reporte de auditoría
npx auth-cli audit report --from 2024-01-01 --to 2024-01-31
```

### Scripts de Utilidad

```typescript
// scripts/reset-password.ts
const resetUserPassword = async (email: string) => {
  const user = await authService.getUserByEmail(email);
  if (!user) {
    console.log('Usuario no encontrado');
    return;
  }
  
  const tempPassword = generateRandomPassword();
  await authService.changePassword(user.id, tempPassword);
  
  console.log(`Nueva contraseña temporal: ${tempPassword}`);
  console.log('El usuario debe cambiarla en el próximo login');
};

// scripts/cleanup-expired.ts
const cleanupExpiredData = async () => {
  // Limpiar tokens expirados
  await jwtService.cleanupExpiredTokens();
  
  // Limpiar sesiones expiradas
  await authService.cleanupExpiredSessions();
  
  // Limpiar logs antiguos (> 90 días)
  await auditService.cleanupOldLogs(90);
  
  console.log('Limpieza completada');
};
```

---

## 📞 Soporte

### 🐛 Reportar Bugs

Cuando reportes un bug, incluye:

1. **Versión de la librería**
2. **Configuración** (sin credenciales)
3. **Pasos para reproducir**
4. **Logs de error completos**
5. **Entorno** (Node.js version, OS, etc.)

### 📧 Canales de Soporte

- **GitHub Issues**: Para bugs y feature requests
- **Documentación**: Para guías y ejemplos
- **Community Discord**: Para preguntas rápidas
- **Email**: Para soporte empresarial

### 🔄 Actualizaciones

Para mantenerte actualizado:

```bash
# Verificar versión actual
npm list @open-bauth/core

# Verificar actualizaciones
npm outdated @open-bauth/core

# Actualizar
npm update @open-bauth/core
```

### 📚 Recursos Adicionales

- **[Ejemplos en GitHub](https://github.com/open-bauth/examples)**
- **[Blog con tutoriales](https://open-bauth.dev/blog)**
- **[Changelog](https://github.com/open-bauth/core/CHANGELOG.md)**
- **[Roadmap](https://github.com/open-bauth/core/projects)**

---

## 🔗 Enlaces Relacionados

- **[API Reference](./08-api-reference.md)** - Documentación completa de la API
- **[Ejemplos Prácticos](./07-examples.md)** - Implementaciones completas
- **[Configuración](./02-installation-config.md)** - Configuración detallada
- **[Guía de Inicio](./01-quick-start.md)** - Primeros pasos

---

[⬅️ API Reference](./08-api-reference.md) | [🏠 Índice](./README.md)