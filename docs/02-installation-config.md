# 📦 Instalación y Configuración

Guía completa para instalar y configurar la Librería de Autenticación en tu proyecto.

## 📋 Requisitos del Sistema

### Requisitos Mínimos

| Componente | Versión Mínima | Recomendada |
|------------|----------------|-------------|
| **Bun** | 1.1.1 | 1.0.25+ |
| **Node.js** | 18.0.0 | 20.0.0+ |
| **TypeScript** | 4.9.0 | 5.0.0+ |
| **SQLite** | 3.35.0 | Incluido con Bun |

### Sistemas Operativos Soportados

- ✅ **Linux** (Ubuntu 20.04+, CentOS 8+, Debian 11+)
- ✅ **macOS** (10.15+)
- ✅ **Windows** (10, 11)
- ✅ **Docker** (Alpine, Ubuntu)

## 🚀 Instalación

### Opción 1: Con Bun (Recomendado)

```bash
# Instalar Bun si no lo tienes
curl -fsSL https://bun.sh/install | bash

# Instalar la librería
bun add @open-bauth/core

# Instalar dependencias de desarrollo (opcional)
bun add -d @types/node
```

### Opción 2: Con npm

```bash
# Instalar la librería
npm install @open-bauth/core

# Instalar dependencias adicionales para Node.js
npm install sqlite3
npm install -D @types/node
```

### Opción 3: Con yarn

```bash
# Instalar la librería
yarn add @open-bauth/core

# Instalar dependencias adicionales
yarn add sqlite3
yarn add -D @types/node
```

### Opción 4: Con pnpm

```bash
# Instalar la librería
pnpm add @open-bauth/core

# Instalar dependencias adicionales
pnpm add sqlite3
pnpm add -D @types/node
```

## ⚙️ Configuración Inicial

### 1. Variables de Entorno

Crea un archivo `.env` en la raíz de tu proyecto:

```bash
# .env

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-here
JWT_EXPIRATION=24h
REFRESH_TOKEN_EXPIRATION=7d

# Database Configuration
DATABASE_PATH=./auth.db
DATABASE_ENABLE_WAL=true
DATABASE_ENABLE_FOREIGN_KEYS=true
DATABASE_BUSY_TIMEOUT=5000

# Security Configuration
PASSWORD_HASH_ALGORITHM=argon2id
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=900000
SESSION_TIMEOUT=86400000
PASSWORD_MIN_LENGTH=8
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_SYMBOLS=false

# CORS Configuration
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
CORS_CREDENTIALS=true
CORS_METHODS=GET,POST,PUT,DELETE,OPTIONS
CORS_HEADERS=Content-Type,Authorization

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
RATE_LIMIT_SKIP_SUCCESSFUL=true

# Logging
LOG_LEVEL=info
LOG_ENABLE_CONSOLE=true
LOG_ENABLE_FILE=false
LOG_FILE_PATH=./logs/auth.log

# Development
NODE_ENV=development
PORT=3000
```

### 2. Archivo de Configuración TypeScript

Crea `src/config/auth.config.ts`:

```typescript
// src/config/auth.config.ts
import { AuthConfig } from '@open-bauth/core';

/**
 * Configuración de autenticación para desarrollo
 */
export const developmentConfig: Partial<AuthConfig> = {
  jwtSecret: process.env.JWT_SECRET || 'dev-secret-key',
  jwtExpiration: process.env.JWT_EXPIRATION || '24h',
  refreshTokenExpiration: process.env.REFRESH_TOKEN_EXPIRATION || '7d',
  
  database: {
    path: process.env.DATABASE_PATH || './auth.db',
    enableWAL: process.env.DATABASE_ENABLE_WAL === 'true',
    enableForeignKeys: process.env.DATABASE_ENABLE_FOREIGN_KEYS === 'true',
    busyTimeout: parseInt(process.env.DATABASE_BUSY_TIMEOUT || '5000')
  },
  
  security: {
    passwordHashAlgorithm: process.env.PASSWORD_HASH_ALGORITHM || 'argon2id',
    maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5'),
    lockoutDuration: parseInt(process.env.LOCKOUT_DURATION || '900000'),
    sessionTimeout: parseInt(process.env.SESSION_TIMEOUT || '86400000'),
    passwordMinLength: parseInt(process.env.PASSWORD_MIN_LENGTH || '8'),
    passwordRequireUppercase: process.env.PASSWORD_REQUIRE_UPPERCASE === 'true',
    passwordRequireLowercase: process.env.PASSWORD_REQUIRE_LOWERCASE === 'true',
    passwordRequireNumbers: process.env.PASSWORD_REQUIRE_NUMBERS === 'true',
    passwordRequireSymbols: process.env.PASSWORD_REQUIRE_SYMBOLS === 'true'
  },
  
  cors: {
    origins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: process.env.CORS_CREDENTIALS === 'true',
    methods: process.env.CORS_METHODS?.split(',') || ['GET', 'POST', 'PUT', 'DELETE'],
    headers: process.env.CORS_HEADERS?.split(',') || ['Content-Type', 'Authorization']
  },
  
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'),
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),
    skipSuccessfulRequests: process.env.RATE_LIMIT_SKIP_SUCCESSFUL === 'true'
  },
  
  logging: {
    level: (process.env.LOG_LEVEL as any) || 'info',
    enableConsole: process.env.LOG_ENABLE_CONSOLE === 'true',
    enableFile: process.env.LOG_ENABLE_FILE === 'true',
    filePath: process.env.LOG_FILE_PATH || './logs/auth.log'
  }
};

/**
 * Configuración de autenticación para producción
 */
export const productionConfig: Partial<AuthConfig> = {
  ...developmentConfig,
  
  // Configuración más estricta para producción
  security: {
    ...developmentConfig.security,
    bcryptRounds: 14,
    maxLoginAttempts: 3,
    lockoutDuration: 1800000, // 30 minutos
    passwordMinLength: 10,
    passwordRequireSymbols: true
  },
  
  logging: {
    ...developmentConfig.logging,
    level: 'warn',
    enableFile: true
  },
  
  rateLimit: {
    ...developmentConfig.rateLimit,
    maxRequests: 50 // Más restrictivo en producción
  }
};

/**
 * Configuración de autenticación para testing
 */
export const testConfig: Partial<AuthConfig> = {
  ...developmentConfig,
  
  database: {
    path: ':memory:', // Base de datos en memoria para tests
    enableWAL: false,
    enableForeignKeys: true,
    busyTimeout: 1000
  },
  
  security: {
    ...developmentConfig.security,
    bcryptRounds: 4, // Más rápido para tests
    maxLoginAttempts: 10
  },
  
  logging: {
    level: 'error',
    enableConsole: false,
    enableFile: false
  }
};

/**
 * Obtener configuración según el entorno
 */
export function getAuthConfig(): Partial<AuthConfig> {
  const env = process.env.NODE_ENV || 'development';
  
  switch (env) {
    case 'production':
      return productionConfig;
    case 'test':
      return testConfig;
    default:
      return developmentConfig;
  }
}

/**
 * Validar que todas las variables requeridas estén presentes
 */
export function validateEnvironment(): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  // Variables requeridas
  const required = [
    'JWT_SECRET'
  ];
  
  for (const variable of required) {
    if (!process.env[variable]) {
      errors.push(`Variable de entorno requerida: ${variable}`);
    }
  }
  
  // Validaciones específicas
  if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
    errors.push('JWT_SECRET debe tener al menos 32 caracteres');
  }
  
  if (process.env.PASSWORD_HASH_ALGORITHM) {
    const validAlgorithms = ['argon2id', 'argon2i', 'argon2d', 'scrypt', 'bcrypt'];
    if (!validAlgorithms.includes(process.env.PASSWORD_HASH_ALGORITHM)) {
      errors.push('PASSWORD_HASH_ALGORITHM debe ser uno de: ' + validAlgorithms.join(', '));
    }
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}
```

### 3. Inicialización de la Aplicación

Crea `src/app.ts`:

```typescript
// src/app.ts
import { initializeAuth, AuthLibrary } from '@open-bauth/core';
import { getAuthConfig, validateEnvironment } from './config/auth.config';

/**
 * Inicializar la aplicación con autenticación
 */
export async function initializeApp(): Promise<AuthLibrary> {
  try {
    // Validar variables de entorno
    const envValidation = validateEnvironment();
    if (!envValidation.valid) {
      console.error('❌ Errores en variables de entorno:');
      envValidation.errors.forEach(error => console.error(`  - ${error}`));
      process.exit(1);
    }
    
    // Obtener configuración
    const config = getAuthConfig();
    
    // Inicializar librería de autenticación
    console.log('🔧 Inicializando librería de autenticación...');
    const authLib = await initializeAuth(config);
    
    console.log('✅ Librería de autenticación inicializada correctamente');
    console.log(`📊 Entorno: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🗄️  Base de datos: ${config.database?.path}`);
    
    return authLib;
    
  } catch (error) {
    console.error('❌ Error inicializando la aplicación:', error);
    process.exit(1);
  }
}

/**
 * Cerrar la aplicación correctamente
 */
export async function closeApp(authLib: AuthLibrary): Promise<void> {
  try {
    await authLib.close();
    console.log('✅ Aplicación cerrada correctamente');
  } catch (error) {
    console.error('❌ Error cerrando la aplicación:', error);
  }
}

// Manejar señales de cierre
process.on('SIGINT', async () => {
  console.log('\n🛑 Recibida señal SIGINT, cerrando aplicación...');
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n🛑 Recibida señal SIGTERM, cerrando aplicación...');
  process.exit(0);
});
```

## 🔧 Configuración por Framework

### Hono

```typescript
// src/server-hono.ts
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { createHonoAuth } from '@open-bauth/core';
import { initializeApp } from './app';

const app = new Hono();

// Inicializar autenticación
const authLib = await initializeApp();
const auth = createHonoAuth();

// Middleware global
app.use('*', logger());
app.use('*', cors());
app.use('*', auth.middleware);

// Rutas de autenticación
app.post('/auth/register', async (c) => {
  // Implementación de registro
});

app.post('/auth/login', async (c) => {
  // Implementación de login
});

// Rutas protegidas
app.get('/profile', auth.required, async (c) => {
  // Ruta que requiere autenticación
});

export default app;
```

### Express

```typescript
// src/server-express.ts
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createExpressAuth } from '@open-bauth/core';
import { initializeApp } from './app';

const app = express();

// Inicializar autenticación
const authLib = await initializeApp();
const auth = createExpressAuth();

// Middleware global
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(auth.middleware);

// Rutas de autenticación
app.post('/auth/register', async (req, res) => {
  // Implementación de registro
});

app.post('/auth/login', async (req, res) => {
  // Implementación de login
});

// Rutas protegidas
app.get('/profile', auth.required, async (req, res) => {
  // Ruta que requiere autenticación
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor Express corriendo en puerto ${PORT}`);
});
```

## 📁 Estructura de Proyecto Recomendada

```
mi-proyecto/
├── src/
│   ├── config/
│   │   ├── auth.config.ts
│   │   └── database.config.ts
│   ├── middleware/
│   │   ├── auth.middleware.ts
│   │   └── validation.middleware.ts
│   ├── routes/
│   │   ├── auth.routes.ts
│   │   ├── user.routes.ts
│   │   └── admin.routes.ts
│   ├── services/
│   │   ├── user.service.ts
│   │   └── email.service.ts
│   ├── types/
│   │   └── custom.types.ts
│   ├── utils/
│   │   └── helpers.ts
│   ├── app.ts
│   └── server.ts
├── tests/
│   ├── integration/
│   ├── unit/
│   └── setup.ts
├── docs/
├── logs/
├── .env
├── .env.example
├── .gitignore
├── package.json
├── tsconfig.json
└── README.md
```

## 🧪 Verificar la Instalación

### Script de Verificación

Crea `scripts/verify-installation.ts`:

```typescript
// scripts/verify-installation.ts
import { initializeAuth } from '@open-bauth/core';
import { getAuthConfig } from '../src/config/auth.config';

async function verifyInstallation() {
  try {
    console.log('🔍 Verificando instalación...');
    
    // Verificar configuración
    const config = getAuthConfig();
    console.log('✅ Configuración cargada correctamente');
    
    // Inicializar librería
    const authLib = await initializeAuth(config);
    console.log('✅ Librería inicializada correctamente');
    
    // Verificar servicios
    const authService = authLib.getAuthService();
    const jwtService = authLib.getJWTService();
    const permissionService = authLib.getPermissionService();
    
    console.log('✅ Servicios disponibles:');
    console.log('  - AuthService');
    console.log('  - JWTService');
    console.log('  - PermissionService');
    
    // Verificar base de datos
    await authLib.checkStatus();
    console.log('✅ Base de datos funcionando correctamente');
    
    // Cerrar conexiones
    await authLib.close();
    
    console.log('\n🎉 ¡Instalación verificada exitosamente!');
    
  } catch (error) {
    console.error('❌ Error en la verificación:', error);
    process.exit(1);
  }
}

verifyInstallation();
```

### Ejecutar Verificación

```bash
# Con Bun
bun run scripts/verify-installation.ts

# Con Node.js
npx tsx scripts/verify-installation.ts
```

## 🐳 Configuración con Docker

### Dockerfile

```dockerfile
# Dockerfile
FROM oven/bun:1.0-alpine

WORKDIR /app

# Copiar archivos de dependencias
COPY package.json bun.lockb ./

# Instalar dependencias
RUN bun install --frozen-lockfile

# Copiar código fuente
COPY . .

# Compilar TypeScript
RUN bun run build

# Exponer puerto
EXPOSE 3000

# Comando de inicio
CMD ["bun", "run", "start"]
```

### docker-compose.yml

```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - JWT_SECRET=your-production-secret
      - DATABASE_PATH=/app/data/auth.db
    volumes:
      - ./data:/app/data
    restart: unless-stopped
```

## 🔧 Scripts de Package.json

```json
{
  "scripts": {
    "dev": "bun run --watch src/server.ts",
    "build": "bun build src/server.ts --outdir ./dist",
    "start": "bun run dist/server.js",
    "test": "bun test",
    "test:watch": "bun test --watch",
    "migrate": "bun run src/scripts/migrate.ts",
    "seed": "bun run src/scripts/seed.ts",
    "reset-db": "bun run src/scripts/reset.ts",
    "verify": "bun run scripts/verify-installation.ts",
    "lint": "eslint src/**/*.ts",
    "format": "prettier --write src/**/*.ts"
  }
}
```

## 🚨 Problemas Comunes

### Error: "Cannot find module '@open-bauth/core'"

```bash
# Reinstalar dependencias
bun install
# o
npm install
```

### Error: "JWT_SECRET is required"

```bash
# Verificar archivo .env
echo $JWT_SECRET

# Generar nuevo secret
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### Error: "Database locked"

```bash
# Verificar permisos del archivo de base de datos
ls -la auth.db

# Cambiar permisos si es necesario
chmod 664 auth.db
```

## 📚 Próximos Pasos

Ahora que tienes la instalación completa:

1. **[Clase AuthLibrary](./03-auth-library.md)** - Explora la clase principal
2. **[Servicios Principales](./04-services.md)** - Aprende sobre los servicios
3. **[Ejemplos Prácticos](./07-examples.md)** - Ve implementaciones completas

---

[⬅️ Inicio Rápido](./01-quick-start.md) | [🏠 Índice](./README.md) | [➡️ Clase AuthLibrary](./03-auth-library.md)