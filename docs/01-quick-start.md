# 🚀 Guía de Inicio Rápido

¡Comienza a usar la Librería de Autenticación en menos de 5 minutos!

## 📋 Requisitos Previos

- **Bun** >= 1.1.1 (recomendado) o **Node.js** >= 18.0.0
- **TypeScript** >= 4.9.0
- Conocimientos básicos de JavaScript/TypeScript

## ⚡ Instalación Rápida

```bash
# Instalar la librería
bun add @open-bauth/core

# O con npm
npm install @open-bauth/core
```

## 🎯 Configuración Básica (2 minutos)

### 1. Crear archivo de configuración

```typescript
// auth.config.ts
import { AuthConfig } from '@open-bauth/core';

export const authConfig: Partial<AuthConfig> = {
  jwtSecret: process.env.JWT_SECRET || 'your-super-secret-key',
  jwtExpiration: '24h',
  database: {
    path: './auth.db'
  }
};
```

### 2. Inicializar la librería

```typescript
// app.ts
import { initializeAuth } from '@open-bauth/core';
import { authConfig } from './auth.config';

// Inicializar la librería
const authLib = await initializeAuth(authConfig);
console.log('✅ Auth Library inicializada');
```

## 🔧 Uso Básico con Hono (3 minutos)

```typescript
import { Hono } from 'hono';
import { 
  createHonoAuth,
  initializeAuth 
} from '@open-bauth/core';

const app = new Hono();

// Inicializar autenticación
const authLib = await initializeAuth({
  jwtSecret: 'your-secret-key',
  database: { path: './auth.db' }
});

// Crear middleware de Hono
const auth = createHonoAuth();

// Middleware global (opcional)
app.use('*', auth.middleware);

// Rutas públicas
app.post('/auth/register', async (c) => {
  const { email, password } = await c.req.json();
  
  const result = await authLib.getAuthService().register({
    email,
    password,
    firstName: 'Usuario',
    lastName: 'Nuevo'
  });
  
  if (result.success) {
    return c.json({ 
      message: 'Usuario registrado exitosamente',
      token: result.token 
    });
  }
  
  return c.json({ error: result.error?.message }, 400);
});

app.post('/auth/login', async (c) => {
  const { email, password } = await c.req.json();
  
  const result = await authLib.getAuthService().login({ email, password });
  
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

app.get('/admin/users', 
  auth.roles(['admin']), 
  async (c) => {
    const authService = authLib.getAuthService();
    const users = await authService.getUsers();
    return c.json(users);
  }
);

export default app;
```

## 🔧 Uso Básico con Express

```typescript
import express from 'express';
import { 
  createExpressAuth,
  initializeAuth 
} from '@open-bauth/core';

const app = express();
app.use(express.json());

// Inicializar autenticación
const authLib = await initializeAuth({
  jwtSecret: 'your-secret-key',
  database: { path: './auth.db' }
});

// Crear middleware de Express
const auth = createExpressAuth();

// Middleware global (opcional)
app.use(auth.middleware);

// Rutas públicas
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body;
  
  const result = await authLib.getAuthService().register({
    email,
    password,
    firstName: 'Usuario',
    lastName: 'Nuevo'
  });
  
  if (result.success) {
    res.json({ 
      message: 'Usuario registrado exitosamente',
      token: result.token 
    });
  } else {
    res.status(400).json({ error: result.error?.message });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  const result = await authLib.getAuthService().login({ email, password });
  
  if (result.success) {
    res.json({ 
      message: 'Login exitoso',
      token: result.token,
      user: result.user 
    });
  } else {
    res.status(401).json({ error: result.error?.message });
  }
});

// Rutas protegidas
app.get('/profile', auth.required, (req, res) => {
  const user = auth.getCurrentUser(req);
  res.json({ user });
});

app.get('/admin/users', 
  auth.roles(['admin']), 
  async (req, res) => {
    const authService = authLib.getAuthService();
    const users = await authService.getUsers();
    res.json(users);
  }
);

app.listen(3000, () => {
  console.log('🚀 Servidor corriendo en puerto 3000');
});
```

## 🧪 Probar la Implementación

### 1. Registrar un usuario

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "usuario@ejemplo.com",
    "password": "password123"
  }'
```

### 2. Hacer login

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "usuario@ejemplo.com",
    "password": "password123"
  }'
```

### 3. Acceder a ruta protegida

```bash
curl -X GET http://localhost:3000/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 🎯 Próximos Pasos

Ahora que tienes la configuración básica funcionando:

1. **[Configuración Avanzada](./02-installation-config.md)** - Personaliza la configuración
2. **[Servicios Principales](./04-services.md)** - Explora todas las funcionalidades
3. **[Ejemplos Prácticos](./07-examples.md)** - Ve implementaciones completas
4. **[Adaptadores de Framework](./05-framework-adapters.md)** - Integración con frameworks

## 🔍 Características que Acabas de Implementar

- ✅ **Registro de usuarios** con validación automática
- ✅ **Login seguro** con JWT
- ✅ **Rutas protegidas** con middleware
- ✅ **Autorización por roles** (admin)
- ✅ **Base de datos SQLite** automática
- ✅ **Migraciones** ejecutadas automáticamente

## 🆘 ¿Problemas?

Si encuentras algún problema:

1. **[Troubleshooting](./09-troubleshooting.md)** - Soluciones comunes
2. **[API Reference](./08-api-reference.md)** - Referencia completa
3. **[GitHub Issues](https://github.com/open-bauth/core/issues)** - Reportar bugs

## 📚 Recursos Adicionales

- **[Documentación Completa](./README.md)** - Índice principal
- **[Ejemplos en GitHub](https://github.com/open-bauth/examples)**
- **[Playground Interactivo](https://open-bauth-playground.vercel.app)**

---

**¡Felicidades! 🎉** Has implementado un sistema de autenticación completo en menos de 5 minutos.

---

[⬅️ Volver al Índice](./README.md) | [➡️ Instalación Detallada](./02-installation-config.md)