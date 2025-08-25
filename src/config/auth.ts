// src/config/auth.ts
import type { AuthConfig, SecurityConfig } from '../types/auth';

/**
 * Configuración por defecto para la librería de autenticación
 */
export const DEFAULT_AUTH_CONFIG: AuthConfig = {
  jwtSecret: process.env.JWT_SECRET || 'change-this-secret-in-production',
  jwtExpiration: process.env.JWT_EXPIRATION || '1h',
  refreshTokenExpiration: process.env.REFRESH_TOKEN_EXPIRATION || '7d',
  
  // Configuración de base de datos
  database: {
    path: process.env.DATABASE_PATH || './auth.db',
    enableWAL: process.env.DATABASE_WAL === 'true',
    enableForeignKeys: true,
    busyTimeout: 5000
  },
  
  // Configuración de seguridad
  security: {
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS || '12'),
    maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5'),
    lockoutDuration: parseInt(process.env.LOCKOUT_DURATION || '900000'), // 15 minutos
    sessionTimeout: parseInt(process.env.SESSION_TIMEOUT || '3600000'), // 1 hora
    requireEmailVerification: process.env.REQUIRE_EMAIL_VERIFICATION === 'true',
    allowMultipleSessions: process.env.ALLOW_MULTIPLE_SESSIONS !== 'false',
    passwordMinLength: parseInt(process.env.PASSWORD_MIN_LENGTH || '8'),
    passwordRequireUppercase: process.env.PASSWORD_REQUIRE_UPPERCASE !== 'false',
    passwordRequireLowercase: process.env.PASSWORD_REQUIRE_LOWERCASE !== 'false',
    passwordRequireNumbers: process.env.PASSWORD_REQUIRE_NUMBERS !== 'false',
    passwordRequireSymbols: process.env.PASSWORD_REQUIRE_SYMBOLS !== 'false'
  },
  
  // Configuración de CORS
  cors: {
    origins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    headers: ['Content-Type', 'Authorization']
  },
  
  // Configuración de rate limiting
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || '900000'), // 15 minutos
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX || '100'),
    skipSuccessfulRequests: false,
    skipFailedRequests: false
  },
  
  // Configuración de logging
  logging: {
    level: (process.env.LOG_LEVEL as 'debug' | 'info' | 'warn' | 'error') || 'info',
    enableConsole: process.env.LOG_CONSOLE !== 'false',
    enableFile: process.env.LOG_FILE === 'true',
    filePath: process.env.LOG_FILE_PATH || './logs/auth.log',
    enableDatabase: process.env.LOG_DATABASE === 'true'
  }
};

/**
 * Configuración de seguridad avanzada
 */
export const SECURITY_CONFIG: SecurityConfig = {
  // Configuración de headers de seguridad
  securityHeaders: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  },
  
  // Configuración de cookies
  cookies: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict' as const,
    maxAge: 24 * 60 * 60 * 1000 // 24 horas
  },
  
  // Configuración de validación de entrada
  validation: {
    maxEmailLength: 254,
    maxNameLength: 100,
    maxPasswordLength: 128,
    allowedEmailDomains: process.env.ALLOWED_EMAIL_DOMAINS?.split(','),
    blockedEmailDomains: process.env.BLOCKED_EMAIL_DOMAINS?.split(',') || [
      'tempmail.org',
      '10minutemail.com',
      'guerrillamail.com'
    ]
  },
  
  // Configuración de IP y geolocalización
  ipSecurity: {
    enableGeoBlocking: process.env.ENABLE_GEO_BLOCKING === 'true',
    blockedCountries: process.env.BLOCKED_COUNTRIES?.split(',') || [],
    enableIPWhitelist: process.env.ENABLE_IP_WHITELIST === 'true',
    ipWhitelist: process.env.IP_WHITELIST?.split(',') || [],
    enableIPBlacklist: process.env.ENABLE_IP_BLACKLIST === 'true',
    ipBlacklist: process.env.IP_BLACKLIST?.split(',') || []
  }
};

/**
 * Configuración de desarrollo
 */
export const DEV_CONFIG: Partial<AuthConfig> = {
  jwtSecret: 'dev-secret-key-not-for-production',
  jwtExpiration: '24h',
  refreshTokenExpiration: '30d',
  
  security: {
    bcryptRounds: 4, // Más rápido para desarrollo
    maxLoginAttempts: 10,
    lockoutDuration: 60000, // 1 minuto
    sessionTimeout: 24 * 60 * 60 * 1000, // 24 horas
    requireEmailVerification: false,
    allowMultipleSessions: true,
    passwordMinLength: 6,
    passwordRequireUppercase: false,
    passwordRequireLowercase: false,
    passwordRequireNumbers: false,
    passwordRequireSymbols: false
  },
  
  logging: {
    level: 'debug',
    enableConsole: true,
    enableFile: false,
    filePath: './logs/auth.log',
    enableDatabase: false
  }
};

/**
 * Configuración de producción
 */
export const PROD_CONFIG: Partial<AuthConfig> = {
  security: {
    bcryptRounds: 14, // Más seguro para producción
    maxLoginAttempts: 3,
    lockoutDuration: 30 * 60 * 1000, // 30 minutos
    sessionTimeout: 60 * 60 * 1000, // 1 hora
    requireEmailVerification: true,
    allowMultipleSessions: false,
    passwordMinLength: 12,
    passwordRequireUppercase: true,
    passwordRequireLowercase: true,
    passwordRequireNumbers: true,
    passwordRequireSymbols: true
  },
  
  logging: {
    level: 'warn',
    enableConsole: false,
    enableFile: true,
    filePath: './logs/auth.log',
    enableDatabase: true
  }
};

/**
 * Función para obtener la configuración según el entorno
 */
export function getAuthConfig(environment?: string): AuthConfig {
  const env = environment || process.env.NODE_ENV || 'development';
  
  let config = { ...DEFAULT_AUTH_CONFIG };
  
  switch (env) {
    case 'development':
      config = mergeConfig(config, DEV_CONFIG);
      break;
    case 'production':
      config = mergeConfig(config, PROD_CONFIG);
      break;
    case 'test':
      config = mergeConfig(config, {
        database: { 
          path: ':memory:',
          enableWAL: false,
          enableForeignKeys: true,
          busyTimeout: 5000
        },
        logging: { 
          level: 'error', 
          enableConsole: false,
          enableFile: false,
          filePath: './logs/auth.log',
          enableDatabase: false
        }
      });
      break;
  }
  
  return config;
}

/**
 * Función para validar la configuración
 */
export function validateAuthConfig(config: AuthConfig): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  // Validar JWT secret
  if (!config.jwtSecret || config.jwtSecret === 'change-this-secret-in-production') {
    if (process.env.NODE_ENV === 'production') {
      errors.push('JWT secret debe ser configurado en producción');
    }
  }
  
  if (config.jwtSecret && config.jwtSecret.length < 32) {
    errors.push('JWT secret debe tener al menos 32 caracteres');
  }
  
  // Validar configuración de base de datos
  if (!config.database?.path) {
    errors.push('Ruta de base de datos es requerida');
  }
  
  // Validar configuración de seguridad
  if (config.security) {
    if (config.security.bcryptRounds < 4 || config.security.bcryptRounds > 20) {
      errors.push('bcryptRounds debe estar entre 4 y 20');
    }
    
    if (config.security.passwordMinLength < 6) {
      errors.push('passwordMinLength debe ser al menos 6');
    }
    
    if (config.security.maxLoginAttempts < 1) {
      errors.push('maxLoginAttempts debe ser al menos 1');
    }
  }
  
  // Validar CORS
  if (config.cors?.origins && config.cors.origins.length === 0) {
    errors.push('Al menos un origen CORS debe ser especificado');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Función para obtener variables de entorno requeridas
 */
export function getRequiredEnvVars(): { [key: string]: string | undefined } {
  return {
    JWT_SECRET: process.env.JWT_SECRET,
    DATABASE_PATH: process.env.DATABASE_PATH,
    NODE_ENV: process.env.NODE_ENV,
    BCRYPT_ROUNDS: process.env.BCRYPT_ROUNDS,
    MAX_LOGIN_ATTEMPTS: process.env.MAX_LOGIN_ATTEMPTS,
    CORS_ORIGINS: process.env.CORS_ORIGINS
  };
}

/**
 * Función para generar un archivo .env de ejemplo
 */
export function generateEnvExample(): string {
  return `# Configuración de Autenticación

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRATION=1h
REFRESH_TOKEN_EXPIRATION=7d

# Database Configuration
DATABASE_PATH=./auth.db
DATABASE_WAL=true

# Security Configuration
BCRYPT_ROUNDS=12
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=900000
SESSION_TIMEOUT=3600000
REQUIRE_EMAIL_VERIFICATION=false
ALLOW_MULTIPLE_SESSIONS=true

# Password Policy
PASSWORD_MIN_LENGTH=8
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_SYMBOLS=true

# CORS Configuration
CORS_ORIGINS=http://localhost:3000,http://localhost:3001

# Rate Limiting
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100

# Logging
LOG_LEVEL=info
LOG_CONSOLE=true
LOG_FILE=false
LOG_FILE_PATH=./logs/auth.log
LOG_DATABASE=false

# Email Validation
ALLOWED_EMAIL_DOMAINS=
BLOCKED_EMAIL_DOMAINS=tempmail.org,10minutemail.com

# IP Security
ENABLE_GEO_BLOCKING=false
BLOCKED_COUNTRIES=
ENABLE_IP_WHITELIST=false
IP_WHITELIST=
ENABLE_IP_BLACKLIST=false
IP_BLACKLIST=

# Environment
NODE_ENV=development
`;
}

/**
 * Función helper para mergear configuraciones
 */
function mergeConfig(base: AuthConfig, override: Partial<AuthConfig>): AuthConfig {
  const result = { ...base };
  
  Object.keys(override).forEach(key => {
    const value = override[key as keyof AuthConfig];
    if (value !== undefined) {
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        const baseValue = result[key as keyof AuthConfig];
        if (typeof baseValue === 'object' && baseValue !== null && !Array.isArray(baseValue)) {
          result[key as keyof AuthConfig] = {
            ...baseValue,
            ...value
          } as any;
        } else {
          result[key as keyof AuthConfig] = value as any;
        }
      } else {
        result[key as keyof AuthConfig] = value as any;
      }
    }
  });
  
  return result;
}

/**
 * Función para imprimir la configuración actual (sin secretos)
 */
export function printConfig(config: AuthConfig): void {
  const safeConfig = { ...config };
  
  // Ocultar información sensible
  if (safeConfig.jwtSecret) {
    safeConfig.jwtSecret = '***HIDDEN***';
  }
  
  console.log('🔧 Configuración de autenticación:');
  console.log(JSON.stringify(safeConfig, null, 2));
}

/**
 * Exportar configuración por defecto
 */
export default getAuthConfig();