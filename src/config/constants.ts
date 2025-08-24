// src/config/constants.ts

/**
 * Authentication configuration constants
 */
export const AUTH_CONFIG = {
  // Password settings
  PASSWORD: {
    MIN_LENGTH: 8,
    MAX_LENGTH: 128,
    BCRYPT_ROUNDS: 12,
    STRENGTH_REGEX: /(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
    REQUIRE_SPECIAL_CHARS: false,
    SPECIAL_CHARS_REGEX: /[!@#$%^&*(),.?":{}|<>]/
  },
  
  // Email settings
  EMAIL: {
    MAX_LENGTH: 254,
    VALIDATION_REGEX: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    NORMALIZE_CASE: true
  },
  
  // Name settings
  NAME: {
    MAX_LENGTH: 50,
    MIN_LENGTH: 1,
    VALIDATION_REGEX: /^[a-zA-Z\s'-]+$/,
    ALLOW_EMPTY: true
  },
  
  // User ID settings
  USER_ID: {
    FORMAT: 'UUID',
    UUID_REGEX: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
  },
  
  // Role settings
  ROLE: {
    MAX_LENGTH: 50,
    MIN_LENGTH: 1,
    VALIDATION_REGEX: /^[a-zA-Z0-9_-]+$/,
    DEFAULT_ROLE: 'user',
    NORMALIZE_CASE: true
  },
  
  // Session settings
  SESSION: {
    MAX_CONCURRENT_SESSIONS: 5,
    CLEANUP_INTERVAL_MS: 60 * 60 * 1000, // 1 hour
    EXTEND_ON_ACTIVITY: true
  },
  
  // Rate limiting
  RATE_LIMIT: {
    LOGIN: {
      MAX_ATTEMPTS: 5,
      WINDOW_MS: 15 * 60 * 1000, // 15 minutes
      BLOCK_DURATION_MS: 30 * 60 * 1000 // 30 minutes
    },
    REGISTER: {
      MAX_ATTEMPTS: 3,
      WINDOW_MS: 60 * 60 * 1000, // 1 hour
      BLOCK_DURATION_MS: 60 * 60 * 1000 // 1 hour
    },
    PASSWORD_RESET: {
      MAX_ATTEMPTS: 3,
      WINDOW_MS: 60 * 60 * 1000, // 1 hour
      BLOCK_DURATION_MS: 60 * 60 * 1000 // 1 hour
    },
    GENERAL: {
      MAX_ATTEMPTS: 1000,
      WINDOW_MS: 15 * 60 * 1000, // 15 minutes
      BLOCK_DURATION_MS: 15 * 60 * 1000 // 15 minutes
    },
    USER_MODIFICATION: {
      MAX_ATTEMPTS: 10,
      WINDOW_MS: 60 * 60 * 1000, // 1 hour
      BLOCK_DURATION_MS: 60 * 60 * 1000 // 1 hour
    }
  },
  
  // Security settings
  SECURITY: {
    HASH_ALGORITHM: 'bcrypt' as const,
    SALT_ROUNDS: 12,
    SECURE_HEADERS: true,
    AUDIT_LOGGING: true,
    INPUT_SANITIZATION: true,
    XSS_PROTECTION: true
  },
  
  // Database settings
  DATABASE: {
    CONNECTION_TIMEOUT_MS: 30000,
    QUERY_TIMEOUT_MS: 10000,
    MAX_RETRIES: 3,
    RETRY_DELAY_MS: 1000
  },
  
  // Pagination settings
  PAGINATION: {
    DEFAULT_PAGE: 1,
    DEFAULT_LIMIT: 10,
    MAX_LIMIT: 100,
    MIN_LIMIT: 1
  },
  
  // Validation messages
  VALIDATION_MESSAGES: {
    EMAIL_REQUIRED: 'Email is required',
    EMAIL_INVALID: 'Invalid email format',
    PASSWORD_REQUIRED: 'Password is required',
    PASSWORD_TOO_SHORT: 'Password must be at least {min} characters long',
    PASSWORD_TOO_LONG: 'Password must not exceed {max} characters',
    PASSWORD_WEAK: 'Password must contain at least one uppercase letter, one lowercase letter, and one number',
    NAME_TOO_LONG: '{field} must not exceed {max} characters',
    NAME_INVALID_CHARS: '{field} contains invalid characters',
    USER_ID_REQUIRED: 'User ID is required',
    USER_ID_INVALID: 'Invalid user ID format',
    ROLE_NAME_REQUIRED: 'Role name is required',
    ROLE_NAME_INVALID: 'Role name contains invalid characters',
    ROLE_NAME_TOO_LONG: 'Role name must not exceed {max} characters'
  },
  
  // Error messages
  ERROR_MESSAGES: {
    USER_NOT_FOUND: 'User not found',
    USER_EXISTS: 'User already exists with this email',
    INVALID_CREDENTIALS: 'Invalid credentials',
    ACCOUNT_INACTIVE: 'Account is inactive',
    ROLE_NOT_FOUND: 'Role not found',
    ROLE_ALREADY_ASSIGNED: 'User already has this role',
    PERMISSION_DENIED: 'Permission denied',
    RATE_LIMIT_EXCEEDED: 'Rate limit exceeded. Please try again later',
    SERVER_ERROR: 'Internal server error',
    DATABASE_ERROR: 'Database operation failed',
    VALIDATION_ERROR: 'Validation failed'
  },
  
  // Success messages
  SUCCESS_MESSAGES: {
    USER_REGISTERED: 'User registered successfully',
    USER_LOGGED_IN: 'User logged in successfully',
    USER_UPDATED: 'User updated successfully',
    USER_DELETED: 'User deleted successfully',
    PASSWORD_UPDATED: 'Password updated successfully',
    ROLE_ASSIGNED: 'Role assigned successfully',
    ROLE_REMOVED: 'Role removed successfully'
  }
} as const;

/**
 * Environment-specific configuration
 */
export const ENV_CONFIG = {
  DEVELOPMENT: {
    LOG_LEVEL: 'debug',
    DETAILED_ERRORS: true,
    RATE_LIMITING_ENABLED: false,
    AUDIT_LOGGING: false
  },
  PRODUCTION: {
    LOG_LEVEL: 'error',
    DETAILED_ERRORS: false,
    RATE_LIMITING_ENABLED: true,
    AUDIT_LOGGING: true
  },
  TEST: {
    LOG_LEVEL: 'silent',
    DETAILED_ERRORS: true,
    RATE_LIMITING_ENABLED: false,
    AUDIT_LOGGING: false
  }
} as const;

/**
 * Get current environment configuration
 */
export function getEnvConfig() {
  const env = process.env.NODE_ENV as keyof typeof ENV_CONFIG || 'DEVELOPMENT';
  return ENV_CONFIG[env] || ENV_CONFIG.DEVELOPMENT;
}

/**
 * Utility function to format validation messages
 */
export function formatValidationMessage(template: string, params: Record<string, any>): string {
  return template.replace(/\{(\w+)\}/g, (match, key) => {
    return params[key]?.toString() || match;
  });
}

/**
 * Type definitions for configuration
 */
export type AuthConfig = typeof AUTH_CONFIG;
export type EnvConfig = typeof ENV_CONFIG;
export type ValidationMessages = typeof AUTH_CONFIG.VALIDATION_MESSAGES;
export type ErrorMessages = typeof AUTH_CONFIG.ERROR_MESSAGES;
export type SuccessMessages = typeof AUTH_CONFIG.SUCCESS_MESSAGES;