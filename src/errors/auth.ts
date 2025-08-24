// src/errors/auth.ts
import { AuthErrorType } from '../types/auth';

/**
 * Base authentication error class
 */
export abstract class AuthError extends Error {
  public abstract readonly type: AuthErrorType;
  public readonly timestamp: Date;
  public readonly context?: Record<string, any>;
  
  constructor(message: string, context?: Record<string, any>) {
    super(message);
    this.name = this.constructor.name;
    this.timestamp = new Date();
    this.context = context;
    
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, new.target.prototype);
  }
  
  /**
   * Convert error to API response format
   */
  toResponse(): {
    success: false;
    error: {
      type: AuthErrorType;
      message: string;
      timestamp: string;
      context?: Record<string, any>;
    };
  } {
    return {
      success: false as const,
      error: {
        type: this.type,
        message: this.message,
        timestamp: this.timestamp.toISOString(),
        ...(this.context && { context: this.context })
      }
    };
  }
}

/**
 * Validation error - for input validation failures
 */
export class ValidationError extends AuthError {
  public readonly type: AuthErrorType = AuthErrorType.VALIDATION_ERROR;
  
  constructor(message: string, field?: string) {
    super(message, field ? { field } : undefined);
  }
}

/**
 * Authentication error - for login/credential failures
 */
export class AuthenticationError extends AuthError {
  public readonly type: AuthErrorType = AuthErrorType.AUTHENTICATION_ERROR;
  
  constructor(message: string = 'Authentication failed', context?: Record<string, any>) {
    super(message, context);
  }
}

/**
 * Authorization error - for permission/access failures
 */
export class AuthorizationError extends AuthError {
  public readonly type: AuthErrorType = AuthErrorType.AUTHORIZATION_ERROR;
  
  constructor(message: string = 'Access denied', context?: Record<string, any>) {
    super(message, context);
  }
}

/**
 * User not found error
 */
export class UserNotFoundError extends AuthError {
  public readonly type: AuthErrorType = AuthErrorType.USER_NOT_FOUND;
  
  constructor(identifier?: string) {
    const message = identifier 
      ? `User not found: ${identifier}`
      : 'User not found';
    super(message, identifier ? { identifier } : undefined);
  }
}

/**
 * Resource not found error
 */
export class NotFoundError extends AuthError {
  public readonly type: AuthErrorType = AuthErrorType.NOT_FOUND_ERROR;
  
  constructor(resource: string, identifier?: string) {
    const message = identifier 
      ? `${resource} not found: ${identifier}`
      : `${resource} not found`;
    super(message, { resource, identifier });
  }
}

/**
 * Database operation error
 */
export class DatabaseError extends AuthError {
  public readonly type: AuthErrorType = AuthErrorType.DATABASE_ERROR;
  
  constructor(message: string = 'Database operation failed', operation?: string) {
    super(message, operation ? { operation } : undefined);
  }
}

/**
 * Server/internal error
 */
export class ServerError extends AuthError {
  public readonly type: AuthErrorType = AuthErrorType.SERVER_ERROR;
  
  constructor(message: string = 'Internal server error', context?: Record<string, any>) {
    super(message, context);
  }
}

/**
 * Rate limiting error
 */
export class RateLimitError extends AuthError {
  public readonly type: AuthErrorType = AuthErrorType.RATE_LIMIT_ERROR;
  public readonly retryAfter?: number;
  
  constructor(message: string = 'Rate limit exceeded', retryAfter?: number) {
    super(message, retryAfter ? { retryAfter } : undefined);
    this.retryAfter = retryAfter;
  }
}

/**
 * Token-related errors
 */
export class TokenError extends AuthError {
  public readonly type: AuthErrorType = AuthErrorType.TOKEN_ERROR;
  
  constructor(message: string = 'Token error', context?: Record<string, any>) {
    super(message, context);
  }
}

/**
 * Account status errors
 */
export class AccountError extends AuthError {
  public readonly type: AuthErrorType = AuthErrorType.ACCOUNT_ERROR;
  
  constructor(message: string, status?: string) {
    super(message, status ? { status } : undefined);
  }
}

/**
 * Error factory for creating appropriate error instances
 */
export class AuthErrorFactory {
  /**
   * Create error from unknown error object
   */
  static fromUnknown(error: unknown, defaultMessage: string = 'Unknown error'): AuthError {
    if (error instanceof AuthError) {
      return error;
    }
    
    if (error instanceof Error) {
      // Try to map common error patterns
      const message = error.message.toLowerCase();
      
      if (message.includes('user not found') || message.includes('user does not exist')) {
        return new UserNotFoundError();
      }
      
      if (message.includes('invalid credentials') || message.includes('authentication')) {
        return new AuthenticationError(error.message);
      }
      
      if (message.includes('validation') || message.includes('invalid') || 
          message.includes('required') || message.includes('must be') || 
          message.includes('cannot be') || message.includes('contains') ||
          message.includes('format') || message.includes('characters long') ||
          message.includes('email') && (message.includes('format') || message.includes('invalid'))) {
        return new ValidationError(error.message);
      }
      
      if (message.includes('database') || message.includes('sql')) {
        return new DatabaseError(error.message);
      }
      
      // Default to server error for unknown Error instances
      return new ServerError(error.message);
    }
    
    // For non-Error objects, create a server error
    return new ServerError(defaultMessage, { originalError: String(error) });
  }
  
  /**
   * Create validation error with field context
   */
  static validation(message: string, field?: string): ValidationError {
    return new ValidationError(message, field);
  }
  
  /**
   * Create authentication error
   */
  static authentication(message?: string): AuthenticationError {
    return new AuthenticationError(message);
  }
  
  /**
   * Create user not found error
   */
  static userNotFound(identifier?: string): UserNotFoundError {
    return new UserNotFoundError(identifier);
  }
  
  /**
   * Create database error
   */
  static database(message?: string, operation?: string): DatabaseError {
    return new DatabaseError(message, operation);
  }
  
  /**
   * Create rate limit error
   */
  static rateLimit(message?: string, retryAfter?: number): RateLimitError {
    return new RateLimitError(message, retryAfter);
  }
  
  /**
   * Create server error
   */
  static server(message?: string, context?: Record<string, any>): ServerError {
    return new ServerError(message, context);
  }
}

/**
 * Error handler utility for consistent error processing
 */
export class ErrorHandler {
  /**
   * Process and normalize errors for API responses
   */
  static handle(error: unknown, operation: string = 'operation'): {
    success: false;
    error: {
      type: AuthErrorType;
      message: string;
      timestamp: string;
      context?: Record<string, any>;
    };
  } {
    const authError = AuthErrorFactory.fromUnknown(error, `${operation} failed`);
    
    // Log error for debugging (in production, use proper logging)
    console.error(`[${operation}] ${authError.type}: ${authError.message}`, {
      stack: authError.stack,
      context: authError.context,
      timestamp: authError.timestamp
    });
    
    return authError.toResponse();
  }
  
  /**
   * Check if error is a specific type
   */
  static isType<T extends AuthError>(error: unknown, ErrorClass: new (...args: any[]) => T): error is T {
    return error instanceof ErrorClass;
  }
  
  /**
   * Extract error message safely
   */
  static getMessage(error: unknown): string {
    if (error instanceof Error) {
      return error.message;
    }
    return String(error);
  }
}