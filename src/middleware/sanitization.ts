import type { Request, Response, NextFunction } from 'express';
import { AuthErrorFactory } from '../errors/auth';

/**
 * Input sanitization configuration
 */
interface SanitizationConfig {
  // HTML sanitization
  stripHtml?: boolean;
  allowedTags?: string[];
  allowedAttributes?: Record<string, string[]>;
  
  // SQL injection protection
  preventSqlInjection?: boolean;
  
  // XSS protection
  preventXss?: boolean;
  
  // NoSQL injection protection
  preventNoSqlInjection?: boolean;
  
  // Path traversal protection
  preventPathTraversal?: boolean;
  
  // Maximum string length
  maxLength?: number;
  
  // Fields to sanitize (if not specified, all string fields are sanitized)
  fields?: string[];
  
  // Fields to skip sanitization
  skipFields?: string[];
}

/**
 * Default sanitization configuration
 */
const DEFAULT_CONFIG: Required<SanitizationConfig> = {
  stripHtml: true,
  allowedTags: [],
  allowedAttributes: {},
  preventSqlInjection: true,
  preventXss: true,
  preventNoSqlInjection: true,
  preventPathTraversal: true,
  maxLength: 10000,
  fields: [],
  skipFields: ['password', 'passwordHash', 'token']
};

/**
 * Input sanitizer class
 */
export class InputSanitizer {
  private config: Required<SanitizationConfig>;

  constructor(config: SanitizationConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Sanitize a string value
   */
  sanitizeString(value: string): string {
    if (typeof value !== 'string') {
      return value;
    }

    let sanitized = value;

    // Length check
    if (sanitized.length > this.config.maxLength) {
      throw AuthErrorFactory.validation(`Input too long. Maximum length is ${this.config.maxLength} characters`);
    }

    // HTML sanitization
    if (this.config.stripHtml) {
      sanitized = this.stripHtml(sanitized);
    }

    // XSS protection
    if (this.config.preventXss) {
      sanitized = this.preventXss(sanitized);
    }

    // SQL injection protection
    if (this.config.preventSqlInjection) {
      this.checkSqlInjection(sanitized);
    }

    // NoSQL injection protection
    if (this.config.preventNoSqlInjection) {
      this.checkNoSqlInjection(sanitized);
    }

    // Path traversal protection
    if (this.config.preventPathTraversal) {
      this.checkPathTraversal(sanitized);
    }

    return sanitized;
  }

  /**
   * Strip HTML tags from string
   */
  private stripHtml(value: string): string {
    if (this.config.allowedTags.length === 0) {
      // Strip all HTML tags
      return value.replace(/<[^>]*>/g, '');
    }
    
    // Allow specific tags (simplified implementation)
    const allowedTagsRegex = new RegExp(
      `<(?!/?(?:${this.config.allowedTags.join('|')})\\b)[^>]*>`,
      'gi'
    );
    return value.replace(allowedTagsRegex, '');
  }

  /**
   * Prevent XSS attacks
   */
  private preventXss(value: string): string {
    return value
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;')
      .replace(/`/g, '&#96;')
      .replace(/=/g, '&#61;');
  }

  /**
   * Check for SQL injection patterns
   */
  private checkSqlInjection(value: string): void {
    const sqlPatterns = [
      /('|(\-\-)|(;)|(\||\|)|(\*|\*))/i,
      /(union|select|insert|delete|update|drop|create|alter|exec|execute)/i,
      /(script|javascript|vbscript|onload|onerror|onclick)/i,
      /(or\s+1\s*=\s*1|and\s+1\s*=\s*1)/i,
      /(\bor\b.*\blike\b|\band\b.*\blike\b)/i
    ];

    for (const pattern of sqlPatterns) {
      if (pattern.test(value)) {
        throw AuthErrorFactory.validation('Potentially malicious input detected');
      }
    }
  }

  /**
   * Check for NoSQL injection patterns
   */
  private checkNoSqlInjection(value: string): void {
    const noSqlPatterns = [
      /\$where/i,
      /\$ne/i,
      /\$gt/i,
      /\$lt/i,
      /\$gte/i,
      /\$lte/i,
      /\$in/i,
      /\$nin/i,
      /\$regex/i,
      /\$exists/i,
      /\$type/i,
      /\$mod/i,
      /\$all/i,
      /\$size/i,
      /\$elemMatch/i
    ];

    for (const pattern of noSqlPatterns) {
      if (pattern.test(value)) {
        throw AuthErrorFactory.validation('Potentially malicious input detected');
      }
    }
  }

  /**
   * Check for path traversal attacks
   */
  private checkPathTraversal(value: string): void {
    const pathTraversalPatterns = [
      /\.\.\//,
      /\.\.\\/, 
      /%2e%2e%2f/i,
      /%2e%2e%5c/i,
      /\.\.%2f/i,
      /\.\.%5c/i
    ];

    for (const pattern of pathTraversalPatterns) {
      if (pattern.test(value)) {
        throw AuthErrorFactory.validation('Path traversal attempt detected');
      }
    }
  }

  /**
   * Sanitize an object recursively
   */
  sanitizeObject(obj: any): any {
    if (obj === null || obj === undefined) {
      return obj;
    }

    if (typeof obj === 'string') {
      return this.sanitizeString(obj);
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitizeObject(item));
    }

    if (typeof obj === 'object') {
      const sanitized: any = {};
      
      for (const [key, value] of Object.entries(obj)) {
        // Skip fields that shouldn't be sanitized
        if (this.config.skipFields.includes(key)) {
          sanitized[key] = value;
          continue;
        }

        // Only sanitize specified fields if fields array is provided
        if (this.config.fields.length > 0 && !this.config.fields.includes(key)) {
          sanitized[key] = value;
          continue;
        }

        sanitized[key] = this.sanitizeObject(value);
      }
      
      return sanitized;
    }

    return obj;
  }

  /**
   * Create middleware function
   */
  middleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      try {
        // Sanitize request body
        if (req.body && typeof req.body === 'object') {
          req.body = this.sanitizeObject(req.body);
        }

        // Sanitize query parameters
        if (req.query && typeof req.query === 'object') {
          req.query = this.sanitizeObject(req.query);
        }

        // Sanitize route parameters
        if (req.params && typeof req.params === 'object') {
          req.params = this.sanitizeObject(req.params);
        }

        next();
      } catch (error) {
        next(error);
      }
    };
  }
}

/**
 * Pre-configured sanitizers for different use cases
 */
export const sanitizers = {
  // Strict sanitization for authentication endpoints
  auth: new InputSanitizer({
    stripHtml: true,
    preventXss: true,
    preventSqlInjection: true,
    preventNoSqlInjection: true,
    preventPathTraversal: true,
    maxLength: 255,
    skipFields: ['password', 'passwordHash', 'token', 'refreshToken']
  }),

  // General API sanitization
  general: new InputSanitizer({
    stripHtml: true,
    preventXss: true,
    preventSqlInjection: true,
    preventNoSqlInjection: true,
    preventPathTraversal: true,
    maxLength: 5000
  }),

  // Content sanitization (allows some HTML)
  content: new InputSanitizer({
    stripHtml: false,
    allowedTags: ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li'],
    preventXss: true,
    preventSqlInjection: true,
    preventNoSqlInjection: true,
    preventPathTraversal: true,
    maxLength: 50000
  }),

  // Minimal sanitization for trusted sources
  minimal: new InputSanitizer({
    stripHtml: false,
    preventXss: false,
    preventSqlInjection: true,
    preventNoSqlInjection: true,
    preventPathTraversal: true,
    maxLength: 10000
  })
};

/**
 * Create a custom sanitizer with specific configuration
 */
export function createSanitizer(config: SanitizationConfig): InputSanitizer {
  return new InputSanitizer(config);
}

/**
 * Utility function to sanitize a single value
 */
export function sanitizeValue(value: any, config: SanitizationConfig = {}): any {
  const sanitizer = new InputSanitizer(config);
  return sanitizer.sanitizeObject(value);
}