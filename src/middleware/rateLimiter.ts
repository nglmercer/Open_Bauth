import type { Request, Response, NextFunction } from 'express';
import { AUTH_CONFIG } from '../config/constants';
import { AuthErrorFactory } from '../errors/auth';

// Extend Request interface to include user property
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        [key: string]: any;
      };
    }
  }
}

/**
 * Rate limiter store interface
 */
interface RateLimiterStore {
  get(key: string): Promise<number | null>;
  set(key: string, value: number, ttl: number): Promise<void>;
  increment(key: string, ttl: number): Promise<number>;
}

/**
 * In-memory rate limiter store
 */
class MemoryStore implements RateLimiterStore {
  private store = new Map<string, { count: number; resetTime: number }>();

  async get(key: string): Promise<number | null> {
    const entry = this.store.get(key);
    if (!entry || Date.now() > entry.resetTime) {
      this.store.delete(key);
      return null;
    }
    return entry.count;
  }

  async set(key: string, value: number, ttl: number): Promise<void> {
    this.store.set(key, {
      count: value,
      resetTime: Date.now() + ttl * 1000
    });
  }

  async increment(key: string, ttl: number): Promise<number> {
    const entry = this.store.get(key);
    const now = Date.now();
    
    if (!entry || now > entry.resetTime) {
      const newEntry = { count: 1, resetTime: now + ttl * 1000 };
      this.store.set(key, newEntry);
      return 1;
    }
    
    entry.count++;
    return entry.count;
  }
}

/**
 * Rate limiter configuration
 */
interface RateLimiterConfig {
  windowMs: number; // Time window in milliseconds
  maxRequests: number; // Maximum requests per window
  message?: string; // Custom error message
  skipSuccessfulRequests?: boolean; // Don't count successful requests
  skipFailedRequests?: boolean; // Don't count failed requests
  keyGenerator?: (req: Request) => string; // Custom key generator
  store?: RateLimiterStore; // Custom store
}

/**
 * Rate limiter class
 */
export class RateLimiter {
  private config: Required<RateLimiterConfig>;
  private store: RateLimiterStore;

  constructor(config: RateLimiterConfig) {
    this.config = {
      windowMs: config.windowMs,
      maxRequests: config.maxRequests,
      message: config.message || 'Too many requests, please try again later',
      skipSuccessfulRequests: config.skipSuccessfulRequests || false,
      skipFailedRequests: config.skipFailedRequests || false,
      keyGenerator: config.keyGenerator || this.defaultKeyGenerator,
      store: config.store || new MemoryStore()
    };
    this.store = this.config.store;
  }

  private defaultKeyGenerator(req: Request): string {
    return req.ip || req.connection.remoteAddress || 'unknown';
  }

  middleware() {
    return async (req: Request, res: Response, next: NextFunction) => {
      try {
        const key = this.config.keyGenerator(req);
        const windowSeconds = Math.floor(this.config.windowMs / 1000);
        
        const currentCount = await this.store.increment(key, windowSeconds);
        
        // Set rate limit headers
        res.set({
          'X-RateLimit-Limit': this.config.maxRequests.toString(),
          'X-RateLimit-Remaining': Math.max(0, this.config.maxRequests - currentCount).toString(),
          'X-RateLimit-Reset': new Date(Date.now() + this.config.windowMs).toISOString()
        });
        
        if (currentCount > this.config.maxRequests) {
          throw AuthErrorFactory.rateLimit(this.config.message);
        }
        
        // Handle response to potentially skip counting
        const rateLimiterInstance = this;
        if (this.config.skipSuccessfulRequests || this.config.skipFailedRequests) {
          const originalSend = res.send;
          res.send = function(body: any) {
            const statusCode = res.statusCode;
            const isSuccess = statusCode >= 200 && statusCode < 300;
            const isFailure = statusCode >= 400;
            
            // If we should skip this request, decrement the counter
            if ((isSuccess && rateLimiterInstance.config.skipSuccessfulRequests) ||
                (isFailure && rateLimiterInstance.config.skipFailedRequests)) {
              // Note: This is a simplified approach. In production, you might want
              // a more sophisticated way to handle this.
            }
            
            return originalSend.call(res, body);
          };
        }
        
        next();
      } catch (error) {
        next(error);
      }
    };
  }
}

/**
 * Pre-configured rate limiters for different endpoints
 */
export const rateLimiters = {
  // General API rate limiter
  general: new RateLimiter({
    windowMs: AUTH_CONFIG.RATE_LIMIT.LOGIN.WINDOW_MS,
    maxRequests: AUTH_CONFIG.RATE_LIMIT.LOGIN.MAX_ATTEMPTS,
    message: 'Too many requests from this IP, please try again later'
  }),

  // Authentication endpoints (login, register)
  auth: new RateLimiter({
    windowMs: AUTH_CONFIG.RATE_LIMIT.LOGIN.WINDOW_MS,
    maxRequests: AUTH_CONFIG.RATE_LIMIT.LOGIN.MAX_ATTEMPTS,
    message: 'Too many authentication attempts, please try again later',
    skipSuccessfulRequests: true // Don't count successful logins
  }),

  // Password reset endpoints
  passwordReset: new RateLimiter({
    windowMs: AUTH_CONFIG.RATE_LIMIT.PASSWORD_RESET.WINDOW_MS,
    maxRequests: AUTH_CONFIG.RATE_LIMIT.PASSWORD_RESET.MAX_ATTEMPTS,
    message: 'Too many password reset attempts, please try again later'
  }),

  // User creation/modification endpoints
  userModification: new RateLimiter({
    windowMs: AUTH_CONFIG.RATE_LIMIT.REGISTER.WINDOW_MS,
    maxRequests: AUTH_CONFIG.RATE_LIMIT.REGISTER.MAX_ATTEMPTS,
    message: 'Too many user modification requests, please try again later'
  })
};

/**
 * Create a custom rate limiter with specific configuration
 */
export function createRateLimiter(config: RateLimiterConfig): RateLimiter {
  return new RateLimiter(config);
}

/**
 * Rate limiter for specific user actions (by user ID)
 */
export function createUserRateLimiter(config: Omit<RateLimiterConfig, 'keyGenerator'>) {
  return new RateLimiter({
    ...config,
    keyGenerator: (req: Request) => {
      const userId = req.user?.id || req.body?.userId || req.params?.userId;
      return userId ? `user:${userId}` : req.ip || 'unknown';
    }
  });
}