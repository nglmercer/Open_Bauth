// src/controllers/auth.controller.ts
import { Context } from 'hono';
import { AuthService } from '../../dist/index';
import { ApiError } from '../api.types';
import { AuthErrorType } from '../../dist/index';

export class AuthController {
  constructor(private authService: AuthService) {}

  // Bind `this` to ensure `authService` is available
  register = async (c: Context) => {
    const body = await c.req.json();
    const result = await this.authService.register(body);

    if (!result.success) {
      const statusCode = result.error?.type === AuthErrorType.USER_ALREADY_EXISTS ? 409 : 400;
      throw new ApiError(statusCode, { 
        name: 'AuthError',
        message: result.error!.message,
        type: result.error!.type,
        timestamp: new Date(),
        toResponse(): { success: false; error: { type: AuthErrorType; message: string; timestamp: string; context?: Record<string, any> } } {
          return {
            success: false,
            error: {
              message: result.error!.message,
              type: result.error!.type,
              timestamp: new Date().toISOString(),
            },
          };
        }
      });
    }
    
    return c.json({
        success: true,
        data: { user: result.user, token: result.token }
    }, 201);
  };

  login = async (c: Context) => {
    const body = await c.req.json();
    const result = await this.authService.login(body);

    if (!result.success) {
      throw new ApiError(401, { 
        name: 'AuthError',
        message: result.error!.message,
        type: result.error!.type,
        timestamp: new Date(),
        toResponse(): { success: false; error: { type: AuthErrorType; message: string; timestamp: string; context?: Record<string, any> } } {
          return {
            success: false,
            error: {
              message: result.error!.message,
              type: result.error!.type,
              timestamp: new Date().toISOString(),
            },
          };
        }
      });
    }
    
    return c.json({
        success: true,
        data: { user: result.user, token: result.token }
    });
  };

  getProfile = (c: Context) => {
    const auth = c.get('auth'); // From middleware
    return c.json({
      success: true,
      data: {
        user: auth.user,
        roles: auth.roles,
        permissions: auth.permissions,
      },
    });
  };
  refreshToken = async (c: Context) => {
    
  }
}