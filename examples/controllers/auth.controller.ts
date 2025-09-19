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
    
    // Generate refresh token
    const jwtService = (this.authService as any).jwtService;
    const refreshToken = await jwtService.generateRefreshToken(result.user?.id);
    
    return c.json({
        success: true,
        data: { 
          user: result.user, 
          token: result.token,
          refreshToken: refreshToken
        }
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
    
    // Generate refresh token
    const jwtService = (this.authService as any).jwtService;
    const refreshToken = await jwtService.generateRefreshToken(result.user?.id);
    
    return c.json({
        success: true,
        data: { 
          user: result.user, 
          token: result.token,
          refreshToken: refreshToken
        }
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
    try {
      const body = await c.req.json();
      const { refreshToken } = body;

      if (!refreshToken) {
        throw new ApiError(400, { 
          name: 'AuthError',
          message: 'Refresh token is required',
          type: AuthErrorType.INVALID_CREDENTIALS,
          timestamp: new Date(),
          toResponse(): { success: false; error: { type: AuthErrorType; message: string; timestamp: string; context?: Record<string, any> } } {
            return {
              success: false,
              error: {
                message: 'Refresh token is required',
                type: AuthErrorType.INVALID_CREDENTIALS,
                timestamp: new Date().toISOString(),
              },
            };
          }
        });
      }

      // Get JWT service from auth service (we need to access it)
      const jwtService = (this.authService as any).jwtService;
      
      // Verify refresh token and get user ID
      const userId = await jwtService.verifyRefreshToken(refreshToken);
      
      // Get user data with roles
      const user = await this.authService.findUserById(userId, { includeRoles: true });
      console.log("data refreshToken",{
        userId,
        user
      })
      if (!user || !user.is_active) {
        throw new ApiError(401, { 
          name: 'AuthError',
          message: 'User not found or inactive',
          type: AuthErrorType.USER_NOT_FOUND,
          timestamp: new Date(),
          toResponse(): { success: false; error: { type: AuthErrorType; message: string; timestamp: string; context?: Record<string, any> } } {
            return {
              success: false,
              error: {
                message: 'User not found or inactive',
                type: AuthErrorType.USER_NOT_FOUND,
                timestamp: new Date().toISOString(),
              },
            };
          }
        });
      }

      // Generate new access token and refresh token
      const newAccessToken = await jwtService.generateToken(user);
      const newRefreshToken = await jwtService.generateRefreshToken(user.id);

      return c.json({
        success: true,
        data: { 
          user,
          token: newAccessToken,
          refreshToken: newRefreshToken
        }
      });

    } catch (error: any) {
      // Handle JWT-specific errors
      // Re-throw ApiError instances
      if (error instanceof ApiError) {
        throw error;
      }
      console.log("error refreshToken",error)
      // Handle unexpected errors
      throw new ApiError(500, { 
        name: 'AuthError',
        message: 'Internal server error during token refresh',
        type: AuthErrorType.TOKEN_ERROR,
        timestamp: new Date(),
        toResponse(): { success: false; error: { type: AuthErrorType; message: string; timestamp: string; context?: Record<string, any> } } {
          return {
            success: false,
            error: {
              message:  error.message || 'Internal server error during token refresh',
              type: AuthErrorType.TOKEN_ERROR,
              timestamp: new Date().toISOString(),
            },
          };
        }
      });
    }
  };
}