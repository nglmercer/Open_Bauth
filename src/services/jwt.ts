// src/services/jwt.ts
import type { JWTPayload, User } from '../types/auth';

/**
 * Servicio para manejar operaciones JWT
 * Utiliza Web Crypto API nativo para firmas HMAC
 * Nota: Bun.password.hash es para hashing de contraseñas, no para JWT
 */
export class JWTService {
  private secret: string;
  private expiresIn: string;

  constructor(secret: string, expiresIn: string = '24h') {
    if (!secret) {
      throw new Error('JWT secret is required');
    }
    this.secret = secret;
    this.expiresIn = expiresIn;
  }

  /**
   * Genera un token JWT para un usuario
   * @param user Usuario para el cual generar el token
   * @returns Token JWT
   */
  async generateToken(user: User): Promise<string> {
    // FIX: Añadir validación de entrada para el objeto de usuario.
    if (!user || !user.id || !user.email) {
      throw new Error('Invalid user object provided. User must have an id and an email.');
    }

    try {
      const now = Math.floor(Date.now() / 1000);
      const expirationTime = this.parseExpirationTime(this.expiresIn);
      
      const payload: JWTPayload = {
        userId: user.id,
        email: user.email,
        roles: user.roles?.map(role => role.name) || [],
        iat: now,
        exp: now + expirationTime
      };

      // Implementar JWT usando Web Crypto API nativo
      const header = {
        alg: 'HS256',
        typ: 'JWT'
      };

      const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
      const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));
      
      const signature = await this.createSignature(`${encodedHeader}.${encodedPayload}`);
      
      return `${encodedHeader}.${encodedPayload}.${signature}`;
    } catch (error:any) {
      console.error('Error generating JWT token:', error);
      throw new Error('Failed to generate token');
    }
  }
  /**
   * Verifica y decodifica un token JWT
   * @param token Token JWT a verificar
   * @returns Payload del token si es válido
   * @throws Error si el token es inválido
   */
  async verifyToken(token: string): Promise<JWTPayload> {
    return Promise.resolve().then(async () => {
      if (!token) {
        throw new Error('Token is required');
      }

      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid token format');
      }

      const [encodedHeader, encodedPayload, signature] = parts;
      
      // Verificar la firma
      const expectedSignature = await this.createSignature(`${encodedHeader}.${encodedPayload}`);
      if (signature !== expectedSignature) {
        throw new Error('Invalid token signature');
      }

      // Decodificar el payload
      const payload: JWTPayload = JSON.parse(this.base64UrlDecode(encodedPayload));
      
      // Verificar expiración
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < now) {
        throw new Error('Token has expired');
      }

      return payload;
    }).catch((error: any) => {
      console.error('Error verifying JWT token:', error);
      throw new Error(`Invalid token: ${error.message}`);
    });
  }

  /**
   * Extrae el token del header Authorization
   * @param authHeader Header de autorización
   * @returns Token JWT o null si no se encuentra
   */
  extractTokenFromHeader(authHeader: string): string | null {
    if (!authHeader) {
      return null;
    }

    const parts = authHeader.trim().split(' ');
    if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
      return null;
    }

    return parts[1];
  }

  /**
   * Verifica si un token está expirado sin verificar la firma
   * @param token Token JWT
   * @returns true si está expirado
   */
  isTokenExpired(token: string): boolean {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return true;
      }

      const payload: JWTPayload = JSON.parse(this.base64UrlDecode(parts[1]));
      const now = Math.floor(Date.now() / 1000);
      
      return payload.exp ? payload.exp < now : false;
    } catch (error:any) {
      return true;
    }
  }

  /**
   * Obtiene el tiempo restante de un token en segundos
   * @param token Token JWT
   * @returns Segundos restantes o 0 si está expirado
   */
  getTokenRemainingTime(token: string): number {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return 0;
      }

      const payload: JWTPayload = JSON.parse(this.base64UrlDecode(parts[1]));
      const now = Math.floor(Date.now() / 1000);
      
      if (!payload.exp) {
        return Infinity;
      }

      const remaining = payload.exp - now;
      return Math.max(0, remaining);
    } catch (error:any) {
      return 0;
    }
  }

  /**
   * Refresca un token si está próximo a expirar
   * @param token Token actual
   * @param user Usuario asociado al token
   * @param refreshThreshold Umbral en segundos para refrescar (default: 1 hora)
   * @returns Nuevo token o el mismo si no necesita refresh
   */
  async refreshTokenIfNeeded(
    token: string, 
    user: User, 
    refreshThreshold: number = 3600
  ): Promise<string> {
    const remainingTime = this.getTokenRemainingTime(token);
    
    if (remainingTime <= refreshThreshold) {
      return await this.generateToken(user);
    }
    
    return token;
  }

  /**
   * Codifica en Base64 URL-safe
   * @param str String a codificar
   * @returns String codificado
   */
  private base64UrlEncode(str: string): string {
    const base64 = Buffer.from(str).toString('base64');
    return base64
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Decodifica de Base64 URL-safe
   * @param str String a decodificar
   * @returns String decodificado
   */
  private base64UrlDecode(str: string): string {
    // Agregar padding si es necesario
    let padded = str;
    while (padded.length % 4) {
      padded += '=';
    }
    
    const base64 = padded
      .replace(/-/g, '+')
      .replace(/_/g, '/');
    
    return Buffer.from(base64, 'base64').toString('utf-8');
  }

  /**
   * Crea una firma HMAC SHA-256
   * @param data Datos a firmar
   * @returns Firma en base64 URL-safe
   */
  private async createSignature(data: string): Promise<string> {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(this.secret);
    const messageData = encoder.encode(data);
    
    // Importar la clave
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    // Crear la firma
    const signature = await crypto.subtle.sign('HMAC', key, messageData);
    const signatureArray = new Uint8Array(signature);
    
    // Convertir a base64 URL-safe
    const base64 = Buffer.from(signatureArray).toString('base64');
    return base64
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Parsea el tiempo de expiración a segundos
   * @param expiresIn String de tiempo (ej: '24h', '7d', '30m')
   * @returns Segundos
   */
  private parseExpirationTime(expiresIn: string): number {
    const units: Record<string, number> = {
      's': 1,
      'm': 60,
      'h': 3600,
      'd': 86400,
      'w': 604800
    };

    const match = expiresIn.match(/^(-?\d+)([smhdw])$/);
    if (!match) {
      throw new Error(`Invalid expiration format: ${expiresIn}`);
    }

    const [, value, unit] = match;
    const multiplier = units[unit];
    
    if (!multiplier) {
      throw new Error(`Invalid time unit: ${unit}`);
    }

    return parseInt(value) * multiplier;
  }

  /**
   * Genera un token de refresh
   * @param userId ID del usuario
   * @returns Token de refresh
   */
  async generateRefreshToken(userId: number): Promise<string> {
    const payload = {
      userId,
      type: 'refresh',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60) // 30 días
    };

    const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));
    const signature = await this.createSignature(encodedPayload);
    
    return `${encodedPayload}.${signature}`;
  }

  /**
   * Verifica un token de refresh
   * @param refreshToken Token de refresh
   * @returns User ID si es válido
   */
  async verifyRefreshToken(refreshToken: string): Promise<number> {
    try {
      const parts = refreshToken.split('.');
      if (parts.length !== 2) {
        throw new Error('Invalid refresh token format');
      }

      const [encodedPayload, signature] = parts;
      
      // Verificar la firma
      const expectedSignature = await this.createSignature(encodedPayload);
      if (signature !== expectedSignature) {
        throw new Error('Invalid refresh token signature');
      }

      const payload = JSON.parse(this.base64UrlDecode(encodedPayload));
      
      // Verificar tipo y expiración
      if (payload.type !== 'refresh') {
        throw new Error('Invalid token type');
      }

      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < now) {
        throw new Error('Refresh token has expired');
      }

      return payload.userId;
    } catch (error:any) {
      throw new Error(`Invalid refresh token: ${error.message}`);
    }
  }
}

/**
 * Instancia singleton del servicio JWT
 */
let jwtServiceInstance: JWTService | null = null;

/**
 * Inicializa el servicio JWT
 * @param secret Secreto para firmar tokens
 * @param expiresIn Tiempo de expiración
 * @returns Instancia del servicio JWT
 */
export function initJWTService(secret: string, expiresIn?: string): JWTService {
  jwtServiceInstance = new JWTService(secret, expiresIn);
  return jwtServiceInstance;
}

/**
 * Obtiene la instancia del servicio JWT
 * @returns Instancia del servicio JWT
 * @throws Error si no ha sido inicializado
 */
export function getJWTService(): JWTService {
  if (!jwtServiceInstance) {
    throw new Error('JWT Service not initialized. Call initJWTService() first.');
  }
  return jwtServiceInstance;
}