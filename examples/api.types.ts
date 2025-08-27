// src/types/api.types.ts
import { AuthError } from '../dist/index';

export class ApiError extends Error {
  constructor(public statusCode: number, message: string | AuthError) {
    super(typeof message === 'string' ? message : message.message);
    this.name = 'ApiError';
  }
}