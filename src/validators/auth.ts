// src/validators/auth.ts

import type { RegisterData, LoginData, UpdateUserData } from '../types/auth';
import { ValidationError } from '../errors/auth';

/**
 * Email validation utility
 */
export class EmailValidator {
  private static readonly EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  
  static validate(email: string): void {
    if (!email || typeof email !== 'string') {
      throw new ValidationError('Email is required');
    }
    
    if (!this.EMAIL_REGEX.test(email.trim())) {
      throw new ValidationError('Invalid email format');
    }
  }
  
  static normalize(email: string): string {
    return email.toLowerCase().trim();
  }
}

/**
 * Password validation utility
 */
export class PasswordValidator {
  private static readonly MIN_LENGTH = 8;
  private static readonly STRENGTH_REGEX = /(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/;
  
  static validate(password: string): void {
    if (!password || typeof password !== 'string') {
      throw new ValidationError('Password is required');
    }
    
    if (password.length < this.MIN_LENGTH) {
      throw new ValidationError(`Password must be at least ${this.MIN_LENGTH} characters long`);
    }
    
    if (!this.STRENGTH_REGEX.test(password)) {
      throw new ValidationError(
        'Password must contain at least one uppercase letter, one lowercase letter, and one number'
      );
    }
  }
}

/**
 * Name validation utility
 */
export class NameValidator {
  private static readonly MAX_LENGTH = 50;
  private static readonly NAME_REGEX = /^[a-zA-Z0-9\s'-]+$/;
  
  static validate(name: string | undefined, fieldName: string): void {
    if (name === undefined || name === null) {
      return; // Optional field
    }
    
    if (typeof name !== 'string') {
      throw new ValidationError(`${fieldName} must be a string`);
    }
    
    const trimmedName = name.trim();
    
    if (trimmedName.length === 0) {
      return; // Empty string is allowed for optional fields
    }
    
    if (trimmedName.length > this.MAX_LENGTH) {
      throw new ValidationError(`${fieldName} must not exceed ${this.MAX_LENGTH} characters`);
    }
    
    if (!this.NAME_REGEX.test(trimmedName)) {
      throw new ValidationError(`${fieldName} contains invalid characters`);
    }
  }
  
  static normalize(name: string | undefined): string {
    if (!name || typeof name !== 'string') {
      return '';
    }
    
    const trimmed = name.trim();
    return trimmed.length > 0 ? trimmed : '';
  }
}

/**
 * Registration data validator
 */
export class RegisterDataValidator {
  static validate(data: RegisterData): void {
    if (!data || typeof data !== 'object') {
      throw new ValidationError('Invalid registration data');
    }
    
    // Validate required fields
    EmailValidator.validate(data.email);
    PasswordValidator.validate(data.password);
    
    // Validate optional fields
    NameValidator.validate(data.firstName, 'First name');
    NameValidator.validate(data.lastName, 'Last name');
    
    // Validate isActive if provided
    if (data.isActive !== undefined && typeof data.isActive !== 'boolean') {
      throw new ValidationError('isActive must be a boolean');
    }
  }
  
  static normalize(data: RegisterData): RegisterData {
    return {
      email: EmailValidator.normalize(data.email),
      password: data.password,
      firstName: NameValidator.normalize(data.firstName),
      lastName: NameValidator.normalize(data.lastName),
      isActive: data.isActive
    };
  }
}

/**
 * Login data validator
 */
export class LoginDataValidator {
  static validate(data: LoginData): void {
    if (!data || typeof data !== 'object') {
      throw new ValidationError('Invalid login data');
    }
    
    EmailValidator.validate(data.email);
    
    if (!data.password || typeof data.password !== 'string') {
      throw new ValidationError('Password is required');
    }
  }
  
  static normalize(data: LoginData): LoginData {
    return {
      email: EmailValidator.normalize(data.email),
      password: data.password
    };
  }
}

/**
 * Update user data validator
 */
export class UpdateUserDataValidator {
  static validate(data: UpdateUserData): UpdateUserData {
    if (!data || typeof data !== 'object') {
      throw new ValidationError('Invalid update data');
    }
    
    // Validate email if provided
    if (data.email !== undefined) {
      EmailValidator.validate(data.email);
    }
    
    // Validate password if provided
    if (data.password !== undefined) {
      PasswordValidator.validate(data.password);
    }
    
    // Validate names if provided
    NameValidator.validate(data.firstName, 'First name');
    NameValidator.validate(data.lastName, 'Last name');
    
    // Validate boolean fields
    if (data.isActive !== undefined && typeof data.isActive !== 'boolean') {
      throw new ValidationError('isActive must be a boolean');
    }
    
    if (data.is_active !== undefined && typeof data.is_active !== 'boolean') {
      throw new ValidationError('is_active must be a boolean');
    }
    return data
  }
  
  static normalize(data: UpdateUserData): UpdateUserData {
    const normalized: UpdateUserData = {};
    
    if (data.email !== undefined) {
      normalized.email = EmailValidator.normalize(data.email);
    }
    
    if (data.password !== undefined) {
      normalized.password = data.password;
    }
    
    if (data.firstName !== undefined) {
      normalized.firstName = NameValidator.normalize(data.firstName);
    }
    
    if (data.lastName !== undefined) {
      normalized.lastName = NameValidator.normalize(data.lastName);
    }
    
    if (data.isActive !== undefined) {
      normalized.isActive = data.isActive;
    }
    
    if (data.is_active !== undefined) {
      normalized.is_active = data.is_active;
    }
    
    if (data.lastLoginAt !== undefined) {
      normalized.lastLoginAt = data.lastLoginAt;
    }
    
    return normalized;
  }
}

/**
 * User ID validator
 */
export class UserIdValidator {
  private static readonly UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  private static readonly NUMERIC_ID_REGEX = /^[0-9]+$/;
  
  static validate(userId: string): void {
    if (!userId || typeof userId !== 'string') {
      throw new ValidationError('User ID is required');
    }
    
    // Allow UUID format or numeric IDs, but reject clearly invalid formats
    if (!this.UUID_REGEX.test(userId) && !this.NUMERIC_ID_REGEX.test(userId)) {
      throw new ValidationError('Invalid user ID format');
    }
  }
}

/**
 * Role name validator
 */
export class RoleNameValidator {
  private static readonly MAX_LENGTH = 50;
  private static readonly ROLE_REGEX = /^[a-zA-Z0-9_-]+$/;
  
  static validate(roleName: string): void {
    if (!roleName || typeof roleName !== 'string') {
      throw new ValidationError('Role name is required');
    }
    
    const trimmed = roleName.trim();
    
    if (trimmed.length === 0) {
      throw new ValidationError('Role name cannot be empty');
    }
    
    if (trimmed.length > this.MAX_LENGTH) {
      throw new ValidationError(`Role name must not exceed ${this.MAX_LENGTH} characters`);
    }
    
    if (!this.ROLE_REGEX.test(trimmed)) {
      throw new ValidationError('Role name contains invalid characters');
    }
  }
  
  static normalize(roleName: string): string {
    return roleName.toLowerCase().trim();
  }
}