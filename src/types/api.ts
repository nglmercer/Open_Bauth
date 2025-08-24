import type { User, Role, Permission } from './auth';
import type { ApiResponse, PaginatedResponse, ValidationError, HttpStatusCode } from './common';

// ============================================================================
// REQUEST TYPES
// ============================================================================

/**
 * Base request interface
 */
export interface BaseRequest {
  timestamp?: string;
  requestId?: string;
  userAgent?: string;
  ipAddress?: string;
}

/**
 * Authentication request types
 */
export interface RegisterRequest extends BaseRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  acceptTerms: boolean;
}

export interface LoginRequest extends BaseRequest {
  email: string;
  password: string;
  rememberMe?: boolean;
}

export interface RefreshTokenRequest extends BaseRequest {
  refreshToken: string;
}

export interface ForgotPasswordRequest extends BaseRequest {
  email: string;
}

export interface ResetPasswordRequest extends BaseRequest {
  token: string;
  newPassword: string;
  confirmPassword: string;
}

export interface ChangePasswordRequest extends BaseRequest {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

/**
 * User management request types
 */
export interface UpdateUserProfileRequest extends BaseRequest {
  firstName?: string;
  lastName?: string;
  email?: string;
  isActive?: boolean;
}

export interface CreateUserRequest extends BaseRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  roles?: string[];
  isActive?: boolean;
}

export interface UpdateUserRequest extends BaseRequest {
  firstName?: string;
  lastName?: string;
  email?: string;
  isActive?: boolean;
  roles?: string[];
}

export interface GetUsersRequest extends BaseRequest {
  page?: number;
  limit?: number;
  search?: string;
  role?: string;
  isActive?: boolean;
  sortBy?: 'firstName' | 'lastName' | 'email' | 'created_at' | 'updated_at';
  sortOrder?: 'asc' | 'desc';
}

/**
 * Role management request types
 */
export interface CreateRoleRequest extends BaseRequest {
  name: string;
  description?: string;
  permissions?: string[];
  isActive?: boolean;
}

export interface UpdateRoleRequest extends BaseRequest {
  name?: string;
  description?: string;
  permissions?: string[];
  isActive?: boolean;
}

export interface AssignRoleRequest extends BaseRequest {
  userId: string;
  roleId: string;
}

export interface RemoveRoleRequest extends BaseRequest {
  userId: string;
  roleId: string;
}

// ============================================================================
// RESPONSE TYPES
// ============================================================================

/**
 * Authentication response types
 */
export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: 'Bearer';
}

export interface LoginResponse extends ApiResponse<{
  user: Omit<User, 'password'>;
  tokens: AuthTokens;
}> {}

export interface RegisterResponse extends ApiResponse<{
  user: Omit<User, 'password'>;
  tokens: AuthTokens;
}> {}

export interface RefreshTokenResponse extends ApiResponse<{
  tokens: AuthTokens;
}> {}

export interface LogoutResponse extends ApiResponse<{
  message: string;
}> {}

export interface ForgotPasswordResponse extends ApiResponse<{
  message: string;
  resetTokenSent: boolean;
}> {}

export interface ResetPasswordResponse extends ApiResponse<{
  message: string;
  passwordReset: boolean;
}> {}

export interface ChangePasswordResponse extends ApiResponse<{
  message: string;
  passwordChanged: boolean;
}> {}

/**
 * User management response types
 */
export interface GetUserResponse extends ApiResponse<{
  user: Omit<User, 'password'>;
}> {}

export interface GetUsersResponse extends PaginatedResponse<Omit<User, 'password'>> {}

export interface CreateUserResponse extends ApiResponse<{
  user: Omit<User, 'password'>;
  created: boolean;
}> {}

export interface UpdateUserResponse extends ApiResponse<{
  user: Omit<User, 'password'>;
  updated: boolean;
}> {}

export interface DeleteUserResponse extends ApiResponse<{
  message: string;
  deleted: boolean;
  userId: string;
}> {}

export interface GetUserProfileResponse extends ApiResponse<{
  user: Omit<User, 'password'>;
}> {}

export interface UpdateUserProfileResponse extends ApiResponse<{
  user: Omit<User, 'password'>;
  updated: boolean;
}> {}

/**
 * Role management response types
 */
export interface GetRoleResponse extends ApiResponse<{
  role: Role;
}> {}

export interface GetRolesResponse extends PaginatedResponse<Role> {}

export interface CreateRoleResponse extends ApiResponse<{
  role: Role;
  created: boolean;
}> {}

export interface UpdateRoleResponse extends ApiResponse<{
  role: Role;
  updated: boolean;
}> {}

export interface DeleteRoleResponse extends ApiResponse<{
  message: string;
  deleted: boolean;
  roleId: string;
}> {}

export interface AssignRoleResponse extends ApiResponse<{
  message: string;
  assigned: boolean;
  userId: string;
  roleId: string;
}> {}

export interface RemoveRoleResponse extends ApiResponse<{
  message: string;
  removed: boolean;
  userId: string;
  roleId: string;
}> {}

/**
 * Permission response types
 */
export interface GetPermissionsResponse extends ApiResponse<{
  permissions: Permission[];
}> {}

export interface GetUserPermissionsResponse extends ApiResponse<{
  permissions: Permission[];
  userId: string;
}> {}

// ============================================================================
// ERROR RESPONSE TYPES
// ============================================================================

/**
 * Validation error response
 */
export interface ValidationErrorResponse extends ApiResponse<null> {
  success: false;
  errors: ValidationError[];
  statusCode: HttpStatusCode.BAD_REQUEST;
}

/**
 * Authentication error response
 */
export interface AuthErrorResponse extends ApiResponse<null> {
  success: false;
  message: string;
  statusCode: HttpStatusCode.UNAUTHORIZED | HttpStatusCode.FORBIDDEN;
  errorCode?: string;
}

/**
 * Not found error response
 */
export interface NotFoundErrorResponse extends ApiResponse<null> {
  success: false;
  message: string;
  statusCode: HttpStatusCode.NOT_FOUND;
  resource?: string;
}

/**
 * Rate limit error response
 */
export interface RateLimitErrorResponse extends ApiResponse<null> {
  success: false;
  message: string;
  statusCode: HttpStatusCode.TOO_MANY_REQUESTS;
  retryAfter?: number;
  limit?: number;
  remaining?: number;
  resetTime?: number;
}

/**
 * Server error response
 */
export interface ServerErrorResponse extends ApiResponse<null> {
  success: false;
  message: string;
  statusCode: HttpStatusCode.INTERNAL_SERVER_ERROR;
  errorId?: string;
  timestamp: string;
}

// ============================================================================
// UTILITY TYPES
// ============================================================================

/**
 * Union type for all possible API responses
 */
export type AnyApiResponse = 
  | LoginResponse
  | RegisterResponse
  | RefreshTokenResponse
  | LogoutResponse
  | ForgotPasswordResponse
  | ResetPasswordResponse
  | ChangePasswordResponse
  | GetUserResponse
  | GetUsersResponse
  | CreateUserResponse
  | UpdateUserResponse
  | DeleteUserResponse
  | GetUserProfileResponse
  | UpdateUserProfileResponse
  | GetRoleResponse
  | GetRolesResponse
  | CreateRoleResponse
  | UpdateRoleResponse
  | DeleteRoleResponse
  | AssignRoleResponse
  | RemoveRoleResponse
  | GetPermissionsResponse
  | GetUserPermissionsResponse
  | ValidationErrorResponse
  | AuthErrorResponse
  | NotFoundErrorResponse
  | RateLimitErrorResponse
  | ServerErrorResponse;

/**
 * Union type for all possible error responses
 */
export type ErrorResponse = 
  | ValidationErrorResponse
  | AuthErrorResponse
  | NotFoundErrorResponse
  | RateLimitErrorResponse
  | ServerErrorResponse;

/**
 * Union type for all possible success responses
 */
export type SuccessResponse = Exclude<AnyApiResponse, ErrorResponse>;

/**
 * Type guard for success responses
 */
export function isSuccessResponse(response: AnyApiResponse): response is SuccessResponse {
  return 'success' in response && response.success === true;
}

/**
 * Type guard for error responses
 */
export function isErrorResponse(response: AnyApiResponse): response is ErrorResponse {
  return 'success' in response && response.success === false;
}

/**
 * Type guard for validation error responses
 */
export function isValidationErrorResponse(response: AnyApiResponse): response is ValidationErrorResponse {
  return 'success' in response && !response.success && 'errors' in response && Array.isArray(response.errors);
}

/**
 * Type guard for rate limit error responses
 */
export function isRateLimitErrorResponse(response: AnyApiResponse): response is RateLimitErrorResponse {
  return isErrorResponse(response) && response.statusCode === 429; // 429 HttpStatusCode.TOO_MANY_REQUESTS
}

// ============================================================================
// REQUEST/RESPONSE MAPPING
// ============================================================================

/**
 * Maps request types to their corresponding response types
 */
export interface RequestResponseMap {
  // Auth endpoints
  '/auth/register': { request: RegisterRequest; response: RegisterResponse };
  '/auth/login': { request: LoginRequest; response: LoginResponse };
  '/auth/refresh': { request: RefreshTokenRequest; response: RefreshTokenResponse };
  '/auth/logout': { request: BaseRequest; response: LogoutResponse };
  '/auth/forgot-password': { request: ForgotPasswordRequest; response: ForgotPasswordResponse };
  '/auth/reset-password': { request: ResetPasswordRequest; response: ResetPasswordResponse };
  '/auth/change-password': { request: ChangePasswordRequest; response: ChangePasswordResponse };
  
  // User endpoints
  '/users': { request: GetUsersRequest; response: GetUsersResponse };
  '/users/:id': { request: BaseRequest; response: GetUserResponse };
  '/users/create': { request: CreateUserRequest; response: CreateUserResponse };
  '/users/:id/update': { request: UpdateUserRequest; response: UpdateUserResponse };
  '/users/:id/delete': { request: BaseRequest; response: DeleteUserResponse };
  '/users/profile': { request: BaseRequest; response: GetUserProfileResponse };
  '/users/profile/update': { request: UpdateUserProfileRequest; response: UpdateUserProfileResponse };
  
  // Role endpoints
  '/roles': { request: BaseRequest; response: GetRolesResponse };
  '/roles/:id': { request: BaseRequest; response: GetRoleResponse };
  '/roles/create': { request: CreateRoleRequest; response: CreateRoleResponse };
  '/roles/:id/update': { request: UpdateRoleRequest; response: UpdateRoleResponse };
  '/roles/:id/delete': { request: BaseRequest; response: DeleteRoleResponse };
  '/roles/assign': { request: AssignRoleRequest; response: AssignRoleResponse };
  '/roles/remove': { request: RemoveRoleRequest; response: RemoveRoleResponse };
  
  // Permission endpoints
  '/permissions': { request: BaseRequest; response: GetPermissionsResponse };
  '/permissions/user/:id': { request: BaseRequest; response: GetUserPermissionsResponse };
}

/**
 * Extract request type for a given endpoint
 */
export type RequestType<T extends keyof RequestResponseMap> = RequestResponseMap[T]['request'];

/**
 * Extract response type for a given endpoint
 */
export type ResponseType<T extends keyof RequestResponseMap> = RequestResponseMap[T]['response'];

/**
 * HTTP method types
 */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

/**
 * API endpoint configuration
 */
export interface ApiEndpoint<T extends keyof RequestResponseMap = keyof RequestResponseMap> {
  path: T;
  method: HttpMethod;
  requiresAuth: boolean;
  requiredPermissions?: string[];
  rateLimit?: {
    windowMs: number;
    maxRequests: number;
  };
  validation?: {
    body?: boolean;
    params?: boolean;
    query?: boolean;
  };
}

/**
 * API client configuration
 */
export interface ApiClientConfig {
  baseUrl: string;
  timeout: number;
  retries: number;
  retryDelay: number;
  defaultHeaders: Record<string, string>;
  interceptors?: {
    request?: (config: any) => any;
    response?: (response: any) => any;
    error?: (error: any) => any;
  };
}