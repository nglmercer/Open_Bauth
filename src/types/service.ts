import type { User, Role, Permission, CreateUserData, UpdateUserData } from './auth';
import type { ApiResponse, PaginatedResponse, ValidationResult, DatabaseTransaction } from './common';
import type { AuditLogEntry } from './middleware';

// ============================================================================
// BASE SERVICE TYPES
// ============================================================================

/**
 * Base service interface
 */
export interface BaseService {
  readonly name: string;
  readonly version: string;
  initialize?(): Promise<void>;
  destroy?(): Promise<void>;
  healthCheck?(): Promise<ServiceHealthStatus>;
}

/**
 * Service health status
 */
export interface ServiceHealthStatus {
  healthy: boolean;
  timestamp: Date;
  service: string;
  version: string;
  uptime: number;
  dependencies?: Record<string, boolean>;
  metrics?: Record<string, any>;
  errors?: string[];
}

/**
 * Service configuration
 */
export interface ServiceConfig {
  name: string;
  version: string;
  environment: string;
  debug: boolean;
  timeout: number;
  retries: number;
  dependencies: string[];
  features: Record<string, boolean>;
}

// ============================================================================
// AUTHENTICATION SERVICE TYPES
// ============================================================================

/**
 * Authentication service interface
 */
export interface AuthServiceInterface extends BaseService {
  register(data: RegisterServiceData): Promise<AuthServiceResult>;
  login(email: string, password: string): Promise<AuthServiceResult>;
  logout(userId: string, refreshToken?: string): Promise<void>;
  refreshToken(refreshToken: string): Promise<TokenServiceResult>;
  forgotPassword(email: string): Promise<void>;
  resetPassword(token: string, newPassword: string): Promise<void>;
  changePassword(userId: string, currentPassword: string, newPassword: string): Promise<void>;
  verifyToken(token: string): Promise<TokenVerificationResult>;
  revokeToken(token: string): Promise<void>;
  revokeAllTokens(userId: string): Promise<void>;
}

/**
 * Registration service data
 */
export interface RegisterServiceData {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  acceptTerms: boolean;
  metadata?: Record<string, any>;
}

/**
 * Authentication service result
 */
export interface AuthServiceResult {
  user: Omit<User, 'password'>;
  tokens: {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
    tokenType: 'Bearer';
  };
  isNewUser?: boolean;
  requiresVerification?: boolean;
}

/**
 * Token service result
 */
export interface TokenServiceResult {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: 'Bearer';
}

/**
 * Token verification result
 */
export interface TokenVerificationResult {
  valid: boolean;
  expired: boolean;
  payload?: {
    userId: string;
    email: string;
    roles: string[];
    permissions: string[];
    iat: number;
    exp: number;
  };
  error?: string;
}

// ============================================================================
// USER SERVICE TYPES
// ============================================================================

/**
 * User service interface
 */
export interface UserServiceInterface extends BaseService {
  getUsers(options?: GetUsersOptions): Promise<PaginatedResponse<Omit<User, 'password'>>>;
  getUserById(id: string, options?: GetUserOptions): Promise<Omit<User, 'password'> | null>;
  getUserByEmail(email: string, options?: GetUserOptions): Promise<Omit<User, 'password'> | null>;
  createUser(data: CreateUserServiceData, transaction?: DatabaseTransaction): Promise<Omit<User, 'password'>>;
  updateUser(id: string, data: UpdateUserServiceData, transaction?: DatabaseTransaction): Promise<Omit<User, 'password'>>;
  deleteUser(id: string, transaction?: DatabaseTransaction): Promise<void>;
  activateUser(id: string): Promise<void>;
  deactivateUser(id: string): Promise<void>;
  getUserProfile(id: string): Promise<UserProfile | null>;
  updateUserProfile(id: string, data: UpdateUserProfileData): Promise<UserProfile>;
  getUserStats(id: string): Promise<UserStats>;
  searchUsers(query: string, options?: SearchUsersOptions): Promise<PaginatedResponse<Omit<User, 'password'>>>;
}

/**
 * Get users options
 */
export interface GetUsersOptions {
  page?: number;
  limit?: number;
  search?: string;
  role?: string;
  isActive?: boolean;
  sortBy?: 'firstName' | 'lastName' | 'email' | 'created_at' | 'updated_at';
  sortOrder?: 'asc' | 'desc';
  includeRoles?: boolean;
  includePermissions?: boolean;
}

/**
 * Get user options
 */
export interface GetUserOptions {
  includeRoles?: boolean;
  includePermissions?: boolean;
  includeProfile?: boolean;
  includeStats?: boolean;
}

/**
 * Create user service data
 */
export interface CreateUserServiceData extends CreateUserData {
  roles?: string[];
  sendWelcomeEmail?: boolean;
  requireEmailVerification?: boolean;
  metadata?: Record<string, any>;
}

/**
 * Update user service data
 */
export interface UpdateUserServiceData extends UpdateUserData {
  roles?: string[];
  metadata?: Record<string, any>;
}

/**
 * User profile
 */
export interface UserProfile {
  id: string;
  userId: string;
  avatar?: string;
  bio?: string;
  website?: string;
  location?: string;
  timezone?: string;
  language?: string;
  theme?: 'light' | 'dark' | 'auto';
  notifications: {
    email: boolean;
    push: boolean;
    sms: boolean;
  };
  privacy: {
    profileVisible: boolean;
    emailVisible: boolean;
    locationVisible: boolean;
  };
  preferences: Record<string, any>;
  created_at: Date;
  updated_at: Date;
}

/**
 * Update user profile data
 */
export interface UpdateUserProfileData {
  avatar?: string;
  bio?: string;
  website?: string;
  location?: string;
  timezone?: string;
  language?: string;
  theme?: 'light' | 'dark' | 'auto';
  notifications?: Partial<UserProfile['notifications']>;
  privacy?: Partial<UserProfile['privacy']>;
  preferences?: Record<string, any>;
}

/**
 * User statistics
 */
export interface UserStats {
  userId: string;
  loginCount: number;
  lastLoginAt?: Date;
  accountAge: number; // days
  profileCompleteness: number; // percentage
  activityScore: number;
  roles: number;
  permissions: number;
}

/**
 * Search users options
 */
export interface SearchUsersOptions extends GetUsersOptions {
  searchFields?: ('firstName' | 'lastName' | 'email')[];
  fuzzy?: boolean;
  minScore?: number;
}

// ============================================================================
// ROLE SERVICE TYPES
// ============================================================================

/**
 * Role service interface
 */
export interface RoleServiceInterface extends BaseService {
  getRoles(options?: GetRolesOptions): Promise<PaginatedResponse<Role>>;
  getRoleById(id: string, options?: GetRoleOptions): Promise<Role | null>;
  getRoleByName(name: string, options?: GetRoleOptions): Promise<Role | null>;
  createRole(data: CreateRoleServiceData, transaction?: DatabaseTransaction): Promise<Role>;
  updateRole(id: string, data: UpdateRoleServiceData, transaction?: DatabaseTransaction): Promise<Role>;
  deleteRole(id: string, transaction?: DatabaseTransaction): Promise<void>;
  assignRoleToUser(userId: string, roleId: string, transaction?: DatabaseTransaction): Promise<void>;
  removeRoleFromUser(userId: string, roleId: string, transaction?: DatabaseTransaction): Promise<void>;
  getUserRoles(userId: string): Promise<Role[]>;
  getRoleUsers(roleId: string, options?: GetRoleUsersOptions): Promise<PaginatedResponse<Omit<User, 'password'>>>;
  checkUserHasRole(userId: string, roleId: string): Promise<boolean>;
  getRoleHierarchy(): Promise<RoleHierarchy[]>;
}

/**
 * Get roles options
 */
export interface GetRolesOptions {
  page?: number;
  limit?: number;
  search?: string;
  isActive?: boolean;
  sortBy?: 'name' | 'created_at' | 'updated_at';
  sortOrder?: 'asc' | 'desc';
  includePermissions?: boolean;
  includeUserCount?: boolean;
}

/**
 * Get role options
 */
export interface GetRoleOptions {
  includePermissions?: boolean;
  includeUsers?: boolean;
  includeUserCount?: boolean;
}

/**
 * Create role service data
 */
export interface CreateRoleServiceData {
  name: string;
  description?: string;
  permissions?: string[];
  isActive?: boolean;
  metadata?: Record<string, any>;
}

/**
 * Update role service data
 */
export interface UpdateRoleServiceData {
  name?: string;
  description?: string;
  permissions?: string[];
  isActive?: boolean;
  metadata?: Record<string, any>;
}

/**
 * Get role users options
 */
export interface GetRoleUsersOptions {
  page?: number;
  limit?: number;
  search?: string;
  isActive?: boolean;
  sortBy?: 'firstName' | 'lastName' | 'email' | 'created_at';
  sortOrder?: 'asc' | 'desc';
}

/**
 * Role hierarchy
 */
export interface RoleHierarchy {
  id: string;
  name: string;
  level: number;
  parent?: string;
  children: string[];
  permissions: string[];
}

// ============================================================================
// PERMISSION SERVICE TYPES
// ============================================================================

/**
 * Permission service interface
 */
export interface PermissionServiceInterface extends BaseService {
  getPermissions(options?: GetPermissionsOptions): Promise<Permission[]>;
  getPermissionById(id: string): Promise<Permission | null>;
  getPermissionByName(name: string): Promise<Permission | null>;
  createPermission(data: CreatePermissionData): Promise<Permission>;
  updatePermission(id: string, data: UpdatePermissionData): Promise<Permission>;
  deletePermission(id: string): Promise<void>;
  getUserPermissions(userId: string): Promise<Permission[]>;
  getRolePermissions(roleId: string): Promise<Permission[]>;
  checkUserHasPermission(userId: string, permission: string): Promise<boolean>;
  checkRoleHasPermission(roleId: string, permission: string): Promise<boolean>;
  getPermissionTree(): Promise<PermissionNode[]>;
}

/**
 * Get permissions options
 */
export interface GetPermissionsOptions {
  category?: string;
  resource?: string;
  action?: string;
  isActive?: boolean;
  sortBy?: 'name' | 'category' | 'created_at';
  sortOrder?: 'asc' | 'desc';
}

/**
 * Create permission data
 */
export interface CreatePermissionData {
  name: string;
  description?: string;
  category: string;
  resource: string;
  action: string;
  isActive?: boolean;
}

/**
 * Update permission data
 */
export interface UpdatePermissionData {
  name?: string;
  description?: string;
  category?: string;
  resource?: string;
  action?: string;
  isActive?: boolean;
}

/**
 * Permission tree node
 */
export interface PermissionNode {
  id: string;
  name: string;
  category: string;
  resource: string;
  action: string;
  children?: PermissionNode[];
  level: number;
}

// ============================================================================
// EMAIL SERVICE TYPES
// ============================================================================

/**
 * Email service interface
 */
export interface EmailServiceInterface extends BaseService {
  sendEmail(data: SendEmailData): Promise<EmailResult>;
  sendWelcomeEmail(user: User): Promise<EmailResult>;
  sendPasswordResetEmail(user: User, resetToken: string): Promise<EmailResult>;
  sendPasswordChangedEmail(user: User): Promise<EmailResult>;
  sendVerificationEmail(user: User, verificationToken: string): Promise<EmailResult>;
  sendBulkEmail(data: BulkEmailData): Promise<BulkEmailResult>;
  getEmailTemplate(name: string): Promise<EmailTemplate | null>;
  renderEmailTemplate(templateName: string, data: Record<string, any>): Promise<RenderedEmail>;
}

/**
 * Send email data
 */
export interface SendEmailData {
  to: string | string[];
  cc?: string | string[];
  bcc?: string | string[];
  subject: string;
  text?: string;
  html?: string;
  template?: {
    name: string;
    data: Record<string, any>;
  };
  attachments?: EmailAttachment[];
  priority?: 'low' | 'normal' | 'high';
  metadata?: Record<string, any>;
}

/**
 * Email attachment
 */
export interface EmailAttachment {
  filename: string;
  content: Buffer | string;
  contentType?: string;
  disposition?: 'attachment' | 'inline';
  cid?: string;
}

/**
 * Email result
 */
export interface EmailResult {
  success: boolean;
  messageId?: string;
  error?: string;
  timestamp: Date;
  recipients: string[];
  metadata?: Record<string, any>;
}

/**
 * Bulk email data
 */
export interface BulkEmailData {
  emails: SendEmailData[];
  batchSize?: number;
  delay?: number;
  template?: {
    name: string;
    defaultData?: Record<string, any>;
  };
}

/**
 * Bulk email result
 */
export interface BulkEmailResult {
  total: number;
  sent: number;
  failed: number;
  results: EmailResult[];
  errors: string[];
}

/**
 * Email template
 */
export interface EmailTemplate {
  id: string;
  name: string;
  subject: string;
  text?: string;
  html?: string;
  variables: string[];
  category: string;
  isActive: boolean;
  created_at: Date;
  updated_at: Date;
}

/**
 * Rendered email
 */
export interface RenderedEmail {
  subject: string;
  text?: string;
  html?: string;
}

// ============================================================================
// AUDIT SERVICE TYPES
// ============================================================================

/**
 * Audit service interface
 */
export interface AuditServiceInterface extends BaseService {
  log(entry: CreateAuditLogEntry): Promise<void>;
  getAuditLogs(options?: GetAuditLogsOptions): Promise<PaginatedResponse<AuditLogEntry>>;
  getAuditLogById(id: string): Promise<AuditLogEntry | null>;
  getUserAuditLogs(userId: string, options?: GetAuditLogsOptions): Promise<PaginatedResponse<AuditLogEntry>>;
  getResourceAuditLogs(resource: string, resourceId?: string, options?: GetAuditLogsOptions): Promise<PaginatedResponse<AuditLogEntry>>;
  deleteOldAuditLogs(olderThan: Date): Promise<number>;
  exportAuditLogs(options?: ExportAuditLogsOptions): Promise<string>;
}

/**
 * Create audit log entry
 */
export interface CreateAuditLogEntry {
  userId?: string;
  action: string;
  resource: string;
  resourceId?: string;
  method: string;
  path: string;
  statusCode?: number;
  ipAddress: string;
  userAgent: string;
  requestId: string;
  duration?: number;
  metadata?: Record<string, any>;
  changes?: {
    before?: any;
    after?: any;
  };
  success: boolean;
  errorMessage?: string;
}

/**
 * Get audit logs options
 */
export interface GetAuditLogsOptions {
  page?: number;
  limit?: number;
  userId?: string;
  action?: string;
  resource?: string;
  method?: string;
  statusCode?: number;
  success?: boolean;
  startDate?: Date;
  endDate?: Date;
  ipAddress?: string;
  sortBy?: keyof AuditLogEntry;
  sortOrder?: 'asc' | 'desc';
}

/**
 * Export audit logs options
 */
export interface ExportAuditLogsOptions extends GetAuditLogsOptions {
  format?: 'csv' | 'json' | 'xlsx';
  includeMetadata?: boolean;
  includeChanges?: boolean;
}

// ============================================================================
// NOTIFICATION SERVICE TYPES
// ============================================================================

/**
 * Notification service interface
 */
export interface NotificationServiceInterface extends BaseService {
  sendNotification(data: SendNotificationData): Promise<NotificationResult>;
  sendBulkNotifications(data: BulkNotificationData): Promise<BulkNotificationResult>;
  getUserNotifications(userId: string, options?: GetNotificationsOptions): Promise<PaginatedResponse<Notification>>;
  markNotificationAsRead(id: string): Promise<void>;
  markAllNotificationsAsRead(userId: string): Promise<void>;
  deleteNotification(id: string): Promise<void>;
  getNotificationSettings(userId: string): Promise<NotificationSettings>;
  updateNotificationSettings(userId: string, settings: UpdateNotificationSettings): Promise<NotificationSettings>;
}

/**
 * Send notification data
 */
export interface SendNotificationData {
  userId: string;
  type: string;
  title: string;
  message: string;
  data?: Record<string, any>;
  channels?: ('email' | 'push' | 'sms' | 'in_app')[];
  priority?: 'low' | 'normal' | 'high' | 'urgent';
  scheduledFor?: Date;
  expiresAt?: Date;
}

/**
 * Notification result
 */
export interface NotificationResult {
  id: string;
  success: boolean;
  channels: Record<string, { success: boolean; error?: string }>;
  timestamp: Date;
}

/**
 * Bulk notification data
 */
export interface BulkNotificationData {
  notifications: SendNotificationData[];
  batchSize?: number;
  delay?: number;
}

/**
 * Bulk notification result
 */
export interface BulkNotificationResult {
  total: number;
  sent: number;
  failed: number;
  results: NotificationResult[];
}

/**
 * Notification
 */
export interface Notification {
  id: string;
  userId: string;
  type: string;
  title: string;
  message: string;
  data?: Record<string, any>;
  read: boolean;
  readAt?: Date;
  priority: 'low' | 'normal' | 'high' | 'urgent';
  expiresAt?: Date;
  created_at: Date;
  updated_at: Date;
}

/**
 * Get notifications options
 */
export interface GetNotificationsOptions {
  page?: number;
  limit?: number;
  type?: string;
  read?: boolean;
  priority?: string;
  startDate?: Date;
  endDate?: Date;
  sortBy?: 'created_at' | 'priority' | 'read';
  sortOrder?: 'asc' | 'desc';
}

/**
 * Notification settings
 */
export interface NotificationSettings {
  userId: string;
  email: {
    enabled: boolean;
    types: string[];
  };
  push: {
    enabled: boolean;
    types: string[];
  };
  sms: {
    enabled: boolean;
    types: string[];
  };
  inApp: {
    enabled: boolean;
    types: string[];
  };
  quietHours: {
    enabled: boolean;
    start: string; // HH:mm format
    end: string; // HH:mm format
    timezone: string;
  };
  frequency: {
    digest: 'immediate' | 'hourly' | 'daily' | 'weekly';
    maxPerDay: number;
  };
}

/**
 * Update notification settings
 */
export interface UpdateNotificationSettings extends Partial<Omit<NotificationSettings, 'userId'>> {}

// ============================================================================
// UTILITY TYPES
// ============================================================================

/**
 * Service registry
 */
export interface ServiceRegistry {
  register<T extends BaseService>(name: string, service: T): void;
  get<T extends BaseService>(name: string): T | null;
  getAll(): Record<string, BaseService>;
  unregister(name: string): void;
  clear(): void;
}

/**
 * Service dependency
 */
export interface ServiceDependency {
  name: string;
  required: boolean;
  version?: string;
}

/**
 * Service lifecycle hooks
 */
export interface ServiceLifecycleHooks {
  beforeInitialize?(): Promise<void>;
  afterInitialize?(): Promise<void>;
  beforeDestroy?(): Promise<void>;
  afterDestroy?(): Promise<void>;
}

/**
 * Service error
 */
export interface ServiceError extends Error {
  service: string;
  code: string;
  statusCode?: number;
  metadata?: Record<string, any>;
}